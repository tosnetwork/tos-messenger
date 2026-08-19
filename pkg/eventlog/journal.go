// Package eventlog implements the durable single-writer journal.
//
// Transport delivery is at least once: a retry, a second Relay, a route
// switch, or a process restart can all present the same event again. This
// journal is where that stops being an application event, and where an event
// that has been accepted but not yet processed survives to be processed
// exactly once.
//
// The journal therefore stores the event itself, not only its identity. A
// journal that recorded "seen" without recording what was seen would create
// the worst outcome available: an event that is deduplicated forever and
// processed never, because the only copy was in the memory of a process that
// died.
//
// Delivery, application, and reading are separate dimensions rather than
// positions on one scale. A person marking a message read in a UI must not be
// able to stop a runtime from ever receiving it, which is what a single
// forward-only enum would do.
//
// This is not a shared multi-process claim store. Concurrent writers on one
// directory would need a transactional store with atomic uniqueness
// constraints, and the exclusive directory lock used here is not that.
package eventlog

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"sync"
	"time"

	"github.com/tosnetwork/tos-messenger/internal/canon"
	"github.com/tosnetwork/tos-messenger/internal/dirlock"
	"github.com/tosnetwork/tos-messenger/internal/ids"
	"github.com/tosnetwork/tos-messenger/pkg/fault"
)

const (
	// Schema is the on-disk record schema identifier.
	Schema = "tos.messaging.event-journal.v1"

	lockName    = ".messenger-event-journal.lock"
	inboundDir  = "inbound"
	outboundDir = "outbound"

	// MaxRecordBytes bounds one on-disk record. It has to hold a complete
	// event, because a record without its event cannot be re-delivered.
	MaxRecordBytes = 256 << 10
	// MaxPayloadBytes bounds the stored event.
	MaxPayloadBytes = 160 << 10

	// MinLeaseSeconds and MaxLeaseSeconds bound an application lease. A lease
	// that never expires strands an event when the worker holding it dies.
	MinLeaseSeconds = 1
	MaxLeaseSeconds = 60 * 60
)

// ApplicationState is how far an event has got towards an Agent runtime.
type ApplicationState string

const (
	// StateQueued means the event is durably received and waiting for a
	// runtime. It is what a DeliveryAck reports: the event survives a restart.
	StateQueued ApplicationState = "queued"
	// StateClaimed means a runtime holds a lease on it.
	StateClaimed ApplicationState = "claimed"
	// StateApplied means a runtime accepted it. It is what an ApplicationAck
	// reports.
	StateApplied ApplicationState = "applied"
	// StateRejected means a runtime refused it and it will not be offered
	// again.
	StateRejected ApplicationState = "rejected"
)

var (
	eventPattern    = ids.Event
	endpointPattern = ids.Endpoint
	convPattern     = ids.Conversation
	leasePattern    = regexp.MustCompile(`^lease_[0-9a-f]{64}$`)
)

// ErrConflict reports that an Event ID was presented with a different binding
// than the one already recorded. Content-addressed identifiers make this a
// forgery signal, never an ordinary duplicate.
var ErrConflict = errors.New("event identity conflicts with an existing claim")

// ErrUnknown reports that no record exists for an Event ID.
var ErrUnknown = errors.New("event has no journal record")

// ErrLeaseMismatch reports a transition presented with the wrong lease. The
// work may have been taken over, so the result of the old attempt is discarded
// rather than applied twice.
var ErrLeaseMismatch = errors.New("application lease does not hold this event")

// Entry is an inbound event to record.
type Entry struct {
	EventID          string
	SenderEndpointID string
	ConversationID   string
	// Payload is the event as it will be handed to a runtime after a restart.
	// Without it an accepted event cannot be re-delivered.
	Payload        []byte
	ReceivedAtUnix uint64
}

// Record is the durable state of one inbound event.
type Record struct {
	Schema           string           `json:"schema"`
	EventID          string           `json:"event_id"`
	SenderEndpointID string           `json:"sender_messaging_endpoint_id"`
	ConversationID   string           `json:"conversation_id"`
	PayloadBase64    string           `json:"payload_base64"`
	PayloadDigest    string           `json:"payload_digest"`
	ReceivedAtUnix   uint64           `json:"received_at_unix"`
	Application      ApplicationState `json:"application"`
	LeaseID          string           `json:"lease_id,omitempty"`
	LeaseExpiresAt   uint64           `json:"lease_expires_at_unix,omitempty"`
	AppliedAtUnix    uint64           `json:"applied_at_unix,omitempty"`
	RejectedAtUnix   uint64           `json:"rejected_at_unix,omitempty"`
	RejectionCode    fault.Code       `json:"rejection_code,omitempty"`
	ReadAtUnix       uint64           `json:"read_at_unix,omitempty"`
}

// Payload returns the stored event.
func (r Record) Payload() ([]byte, error) {
	payload, err := base64.StdEncoding.Strict().DecodeString(r.PayloadBase64)
	if err != nil {
		return nil, errors.New("invalid stored event payload")
	}
	if canon.Digest(payload) != r.PayloadDigest {
		return nil, errors.New("stored event payload does not match its digest")
	}
	return payload, nil
}

// Terminal reports whether the runtime is finished with this event.
func (r Record) Terminal() bool {
	return r.Application == StateApplied || r.Application == StateRejected
}

// Journal is the single-writer durable store for one state directory.
type Journal struct {
	root  string
	lock  *dirlock.Lock
	mutex sync.Mutex
}

// Open takes ownership of a private state directory. A second Open on the same
// directory fails with dirlock.ErrHeld rather than quietly sharing it.
func Open(root string) (*Journal, error) {
	if !filepath.IsAbs(root) || filepath.Clean(root) != root {
		return nil, errors.New("invalid event journal root")
	}
	if err := os.MkdirAll(root, 0o700); err != nil {
		return nil, errors.New("create event journal root")
	}
	info, err := os.Lstat(root)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm() != 0o700 {
		return nil, errors.New("event journal root must be a private directory")
	}
	for _, name := range []string{inboundDir, outboundDir} {
		if err := os.MkdirAll(filepath.Join(root, name), 0o700); err != nil {
			return nil, errors.New("create event journal directory")
		}
	}
	ownership, err := dirlock.Acquire(root, lockName)
	if err != nil {
		return nil, err
	}
	return &Journal{root: root, lock: ownership}, nil
}

// Accept durably records an event exactly once, together with the event
// itself.
//
// It returns fresh=true only after the record is on disk and fsynced, so a
// caller that acknowledges delivery on fresh=true is telling the truth: the
// event survives a crash and will be offered to a runtime by ListPending.
func (j *Journal) Accept(entry Entry) (bool, Record, error) {
	if err := j.usable(); err != nil {
		return false, Record{}, err
	}
	if err := validateEntry(entry); err != nil {
		return false, Record{}, err
	}
	j.mutex.Lock()
	defer j.mutex.Unlock()

	path := j.path(entry.EventID)
	record := Record{
		Schema:           Schema,
		EventID:          entry.EventID,
		SenderEndpointID: entry.SenderEndpointID,
		ConversationID:   entry.ConversationID,
		PayloadBase64:    base64.StdEncoding.EncodeToString(entry.Payload),
		PayloadDigest:    canon.Digest(entry.Payload),
		ReceivedAtUnix:   entry.ReceivedAtUnix,
		Application:      StateQueued,
	}
	encoded, err := json.Marshal(record)
	if err != nil {
		return false, Record{}, err
	}
	if len(encoded) > MaxRecordBytes {
		return false, Record{}, errors.New("event record exceeds its bound")
	}
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err == nil {
		if err := writeAndSync(file, path, encoded); err != nil {
			return false, Record{}, err
		}
		if err := syncDirectory(j.inboundRoot()); err != nil {
			_ = os.Remove(path)
			return false, Record{}, err
		}
		return true, record, nil
	}
	if !errors.Is(err, os.ErrExist) {
		return false, Record{}, errors.New("create event record")
	}
	existing, err := readRecord(path)
	if err != nil {
		return false, Record{}, err
	}
	if existing.SenderEndpointID != entry.SenderEndpointID ||
		existing.ConversationID != entry.ConversationID ||
		existing.PayloadDigest != record.PayloadDigest {
		return false, Record{}, ErrConflict
	}
	return false, existing, nil
}

// ListPending returns the events a runtime still has to process, oldest first.
//
// It includes events whose lease has expired, which is how work is recovered
// from a worker that died holding it. This is the call that closes the gap
// between "deduplicated" and "processed": without it, an event accepted before
// a crash would be recognised as a duplicate forever and delivered never.
func (j *Journal) ListPending(now time.Time, limit int) ([]Record, error) {
	if err := j.usable(); err != nil {
		return nil, err
	}
	if now.IsZero() || now.Unix() < 0 {
		return nil, errors.New("invalid pending sweep time")
	}
	j.mutex.Lock()
	defer j.mutex.Unlock()

	entries, err := os.ReadDir(j.inboundRoot())
	if err != nil {
		return nil, errors.New("read event journal")
	}
	seconds := uint64(now.Unix())
	var pending []Record
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		record, err := readRecord(filepath.Join(j.inboundRoot(), entry.Name()))
		if err != nil {
			continue
		}
		switch record.Application {
		case StateQueued:
		case StateClaimed:
			if record.LeaseExpiresAt > seconds {
				continue
			}
		default:
			continue
		}
		pending = append(pending, record)
	}
	sort.Slice(pending, func(first, second int) bool {
		if pending[first].ReceivedAtUnix != pending[second].ReceivedAtUnix {
			return pending[first].ReceivedAtUnix < pending[second].ReceivedAtUnix
		}
		return pending[first].EventID < pending[second].EventID
	})
	if limit > 0 && len(pending) > limit {
		pending = pending[:limit]
	}
	return pending, nil
}

// ClaimForApplication takes a lease on an event so exactly one runtime
// attempt owns it.
//
// A queued event, or one whose previous lease has expired, may be claimed. An
// event under a live lease may not, which is what stops two attempts from
// calling the same tool or asking for the same approval twice.
func (j *Journal) ClaimForApplication(eventID, leaseID string, now time.Time, lease time.Duration) (Record, error) {
	if err := j.usable(); err != nil {
		return Record{}, err
	}
	if !eventPattern.MatchString(eventID) {
		return Record{}, errors.New("invalid event identifier")
	}
	if !leasePattern.MatchString(leaseID) {
		return Record{}, errors.New("invalid application lease identifier")
	}
	if now.IsZero() || now.Unix() < 0 {
		return Record{}, errors.New("invalid application claim time")
	}
	seconds := lease / time.Second
	if seconds < MinLeaseSeconds || seconds > MaxLeaseSeconds {
		return Record{}, errors.New("application lease is outside its bounds")
	}
	j.mutex.Lock()
	defer j.mutex.Unlock()

	path := j.path(eventID)
	record, err := readRecord(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return Record{}, ErrUnknown
		}
		return Record{}, err
	}
	current := uint64(now.Unix())
	switch record.Application {
	case StateQueued:
	case StateClaimed:
		if record.LeaseExpiresAt > current {
			return Record{}, ErrLeaseMismatch
		}
	default:
		return Record{}, ErrNotPending
	}
	if record.LeaseID == leaseID {
		return Record{}, errors.New("application lease identifier was reused")
	}
	record.Application = StateClaimed
	record.LeaseID = leaseID
	record.LeaseExpiresAt = current + uint64(seconds)
	return j.commit(path, record)
}

// CompleteApplication records that a runtime accepted the event.
//
// The lease identifier must still be the one on the record. If another attempt
// took the work over, this attempt's result is discarded rather than applied a
// second time.
func (j *Journal) CompleteApplication(eventID, leaseID string, now time.Time) (Record, error) {
	return j.finish(eventID, leaseID, StateApplied, "", now)
}

// RejectApplication records that a runtime refused the event. It is not
// offered again.
func (j *Journal) RejectApplication(eventID, leaseID string, code fault.Code, now time.Time) (Record, error) {
	if code != "" && !fault.Known(code) {
		return Record{}, errors.New("unknown rejection code")
	}
	return j.finish(eventID, leaseID, StateRejected, code, now)
}

// MarkRead records an optional user-facing read indication.
//
// It is independent of the application dimension. A person reading a message
// in a UI before a runtime has seen it must not prevent the runtime from ever
// seeing it.
func (j *Journal) MarkRead(eventID string, now time.Time) (Record, error) {
	if err := j.usable(); err != nil {
		return Record{}, err
	}
	if !eventPattern.MatchString(eventID) {
		return Record{}, errors.New("invalid event identifier")
	}
	if now.IsZero() || now.Unix() < 0 {
		return Record{}, errors.New("invalid read time")
	}
	j.mutex.Lock()
	defer j.mutex.Unlock()

	path := j.path(eventID)
	record, err := readRecord(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return Record{}, ErrUnknown
		}
		return Record{}, err
	}
	if record.ReadAtUnix != 0 {
		return record, nil
	}
	current := uint64(now.Unix())
	if current < record.ReceivedAtUnix {
		return Record{}, errors.New("event read before it was received")
	}
	record.ReadAtUnix = current
	return j.commit(path, record)
}

// Lookup returns the durable record for an event.
func (j *Journal) Lookup(eventID string) (Record, bool, error) {
	if err := j.usable(); err != nil {
		return Record{}, false, err
	}
	if !eventPattern.MatchString(eventID) {
		return Record{}, false, errors.New("invalid event identifier")
	}
	j.mutex.Lock()
	defer j.mutex.Unlock()
	record, err := readRecord(j.path(eventID))
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return Record{}, false, nil
		}
		return Record{}, false, err
	}
	return record, true, nil
}

// Close releases directory ownership.
func (j *Journal) Close() error {
	if j == nil {
		return nil
	}
	j.mutex.Lock()
	defer j.mutex.Unlock()
	if j.lock == nil {
		return nil
	}
	lock := j.lock
	j.lock = nil
	return lock.Close()
}

func (j *Journal) finish(eventID, leaseID string, state ApplicationState, code fault.Code, now time.Time) (Record, error) {
	if err := j.usable(); err != nil {
		return Record{}, err
	}
	if !eventPattern.MatchString(eventID) {
		return Record{}, errors.New("invalid event identifier")
	}
	if !leasePattern.MatchString(leaseID) {
		return Record{}, errors.New("invalid application lease identifier")
	}
	if now.IsZero() || now.Unix() < 0 {
		return Record{}, errors.New("invalid application completion time")
	}
	j.mutex.Lock()
	defer j.mutex.Unlock()

	path := j.path(eventID)
	record, err := readRecord(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return Record{}, ErrUnknown
		}
		return Record{}, err
	}
	if record.Application != StateClaimed {
		return Record{}, ErrNotPending
	}
	if record.LeaseID != leaseID {
		return Record{}, ErrLeaseMismatch
	}
	current := uint64(now.Unix())
	record.Application = state
	record.LeaseID = ""
	record.LeaseExpiresAt = 0
	if state == StateApplied {
		record.AppliedAtUnix = current
	} else {
		record.RejectedAtUnix = current
		record.RejectionCode = code
	}
	return j.commit(path, record)
}

func (j *Journal) commit(path string, record Record) (Record, error) {
	encoded, err := json.Marshal(record)
	if err != nil {
		return Record{}, err
	}
	if err := j.replace(path, encoded); err != nil {
		return Record{}, err
	}
	return record, nil
}

// replace commits a new record body through a temporary file and an atomic
// rename, so a crash leaves either the old record or the new one.
func (j *Journal) replace(path string, encoded []byte) error {
	if len(encoded) > MaxRecordBytes {
		return errors.New("event record exceeds its bound")
	}
	temporary, err := os.CreateTemp(filepath.Dir(path), ".transition-")
	if err != nil {
		return errors.New("create event transition")
	}
	name := temporary.Name()
	defer os.Remove(name)
	if err := temporary.Chmod(0o600); err != nil {
		_ = temporary.Close()
		return errors.New("protect event transition")
	}
	if err := writeAndSync(temporary, name, encoded); err != nil {
		return err
	}
	if err := os.Rename(name, path); err != nil {
		return errors.New("commit event transition")
	}
	return syncDirectory(filepath.Dir(path))
}

func (j *Journal) usable() error {
	if j == nil || j.lock == nil || !j.lock.Held() {
		return errors.New("event journal is not owned by this process")
	}
	return nil
}

func (j *Journal) path(eventID string) string {
	return filepath.Join(j.root, inboundDir, eventID[len("evt_"):]+".json")
}

func (j *Journal) deliveryPath(eventID string) string {
	return filepath.Join(j.root, outboundDir, eventID[len("evt_"):]+".json")
}

func (j *Journal) inboundRoot() string  { return filepath.Join(j.root, inboundDir) }
func (j *Journal) outboundRoot() string { return filepath.Join(j.root, outboundDir) }

func validateEntry(entry Entry) error {
	if !eventPattern.MatchString(entry.EventID) {
		return errors.New("invalid event identifier")
	}
	if !endpointPattern.MatchString(entry.SenderEndpointID) {
		return errors.New("invalid event sender endpoint")
	}
	if !convPattern.MatchString(entry.ConversationID) {
		return errors.New("invalid event conversation identifier")
	}
	if len(entry.Payload) == 0 || len(entry.Payload) > MaxPayloadBytes {
		return errors.New("invalid stored event payload")
	}
	if entry.ReceivedAtUnix == 0 {
		return errors.New("invalid event receipt time")
	}
	return nil
}

func writeAndSync(file *os.File, path string, encoded []byte) error {
	if _, err := file.Write(append(encoded, '\n')); err != nil {
		_ = file.Close()
		_ = os.Remove(path)
		return errors.New("write event record")
	}
	if err := file.Sync(); err != nil {
		_ = file.Close()
		_ = os.Remove(path)
		return errors.New("sync event record")
	}
	if err := file.Close(); err != nil {
		_ = os.Remove(path)
		return errors.New("close event record")
	}
	return nil
}

func syncDirectory(path string) error {
	directory, err := os.Open(path)
	if err != nil {
		return errors.New("open event journal directory")
	}
	defer directory.Close()
	if err := directory.Sync(); err != nil {
		return errors.New("sync event journal directory")
	}
	return nil
}

// readRecordBytes applies the file-level checks every journal record shares: a
// regular, private, bounded file that is not a symlink.
func readRecordBytes(path string) ([]byte, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm() != 0o600 ||
		info.Size() <= 0 || info.Size() > MaxRecordBytes {
		return nil, errors.New("invalid event journal record")
	}
	value, err := os.ReadFile(path)
	if err != nil {
		return nil, errors.New("read event journal record")
	}
	return value, nil
}

func readRecord(path string) (Record, error) {
	value, err := readRecordBytes(path)
	if err != nil {
		return Record{}, err
	}
	var record Record
	if err := json.Unmarshal(value, &record); err != nil {
		return Record{}, errors.New("invalid event journal record")
	}
	if record.Schema != Schema || !eventPattern.MatchString(record.EventID) ||
		!endpointPattern.MatchString(record.SenderEndpointID) ||
		!convPattern.MatchString(record.ConversationID) ||
		record.ReceivedAtUnix == 0 || !canon.ValidDigest(record.PayloadDigest) {
		return Record{}, errors.New("invalid event journal record")
	}
	switch record.Application {
	case StateQueued, StateClaimed, StateApplied, StateRejected:
	default:
		return Record{}, errors.New("invalid event journal record")
	}
	if record.Application == StateClaimed && (!leasePattern.MatchString(record.LeaseID) || record.LeaseExpiresAt == 0) {
		return Record{}, errors.New("invalid event journal record")
	}
	if record.RejectionCode != "" && !fault.Known(record.RejectionCode) {
		return Record{}, errors.New("invalid event journal record")
	}
	if _, err := record.Payload(); err != nil {
		return Record{}, errors.New("invalid event journal record")
	}
	return record, nil
}

// NewLeaseID formats an application lease identifier.
func NewLeaseID(raw []byte) (string, error) {
	return ids.Format("lease_", raw)
}
