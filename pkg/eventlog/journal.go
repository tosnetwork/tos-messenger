// Package eventlog implements the durable single-writer event journal.
//
// Transport delivery is at least once: a retry, a second Relay, a route
// switch, or a process restart can all present the same event again. This
// journal is the point where that stops being an application event. One
// process owns one state directory, every claim is atomic and fsynced before
// it is reported as fresh, and a restart does not erase replay protection.
//
// This is not a shared multi-process claim store. Concurrent writers on one
// directory would need a transactional store with atomic uniqueness
// constraints, and the exclusive directory lock used here is not that.
package eventlog

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"regexp"
	"sync"

	"github.com/tosnetwork/tos-messenger/internal/dirlock"
)

const (
	// Schema is the on-disk record schema identifier.
	Schema = "tos.messaging.event-journal.v1"

	lockName    = ".messenger-event-journal.lock"
	inboundDir  = "inbound"
	outboundDir = "outbound"

	// MaxRecordBytes bounds one on-disk record.
	MaxRecordBytes = 32 << 10
)

// State is the local delivery state of one event. It only ever moves forward.
type State string

const (
	// StateAccepted means the event was durably claimed and deduplicated. It
	// is what a DeliveryAck may report.
	StateAccepted State = "accepted"
	// StateApplied means an Agent runtime accepted the typed event. It is what
	// an ApplicationAck may report.
	StateApplied State = "applied"
	// StateRead means a person saw it. It is the only optional, user-facing
	// state, and it carries no protocol weight.
	StateRead State = "read"
)

var (
	eventPattern    = regexp.MustCompile(`^evt_[0-9a-f]{64}$`)
	endpointPattern = regexp.MustCompile(`^mep_[0-9a-f]{64}$`)
	convPattern     = regexp.MustCompile(`^conv_[0-9a-f]{64}$`)
)

// ErrConflict reports that an Event ID was presented with a different sender
// binding than the one already recorded. Content-addressed identifiers make
// this a forgery signal, never an ordinary duplicate.
var ErrConflict = errors.New("event identity conflicts with an existing claim")

// ErrUnknown reports that no claim exists for an Event ID.
var ErrUnknown = errors.New("event has no journal claim")

// Entry is a claim request.
type Entry struct {
	EventID          string
	SenderEndpointID string
	ConversationID   string
	AcceptedAtUnix   uint64
}

// Record is the durable state of one event.
type Record struct {
	Schema           string `json:"schema"`
	EventID          string `json:"event_id"`
	SenderEndpointID string `json:"sender_messaging_endpoint_id"`
	ConversationID   string `json:"conversation_id"`
	State            State  `json:"state"`
	AcceptedAtUnix   uint64 `json:"accepted_at_unix"`
	AppliedAtUnix    uint64 `json:"applied_at_unix,omitempty"`
	ReadAtUnix       uint64 `json:"read_at_unix,omitempty"`
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

// Accept durably claims an event exactly once.
//
// It returns fresh=true only after the claim is on disk and fsynced, so a
// caller that acts on fresh=true can be interrupted at any point without the
// event being processed twice on restart.
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
		State:            StateAccepted,
		AcceptedAtUnix:   entry.AcceptedAtUnix,
	}
	encoded, err := json.Marshal(record)
	if err != nil {
		return false, Record{}, err
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
		return false, Record{}, errors.New("create event claim")
	}
	existing, err := readRecord(path)
	if err != nil {
		return false, Record{}, err
	}
	if existing.SenderEndpointID != entry.SenderEndpointID || existing.ConversationID != entry.ConversationID {
		return false, Record{}, ErrConflict
	}
	return false, existing, nil
}

// MarkApplied records that an Agent runtime accepted the event.
func (j *Journal) MarkApplied(eventID string, atUnix uint64) (Record, error) {
	return j.advance(eventID, StateApplied, atUnix)
}

// MarkRead records an optional user-facing read indication.
func (j *Journal) MarkRead(eventID string, atUnix uint64) (Record, error) {
	return j.advance(eventID, StateRead, atUnix)
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

// advance moves one record forward. Regressions and repeated transitions are
// refused: a state machine that can be walked backwards is a state machine an
// attacker can use to replay an application event.
func (j *Journal) advance(eventID string, target State, atUnix uint64) (Record, error) {
	if err := j.usable(); err != nil {
		return Record{}, err
	}
	if !eventPattern.MatchString(eventID) {
		return Record{}, errors.New("invalid event identifier")
	}
	if atUnix == 0 {
		return Record{}, errors.New("invalid event transition time")
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
	if !canAdvance(record.State, target) {
		return Record{}, errors.New("event journal transition is not permitted")
	}
	switch target {
	case StateApplied:
		if atUnix < record.AcceptedAtUnix {
			return Record{}, errors.New("event applied before it was accepted")
		}
		record.AppliedAtUnix = atUnix
	case StateRead:
		if atUnix < record.AcceptedAtUnix {
			return Record{}, errors.New("event read before it was accepted")
		}
		record.ReadAtUnix = atUnix
	default:
		return Record{}, errors.New("unsupported event journal state")
	}
	record.State = target
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

// canAdvance encodes the forward-only state machine.
func canAdvance(current, target State) bool {
	switch target {
	case StateApplied:
		return current == StateAccepted
	case StateRead:
		return current == StateAccepted || current == StateApplied
	default:
		return false
	}
}

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
	if entry.AcceptedAtUnix == 0 {
		return errors.New("invalid event acceptance time")
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
		!endpointPattern.MatchString(record.SenderEndpointID) || !convPattern.MatchString(record.ConversationID) ||
		record.AcceptedAtUnix == 0 ||
		(record.State != StateAccepted && record.State != StateApplied && record.State != StateRead) {
		return Record{}, errors.New("invalid event journal record")
	}
	return record, nil
}
