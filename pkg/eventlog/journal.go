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
	// canonicalStateMarker prevents a binary whose content-addressed network
	// preimages changed from silently treating an older state tree as empty.
	// There is deliberately no automatic upgrade: events, mandates, budgets,
	// approvals and sessions must migrate as one reviewed transaction.
	canonicalStateMarkerName = ".canonical-network-preimages"
	canonicalStateMarker     = "tos.messaging.canonical-network-preimages.v2\n"

	lockName       = ".messenger-event-journal.lock"
	inboundDir     = "inbound"
	outboundDir    = "outbound"
	compositionDir = "outbound-compositions"
	moderationDir  = "room-moderation"
	historySyncDir = "history-sync"

	// MaxRecordBytes bounds one on-disk record. It has to hold a complete
	// event, because a record without its event cannot be re-delivered, and an
	// outbound record holds both the queued event and its sealed form.
	MaxRecordBytes = 768 << 10
	// MaxPayloadBytes bounds the stored event.
	MaxPayloadBytes = 160 << 10
	// MaxCiphertextBytes bounds a stored sealed message. Retrying a delivery
	// must send the same ciphertext rather than sealing again, or every network
	// retry would consume another message key.
	MaxCiphertextBytes = MaxPayloadBytes + 4<<10

	// MinLeaseSeconds and MaxLeaseSeconds bound an application lease. A lease
	// that never expires strands an event when the worker holding it dies.
	MinLeaseSeconds = 1
	MaxLeaseSeconds = 60 * 60
)

// AdmissionState is whether an event may be offered to a runtime at all.
//
// It is a separate dimension from the application state because it answers a
// different question and a different party answers it. Application state is
// how far the runtime has got with an event it was allowed to see; admission
// is whether the owner allows it to see it. Folding the two together is how an
// event that was supposed to be waiting for a person ends up in the runtime's
// queue.
type AdmissionState string

const (
	// AdmissionAdmitted means the event may be offered to a runtime.
	AdmissionAdmitted AdmissionState = "admitted"
	// AdmissionPending means the owner has not decided yet. The runtime does
	// not see it.
	AdmissionPending AdmissionState = "pending"
	// AdmissionDenied means the owner refused it. It is never offered.
	AdmissionDenied AdmissionState = "denied"
)

// CryptoState is whether the session transition that decrypted an event has
// been committed.
//
// It is a third dimension, separate from admission and from application, and
// it exists because those two answer questions about people and runtimes while
// this one answers a question about the ratchet. Folding it into either would
// mean an event could be handed to a runtime -- acted on, tools run, money
// discussed -- while the session state still says the ciphertext was never
// opened. The sender's retry would then be accepted a second time, or, if no
// retry came, the local ratchet would sit one message behind for good.
type CryptoState string

const (
	// CryptoUnbound marks a record whose caller never named a session. There
	// is no transition to commit, so there is nothing to wait for.
	CryptoUnbound CryptoState = "unbound"
	// CryptoStaged marks a record whose session transition has not been
	// committed yet. It is never offered to a runtime.
	CryptoStaged CryptoState = "staged"
	// CryptoCommitted marks a record whose session transition is durable.
	CryptoCommitted CryptoState = "committed"
	// CryptoAbandoned marks a staged record whose transition can no longer be
	// applied, because the session moved on without it. The ciphertext was
	// never consumed, so the event is not delivered and a resend will decrypt
	// normally.
	CryptoAbandoned CryptoState = "abandoned"
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
	attemptPattern  = regexp.MustCompile(`^send_[0-9a-f]{64}$`)
)

// ErrConflict reports that an Event ID was presented with a different binding
// than the one already recorded. Content-addressed identifiers make this a
// forgery signal, never an ordinary duplicate.
var ErrConflict = errors.New("event identity conflicts with an existing claim")

// ErrUnknown reports that no record exists for an Event ID.
var ErrUnknown = errors.New("event has no journal record")

// ErrNotAdmitted reports work on an event the owner has not allowed a runtime
// to see.
var ErrNotAdmitted = errors.New("event has not been admitted")

// ErrLeaseMismatch reports a transition presented with the wrong lease. The
// work may have been taken over, so the result of the old attempt is discarded
// rather than applied twice.
var ErrLeaseMismatch = errors.New("application lease does not hold this event")

// ErrApplicationKind reports that a caller tried to claim an event reserved
// for another application adapter. In particular, typed Agent Packets belong
// to the daemon-owned provider bridge rather than to the general Agent
// runtime.
var ErrApplicationKind = errors.New("event belongs to another application adapter")

// Entry is an inbound event to record.
type Entry struct {
	EventID          string
	SenderEndpointID string
	ConversationID   string
	// Payload is the event as it will be handed to a runtime after a restart.
	// Without it an accepted event cannot be re-delivered.
	Payload []byte
	// Admission is whether the owner has allowed this event to reach a
	// runtime. An entry that does not say is not admitted by default.
	Admission      AdmissionState
	ReceivedAtUnix uint64
	// ExpiresAtUnix is the event's own expiry, carried here so the journal can
	// retire an undecided event without decoding it. A queue that only a
	// person can drain must not depend on that person for its bounds.
	ExpiresAtUnix uint64

	// Transition describes the session commitment this event is part of. It is
	// set by CommitInbound and left empty by callers that decrypted elsewhere.
	Transition *Transition
}

// Transition is the session advance one inbound event depends on.
//
// It is stored with the event so a process that dies between writing the event
// and advancing the session can finish the job by itself. Recovering by
// waiting for the sender to retry would leave correctness in somebody else's
// hands, and a sender that never retries would leave this ratchet behind for
// good.
type Transition struct {
	SessionID string
	Algorithm string
	// ExpectedGeneration is the session generation the transition was prepared
	// against. It is what tells recovery whether the advance already happened.
	ExpectedGeneration uint64
	// NextState is the session state after the ciphertext was opened.
	NextState []byte
}

// Record is the durable state of one inbound event.
type Record struct {
	Schema           string           `json:"schema"`
	EventID          string           `json:"event_id"`
	SenderEndpointID string           `json:"sender_messaging_endpoint_id"`
	ConversationID   string           `json:"conversation_id"`
	Admission        AdmissionState   `json:"admission"`
	AdmissionAtUnix  uint64           `json:"admission_at_unix,omitempty"`
	AdmissionCode    fault.Code       `json:"admission_code,omitempty"`
	PayloadBase64    string           `json:"payload_base64"`
	PayloadDigest    string           `json:"payload_digest"`
	ReceivedAtUnix   uint64           `json:"received_at_unix"`
	EventExpiresAt   uint64           `json:"event_expires_at_unix,omitempty"`
	Crypto           CryptoState      `json:"crypto"`
	CryptoAtUnix     uint64           `json:"crypto_at_unix,omitempty"`
	SessionID        string           `json:"session_id,omitempty"`
	AlgorithmID      string           `json:"algorithm_id,omitempty"`
	ExpectedGen      uint64           `json:"expected_session_generation,omitempty"`
	NextStateBase64  string           `json:"next_session_state_base64,omitempty"`
	NextStateDigest  string           `json:"next_session_state_digest,omitempty"`
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

// NextState returns the session state this event's transition would install.
func (r Record) NextState() ([]byte, error) {
	if r.NextStateBase64 == "" {
		return nil, errors.New("record carries no session transition")
	}
	state, err := base64.StdEncoding.Strict().DecodeString(r.NextStateBase64)
	if err != nil {
		return nil, errors.New("invalid stored session transition")
	}
	if canon.Digest(state) != r.NextStateDigest {
		return nil, errors.New("stored session transition does not match its digest")
	}
	return state, nil
}

// Deliverable reports whether an event may be offered to a runtime.
//
// A staged or abandoned transition is not deliverable whatever its admission
// or application state says: the ratchet has not recorded that this ciphertext
// was opened, so handing the event over would be acting on a message the
// session still considers unread.
func (r Record) Deliverable() bool {
	return r.Crypto == CryptoCommitted || r.Crypto == CryptoUnbound
}

// Terminal reports whether the runtime is finished with this event.
func (r Record) Terminal() bool {
	return r.Application == StateApplied || r.Application == StateRejected
}

// Journal is the single-writer durable store for one state directory.
type Journal struct {
	root  string
	lock  *dirlock.Lock
	quota Quota
	mutex sync.Mutex
}

// Open takes ownership of a private state directory. A second Open on the same
// directory fails with dirlock.ErrHeld rather than quietly sharing it.
func Open(root string) (*Journal, error) { return OpenWith(root, DefaultQuota()) }

// OpenWith takes ownership of a state directory under stated bounds.
func OpenWith(root string, quota Quota) (*Journal, error) {
	if err := quota.Validate(); err != nil {
		return nil, err
	}
	return openJournalAt(root, quota)
}

func openJournalAt(root string, quota Quota) (*Journal, error) {
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
	if err := ensureCanonicalStateMarker(root); err != nil {
		return nil, err
	}
	for _, name := range []string{inboundDir, outboundDir, compositionDir, moderationDir, historySyncDir, sessionDir, approvalDir, mandateDir, budgetDir, mandateBudgetDir, negotiationDir, devicePrekeyDir, prekeyContributionDir, prekeyPublicationDir, deviceDir, roomDir, mlsDir, executionDir, toolExecutionDir, escrowLocatorDir, agentPacketDir, admissionInviteDir} {
		if err := os.MkdirAll(filepath.Join(root, name), 0o700); err != nil {
			return nil, errors.New("create event journal directory")
		}
	}
	ownership, err := dirlock.Acquire(root, lockName)
	if err != nil {
		return nil, err
	}
	journal := &Journal{root: root, lock: ownership, quota: quota}
	// A process that died between staging an event and advancing its session
	// left a decision nobody made. Finishing it here means recovery does not
	// depend on the sender noticing and trying again.
	if err := journal.recoverStaged(); err != nil {
		_ = ownership.Close()
		return nil, err
	}
	// The seam between budgets and negotiations is repaired the same way, for
	// the same reason: a decision a crash interrupted is finished by the
	// process that owns the records, not left for a person to notice.
	if err := journal.reconcileCommerce(); err != nil {
		_ = ownership.Close()
		return nil, err
	}
	return journal, nil
}

func ensureCanonicalStateMarker(root string) error {
	path := filepath.Join(root, canonicalStateMarkerName)
	if err := verifyCanonicalStateMarker(path); err == nil {
		return nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	entries, err := os.ReadDir(root)
	if err != nil {
		return errors.New("read event journal root")
	}
	if len(entries) != 0 {
		if err := verifyCanonicalStateMarker(path); err == nil {
			return nil
		}
		return errors.New("event journal predates the canonical network representation; explicit state migration is required")
	}
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if errors.Is(err, os.ErrExist) {
		return verifyCanonicalStateMarker(path)
	}
	if err != nil {
		return errors.New("create canonical state marker")
	}
	remove := true
	defer func() {
		_ = file.Close()
		if remove {
			_ = os.Remove(path)
		}
	}()
	if _, err := file.WriteString(canonicalStateMarker); err != nil {
		return errors.New("write canonical state marker")
	}
	if err := file.Sync(); err != nil {
		return errors.New("sync canonical state marker")
	}
	if err := file.Close(); err != nil {
		return errors.New("close canonical state marker")
	}
	if err := syncDirectory(root); err != nil {
		return err
	}
	remove = false
	return nil
}

func verifyCanonicalStateMarker(path string) error {
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm() != 0o600 || info.Size() != int64(len(canonicalStateMarker)) {
		return errors.New("invalid canonical state marker")
	}
	raw, err := os.ReadFile(path)
	if err != nil || string(raw) != canonicalStateMarker {
		return errors.New("unsupported canonical state generation")
	}
	return nil
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

	// An event waiting on a person is bounded. Without that, a delegated
	// counterparty inside its own scope can send a new identifier every second
	// and fill the owner's queue and the disk behind it.
	if entry.Admission == AdmissionPending {
		if err := j.pendingCapacity(entry.SenderEndpointID, len(entry.Payload), entry.receivedAt()); err != nil {
			return false, Record{}, err
		}
	}
	path := j.path(entry.EventID)
	record := Record{
		Schema:           Schema,
		EventID:          entry.EventID,
		SenderEndpointID: entry.SenderEndpointID,
		ConversationID:   entry.ConversationID,
		Admission:        entry.Admission,
		PayloadBase64:    base64.StdEncoding.EncodeToString(entry.Payload),
		PayloadDigest:    canon.Digest(entry.Payload),
		ReceivedAtUnix:   entry.ReceivedAtUnix,
		EventExpiresAt:   entry.ExpiresAtUnix,
		Crypto:           CryptoUnbound,
		Application:      StateQueued,
	}
	// A record that names a session is staged, not delivered. It becomes
	// visible to a runtime only once the session has recorded that this
	// ciphertext was opened.
	if entry.Transition != nil {
		record.Crypto = CryptoStaged
		record.SessionID = entry.Transition.SessionID
		record.AlgorithmID = entry.Transition.Algorithm
		record.ExpectedGen = entry.Transition.ExpectedGeneration
		record.NextStateBase64 = base64.StdEncoding.EncodeToString(entry.Transition.NextState)
		record.NextStateDigest = canon.Digest(entry.Transition.NextState)
		record.CryptoAtUnix = entry.ReceivedAtUnix
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
		// An event the owner has not admitted is not the runtime's to see.
		if record.Admission != AdmissionAdmitted {
			continue
		}
		// Nor is one whose session transition is not committed. The ratchet
		// has not recorded that this ciphertext was opened, so handing the
		// event over would be acting on a message the session considers
		// unread.
		if !record.Deliverable() {
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
		// Moderation is an auditable presentation overlay: keep the immutable
		// target record, but do not offer a currently hidden queued message to a
		// runtime. A damaged decision fails the whole listing closed rather than
		// exposing content whose authority cannot be determined.
		decision, moderated, moderationErr := (&ModerationLedger{journal: j}).read(record.EventID)
		if moderationErr != nil {
			return nil, moderationErr
		}
		if moderated && decision.Action == "hide" {
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
	return j.claimForApplicationKind(eventID, leaseID, now, lease, "", nil)
}

// ClaimForApplicationKind atomically leases an event only when its decoded
// kind is exactly kind. This prevents a general runtime and a typed daemon
// adapter from racing after both observed the same pending listing.
func (j *Journal) ClaimForApplicationKind(eventID, leaseID string, now time.Time, lease time.Duration, kind string) (Record, error) {
	if kind == "" {
		return Record{}, errors.New("application event kind is required")
	}
	return j.claimForApplicationKind(eventID, leaseID, now, lease, kind, nil)
}

// ClaimForApplicationExceptKind atomically leases an event unless it carries
// the reserved kind. It is the claim primitive exposed to the general runtime.
func (j *Journal) ClaimForApplicationExceptKind(eventID, leaseID string, now time.Time, lease time.Duration, kind string) (Record, error) {
	if kind == "" {
		return Record{}, errors.New("excluded application event kind is required")
	}
	return j.ClaimForApplicationExceptKinds(eventID, leaseID, now, lease, []string{kind})
}

// ClaimForApplicationExceptKinds atomically excludes every daemon-owned typed
// adapter from the general runtime claim path.
func (j *Journal) ClaimForApplicationExceptKinds(eventID, leaseID string, now time.Time, lease time.Duration, kinds []string) (Record, error) {
	if len(kinds) == 0 || len(kinds) > 16 {
		return Record{}, errors.New("excluded application event kinds are required and bounded")
	}
	excluded := make(map[string]struct{}, len(kinds))
	for _, kind := range kinds {
		if kind == "" {
			return Record{}, errors.New("excluded application event kind is required")
		}
		if _, duplicate := excluded[kind]; duplicate {
			return Record{}, errors.New("excluded application event kinds must be unique")
		}
		excluded[kind] = struct{}{}
	}
	return j.claimForApplicationKind(eventID, leaseID, now, lease, "", excluded)
}

func (j *Journal) claimForApplicationKind(eventID, leaseID string, now time.Time, lease time.Duration, required string, excluded map[string]struct{}) (Record, error) {
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
	if required != "" || len(excluded) != 0 {
		payload, payloadErr := record.Payload()
		if payloadErr != nil {
			return Record{}, payloadErr
		}
		var document struct {
			Kind string `json:"event_kind"`
		}
		if json.Unmarshal(payload, &document) != nil || document.Kind == "" {
			return Record{}, errors.New("stored event has no application kind")
		}
		if required != "" && document.Kind != required {
			return Record{}, ErrApplicationKind
		}
		if _, blocked := excluded[document.Kind]; blocked {
			return Record{}, ErrApplicationKind
		}
	}
	if record.Admission != AdmissionAdmitted {
		return Record{}, ErrNotAdmitted
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
	switch entry.Admission {
	case AdmissionAdmitted, AdmissionPending, AdmissionDenied:
	default:
		return errors.New("an entry must say whether it was admitted")
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
	switch record.Admission {
	case AdmissionAdmitted, AdmissionPending, AdmissionDenied:
	default:
		return Record{}, errors.New("invalid event journal record")
	}
	if record.AdmissionCode != "" && !fault.Known(record.AdmissionCode) {
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

// NewAttemptID formats a send attempt identifier.
func NewAttemptID(raw []byte) (string, error) {
	return ids.Format("send_", raw)
}

// NewLeaseID formats an application lease identifier.
func NewLeaseID(raw []byte) (string, error) {
	return ids.Format("lease_", raw)
}

func idsFormat(prefix string, raw []byte) (string, error) {
	return ids.Format(prefix, raw)
}

// ListAwaitingAdmission returns the events the owner has yet to decide about.
//
// It is a separate listing from ListPending and serves a different caller.
// Merging them would put an event that is waiting for a person in the queue a
// runtime drains, which is the whole failure this dimension exists to prevent.
func (j *Journal) ListAwaitingAdmission(now time.Time, limit int) ([]Record, error) {
	if err := j.usable(); err != nil {
		return nil, err
	}
	j.mutex.Lock()
	defer j.mutex.Unlock()

	entries, err := os.ReadDir(j.inboundRoot())
	if err != nil {
		return nil, errors.New("read event journal")
	}
	var waiting []Record
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		record, err := readRecord(filepath.Join(j.inboundRoot(), entry.Name()))
		if err != nil {
			continue
		}
		if record.Admission != AdmissionPending {
			continue
		}
		// An event that ran out of time is not still waiting for a decision.
		if record.expired(j.quota, uint64(now.Unix())) {
			continue
		}
		waiting = append(waiting, record)
	}
	sort.Slice(waiting, func(first, second int) bool {
		if waiting[first].ReceivedAtUnix != waiting[second].ReceivedAtUnix {
			return waiting[first].ReceivedAtUnix < waiting[second].ReceivedAtUnix
		}
		return waiting[first].EventID < waiting[second].EventID
	})
	if limit > 0 && len(waiting) > limit {
		waiting = waiting[:limit]
	}
	return waiting, nil
}

// AdmitEvent records the owner allowing an event through to a runtime.
func (j *Journal) AdmitEvent(eventID string, now time.Time) (Record, error) {
	return j.decideAdmission(eventID, AdmissionAdmitted, "", now)
}

// DenyEvent records the owner refusing one. It is never offered to a runtime,
// and its application state is settled so nothing else picks it up.
func (j *Journal) DenyEvent(eventID string, code fault.Code, now time.Time) (Record, error) {
	if code != "" && !fault.Known(code) {
		return Record{}, errors.New("unknown admission code")
	}
	return j.decideAdmission(eventID, AdmissionDenied, code, now)
}

func (j *Journal) decideAdmission(eventID string, state AdmissionState, code fault.Code, now time.Time) (Record, error) {
	if err := j.usable(); err != nil {
		return Record{}, err
	}
	if !eventPattern.MatchString(eventID) {
		return Record{}, errors.New("invalid event identifier")
	}
	if now.IsZero() || now.Unix() < 0 {
		return Record{}, errors.New("invalid admission time")
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
	// The owner decides once. A second decision on the same event would let a
	// denied message be admitted later by anything that can reach this API.
	if record.Admission != AdmissionPending {
		return Record{}, ErrNotPending
	}
	record.Admission = state
	record.AdmissionAtUnix = uint64(now.Unix())
	record.AdmissionCode = code
	if state == AdmissionDenied {
		record.Application = StateRejected
		record.RejectedAtUnix = uint64(now.Unix())
		if record.RejectionCode == "" {
			record.RejectionCode = code
		}
	}
	return j.commit(path, record)
}

// recoverStaged finishes inbound commitments a crash interrupted.
//
// There are exactly three states a staged record can be found in, and each has
// one right answer:
//
//   - the session is still at the generation the transition was prepared
//     against, so the ciphertext was never consumed. The transition is applied
//     and the event becomes deliverable.
//   - the session has already moved past it and names this event as the one
//     that moved it, so the advance happened and only the record's own marker
//     was lost. The record is marked committed.
//   - the session moved on for some other reason. This transition can no
//     longer be applied on top of it, so the event is abandoned rather than
//     delivered: the ratchet never opened this ciphertext, and a resend will
//     decrypt normally.
//
// The alternative -- leaving staged records for the sender to resolve by
// retrying -- puts local consistency in a remote party's hands, and a sender
// that never retries leaves this ratchet a message behind for good.
func (j *Journal) recoverStaged() error {
	entries, err := os.ReadDir(j.inboundRoot())
	if err != nil {
		return errors.New("read event journal")
	}
	j.mutex.Lock()
	defer j.mutex.Unlock()
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		path := filepath.Join(j.inboundRoot(), entry.Name())
		record, err := readRecord(path)
		if err != nil || record.Crypto != CryptoStaged {
			continue
		}
		if err := j.resolveStaged(path, record); err != nil {
			return err
		}
	}
	return nil
}

func (j *Journal) resolveStaged(path string, record Record) error {
	if !sessionPattern.MatchString(record.SessionID) {
		record.Crypto = CryptoAbandoned
		_, err := j.commit(path, record)
		return err
	}
	current, err := readSession(j.sessionPath(record.SessionID))
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	switch {
	case current.Generation == record.ExpectedGen:
		next, err := record.NextState()
		if err != nil {
			record.Crypto = CryptoAbandoned
			_, commitErr := j.commit(path, record)
			return commitErr
		}
		if err := j.writeSessionInbound(record.SessionID, record.AlgorithmID,
			record.ExpectedGen+1, next, record.EventID, record.CryptoAtUnix); err != nil {
			return err
		}
		record.Crypto = CryptoCommitted
	case current.Generation == record.ExpectedGen+1 && current.LastInboundEventID == record.EventID:
		record.Crypto = CryptoCommitted
	default:
		record.Crypto = CryptoAbandoned
	}
	_, err = j.commit(path, record)
	return err
}
