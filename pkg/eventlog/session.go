package eventlog

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"regexp"
	"time"

	"github.com/tosnetwork/tos-messenger/internal/canon"
	"github.com/tosnetwork/tos-messenger/pkg/e2ee"
)

const (
	// SessionSchema is the on-disk schema of a persisted session state.
	SessionSchema = "tos.messaging.session-state.v1"

	sessionDir = "sessions"
)

var sessionPattern = regexp.MustCompile(`^ses_[0-9a-f]{64}$`)

// ErrSessionConflict reports that a session advanced while a caller was
// working from an earlier version of it.
//
// It exists because sealing is not instantaneous. A caller reads a state,
// performs a cryptographic transition outside any lock, and commits the
// result; if two callers do that at once and both commit, one ratchet advance
// is lost and two messages are sent under the same message key. Refusing the
// second commit is what makes that impossible, and the loser's transition is
// discarded rather than persisted.
var ErrSessionConflict = errors.New("session advanced while this transition was being prepared")

// SessionRecord is one session's persisted cryptographic state.
type SessionRecord struct {
	Schema string `json:"schema"`
	// Generation increments on every commit. A caller presents the generation
	// it read, and a commit against a stale one is refused.
	Generation    uint64 `json:"generation"`
	SessionID     string `json:"session_id"`
	AlgorithmID   string `json:"algorithm_id"`
	StateBase64   string `json:"state_base64"`
	StateDigest   string `json:"state_digest"`
	UpdatedAtUnix uint64 `json:"updated_at_unix"`
	// LastInboundEventID names the inbound event whose transition produced
	// this state, when one did. It is what lets a restart tell "the advance
	// already happened and only the record's marker was lost" apart from "the
	// session moved on for some other reason", which are the same generation
	// number and opposite answers.
	LastInboundEventID string `json:"last_inbound_event_id,omitempty"`
}

// State returns the persisted suite state.
func (s SessionRecord) State() (e2ee.State, error) {
	state, err := base64.StdEncoding.Strict().DecodeString(s.StateBase64)
	if err != nil {
		return nil, errors.New("invalid persisted session state")
	}
	if canon.Digest(state) != s.StateDigest {
		return nil, errors.New("persisted session state does not match its digest")
	}
	return state, nil
}

// SessionState returns the persisted state for one session.
func (j *Journal) SessionState(sessionID string) (SessionRecord, bool, error) {
	if err := j.usable(); err != nil {
		return SessionRecord{}, false, err
	}
	if !sessionPattern.MatchString(sessionID) {
		return SessionRecord{}, false, errors.New("invalid session identifier")
	}
	j.mutex.Lock()
	defer j.mutex.Unlock()
	record, err := readSession(j.sessionPath(sessionID))
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return SessionRecord{}, false, nil
		}
		return SessionRecord{}, false, err
	}
	return record, true, nil
}

// PutSessionState persists a session's state on its own.
//
// It is the right call when establishing a session, where there is no event to
// commit with it. Once messages are flowing, the ordered commits below are the
// only correct way to write state, because state written on its own alongside
// a separately written record is exactly the pair of truths a crash gets to
// choose between.
func (j *Journal) PutSessionState(sessionID, algorithm string, state e2ee.State, now time.Time) error {
	if err := j.usable(); err != nil {
		return err
	}
	if err := validateSessionInput(sessionID, algorithm, state, now); err != nil {
		return err
	}
	j.mutex.Lock()
	defer j.mutex.Unlock()
	return j.writeSession(sessionID, algorithm, state, now)
}

// CommitInbound makes an opened event durable, then advances the session, in
// one recoverable transaction.
//
// The event is written first and the session second, because a crash between
// them must leave the event stored rather than the message key spent: the same
// ciphertext opens again to the same next state, so nothing is lost, whereas
// the other order consumes the key and then loses the event, and no retry
// recovers it.
//
// What the order alone does not give is the invariant that matters more: an
// event must not reach a runtime before the session records that its
// ciphertext was opened. Between the two writes the event exists, and a
// runtime acting on it would be acting on a message the session still
// considers unread -- so the sender's retry would open a second time, or, if no
// retry came, this ratchet would sit a message behind for good. The event is
// therefore staged: written, not deliverable, and carrying the transition it
// is waiting for. A restart finishes it without needing the sender to try
// again.
func (j *Journal) CommitInbound(sessionID, algorithm string, expectedGeneration uint64, next e2ee.State, entry Entry, now time.Time) (bool, Record, error) {
	if err := j.usable(); err != nil {
		return false, Record{}, err
	}
	if err := validateSessionInput(sessionID, algorithm, next, now); err != nil {
		return false, Record{}, err
	}
	entry.Transition = &Transition{
		SessionID: sessionID, Algorithm: algorithm,
		ExpectedGeneration: expectedGeneration, NextState: next,
	}
	fresh, record, err := j.Accept(entry)
	if err != nil {
		return false, Record{}, err
	}
	// A duplicate that is already committed needs no second transition: the
	// ciphertext was opened once and the session recorded it once.
	if !fresh && record.Crypto == CryptoCommitted {
		return false, record, nil
	}
	j.mutex.Lock()
	defer j.mutex.Unlock()

	current, err := readSession(j.sessionPath(sessionID))
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return false, Record{}, err
	}
	if current.Generation != expectedGeneration {
		// Another transition got there first, so this one can no longer be
		// applied on top of the state that exists. The staged event is
		// abandoned rather than left waiting: its ciphertext was never
		// consumed, and a resend opens normally.
		record.Crypto = CryptoAbandoned
		if _, commitErr := j.commit(j.path(entry.EventID), record); commitErr != nil {
			return false, Record{}, commitErr
		}
		return false, Record{}, ErrSessionConflict
	}
	if err := j.writeSessionInbound(sessionID, algorithm, expectedGeneration+1, next,
		entry.EventID, uint64(now.Unix())); err != nil {
		return false, Record{}, err
	}
	record.Crypto = CryptoCommitted
	record.CryptoAtUnix = uint64(now.Unix())
	committed, err := j.commit(j.path(entry.EventID), record)
	if err != nil {
		return false, Record{}, err
	}
	return fresh, committed, nil
}

// CommitSealed advances the session, then stores the ciphertext.
//
// This order is the opposite of the inbound one, for the opposite reason. A
// crash between the two writes advances the state and loses the ciphertext, so
// the queued event is sealed again from the new state under a fresh key. The
// other order would leave a ciphertext that may already have been released
// while the state rolled back, and the next seal would reuse a message key and
// nonce, which is the one failure a ratchet cannot absorb.
func (j *Journal) CommitSealed(sessionID, algorithm string, expectedGeneration uint64, next e2ee.State,
	eventID, attemptID string, ciphertext []byte, now time.Time) (Delivery, error) {
	if err := j.usable(); err != nil {
		return Delivery{}, err
	}
	if err := validateSessionInput(sessionID, algorithm, next, now); err != nil {
		return Delivery{}, err
	}
	if !eventPattern.MatchString(eventID) {
		return Delivery{}, errors.New("invalid event identifier")
	}
	if !attemptPattern.MatchString(attemptID) {
		return Delivery{}, errors.New("invalid send attempt identifier")
	}
	if len(ciphertext) == 0 || len(ciphertext) > MaxCiphertextBytes {
		return Delivery{}, errors.New("invalid sealed ciphertext")
	}
	j.mutex.Lock()
	defer j.mutex.Unlock()

	path := j.deliveryPath(eventID)
	delivery, err := readDelivery(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return Delivery{}, ErrUnknown
		}
		return Delivery{}, err
	}
	if delivery.State != StatePending {
		return Delivery{}, ErrNotPending
	}
	if delivery.SessionID != sessionID {
		return Delivery{}, errors.New("sealed message belongs to another session")
	}
	// The attempt that seals must be the attempt that holds the delivery.
	//
	// Leases expire, and an expired lease is how work is recovered from a
	// worker that died. Without this check the old attempt could come back,
	// find its own transition still valid, and advance the ratchet for a
	// delivery it no longer owns -- two sealers, one session, and a message key
	// spent twice.
	if delivery.AttemptID != attemptID {
		return Delivery{}, ErrLeaseMismatch
	}
	if delivery.AttemptExpiresAt != 0 && uint64(now.Unix()) >= delivery.AttemptExpiresAt {
		return Delivery{}, ErrLeaseMismatch
	}
	// And a delivery that already carries a ciphertext has been sealed. Sealing
	// it again would spend another message key for a message that already
	// exists.
	if delivery.CiphertextBase64 != "" {
		return Delivery{}, ErrAlreadySealed
	}
	if err := j.advanceSession(sessionID, algorithm, expectedGeneration, next, now); err != nil {
		return Delivery{}, err
	}
	delivery.CiphertextBase64 = base64.StdEncoding.EncodeToString(ciphertext)
	delivery.CiphertextDigest = canon.Digest(ciphertext)
	return j.commitDelivery(path, delivery)
}

// advanceSession commits a transition only if the session is still where the
// caller left it.
func (j *Journal) advanceSession(sessionID, algorithm string, expectedGeneration uint64, state e2ee.State, now time.Time) error {
	current, err := readSession(j.sessionPath(sessionID))
	if err != nil {
		if !errors.Is(err, os.ErrNotExist) {
			return err
		}
		current = SessionRecord{}
	}
	if current.Generation != expectedGeneration {
		return ErrSessionConflict
	}
	return j.writeSessionAt(sessionID, algorithm, expectedGeneration+1, state, now)
}

func (j *Journal) writeSession(sessionID, algorithm string, state e2ee.State, now time.Time) error {
	current, err := readSession(j.sessionPath(sessionID))
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return j.writeSessionAt(sessionID, algorithm, current.Generation+1, state, now)
}

func (j *Journal) writeSessionAt(sessionID, algorithm string, generation uint64, state e2ee.State, now time.Time) error {
	return j.writeSessionInbound(sessionID, algorithm, generation, state, "", uint64(now.Unix()))
}

func (j *Journal) writeSessionInbound(sessionID, algorithm string, generation uint64,
	state e2ee.State, inboundEventID string, seconds uint64) error {
	record := SessionRecord{
		Schema:             SessionSchema,
		Generation:         generation,
		SessionID:          sessionID,
		AlgorithmID:        algorithm,
		StateBase64:        base64.StdEncoding.EncodeToString(state),
		StateDigest:        canon.Digest(state),
		UpdatedAtUnix:      seconds,
		LastInboundEventID: inboundEventID,
	}
	encoded, err := json.Marshal(record)
	if err != nil {
		return err
	}
	return j.replace(j.sessionPath(sessionID), encoded)
}

func (j *Journal) sessionPath(sessionID string) string {
	return filepath.Join(j.root, sessionDir, sessionID[len("ses_"):]+".json")
}

func (j *Journal) sessionRoot() string { return filepath.Join(j.root, sessionDir) }

func validateSessionInput(sessionID, algorithm string, state e2ee.State, now time.Time) error {
	if !sessionPattern.MatchString(sessionID) {
		return errors.New("invalid session identifier")
	}
	if err := e2ee.ValidateAlgorithmID(algorithm); err != nil {
		return err
	}
	if err := e2ee.ValidateState(state); err != nil {
		return err
	}
	if now.IsZero() || now.Unix() < 0 {
		return errors.New("invalid session commit time")
	}
	return nil
}

func readSession(path string) (SessionRecord, error) {
	value, err := readRecordBytes(path)
	if err != nil {
		return SessionRecord{}, err
	}
	var record SessionRecord
	if err := json.Unmarshal(value, &record); err != nil {
		return SessionRecord{}, errors.New("invalid session record")
	}
	if record.Schema != SessionSchema || !sessionPattern.MatchString(record.SessionID) ||
		record.Generation == 0 || record.UpdatedAtUnix == 0 || !canon.ValidDigest(record.StateDigest) ||
		e2ee.ValidateAlgorithmID(record.AlgorithmID) != nil {
		return SessionRecord{}, errors.New("invalid session record")
	}
	if _, err := record.State(); err != nil {
		return SessionRecord{}, errors.New("invalid session record")
	}
	return record, nil
}

// NewSessionID formats a session identifier.
func NewSessionID(raw []byte) (string, error) {
	return idsFormat("ses_", raw)
}
