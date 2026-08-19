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

// SessionRecord is one session's persisted cryptographic state.
type SessionRecord struct {
	Schema        string `json:"schema"`
	SessionID     string `json:"session_id"`
	AlgorithmID   string `json:"algorithm_id"`
	StateBase64   string `json:"state_base64"`
	StateDigest   string `json:"state_digest"`
	UpdatedAtUnix uint64 `json:"updated_at_unix"`
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

// CommitInbound makes an opened event durable, then advances the session.
//
// The order is not a preference. A crash between the two writes leaves the
// event stored and the session behind, and the same ciphertext opens again to
// the same next state, so nothing is lost. The other order consumes the
// message key first and then loses the event, and no retry recovers it: the
// peer's copy no longer opens against the advanced state.
func (j *Journal) CommitInbound(sessionID, algorithm string, next e2ee.State, entry Entry, now time.Time) (bool, Record, error) {
	if err := j.usable(); err != nil {
		return false, Record{}, err
	}
	if err := validateSessionInput(sessionID, algorithm, next, now); err != nil {
		return false, Record{}, err
	}
	fresh, record, err := j.Accept(entry)
	if err != nil {
		return false, Record{}, err
	}
	j.mutex.Lock()
	defer j.mutex.Unlock()
	if err := j.writeSession(sessionID, algorithm, next, now); err != nil {
		return false, Record{}, err
	}
	return fresh, record, nil
}

// CommitSealed advances the session, then stores the ciphertext.
//
// This order is the opposite of the inbound one, for the opposite reason. A
// crash between the two writes advances the state and loses the ciphertext, so
// the queued event is sealed again from the new state under a fresh key. The
// other order would leave a ciphertext that may already have been released
// while the state rolled back, and the next seal would reuse a message key and
// nonce, which is the one failure a ratchet cannot absorb.
func (j *Journal) CommitSealed(sessionID, algorithm string, next e2ee.State, eventID string, ciphertext []byte, now time.Time) (Delivery, error) {
	if err := j.usable(); err != nil {
		return Delivery{}, err
	}
	if err := validateSessionInput(sessionID, algorithm, next, now); err != nil {
		return Delivery{}, err
	}
	if !eventPattern.MatchString(eventID) {
		return Delivery{}, errors.New("invalid event identifier")
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
	if err := j.writeSession(sessionID, algorithm, next, now); err != nil {
		return Delivery{}, err
	}
	delivery.SessionID = sessionID
	delivery.CiphertextBase64 = base64.StdEncoding.EncodeToString(ciphertext)
	delivery.CiphertextDigest = canon.Digest(ciphertext)
	return j.commitDelivery(path, delivery)
}

func (j *Journal) writeSession(sessionID, algorithm string, state e2ee.State, now time.Time) error {
	record := SessionRecord{
		Schema:        SessionSchema,
		SessionID:     sessionID,
		AlgorithmID:   algorithm,
		StateBase64:   base64.StdEncoding.EncodeToString(state),
		StateDigest:   canon.Digest(state),
		UpdatedAtUnix: uint64(now.Unix()),
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
		record.UpdatedAtUnix == 0 || !canon.ValidDigest(record.StateDigest) ||
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
