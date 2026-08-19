package eventlog

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"
	"sort"
	"time"

	"github.com/tosnetwork/tos-messenger/internal/canon"
	"github.com/tosnetwork/tos-messenger/pkg/fault"
)

// Payload returns the queued event.
func (d Delivery) Payload() ([]byte, error) {
	payload, err := base64.StdEncoding.Strict().DecodeString(d.PayloadBase64)
	if err != nil {
		return nil, errors.New("invalid queued event payload")
	}
	if canon.Digest(payload) != d.PayloadDigest {
		return nil, errors.New("queued event payload does not match its digest")
	}
	return payload, nil
}

// Ciphertext returns the sealed message, if one has been committed. A delivery
// without one has not been sealed yet, or lost its ciphertext to a crash and
// must be sealed again from the current session state.
func (d Delivery) Ciphertext() ([]byte, error) {
	if d.CiphertextBase64 == "" {
		return nil, nil
	}
	ciphertext, err := base64.StdEncoding.Strict().DecodeString(d.CiphertextBase64)
	if err != nil {
		return nil, errors.New("invalid sealed ciphertext")
	}
	if canon.Digest(ciphertext) != d.CiphertextDigest {
		return nil, errors.New("sealed ciphertext does not match its digest")
	}
	return ciphertext, nil
}

// DeliverySchema is the on-disk record schema for an outbound event.
const DeliverySchema = "tos.messaging.delivery-journal.v1"

// DeliveryState is where one outbound event stands.
type DeliveryState string

const (
	// StatePending means the event is waiting for its next attempt.
	StatePending DeliveryState = "pending"
	// StateHeld means the event is waiting on an owner decision rather than on
	// time. It is never selected by Due: a timer would ask the same person the
	// same question repeatedly.
	StateHeld DeliveryState = "held"
	// StateDelivered means a recipient device durably accepted the event.
	StateDelivered DeliveryState = "delivered"
	// StateAbandoned means no further attempt can succeed, or the event
	// outlived its own expiry.
	StateAbandoned DeliveryState = "abandoned"
)

// ErrNotPending reports a transition on a delivery that is no longer waiting.
var ErrNotPending = errors.New("delivery is not awaiting an attempt")

// Delivery is the durable state of one outbound event.
//
// It exists so that at-least-once delivery survives a restart. Without it, a
// process that crashes between sealing an event and receiving an
// acknowledgement has no way to know whether to send again, and the choice
// between losing the event and duplicating it would be made by whichever
// failure happened.
type Delivery struct {
	Schema              string        `json:"schema"`
	EventID             string        `json:"event_id"`
	SessionID           string        `json:"session_id,omitempty"`
	PayloadBase64       string        `json:"payload_base64"`
	PayloadDigest       string        `json:"payload_digest"`
	CiphertextBase64    string        `json:"ciphertext_base64,omitempty"`
	CiphertextDigest    string        `json:"ciphertext_digest,omitempty"`
	RecipientEndpointID string        `json:"recipient_messaging_endpoint_id"`
	ConversationID      string        `json:"conversation_id"`
	State               DeliveryState `json:"state"`
	Attempts            uint32        `json:"attempts"`
	LastCode            fault.Code    `json:"last_code,omitempty"`
	NextAttemptAtUnix   uint64        `json:"next_attempt_at_unix,omitempty"`
	CreatedAtUnix       uint64        `json:"created_at_unix"`
	ExpiresAtUnix       uint64        `json:"expires_at_unix"`
	SettledAtUnix       uint64        `json:"settled_at_unix,omitempty"`
}

// Outbound is a request to deliver one event.
type Outbound struct {
	EventID string
	// SessionID is known when the event is queued, not when it is sealed. A
	// process that picked up a queued event after a restart would otherwise
	// have no way to find the session it belongs to.
	SessionID           string
	RecipientEndpointID string
	ConversationID      string
	// Payload is the event to send. It is queued before it is sealed, so that
	// a crash between advancing the session and storing the ciphertext leaves
	// something to seal again.
	Payload       []byte
	CreatedAtUnix uint64
	ExpiresAtUnix uint64
}

// Enqueue records an outbound event exactly once.
//
// Re-enqueuing the same event is not an error and does not reset its attempt
// count: a caller that retries its own submission after a crash must not be
// able to restart a backoff that exists to protect the recipient.
func (j *Journal) Enqueue(request Outbound) (bool, Delivery, error) {
	if err := j.usable(); err != nil {
		return false, Delivery{}, err
	}
	if err := validateOutbound(request); err != nil {
		return false, Delivery{}, err
	}
	j.mutex.Lock()
	defer j.mutex.Unlock()

	path := j.deliveryPath(request.EventID)
	delivery := Delivery{
		Schema:              DeliverySchema,
		EventID:             request.EventID,
		SessionID:           request.SessionID,
		PayloadBase64:       base64.StdEncoding.EncodeToString(request.Payload),
		PayloadDigest:       canon.Digest(request.Payload),
		RecipientEndpointID: request.RecipientEndpointID,
		ConversationID:      request.ConversationID,
		State:               StatePending,
		NextAttemptAtUnix:   request.CreatedAtUnix,
		CreatedAtUnix:       request.CreatedAtUnix,
		ExpiresAtUnix:       request.ExpiresAtUnix,
	}
	encoded, err := json.Marshal(delivery)
	if err != nil {
		return false, Delivery{}, err
	}
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err == nil {
		if err := writeAndSync(file, path, encoded); err != nil {
			return false, Delivery{}, err
		}
		if err := syncDirectory(j.outboundRoot()); err != nil {
			_ = os.Remove(path)
			return false, Delivery{}, err
		}
		return true, delivery, nil
	}
	if !errors.Is(err, os.ErrExist) {
		return false, Delivery{}, errors.New("create delivery record")
	}
	existing, err := readDelivery(path)
	if err != nil {
		return false, Delivery{}, err
	}
	if existing.RecipientEndpointID != request.RecipientEndpointID ||
		existing.ConversationID != request.ConversationID ||
		existing.SessionID != request.SessionID ||
		existing.PayloadDigest != canon.Digest(request.Payload) {
		return false, Delivery{}, ErrConflict
	}
	return false, existing, nil
}

// Due returns the deliveries whose next attempt has arrived, oldest first.
//
// A malformed record is skipped rather than failing the sweep: one unreadable
// file must not stop every other event from being delivered, and Prune is
// where an unreadable record is dealt with.
func (j *Journal) Due(now time.Time) ([]Delivery, error) {
	if err := j.usable(); err != nil {
		return nil, err
	}
	if now.IsZero() || now.Unix() < 0 {
		return nil, errors.New("invalid delivery sweep time")
	}
	j.mutex.Lock()
	defer j.mutex.Unlock()

	entries, err := os.ReadDir(j.outboundRoot())
	if err != nil {
		return nil, errors.New("read delivery journal")
	}
	seconds := uint64(now.Unix())
	var due []Delivery
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		delivery, err := readDelivery(j.deliveryPathForFile(entry.Name()))
		if err != nil {
			continue
		}
		if delivery.State != StatePending {
			continue
		}
		if delivery.ExpiresAtUnix <= seconds {
			continue
		}
		if delivery.NextAttemptAtUnix > seconds {
			continue
		}
		due = append(due, delivery)
	}
	sort.Slice(due, func(first, second int) bool {
		if due[first].NextAttemptAtUnix != due[second].NextAttemptAtUnix {
			return due[first].NextAttemptAtUnix < due[second].NextAttemptAtUnix
		}
		return due[first].EventID < due[second].EventID
	})
	return due, nil
}

// Failed records a failed attempt and applies the retry disposition of its
// code.
//
// The schedule is not the caller's to choose. A permanent code abandons the
// event, an approval hold stops the timer without abandoning anything, and a
// retryable code moves the next attempt out along the fixed curve until the
// attempt budget is spent.
func (j *Journal) Failed(eventID string, code fault.Code, now time.Time) (Delivery, error) {
	if err := j.usable(); err != nil {
		return Delivery{}, err
	}
	if !eventPattern.MatchString(eventID) {
		return Delivery{}, errors.New("invalid event identifier")
	}
	if now.IsZero() || now.Unix() < 0 {
		return Delivery{}, errors.New("invalid delivery attempt time")
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
	seconds := uint64(now.Unix())
	delivery.Attempts++
	delivery.LastCode = code

	retry := fault.NextCode(code, int(delivery.Attempts))
	switch {
	case delivery.ExpiresAtUnix <= seconds:
		// An event that outlived its own expiry is not worth another attempt
		// whatever its failure said.
		delivery.State = StateAbandoned
		delivery.NextAttemptAtUnix = 0
		delivery.SettledAtUnix = seconds
	case retry.Allowed:
		next := seconds + uint64(retry.After/time.Second)
		if next >= delivery.ExpiresAtUnix {
			delivery.State = StateAbandoned
			delivery.NextAttemptAtUnix = 0
			delivery.SettledAtUnix = seconds
			break
		}
		delivery.NextAttemptAtUnix = next
	case retry.Disposition == fault.Approval:
		delivery.State = StateHeld
		delivery.NextAttemptAtUnix = 0
	default:
		delivery.State = StateAbandoned
		delivery.NextAttemptAtUnix = 0
		delivery.SettledAtUnix = seconds
	}
	return j.commitDelivery(path, delivery)
}

// Delivered records that a recipient device durably accepted the event.
func (j *Journal) Delivered(eventID string, now time.Time) (Delivery, error) {
	return j.settle(eventID, StateDelivered, now)
}

// Abandon gives up on an event on the owner's instruction.
func (j *Journal) Abandon(eventID string, now time.Time) (Delivery, error) {
	return j.settle(eventID, StateAbandoned, now)
}

// Resume returns a held delivery to the queue once the decision it was waiting
// on has been made.
func (j *Journal) Resume(eventID string, now time.Time) (Delivery, error) {
	if err := j.usable(); err != nil {
		return Delivery{}, err
	}
	if !eventPattern.MatchString(eventID) {
		return Delivery{}, errors.New("invalid event identifier")
	}
	if now.IsZero() || now.Unix() < 0 {
		return Delivery{}, errors.New("invalid delivery resume time")
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
	if delivery.State != StateHeld {
		return Delivery{}, ErrNotPending
	}
	seconds := uint64(now.Unix())
	if delivery.ExpiresAtUnix <= seconds {
		return Delivery{}, errors.New("delivery expired while it was held")
	}
	delivery.State = StatePending
	delivery.NextAttemptAtUnix = seconds
	return j.commitDelivery(path, delivery)
}

// LookupDelivery returns the durable state of an outbound event.
func (j *Journal) LookupDelivery(eventID string) (Delivery, bool, error) {
	if err := j.usable(); err != nil {
		return Delivery{}, false, err
	}
	if !eventPattern.MatchString(eventID) {
		return Delivery{}, false, errors.New("invalid event identifier")
	}
	j.mutex.Lock()
	defer j.mutex.Unlock()
	delivery, err := readDelivery(j.deliveryPath(eventID))
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return Delivery{}, false, nil
		}
		return Delivery{}, false, err
	}
	return delivery, true, nil
}

func (j *Journal) settle(eventID string, state DeliveryState, now time.Time) (Delivery, error) {
	if err := j.usable(); err != nil {
		return Delivery{}, err
	}
	if !eventPattern.MatchString(eventID) {
		return Delivery{}, errors.New("invalid event identifier")
	}
	if now.IsZero() || now.Unix() < 0 {
		return Delivery{}, errors.New("invalid delivery settle time")
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
	if delivery.State != StatePending && delivery.State != StateHeld {
		return Delivery{}, ErrNotPending
	}
	delivery.State = state
	delivery.NextAttemptAtUnix = 0
	delivery.SettledAtUnix = uint64(now.Unix())
	return j.commitDelivery(path, delivery)
}

func (j *Journal) commitDelivery(path string, delivery Delivery) (Delivery, error) {
	encoded, err := json.Marshal(delivery)
	if err != nil {
		return Delivery{}, err
	}
	if err := j.replace(path, encoded); err != nil {
		return Delivery{}, err
	}
	return delivery, nil
}

func (j *Journal) deliveryPathForFile(name string) string {
	return j.outboundRoot() + string(os.PathSeparator) + name
}

func validateOutbound(request Outbound) error {
	if !eventPattern.MatchString(request.EventID) {
		return errors.New("invalid event identifier")
	}
	if !endpointPattern.MatchString(request.RecipientEndpointID) {
		return errors.New("invalid delivery recipient endpoint")
	}
	if !convPattern.MatchString(request.ConversationID) {
		return errors.New("invalid delivery conversation identifier")
	}
	if !sessionPattern.MatchString(request.SessionID) {
		return errors.New("invalid delivery session identifier")
	}
	if len(request.Payload) == 0 || len(request.Payload) > MaxPayloadBytes {
		return errors.New("invalid queued event payload")
	}
	if request.CreatedAtUnix == 0 || request.ExpiresAtUnix <= request.CreatedAtUnix {
		return errors.New("invalid delivery validity window")
	}
	return nil
}

func readDelivery(path string) (Delivery, error) {
	value, err := readRecordBytes(path)
	if err != nil {
		return Delivery{}, err
	}
	var delivery Delivery
	if err := json.Unmarshal(value, &delivery); err != nil {
		return Delivery{}, errors.New("invalid delivery record")
	}
	if delivery.Schema != DeliverySchema || !eventPattern.MatchString(delivery.EventID) ||
		!endpointPattern.MatchString(delivery.RecipientEndpointID) ||
		!convPattern.MatchString(delivery.ConversationID) ||
		delivery.CreatedAtUnix == 0 || delivery.ExpiresAtUnix <= delivery.CreatedAtUnix ||
		!canon.ValidDigest(delivery.PayloadDigest) {
		return Delivery{}, errors.New("invalid delivery record")
	}
	if !sessionPattern.MatchString(delivery.SessionID) {
		return Delivery{}, errors.New("invalid delivery record")
	}
	if _, err := delivery.Payload(); err != nil {
		return Delivery{}, errors.New("invalid delivery record")
	}
	if delivery.CiphertextBase64 != "" {
		if _, err := delivery.Ciphertext(); err != nil {
			return Delivery{}, errors.New("invalid delivery record")
		}
	}
	switch delivery.State {
	case StatePending, StateHeld, StateDelivered, StateAbandoned:
	default:
		return Delivery{}, errors.New("invalid delivery record")
	}
	if delivery.LastCode != "" && !fault.Known(delivery.LastCode) {
		return Delivery{}, errors.New("invalid delivery record")
	}
	return delivery, nil
}
