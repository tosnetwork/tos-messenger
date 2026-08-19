// Package envelope implements the two-layer Messenger wire model.
//
// The outer Relay Envelope is what a Mailbox Relay sees: an opaque mailbox
// identifier, bounded ciphertext, and the resource fields needed to store and
// expire it. It carries no sender identity, no conversation identity, and no
// commercial state.
//
// That is a narrower claim than it sounds. A Relay cannot read a message or
// resolve the canonical Agent and Conversation it belongs to, and it can still
// observe and correlate what is left: a stable mailbox identifier, message
// identifiers, storage tokens, ciphertext sizes, expiry, timing, addresses,
// and how often each appears. Reducing that residue is mailbox rotation,
// padding, and batching, none of which exists yet, and the honest description
// is that the content is closed and the metadata is not.
//
// The inner Messaging Event is what the recipient obtains after decryption.
// Nothing in this package performs encryption: the cryptographic suite is an
// M0 freeze decision, and inventing one here is exactly what the architecture
// forbids.
package envelope

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"regexp"
	"time"

	"github.com/tosnetwork/tos-messenger/internal/canon"
	"github.com/tosnetwork/tos-messenger/internal/ids"
)

const (
	// RelaySchema is the strict wire schema identifier.
	RelaySchema = "tos.messaging.relay-envelope.v1"

	// MaxCiphertextBytes bounds one stored envelope.
	MaxCiphertextBytes = 1 << 20
	// MinCiphertextBytes rejects an empty or obviously truncated body.
	MinCiphertextBytes = 32
	// MaxStorageTokenBytes bounds the optional opaque storage token.
	MaxStorageTokenBytes = 256
	// MaxEnvelopeLifetimeSeconds bounds how long a Relay may be asked to hold
	// ciphertext. Retention is a resource commitment, so it is never open ended.
	MaxEnvelopeLifetimeSeconds = 30 * 24 * 60 * 60
)

var (
	mailboxPattern      = ids.Mailbox
	messagePattern      = ids.RelayMessage
	storageTokenPattern = regexp.MustCompile(`^[0-9a-zA-Z._~-]+$`)
)

// RelayEnvelope is the outer object a Relay stores. It is not an Agent
// signature, a payment receipt, or proof that an application accepted
// anything.
type RelayEnvelope struct {
	OpaqueMailboxID string
	MessageID       string
	Ciphertext      []byte
	ExpiresAtUnix   uint64
	StorageToken    string
}

type wireRelayEnvelope struct {
	Schema           string `json:"schema"`
	OpaqueMailboxID  string `json:"opaque_mailbox_id"`
	MessageID        string `json:"message_id"`
	CiphertextBase64 string `json:"ciphertext_base64"`
	CiphertextSize   uint32 `json:"ciphertext_size"`
	ExpiresAtUnix    uint64 `json:"expires_at_unix"`
	StorageToken     string `json:"storage_token,omitempty"`
}

// EncodeRelayJSON returns the transport representation of a valid envelope.
func EncodeRelayJSON(relayEnvelope RelayEnvelope) ([]byte, error) {
	if err := ValidateRelay(relayEnvelope); err != nil {
		return nil, err
	}
	return json.Marshal(wireRelayEnvelope{
		Schema:           RelaySchema,
		OpaqueMailboxID:  relayEnvelope.OpaqueMailboxID,
		MessageID:        relayEnvelope.MessageID,
		CiphertextBase64: base64.StdEncoding.EncodeToString(relayEnvelope.Ciphertext),
		CiphertextSize:   uint32(len(relayEnvelope.Ciphertext)),
		ExpiresAtUnix:    relayEnvelope.ExpiresAtUnix,
		StorageToken:     relayEnvelope.StorageToken,
	})
}

// DecodeRelayJSON rejects unknown fields, trailing data, and a declared size
// that disagrees with the body. A size field that is trusted over the body it
// describes is a parser-confusion bug waiting to happen, so the two must agree
// exactly.
func DecodeRelayJSON(raw []byte) (RelayEnvelope, error) {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	var value wireRelayEnvelope
	if err := decoder.Decode(&value); err != nil {
		return RelayEnvelope{}, err
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return RelayEnvelope{}, errors.New("relay envelope has trailing JSON")
	}
	if value.Schema != RelaySchema {
		return RelayEnvelope{}, errors.New("unsupported relay envelope schema")
	}
	ciphertext, err := base64.StdEncoding.Strict().DecodeString(value.CiphertextBase64)
	if err != nil {
		return RelayEnvelope{}, errors.New("invalid relay envelope ciphertext")
	}
	if uint32(len(ciphertext)) != value.CiphertextSize {
		return RelayEnvelope{}, errors.New("relay envelope size does not match its ciphertext")
	}
	relayEnvelope := RelayEnvelope{
		OpaqueMailboxID: value.OpaqueMailboxID,
		MessageID:       value.MessageID,
		Ciphertext:      ciphertext,
		ExpiresAtUnix:   value.ExpiresAtUnix,
		StorageToken:    value.StorageToken,
	}
	if err := ValidateRelay(relayEnvelope); err != nil {
		return RelayEnvelope{}, err
	}
	return relayEnvelope, nil
}

// ValidateRelay enforces every structural rule.
func ValidateRelay(relayEnvelope RelayEnvelope) error {
	if !mailboxPattern.MatchString(relayEnvelope.OpaqueMailboxID) {
		return errors.New("invalid opaque mailbox identifier")
	}
	if !messagePattern.MatchString(relayEnvelope.MessageID) {
		return errors.New("invalid relay message identifier")
	}
	if len(relayEnvelope.Ciphertext) < MinCiphertextBytes || len(relayEnvelope.Ciphertext) > MaxCiphertextBytes {
		return errors.New("relay envelope ciphertext is outside its bounds")
	}
	if canon.IsZero(relayEnvelope.Ciphertext) {
		return errors.New("relay envelope ciphertext is empty")
	}
	if relayEnvelope.ExpiresAtUnix == 0 {
		return errors.New("relay envelope has no expiry")
	}
	if relayEnvelope.StorageToken != "" &&
		(len(relayEnvelope.StorageToken) > MaxStorageTokenBytes || !storageTokenPattern.MatchString(relayEnvelope.StorageToken)) {
		return errors.New("invalid relay envelope storage token")
	}
	return nil
}

// AcceptedForStorage is the check a Relay runs before it commits resources: a
// well-formed envelope, an expiry in the future, and a retention request
// within the operator's bound.
func AcceptedForStorage(relayEnvelope RelayEnvelope, now time.Time, maxRetention time.Duration) error {
	if now.IsZero() {
		return errors.New("invalid relay storage time")
	}
	if err := ValidateRelay(relayEnvelope); err != nil {
		return err
	}
	seconds := now.Unix()
	if seconds < 0 {
		return errors.New("invalid relay storage time")
	}
	if relayEnvelope.ExpiresAtUnix <= uint64(seconds) {
		return errors.New("relay envelope is already expired")
	}
	retention := relayEnvelope.ExpiresAtUnix - uint64(seconds)
	if retention > MaxEnvelopeLifetimeSeconds {
		return errors.New("relay envelope exceeds the protocol retention bound")
	}
	if maxRetention <= 0 {
		return errors.New("invalid relay retention bound")
	}
	if retention > uint64(maxRetention/time.Second) {
		return errors.New("relay envelope exceeds the operator retention bound")
	}
	return nil
}

// MailboxID formats a recipient-generated opaque mailbox identifier. The
// recipient chooses the bytes; the Relay only ever sees the formatted value.
func MailboxID(raw []byte) (string, error) {
	return ids.Format("mbx_", raw)
}

// MessageID formats a per-envelope identifier used for Relay-level
// deduplication. It is not the application Event ID and must never be treated
// as one: a Relay can forge it, an Event ID it cannot.
func MessageID(raw []byte) (string, error) {
	return ids.Format("msg_", raw)
}
