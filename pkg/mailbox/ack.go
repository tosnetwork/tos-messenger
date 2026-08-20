// Package mailbox implements the route-independent Mailbox Relay contract.
// It stores opaque Relay Envelopes and proves durable acceptance without
// claiming delivery to, or application by, the recipient.
package mailbox

import (
	"bytes"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"

	"github.com/tosnetwork/tos-messenger/internal/canon"
	"github.com/tosnetwork/tos-messenger/internal/ids"
	"github.com/tosnetwork/tos-messenger/pkg/envelope"
)

const AckSchema = "tos.messaging.stored-ack.v1"
const MaxAckBytes = 2048

// StoredAck is issued only after the ciphertext record and its directory entry
// are synced. It is a Relay receipt, never a TOS commercial Receipt.
type StoredAck struct {
	Schema            string `json:"schema"`
	MailboxID         string `json:"opaque_mailbox_id"`
	MessageID         string `json:"message_id"`
	CiphertextDigest  string `json:"ciphertext_digest"`
	StoredAtUnix      uint64 `json:"stored_at_unix"`
	ExpiresAtUnix     uint64 `json:"expires_at_unix"`
	RelayPublicKeyHex string `json:"relay_public_key_hex"`
	SignatureHex      string `json:"relay_signature_hex"`
}

// CanonicalBytes returns the exact preimage the Relay signs.
func CanonicalBytes(a StoredAck) ([]byte, error) {
	if a.Schema != AckSchema || !ids.Mailbox.MatchString(a.MailboxID) || !ids.RelayMessage.MatchString(a.MessageID) ||
		!canon.ValidDigest(a.CiphertextDigest) || a.StoredAtUnix == 0 || a.ExpiresAtUnix <= a.StoredAtUnix ||
		a.ExpiresAtUnix-a.StoredAtUnix > envelope.MaxEnvelopeLifetimeSeconds {
		return nil, errors.New("invalid StoredAck")
	}
	key, err := hex.DecodeString(a.RelayPublicKeyHex)
	if err != nil || len(key) != ed25519.PublicKeySize || canon.IsZero(key) {
		return nil, errors.New("invalid StoredAck Relay key")
	}
	b := bytes.NewBufferString(canon.DomainStoredAck)
	canon.Text(b, AckSchema)
	canon.Text(b, a.MailboxID)
	canon.Text(b, a.MessageID)
	canon.Text(b, a.CiphertextDigest)
	canon.Uint64(b, a.StoredAtUnix)
	canon.Uint64(b, a.ExpiresAtUnix)
	canon.Bytes(b, key)
	return b.Bytes(), nil
}

func SignAck(a StoredAck, key ed25519.PrivateKey) (StoredAck, error) {
	if len(key) != ed25519.PrivateKeySize {
		return StoredAck{}, errors.New("invalid Relay signing key")
	}
	public := key.Public().(ed25519.PublicKey)
	a.Schema = AckSchema
	a.RelayPublicKeyHex = hex.EncodeToString(public)
	a.SignatureHex = ""
	preimage, err := CanonicalBytes(a)
	if err != nil {
		return StoredAck{}, err
	}
	a.SignatureHex = hex.EncodeToString(ed25519.Sign(key, preimage))
	return a, nil
}

func VerifyAck(a StoredAck) error {
	preimage, err := CanonicalBytes(a)
	if err != nil {
		return err
	}
	key, _ := hex.DecodeString(a.RelayPublicKeyHex)
	signature, err := hex.DecodeString(a.SignatureHex)
	if err != nil || len(signature) != ed25519.SignatureSize || !ed25519.Verify(ed25519.PublicKey(key), preimage, signature) {
		return errors.New("invalid StoredAck signature")
	}
	return nil
}

func EncodeAckJSON(a StoredAck) ([]byte, error) {
	if err := VerifyAck(a); err != nil {
		return nil, err
	}
	return json.Marshal(a)
}

func DecodeAckJSON(raw []byte) (StoredAck, error) {
	if len(raw) == 0 || len(raw) > MaxAckBytes {
		return StoredAck{}, errors.New("StoredAck wire is outside its bound")
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	var ack StoredAck
	if err := decoder.Decode(&ack); err != nil {
		return StoredAck{}, err
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return StoredAck{}, errors.New("StoredAck has trailing JSON")
	}
	if err := VerifyAck(ack); err != nil {
		return StoredAck{}, err
	}
	return ack, nil
}
