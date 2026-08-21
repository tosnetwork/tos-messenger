package eventlog

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"regexp"

	"github.com/tosnetwork/tos-messenger/internal/canon"
)

const OutboundCompositionSchema = "tos.messaging.outbound-composition.v1"

var outboundIdempotencyPattern = regexp.MustCompile(`^idem_[0-9a-f]{64}$`)

type outboundComposition struct {
	Schema              string `json:"schema"`
	IdempotencyKey      string `json:"idempotency_key"`
	IntentDigest        string `json:"intent_digest"`
	EventID             string `json:"event_id"`
	SessionID           string `json:"session_id"`
	RecipientEndpointID string `json:"recipient_messaging_endpoint_id"`
	ConversationID      string `json:"conversation_id"`
	PayloadBase64       string `json:"payload_base64"`
	PayloadDigest       string `json:"payload_digest"`
	CreatedAtUnix       uint64 `json:"created_at_unix"`
	ExpiresAtUnix       uint64 `json:"expires_at_unix"`
}

// ClaimOutboundComposition durably binds an idempotency key to the first
// complete event and route presented under it. A retry gets the original
// bytes; changing any semantic field or recipient is a conflict.
func (j *Journal) ClaimOutboundComposition(idempotencyKey, intentDigest string, request Outbound) (Outbound, bool, error) {
	if err := j.usable(); err != nil {
		return Outbound{}, false, err
	}
	if !outboundIdempotencyPattern.MatchString(idempotencyKey) {
		return Outbound{}, false, errors.New("invalid outbound idempotency key")
	}
	if !canon.ValidDigest(intentDigest) {
		return Outbound{}, false, errors.New("invalid outbound intent digest")
	}
	if err := validateOutbound(request); err != nil {
		return Outbound{}, false, err
	}
	record := outboundComposition{
		Schema: OutboundCompositionSchema, IdempotencyKey: idempotencyKey, IntentDigest: intentDigest,
		EventID: request.EventID, SessionID: request.SessionID,
		RecipientEndpointID: request.RecipientEndpointID, ConversationID: request.ConversationID,
		PayloadBase64: base64.StdEncoding.EncodeToString(request.Payload), PayloadDigest: canon.Digest(request.Payload),
		CreatedAtUnix: request.CreatedAtUnix, ExpiresAtUnix: request.ExpiresAtUnix,
	}
	encoded, err := json.Marshal(record)
	if err != nil {
		return Outbound{}, false, err
	}
	path := filepath.Join(j.root, compositionDir, idempotencyKey[len("idem_"):]+".json")
	j.mutex.Lock()
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err == nil {
		if err := writeAndSync(file, path, encoded); err != nil {
			j.mutex.Unlock()
			return Outbound{}, false, err
		}
		if err := syncDirectory(filepath.Dir(path)); err != nil {
			_ = os.Remove(path)
			j.mutex.Unlock()
			return Outbound{}, false, err
		}
		j.mutex.Unlock()
		return request, true, nil
	}
	if !errors.Is(err, os.ErrExist) {
		j.mutex.Unlock()
		return Outbound{}, false, errors.New("create outbound composition")
	}
	raw, err := os.ReadFile(path)
	j.mutex.Unlock()
	if err != nil {
		return Outbound{}, false, err
	}
	var existing outboundComposition
	if err := json.Unmarshal(raw, &existing); err != nil || existing.Schema != OutboundCompositionSchema || existing.IdempotencyKey != idempotencyKey || !canon.ValidDigest(existing.IntentDigest) {
		return Outbound{}, false, errors.New("invalid outbound composition record")
	}
	payloadBytes, err := base64.StdEncoding.Strict().DecodeString(existing.PayloadBase64)
	if err != nil || canon.Digest(payloadBytes) != existing.PayloadDigest {
		return Outbound{}, false, errors.New("invalid outbound composition payload")
	}
	chosen := Outbound{EventID: existing.EventID, SessionID: existing.SessionID,
		RecipientEndpointID: existing.RecipientEndpointID, ConversationID: existing.ConversationID,
		Payload: payloadBytes, CreatedAtUnix: existing.CreatedAtUnix, ExpiresAtUnix: existing.ExpiresAtUnix}
	if intentDigest != existing.IntentDigest {
		return Outbound{}, false, ErrConflict
	}
	return chosen, false, nil
}

// OutboundComposition returns an already committed composition only when the
// caller presents the exact original intent. It lets a restart avoid
// re-encrypting or re-uploading a completed attachment merely to rediscover
// the Event already bound to its idempotency key.
func (j *Journal) OutboundComposition(idempotencyKey, intentDigest string) (Outbound, bool, error) {
	if err := j.usable(); err != nil {
		return Outbound{}, false, err
	}
	if !outboundIdempotencyPattern.MatchString(idempotencyKey) || !canon.ValidDigest(intentDigest) {
		return Outbound{}, false, errors.New("invalid outbound composition lookup")
	}
	path := filepath.Join(j.root, compositionDir, idempotencyKey[len("idem_"):]+".json")
	j.mutex.Lock()
	raw, err := os.ReadFile(path)
	j.mutex.Unlock()
	if errors.Is(err, os.ErrNotExist) {
		return Outbound{}, false, nil
	}
	if err != nil {
		return Outbound{}, false, err
	}
	chosen, existingIntent, err := decodeOutboundComposition(raw, idempotencyKey)
	if err != nil {
		return Outbound{}, false, err
	}
	if existingIntent != intentDigest {
		return Outbound{}, false, ErrConflict
	}
	return chosen, true, nil
}

func decodeOutboundComposition(raw []byte, idempotencyKey string) (Outbound, string, error) {
	var existing outboundComposition
	if err := json.Unmarshal(raw, &existing); err != nil || existing.Schema != OutboundCompositionSchema ||
		existing.IdempotencyKey != idempotencyKey || !canon.ValidDigest(existing.IntentDigest) {
		return Outbound{}, "", errors.New("invalid outbound composition record")
	}
	payloadBytes, err := base64.StdEncoding.Strict().DecodeString(existing.PayloadBase64)
	if err != nil || canon.Digest(payloadBytes) != existing.PayloadDigest {
		return Outbound{}, "", errors.New("invalid outbound composition payload")
	}
	chosen := Outbound{EventID: existing.EventID, SessionID: existing.SessionID,
		RecipientEndpointID: existing.RecipientEndpointID, ConversationID: existing.ConversationID,
		Payload: payloadBytes, CreatedAtUnix: existing.CreatedAtUnix, ExpiresAtUnix: existing.ExpiresAtUnix}
	if err := validateOutbound(chosen); err != nil {
		return Outbound{}, "", errors.New("invalid stored outbound composition")
	}
	return chosen, existing.IntentDigest, nil
}
