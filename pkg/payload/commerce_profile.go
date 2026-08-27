package payload

import (
	"bytes"
	"errors"
	"time"

	"github.com/tosnetwork/tos-messenger/internal/canon"
	commerce "github.com/tosnetwork/tos-service-protocol/pkg/agentcommerce"
	protocolcodec "github.com/tosnetwork/tos-service-protocol/pkg/codec"
)

// CommerceProfileEvent carries one exact, profile-qualified economic object
// envelope. Messenger verifies canonical structure; the installed profile
// verifier remains the authority for the enclosed object.
type CommerceProfileEvent struct {
	ObjectDigest   string
	CanonicalEvent []byte
}

func (CommerceProfileEvent) Schema() string {
	return "tos.messaging.payload.commerce-profile-event.v1"
}

func (value CommerceProfileEvent) Validate() error {
	if !canon.ValidDigest(value.ObjectDigest) || len(value.CanonicalEvent) == 0 ||
		len(value.CanonicalEvent) > commerce.MaxProfileEventBytes {
		return errors.New("commerce profile event payload is invalid or oversized")
	}
	var event commerce.CommerceProfileEventV1
	if err := protocolcodec.Unmarshal(value.CanonicalEvent, &event); err != nil {
		return err
	}
	if event.ObjectDigest != value.ObjectDigest || event.CreatedAtUnix == 0 {
		return errors.New("commerce profile event payload digest mismatch")
	}
	// Immutable history remains decodable after expiry. The receiving profile
	// coordinator performs current-time and object verification before use.
	created := time.Unix(int64(event.CreatedAtUnix), 0).UTC()
	canonical, err := commerce.CanonicalCommerceProfileEventV1(event, created)
	if err != nil || !bytes.Equal(canonical, value.CanonicalEvent) {
		return errors.New("commerce profile event payload is not canonical")
	}
	return nil
}

func (value CommerceProfileEvent) encode(buffer *bytes.Buffer) {
	canon.Text(buffer, value.ObjectDigest)
	canon.Bytes(buffer, value.CanonicalEvent)
}

func decodeCommerceProfileEvent(reader *canon.Reader) Payload {
	return CommerceProfileEvent{
		ObjectDigest:   reader.Text(MaxDigestBytes),
		CanonicalEvent: reader.Bytes(commerce.MaxProfileEventBytes),
	}
}
