package payload

import (
	"bytes"
	"errors"

	"github.com/tosnetwork/tos-messenger/internal/canon"
)

const MaxGiftCanonicalBytes = 64 << 10

// Gift payloads carry the exact canonical object produced by
// tos-service-protocol. Messenger authenticates and durably transports those
// bytes; it does not reinterpret an address or rebuild a signed BOC.
type GiftAddressRequest struct{ CanonicalRequest []byte }

func (GiftAddressRequest) Schema() string {
	return "tos.messaging.payload.agent-gift-address-request.v1"
}
func (v GiftAddressRequest) Validate() error        { return validateGiftCanonical(v.CanonicalRequest) }
func (v GiftAddressRequest) encode(b *bytes.Buffer) { canon.Bytes(b, v.CanonicalRequest) }
func decodeGiftAddressRequest(r *canon.Reader) Payload {
	return GiftAddressRequest{CanonicalRequest: r.Bytes(MaxGiftCanonicalBytes)}
}

type GiftAddressResponse struct{ CanonicalResponse []byte }

func (GiftAddressResponse) Schema() string {
	return "tos.messaging.payload.agent-gift-address-response.v1"
}
func (v GiftAddressResponse) Validate() error        { return validateGiftCanonical(v.CanonicalResponse) }
func (v GiftAddressResponse) encode(b *bytes.Buffer) { canon.Bytes(b, v.CanonicalResponse) }
func decodeGiftAddressResponse(r *canon.Reader) Payload {
	return GiftAddressResponse{CanonicalResponse: r.Bytes(MaxGiftCanonicalBytes)}
}

type GiftSignedBOCOffer struct{ CanonicalOffer []byte }

func (GiftSignedBOCOffer) Schema() string {
	return "tos.messaging.payload.agent-gift-signed-boc-offer.v1"
}
func (v GiftSignedBOCOffer) Validate() error        { return validateGiftCanonical(v.CanonicalOffer) }
func (v GiftSignedBOCOffer) encode(b *bytes.Buffer) { canon.Bytes(b, v.CanonicalOffer) }
func decodeGiftSignedBOCOffer(r *canon.Reader) Payload {
	return GiftSignedBOCOffer{CanonicalOffer: r.Bytes(MaxGiftCanonicalBytes)}
}

func validateGiftCanonical(value []byte) error {
	if len(value) == 0 || len(value) > MaxGiftCanonicalBytes {
		return errors.New("canonical Agent Gift object has invalid size")
	}
	return nil
}
