package payload

import (
	"bytes"
	"errors"

	"github.com/tosnetwork/tos-messenger/internal/canon"
	commerce "github.com/tosnetwork/tos-service-protocol/pkg/agentcommerce"
	protocolcodec "github.com/tosnetwork/tos-service-protocol/pkg/codec"
)

const MaxInlineOperationOutcomeBytes = 96 << 10

// OperationOutcome carries one exact private-send request. It is isolated
// from chat/model ingestion and confers no Agreement, execution or payment
// authority. Larger envelopes use the existing encrypted attachment path.
type OperationOutcome struct {
	OperationID             string
	OperationEnvelopeDigest string
	CanonicalRequest        []byte
}

func (OperationOutcome) Schema() string { return "tos.messaging.payload.operation-outcome.v1" }

func (value OperationOutcome) Validate() error {
	if !canon.ValidDigest(value.OperationID) || !canon.ValidDigest(value.OperationEnvelopeDigest) ||
		len(value.CanonicalRequest) == 0 || len(value.CanonicalRequest) > MaxInlineOperationOutcomeBytes {
		return errors.New("operation outcome payload is invalid or oversized")
	}
	var request commerce.OperationPrivateRequestV1
	if err := protocolcodec.Unmarshal(value.CanonicalRequest, &request); err != nil ||
		commerce.ValidateOperationPrivateRequestV1(request) != nil || request.OperationID != value.OperationID ||
		request.OperationEnvelopeDigest != value.OperationEnvelopeDigest {
		return errors.New("operation outcome request binding is invalid")
	}
	canonical, err := protocolcodec.Marshal(request)
	if err != nil || !bytes.Equal(canonical, value.CanonicalRequest) {
		return errors.New("operation outcome request is not canonical")
	}
	return nil
}

func (value OperationOutcome) encode(buffer *bytes.Buffer) {
	canon.Text(buffer, value.OperationID)
	canon.Text(buffer, value.OperationEnvelopeDigest)
	canon.Bytes(buffer, value.CanonicalRequest)
}

func decodeOperationOutcome(reader *canon.Reader) Payload {
	return OperationOutcome{OperationID: reader.Text(MaxDigestBytes), OperationEnvelopeDigest: reader.Text(MaxDigestBytes),
		CanonicalRequest: reader.Bytes(MaxInlineOperationOutcomeBytes)}
}
