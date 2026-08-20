// Package mailboxapi is the bounded, transport-neutral service protocol for
// an authenticated Mailbox store. A future M0-R-selected adapter may carry
// these frames over ADNL/RLDP or HTTPS without changing their authority.
package mailboxapi

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"

	"github.com/tosnetwork/tos-messenger/internal/canon"
	"github.com/tosnetwork/tos-messenger/internal/ids"
	"github.com/tosnetwork/tos-messenger/internal/localwire"
	"github.com/tosnetwork/tos-messenger/pkg/envelope"
	"github.com/tosnetwork/tos-messenger/pkg/mailbox"
)

const (
	RequestSchema                = "tos.messaging.mailbox-service-request.v1"
	ResponseSchema               = "tos.messaging.mailbox-service-response.v1"
	MaxRequestBytes       uint32 = 2 << 20
	MaxResponseBytes      uint32 = 16 << 20
	MaxServiceListResults        = 8
)

type Operation string

const (
	OpDeposit Operation = "deposit"
	OpRead    Operation = "read"
	OpDelete  Operation = "delete"
)

type Code string

const (
	CodeInvalid  Code = "invalid-request"
	CodeDenied   Code = "denied"
	CodeConflict Code = "conflict"
	CodeQuota    Code = "quota"
	CodeInternal Code = "internal"
)

type Request struct {
	Schema           string          `json:"schema"`
	Op               Operation       `json:"op"`
	Grant            json.RawMessage `json:"grant"`
	Access           json.RawMessage `json:"access"`
	Envelope         json.RawMessage `json:"envelope,omitempty"`
	Limit            int             `json:"limit,omitempty"`
	MessageID        string          `json:"message_id,omitempty"`
	CiphertextDigest string          `json:"ciphertext_digest,omitempty"`
}

type Response struct {
	Schema    string             `json:"schema"`
	OK        bool               `json:"ok"`
	Code      Code               `json:"code,omitempty"`
	Detail    string             `json:"detail,omitempty"`
	Fresh     bool               `json:"fresh,omitempty"`
	Ack       json.RawMessage    `json:"stored_ack,omitempty"`
	Envelopes *[]json.RawMessage `json:"envelopes,omitempty"`
	Deleted   *bool              `json:"deleted,omitempty"`
}

func EncodeRequest(request Request) ([]byte, error) {
	request.Schema = RequestSchema
	raw, err := json.Marshal(request)
	if err != nil {
		return nil, err
	}
	if _, err := DecodeRequest(raw); err != nil {
		return nil, err
	}
	return localwire.Frame(raw, MaxRequestBytes)
}

func DecodeRequest(raw []byte) (Request, error) {
	if len(raw) == 0 || len(raw) > int(MaxRequestBytes) {
		return Request{}, errors.New("Mailbox service request is outside its bound")
	}
	var request Request
	if err := strict(raw, &request); err != nil {
		return Request{}, err
	}
	if request.Schema != RequestSchema {
		return Request{}, errors.New("unsupported Mailbox service request schema")
	}
	if _, err := mailbox.DecodeGrantJSON(request.Grant); err != nil {
		return Request{}, err
	}
	if _, err := mailbox.DecodeAccessRequestJSON(request.Access); err != nil {
		return Request{}, err
	}
	switch request.Op {
	case OpDeposit:
		if len(request.Envelope) == 0 || request.Limit != 0 || request.MessageID != "" || request.CiphertextDigest != "" {
			return Request{}, errors.New("invalid Mailbox deposit shape")
		}
		if _, err := envelope.DecodeRelayJSON(request.Envelope); err != nil {
			return Request{}, err
		}
	case OpRead:
		if len(request.Envelope) != 0 || request.Limit < 1 || request.Limit > MaxServiceListResults || request.MessageID != "" || request.CiphertextDigest != "" {
			return Request{}, errors.New("invalid Mailbox read shape")
		}
	case OpDelete:
		if len(request.Envelope) != 0 || request.Limit != 0 || !ids.RelayMessage.MatchString(request.MessageID) || !canon.ValidDigest(request.CiphertextDigest) {
			return Request{}, errors.New("invalid Mailbox delete shape")
		}
	default:
		return Request{}, errors.New("unknown Mailbox service operation")
	}
	return request, nil
}

func DecodeResponse(raw []byte) (Response, error) {
	if len(raw) == 0 || len(raw) > int(MaxResponseBytes) {
		return Response{}, errors.New("Mailbox service response is outside its bound")
	}
	var response Response
	if err := strict(raw, &response); err != nil {
		return Response{}, err
	}
	if err := validateResponse(response); err != nil {
		return Response{}, err
	}
	return response, nil
}

func encodeResponse(response Response) ([]byte, error) {
	response.Schema = ResponseSchema
	if err := validateResponse(response); err != nil {
		return nil, err
	}
	raw, err := json.Marshal(response)
	if err != nil {
		return nil, err
	}
	return localwire.Frame(raw, MaxResponseBytes)
}

func validateResponse(r Response) error {
	if r.Schema != ResponseSchema {
		return errors.New("unsupported Mailbox service response schema")
	}
	if !r.OK {
		if r.Detail == "" || r.Fresh || len(r.Ack) != 0 || r.Envelopes != nil || r.Deleted != nil {
			return errors.New("invalid refused Mailbox response")
		}
		switch r.Code {
		case CodeInvalid, CodeDenied, CodeConflict, CodeQuota, CodeInternal:
			return nil
		}
		return errors.New("unknown Mailbox response code")
	}
	if r.Code != "" || r.Detail != "" {
		return errors.New("invalid successful Mailbox response")
	}
	present := 0
	if len(r.Ack) != 0 {
		if _, err := mailbox.DecodeAckJSON(r.Ack); err != nil {
			return err
		}
		present++
	}
	if r.Envelopes != nil {
		if len(*r.Envelopes) > MaxServiceListResults {
			return errors.New("too many Mailbox response envelopes")
		}
		for _, raw := range *r.Envelopes {
			if _, err := envelope.DecodeRelayJSON(raw); err != nil {
				return err
			}
		}
		present++
	}
	if r.Deleted != nil {
		present++
	}
	if present != 1 || r.Fresh && len(r.Ack) == 0 {
		return errors.New("ambiguous successful Mailbox response")
	}
	return nil
}

func ReadRequestFrame(r io.Reader) ([]byte, error)  { return localwire.ReadFrame(r, MaxRequestBytes) }
func ReadResponseFrame(r io.Reader) ([]byte, error) { return localwire.ReadFrame(r, MaxResponseBytes) }

func strict(raw []byte, target any) error {
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if err := d.Decode(target); err != nil {
		return err
	}
	if err := d.Decode(new(any)); !errors.Is(err, io.EOF) {
		return errors.New("Mailbox service wire has trailing JSON")
	}
	return nil
}
