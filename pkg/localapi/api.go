// Package localapi is the owner-private boundary between the Messenger daemon
// and the Agent runtime that uses it.
//
// The split it enforces is the one the architecture draws. The runtime decides
// whether and how to answer a message, which model or tool to use, and whether
// the owner must approve something. The daemon decides how to discover,
// encrypt, transmit, store, deduplicate, and deliver. Neither reaches into the
// other's half.
//
// It is also the only place an owner approval exists. Those event kinds are
// refused on every network route, so authority to act here can be expressed
// over this socket and nowhere else. That is the whole reason the boundary is
// a socket with an owner-private mode rather than a port.
//
// Nothing here hands out key material. The runtime receives events, which the
// owner is entitled to read, and never session state.
package localapi

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"
	"regexp"

	"github.com/tosnetwork/tos-messenger/pkg/fault"
)

const (
	// RequestSchema is the strict wire schema of a request.
	RequestSchema = "tos.messaging.local-request.v1"
	// ResponseSchema is the strict wire schema of a response.
	ResponseSchema = "tos.messaging.local-response.v1"

	// MaxFrameBytes bounds one request or response body. It has to hold an
	// event, because a claim hands one back.
	MaxFrameBytes = 512 << 10
	// frameHeaderBytes is the length prefix.
	frameHeaderBytes = 4
	// MaxEventsPerResponse bounds one pending listing.
	MaxEventsPerResponse = 64
)

// Operation is what a caller is asking for.
type Operation string

const (
	// OpPending lists inbound events waiting for the runtime, including any
	// whose lease expired.
	OpPending Operation = "inbox.pending"
	// OpClaim takes a lease on one event and returns it.
	OpClaim Operation = "inbox.claim"
	// OpComplete records that the runtime accepted an event.
	OpComplete Operation = "inbox.complete"
	// OpReject records that the runtime refused one.
	OpReject Operation = "inbox.reject"
	// OpQueue submits an event for delivery.
	OpQueue Operation = "outbox.queue"

	// OpAwaitingAdmission lists inbound events waiting for the owner. A
	// runtime never sees these; deciding about them is what the owner is for.
	OpAwaitingAdmission Operation = "approvals.pending"
	// OpAdmit is the owner letting an inbound event reach the runtime.
	OpAdmit Operation = "approvals.admit"
	// OpRefuse is the owner refusing one.
	OpRefuse Operation = "approvals.refuse"

	// OpApprove is the owner releasing a held outbound delivery.
	OpApprove Operation = "owner.approve"
	// OpDeny is the owner abandoning one.
	OpDeny Operation = "owner.deny"
)

// Principal is which side of the boundary a connection speaks for.
//
// The separation exists because of one invariant: the party that asks for an
// approval must not be able to grant it. A runtime that could call the
// approval operations would be approving its own requests, and calling that a
// human decision would be a fiction the code supports.
type Principal string

const (
	// PrincipalRuntime is the Agent runtime. It drains the inbox and submits
	// events, and it can approve nothing.
	PrincipalRuntime Principal = "runtime"
	// PrincipalOwner is the owner's own interface. It decides, and it does no
	// Agent work.
	PrincipalOwner Principal = "owner"
)

var permitted = map[Principal]map[Operation]struct{}{
	PrincipalRuntime: {
		OpPending: {}, OpClaim: {}, OpComplete: {}, OpReject: {}, OpQueue: {},
	},
	PrincipalOwner: {
		OpAwaitingAdmission: {}, OpAdmit: {}, OpRefuse: {},
		OpApprove: {}, OpDeny: {},
	},
}

// Permits reports whether a principal may perform an operation.
func Permits(principal Principal, operation Operation) bool {
	operations, known := permitted[principal]
	if !known {
		return false
	}
	_, allowed := operations[operation]
	return allowed
}

var operations = map[Operation]struct{}{
	OpPending: {}, OpClaim: {}, OpComplete: {}, OpReject: {}, OpQueue: {},
	OpAwaitingAdmission: {}, OpAdmit: {}, OpRefuse: {},
	OpApprove: {}, OpDeny: {},
}

var (
	eventPattern    = regexp.MustCompile(`^evt_[0-9a-f]{64}$`)
	leasePattern    = regexp.MustCompile(`^lease_[0-9a-f]{64}$`)
	sessionPattern  = regexp.MustCompile(`^ses_[0-9a-f]{64}$`)
	endpointPattern = regexp.MustCompile(`^mep_[0-9a-f]{64}$`)
)

// Request is one call over the local socket.
type Request struct {
	Schema string    `json:"schema"`
	Op     Operation `json:"op"`

	EventID      string     `json:"event_id,omitempty"`
	LeaseID      string     `json:"lease_id,omitempty"`
	LeaseSeconds uint64     `json:"lease_seconds,omitempty"`
	Code         fault.Code `json:"code,omitempty"`
	Limit        int        `json:"limit,omitempty"`

	// Event is an encoded Messaging Event, for submission.
	Event               json.RawMessage `json:"event,omitempty"`
	SessionID           string          `json:"session_id,omitempty"`
	RecipientEndpointID string          `json:"recipient_endpoint_id,omitempty"`
	ExpiresAtUnix       uint64          `json:"expires_at_unix,omitempty"`
}

// PendingEvent is one inbound event offered to the runtime.
type PendingEvent struct {
	EventID          string          `json:"event_id"`
	SenderEndpointID string          `json:"sender_messaging_endpoint_id"`
	ConversationID   string          `json:"conversation_id"`
	ReceivedAtUnix   uint64          `json:"received_at_unix"`
	Event            json.RawMessage `json:"event"`
}

// Response is one answer.
type Response struct {
	Schema string     `json:"schema"`
	OK     bool       `json:"ok"`
	Code   fault.Code `json:"code,omitempty"`
	Detail string     `json:"detail,omitempty"`

	Events []PendingEvent `json:"events,omitempty"`
	Event  *PendingEvent  `json:"claimed,omitempty"`
	Fresh  bool           `json:"fresh,omitempty"`
}

// EncodeRequest returns one framed request.
//
// Framing is a length prefix rather than a delimiter. A delimited frame is
// bounded by whatever buffer the reader happened to allocate, and a bound that
// depends on a buffer size is a bound nobody stated.
func EncodeRequest(request Request) ([]byte, error) {
	if err := ValidateRequest(request); err != nil {
		return nil, err
	}
	request.Schema = RequestSchema
	encoded, err := json.Marshal(request)
	if err != nil {
		return nil, err
	}
	return frame(encoded)
}

// DecodeRequest parses one framed request.
func DecodeRequest(raw []byte) (Request, error) {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	var request Request
	if err := decoder.Decode(&request); err != nil {
		return Request{}, err
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return Request{}, errors.New("request has trailing JSON")
	}
	if request.Schema != RequestSchema {
		return Request{}, errors.New("unsupported request schema")
	}
	if err := ValidateRequest(request); err != nil {
		return Request{}, err
	}
	return request, nil
}

// EncodeResponse returns one framed response.
func EncodeResponse(response Response) ([]byte, error) {
	response.Schema = ResponseSchema
	if !response.OK && response.Code == "" {
		return nil, errors.New("a refusal must carry a code")
	}
	encoded, err := json.Marshal(response)
	if err != nil {
		return nil, err
	}
	return frame(encoded)
}

func frame(body []byte) ([]byte, error) {
	if len(body) > MaxFrameBytes {
		return nil, errors.New("frame exceeds its bound")
	}
	out := make([]byte, frameHeaderBytes, frameHeaderBytes+len(body))
	binary.BigEndian.PutUint32(out, uint32(len(body)))
	return append(out, body...), nil
}

// ReadFrame reads one length-prefixed body.
//
// The declared length is checked before anything is allocated, so an oversized
// frame costs four bytes rather than the size it claimed.
func ReadFrame(reader io.Reader) ([]byte, error) {
	var header [frameHeaderBytes]byte
	if _, err := io.ReadFull(reader, header[:]); err != nil {
		return nil, err
	}
	length := binary.BigEndian.Uint32(header[:])
	if length == 0 {
		return nil, errors.New("empty frame")
	}
	if length > MaxFrameBytes {
		return nil, errors.New("frame exceeds its bound")
	}
	body := make([]byte, length)
	if _, err := io.ReadFull(reader, body); err != nil {
		return nil, err
	}
	return body, nil
}

// WriteFrame writes one length-prefixed body.
func WriteFrame(writer io.Writer, body []byte) error {
	framed, err := frame(body)
	if err != nil {
		return err
	}
	_, err = writer.Write(framed)
	return err
}

// DecodeResponse parses one framed response.
func DecodeResponse(raw []byte) (Response, error) {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	var response Response
	if err := decoder.Decode(&response); err != nil {
		return Response{}, err
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return Response{}, errors.New("response has trailing JSON")
	}
	if response.Schema != ResponseSchema {
		return Response{}, errors.New("unsupported response schema")
	}
	return response, nil
}

// ValidateRequest enforces the shape each operation needs.
//
// Every operation names exactly the fields it uses. A request carrying a lease
// for an operation that has no lease is not tolerated and ignored, because a
// caller sending one is not doing what it thinks it is doing.
func ValidateRequest(request Request) error {
	if _, known := operations[request.Op]; !known {
		return errors.New("unknown local operation")
	}
	switch request.Op {
	case OpPending, OpAwaitingAdmission:
		if request.Limit < 0 || request.Limit > MaxEventsPerResponse {
			return errors.New("invalid pending limit")
		}
		return requireEmpty(request, "a listing", request.EventID, request.LeaseID, request.SessionID)
	case OpClaim:
		if !eventPattern.MatchString(request.EventID) || !leasePattern.MatchString(request.LeaseID) {
			return errors.New("a claim needs an event and a lease")
		}
		if request.LeaseSeconds == 0 {
			return errors.New("a claim needs a lease duration")
		}
		return nil
	case OpComplete, OpReject:
		if !eventPattern.MatchString(request.EventID) || !leasePattern.MatchString(request.LeaseID) {
			return errors.New("an application outcome needs an event and a lease")
		}
		if request.Op == OpReject && request.Code != "" && !fault.Known(request.Code) {
			return errors.New("unknown rejection code")
		}
		return nil
	case OpQueue:
		if len(request.Event) == 0 {
			return errors.New("a submission needs an event")
		}
		if !sessionPattern.MatchString(request.SessionID) {
			return errors.New("a submission needs a session")
		}
		if !endpointPattern.MatchString(request.RecipientEndpointID) {
			return errors.New("a submission needs a recipient endpoint")
		}
		if request.ExpiresAtUnix == 0 {
			return errors.New("a submission needs an expiry")
		}
		return nil
	case OpApprove, OpDeny, OpAdmit:
		if !eventPattern.MatchString(request.EventID) {
			return errors.New("an owner decision needs an event")
		}
		return requireEmpty(request, "an owner decision", request.LeaseID, request.SessionID)
	case OpRefuse:
		if !eventPattern.MatchString(request.EventID) {
			return errors.New("an owner decision needs an event")
		}
		if request.Code != "" && !fault.Known(request.Code) {
			return errors.New("unknown refusal code")
		}
		return requireEmpty(request, "an owner decision", request.LeaseID, request.SessionID)
	}
	return errors.New("unknown local operation")
}

func requireEmpty(request Request, operation string, fields ...string) error {
	for _, field := range fields {
		if field != "" {
			return errors.New(operation + " carries a field it does not use")
		}
	}
	if len(request.Event) != 0 {
		return errors.New(operation + " carries an event it does not use")
	}
	return nil
}
