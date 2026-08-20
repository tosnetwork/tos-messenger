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
	"encoding/json"
	"errors"
	"io"
	"regexp"

	"github.com/tosnetwork/tos-messenger/internal/localwire"
	"github.com/tosnetwork/tos-messenger/pkg/fault"
	"github.com/tosnetwork/tos-messenger/pkg/negotiation"
)

const (
	// RequestSchema is the strict wire schema of a request.
	RequestSchema = "tos.messaging.local-request.v2"
	// ResponseSchema is the strict wire schema of a response.
	ResponseSchema = "tos.messaging.local-response.v1"

	// MaxFrameBytes bounds one request or response body. It has to hold an
	// event, because a claim hands one back.
	MaxFrameBytes = 512 << 10
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

	// OpRequestAction is the runtime asking the owner to authorise an action
	// the firewall stopped. The runtime may ask; it may not answer.
	OpRequestAction Operation = "actions.request"
	// OpActionStatus is the runtime reading whether an action it asked about
	// has been decided. It changes nothing, so a runtime may poll it.
	OpActionStatus Operation = "actions.status"
	// OpClaimAction consumes a granted authorisation. It succeeds exactly
	// once: an authorisation that could be claimed twice would permit the
	// second occurrence of an action the owner saw once.
	OpClaimAction Operation = "actions.claim"
	// OpPendingActions lists the actions waiting for the owner.
	OpPendingActions Operation = "actions.pending"
	// OpGrantAction is the owner authorising one action.
	OpGrantAction Operation = "actions.grant"
	// OpDenyAction is the owner refusing one.
	OpDenyAction Operation = "actions.deny"

	// OpPlaceMandate is the owner placing a standing authorisation. Only the
	// owner may: a runtime that could write its own mandate would be choosing
	// its own bounds, which is the one thing a mandate exists to prevent.
	OpPlaceMandate Operation = "mandates.place"
	// OpRevokeMandate is the owner withdrawing one.
	OpRevokeMandate Operation = "mandates.revoke"
	// OpChallenge issues a single-use nonce for one owner decision. It is the
	// first half of proving the decision came from the owner rather than from
	// whatever else happens to run under the same Unix user.
	OpChallenge Operation = "owner.challenge"
	// OpListMandates reads what this installation holds. Both sides may: the
	// Agent has to know what it may spend before it negotiates, and reading is
	// not deciding.
	OpListMandates Operation = "mandates.list"
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
		OpRequestAction: {}, OpActionStatus: {}, OpClaimAction: {}, OpListMandates: {},
	},
	PrincipalOwner: {
		OpAwaitingAdmission: {}, OpAdmit: {}, OpRefuse: {},
		OpApprove: {}, OpDeny: {},
		OpPendingActions: {}, OpGrantAction: {}, OpDenyAction: {},
		OpPlaceMandate: {}, OpRevokeMandate: {}, OpListMandates: {}, OpChallenge: {},
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
	OpRequestAction: {}, OpActionStatus: {}, OpClaimAction: {}, OpPendingActions: {},
	OpGrantAction: {}, OpDenyAction: {},
	OpPlaceMandate: {}, OpRevokeMandate: {}, OpListMandates: {}, OpChallenge: {},
}

var (
	eventPattern       = regexp.MustCompile(`^evt_[0-9a-f]{64}$`)
	leasePattern       = regexp.MustCompile(`^lease_[0-9a-f]{64}$`)
	sessionPattern     = regexp.MustCompile(`^ses_[0-9a-f]{64}$`)
	endpointPattern    = regexp.MustCompile(`^mep_[0-9a-f]{64}$`)
	actionPattern      = regexp.MustCompile(`^act_[0-9a-f]{64}$`)
	idempotencyPattern = regexp.MustCompile(`^idem_[0-9a-f]{64}$`)
	mandatePattern     = regexp.MustCompile(`^mdt_[0-9a-f]{64}$`)
	challengePattern   = regexp.MustCompile(`^[0-9a-f]{64}$`)
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

	// Action is one proposed action, for the firewall operations. It is the
	// action itself rather than an identifier, because the identifier is
	// derived from it: a runtime that could name an identifier without
	// presenting the action could have one approved and perform another.
	Action *ProposedAction `json:"action,omitempty"`
	// ActionID names an already-proposed action.
	ActionID string `json:"action_id,omitempty"`
	// Reason is why the owner refused.
	Reason string `json:"reason,omitempty"`

	// Mandate is a standing authorisation the owner is placing.
	Mandate *MandateTerms `json:"mandate,omitempty"`
	// Challenge and OwnerSignature carry the owner's authorisation for a
	// decision. They are required on every operation that decides something,
	// because the socket the request arrived on proves only which Unix user
	// sent it, and the Agent runtime usually is that user.
	Challenge      string `json:"challenge,omitempty"`
	OwnerSignature string `json:"owner_signature,omitempty"`

	// MandateID names one already placed. A runtime proposing a spend names
	// the mandate; it never supplies one.
	MandateID string `json:"mandate_id,omitempty"`
}

// AssetIdentity names an asset the way the chain does.
//
// A ticker is not carried, because a ticker is not an identity: two contracts
// may both call themselves USDT, and an authorisation that named one by ticker
// could be satisfied with the other. The network -- id and both genesis
// hashes, bare hex -- is part of the identity for the same reason: the same
// contract tuple exists on other TOS networks, and an authorisation or a
// purchase that omitted it could be satisfied elsewhere.
type AssetIdentity struct {
	NetworkID       string `json:"network_id"`
	GenesisRootHash string `json:"genesis_root_hash"`
	GenesisFileHash string `json:"genesis_file_hash"`
	Workchain       int32  `json:"workchain"`
	AccountID       string `json:"master_account_id"`
	MasterCodeHash  string `json:"master_code_hash"`
	WalletCodeHash  string `json:"wallet_code_hash"`
	Decimals        uint32 `json:"decimals"`
}

// MandateTerms is what an owner authorises in advance.
type MandateTerms struct {
	Objective       string        `json:"objective"`
	Authority       string        `json:"authority"`
	CapabilityClass string        `json:"capability_class"`
	Asset           AssetIdentity `json:"asset"`
	// MaxTotalAtomic and ApprovalAboveAtomic are counts of atomic units as
	// canonical decimal strings, which is what the chain carries. A fixed-width
	// integer cannot express eighteen decimal places of an ordinary token.
	MaxTotalAtomic      string `json:"max_total_atomic"`
	ApprovalAboveAtomic string `json:"approval_above_atomic"`
	MaxCounteroffers    uint32 `json:"max_counteroffers"`
	ExpiresAtUnix       uint64 `json:"expires_at_unix"`
}

// PurchaseTerms is the exact purchase a proposed spend would commit to.
//
// It carries every field a canonical Quote Proposal carries. Terms that named
// only the capability and the price would let the canonical form differ from
// what was approved in provider, manifest, escrow conditions, dispute policy
// or transport binding -- each of which changes what was bought while the
// number stays the same.
type PurchaseTerms struct {
	CapabilityID           string        `json:"capability_id"`
	CapabilityVersion      string        `json:"capability_version"`
	CapabilityClass        string        `json:"capability_class"`
	ProviderAgentID        string        `json:"provider_agent_id"`
	ManifestDigest         string        `json:"manifest_digest"`
	TransportBindingDigest string        `json:"transport_binding_digest"`
	Asset                  AssetIdentity `json:"asset"`
	PriceAtomic            string        `json:"price_atomic"`
	EscrowTermsDigest      string        `json:"escrow_terms_digest"`
	DisputePolicyDigest    string        `json:"dispute_policy_digest"`
	NotAfterUnix           uint64        `json:"not_after_unix"`
}

// HeldMandate is one standing authorisation as it is read back.
type HeldMandate struct {
	MandateID           string        `json:"mandate_id"`
	Objective           string        `json:"objective"`
	Authority           string        `json:"authority"`
	CapabilityClass     string        `json:"capability_class"`
	Asset               AssetIdentity `json:"asset"`
	MaxTotalAtomic      string        `json:"max_total_atomic"`
	ApprovalAboveAtomic string        `json:"approval_above_atomic"`
	MaxCounteroffers    uint32        `json:"max_counteroffers"`
	ExpiresAtUnix       uint64        `json:"expires_at_unix"`
	PlacedAtUnix        uint64        `json:"placed_at_unix"`
	RevokedAtUnix       uint64        `json:"revoked_at_unix,omitempty"`
}

// ProposedAction is what a runtime says it intends to do.
type ProposedAction struct {
	Effect         string         `json:"effect"`
	Summary        string         `json:"summary"`
	IdempotencyKey string         `json:"idempotency_key,omitempty"`
	Derived        []ActionOrigin `json:"derived_from,omitempty"`
	// Terms is what a spend would buy. It is part of the action, so the
	// identifier commits it and an approval for one price cannot be spent on
	// another.
	Terms *PurchaseTerms `json:"terms,omitempty"`
}

// ActionOrigin is one piece of received content behind a proposed action.
type ActionOrigin struct {
	AgentID        string `json:"agent_id"`
	EndpointID     string `json:"messaging_endpoint_id"`
	DeviceID       string `json:"device_id"`
	EventID        string `json:"event_id"`
	ConversationID string `json:"conversation_id"`
	Kind           string `json:"event_kind"`
	ReceivedAtUnix uint64 `json:"received_at_unix"`
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

	// Actions lists decisions waiting for the owner.
	Actions []WaitingAction `json:"actions,omitempty"`
	// ActionID is the identifier derived from a proposed action.
	ActionID string `json:"action_id,omitempty"`
	// Decision is what the firewall said, and Authorised reports whether the
	// runtime may proceed now. They are separate because "allowed" and "the
	// owner has decided" are different answers to different questions.
	Decision   string `json:"decision,omitempty"`
	Authorised bool   `json:"authorised,omitempty"`
	// State is where an approval request has got to.
	State string `json:"approval_state,omitempty"`
	// Mandates lists what this installation holds.
	Mandates []HeldMandate `json:"mandates,omitempty"`
	// MandateID is the identifier derived from a placed mandate.
	MandateID string `json:"mandate_id,omitempty"`
	// Challenge is a freshly issued single-use decision nonce.
	Challenge string `json:"challenge,omitempty"`
}

// WaitingAction is one decision the owner has not made yet.
type WaitingAction struct {
	ActionID       string         `json:"action_id"`
	Effect         string         `json:"effect"`
	Summary        string         `json:"summary"`
	IdempotencyKey string         `json:"idempotency_key,omitempty"`
	Reason         string         `json:"reason"`
	Origins        []ActionOrigin `json:"origins,omitempty"`
	// Terms is the structured purchase, present for a spend. The owner renders
	// the amount, asset, provider, and expiry from this rather than from the
	// summary, and recomputes the action identifier from it to confirm the
	// signature commits the purchase actually shown.
	Terms       *negotiation.Terms `json:"terms,omitempty"`
	AskedAtUnix uint64             `json:"asked_at_unix"`
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
	return localwire.Frame(body, MaxFrameBytes)
}

// ReadFrame reads one length-prefixed body.
//
// The declared length is checked before anything is allocated, so an oversized
// frame costs four bytes rather than the size it claimed.
func ReadFrame(reader io.Reader) ([]byte, error) {
	return localwire.ReadFrame(reader, MaxFrameBytes)
}

// WriteFrame writes one length-prefixed body.
func WriteFrame(writer io.Writer, body []byte) error {
	return localwire.WriteFrame(writer, body, MaxFrameBytes)
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
	// Every deciding operation carries the owner's authorisation, and no other
	// operation may carry one: a signature on a read would be a signature
	// somebody could keep.
	if Deciding(request.Op) {
		if !challengePattern.MatchString(request.Challenge) {
			return errors.New("an owner decision needs a challenge")
		}
		if request.OwnerSignature == "" {
			return errors.New("an owner decision needs the owner's signature")
		}
	} else if request.Challenge != "" || request.OwnerSignature != "" {
		return errors.New("only an owner decision carries a challenge and a signature")
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
	case OpRequestAction:
		if request.Action == nil {
			return errors.New("a firewall decision needs the action itself")
		}
		if request.ActionID != "" {
			return errors.New("the action identifier is derived, not declared")
		}
		if request.Action.Effect == "tool-call" && !idempotencyPattern.MatchString(request.Action.IdempotencyKey) {
			return errors.New("a tool call needs a canonical idempotency key")
		}
		if request.Action.Effect != "tool-call" && request.Action.IdempotencyKey != "" {
			return errors.New("only a tool call carries an idempotency key")
		}
		if request.Action.Effect == "spend" {
			if request.Action.Terms == nil {
				return errors.New("a spend must say what it is buying")
			}
			if !mandatePattern.MatchString(request.MandateID) {
				return errors.New("a spend must name the mandate it is made under")
			}
		} else if request.Action.Terms != nil || request.MandateID != "" {
			return errors.New("only a spend carries terms and a mandate")
		}
		return nil
	case OpPlaceMandate:
		if request.Mandate == nil {
			return errors.New("placing a mandate needs the mandate")
		}
		if request.MandateID != "" {
			return errors.New("the mandate identifier is derived, not declared")
		}
		return nil
	case OpRevokeMandate:
		if !mandatePattern.MatchString(request.MandateID) {
			return errors.New("withdrawing a mandate needs the mandate")
		}
		return requireEmpty(request, "an owner decision", request.EventID, request.LeaseID, request.SessionID)
	case OpListMandates, OpChallenge:
		return requireEmpty(request, "a listing", request.EventID, request.LeaseID, request.SessionID)
	case OpActionStatus, OpClaimAction:
		if !actionPattern.MatchString(request.ActionID) {
			return errors.New("an action status needs an action")
		}
		return requireEmpty(request, "an action status", request.EventID, request.LeaseID, request.SessionID)
	case OpPendingActions:
		if request.Limit < 0 || request.Limit > MaxEventsPerResponse {
			return errors.New("invalid pending limit")
		}
		return requireEmpty(request, "a listing", request.EventID, request.LeaseID, request.SessionID)
	case OpGrantAction:
		if !actionPattern.MatchString(request.ActionID) {
			return errors.New("an owner decision needs an action")
		}
		if request.Reason != "" {
			return errors.New("a grant carries no reason")
		}
		return requireEmpty(request, "an owner decision", request.EventID, request.LeaseID, request.SessionID)
	case OpDenyAction:
		if !actionPattern.MatchString(request.ActionID) {
			return errors.New("an owner decision needs an action")
		}
		if request.Reason == "" {
			return errors.New("a refusal must say why")
		}
		return requireEmpty(request, "an owner decision", request.EventID, request.LeaseID, request.SessionID)
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
