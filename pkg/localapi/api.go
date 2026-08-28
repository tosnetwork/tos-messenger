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

	"github.com/tosnetwork/tos-messenger/internal/canon"
	"github.com/tosnetwork/tos-messenger/internal/localwire"
	"github.com/tosnetwork/tos-messenger/pkg/fault"
	"github.com/tosnetwork/tos-messenger/pkg/firewall"
	"github.com/tosnetwork/tos-messenger/pkg/negotiation"
	"github.com/tosnetwork/tos-messenger/pkg/payload"
	commerce "github.com/tosnetwork/tos-service-protocol/pkg/agentcommerce"
)

const (
	// RequestSchema is the strict wire schema of a request.
	RequestSchema    = "tos.messaging.local-request.v15"
	RequestSchemaV14 = "tos.messaging.local-request.v14"
	RequestSchemaV13 = "tos.messaging.local-request.v13"
	RequestSchemaV12 = "tos.messaging.local-request.v12"
	RequestSchemaV11 = "tos.messaging.local-request.v11"
	RequestSchemaV10 = "tos.messaging.local-request.v10"
	// RequestSchemaV6 through RequestSchemaV11 remain accepted for the operations
	// they can express. Per-operation strict field validation prevents an older
	// client from smuggling newer authority while allowing rolling upgrades.
	RequestSchemaV6 = "tos.messaging.local-request.v6"
	RequestSchemaV7 = "tos.messaging.local-request.v7"
	RequestSchemaV8 = "tos.messaging.local-request.v8"
	RequestSchemaV9 = "tos.messaging.local-request.v9"
	// ResponseSchema is the strict wire schema of a response.
	ResponseSchema = "tos.messaging.local-response.v5"

	// MaxFrameBytes bounds one request or response body. It has to hold an
	// event, because a claim hands one back.
	MaxFrameBytes = 2 << 20
	// MaxEventsPerResponse bounds one pending listing.
	MaxEventsPerResponse = 64
	// MaxHistoryEventsPerResponse keeps worst-case canonical Event JSON below
	// the local response frame even when every Event is near its wire bound.
	MaxHistoryEventsPerResponse = 3
)

// Operation is what a caller is asking for.
type Operation string

const (
	// OpPending lists inbound events waiting for the runtime, including any
	// whose lease expired.
	OpPending Operation = "inbox.pending"
	// OpClaim takes a lease on one event and returns it.
	OpClaim Operation = "inbox.claim"
	// OpPendingAgentGifts lists only the three Agent Gift application kinds.
	// Its filtering occurs before pagination so unrelated traffic cannot starve
	// the Gift reconciler.
	OpPendingAgentGifts Operation = "agent-gifts.pending"
	// OpClaimAgentGift atomically leases only an Agent Gift Event.
	OpClaimAgentGift Operation = "agent-gifts.claim"
	// OpPendingAgreements lists only typed Agreement promotion events so they
	// never enter the ordinary chat/model inbox.
	OpPendingAgreements Operation = "agreements.pending"
	// OpClaimAgreement atomically leases one typed Agreement event.
	OpClaimAgreement Operation = "agreements.claim"
	// OpPendingPrivateHandoffs lists only typed private-handoff control events;
	// they never enter the ordinary chat/model inbox.
	OpPendingPrivateHandoffs Operation = "private-handoffs.pending"
	// OpClaimPrivateHandoff atomically leases one private-handoff control event.
	OpClaimPrivateHandoff Operation = "private-handoffs.claim"
	// OpPendingCommerceProfileEvents lists generic profile-qualified economic
	// objects and immutable operation-outcome events. They are isolated from
	// ordinary chat and model ingestion.
	OpPendingCommerceProfileEvents Operation = "commerce-profile-events.pending"
	// OpClaimCommerceProfileEvent atomically leases one such typed event.
	OpClaimCommerceProfileEvent Operation = "commerce-profile-events.claim"
	// OpComplete records that the runtime accepted an event.
	OpComplete Operation = "inbox.complete"
	// OpReject records that the runtime refused one.
	OpReject Operation = "inbox.reject"
	// OpQueue submits an event for delivery.
	OpQueue Operation = "outbox.queue"
	// OpCompose submits message meaning; the daemon supplies identity, network,
	// clock, payload schema, kind and Event ID.
	OpCompose Operation = "outbox.compose"
	// OpComposeProtocolResult queues a daemon-identified A2A response or MCP
	// result. It cannot synthesize an inbound call.
	OpComposeProtocolResult Operation = "outbox.compose-protocol-result"
	// OpResolveContact canonicalizes one human recipient input. It returns an
	// AgentID only after the normal finalized identity and directory chain has
	// succeeded; CanonicalName is non-authoritative display metadata.
	OpResolveContact Operation = "contacts.resolve"
	// OpEnsureDirectConversation resolves one human recipient input and creates
	// or reuses the daemon's AgentID-keyed discovered conversation. It exposes
	// no route/session authority and makes no transport-delivery claim.
	OpEnsureDirectConversation Operation = "conversations.ensure-direct"
	// OpSendDirect accepts recipient intent plus message semantics and delegates
	// all identity, session, device fan-out and route authority to the daemon.
	OpSendDirect Operation = "messages.send-direct"
	// OpSendDirectApplication carries one daemon-wrapped, established-direct
	// private application object. V1 restricts this surface to Agent Gifts.
	OpSendDirectApplication Operation = "messages.send-direct-application"
	// OpEconomicSendDirect is the only autonomous economic messaging surface.
	// It carries an independently verifiable action/fence envelope and the
	// exact canonical Messenger effect rather than route or session authority.
	OpEconomicSendDirect Operation = "economic.messages.send-direct"
	// OpEconomicActionStatus recovers a prior ambiguous send by the same stable
	// semantic ID and exact request digest; it never creates a new action.
	OpEconomicActionStatus Operation = "economic.actions.status"
	// OpReplyDirect derives all addressing from an authenticated inbound Event.
	OpReplyDirect Operation = "messages.reply-direct"
	// OpPendingAttachments lists only opaque metadata for encrypted attachment
	// Events. It never exposes the E2EE-carried Reference or fetch key.
	OpPendingAttachments Operation = "attachments.pending"
	// OpClaimAttachment atomically claims one encrypted attachment Event and
	// returns content only after daemon-owned fetch, AEAD verification and all
	// configured scanners allow it.
	OpClaimAttachment Operation = "attachments.claim"
	// OpBeginOutboundAttachment binds exact plaintext evidence and a fixed
	// route before daemon-owned streaming encryption begins.
	OpBeginOutboundAttachment Operation = "attachments.outbound.begin"
	// OpAppendOutboundAttachment submits one bounded sequential plaintext chunk;
	// the daemon persists only its authenticated ciphertext.
	OpAppendOutboundAttachment Operation = "attachments.outbound.chunk"
	// OpCommitOutboundAttachment obtains Endpoint grants, uploads and verifies
	// the lease, then queues the exact durable Event.
	OpCommitOutboundAttachment Operation = "attachments.outbound.commit"

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
	// OpCreateAdmissionInvite creates one random, expiring first-contact
	// bearer. It is an owner decision because it grants an unknown sender the
	// ability to place exactly one authenticated event in this inbox.
	OpCreateAdmissionInvite Operation = "invites.create"
	// OpRecordEscrowLocation lets the owner-side funding/wallet workflow bind
	// the finalized Quote commitment it funded to the exact escrow account the
	// chain resolver must read. A runtime may not create this authority map.
	OpRecordEscrowLocation Operation = "escrow-locations.record"
	// OpVerifyAcceptedQuote resolves one commitment from finalized state and
	// accepts the supplied escrow address only when that finalized account holds
	// the commitment and every expected purchase term plus this installation's
	// complete network identity matches.
	OpVerifyAcceptedQuote Operation = "quotes.verify"
	// OpExportDeviceHistory is an explicit owner decision to disclose one
	// bounded direct-conversation history page to another current device of
	// this Endpoint. The Agent runtime may neither request nor receive it.
	OpExportDeviceHistory Operation = "device-history.export"
	// OpListDeviceHistory reads checkpoint-reachable display history. It is
	// owner-side observability, not an application queue or execution trigger.
	OpListDeviceHistory Operation = "device-history.list"
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
		OpPending: {}, OpClaim: {}, OpPendingAgentGifts: {}, OpClaimAgentGift: {}, OpPendingAgreements: {}, OpClaimAgreement: {}, OpPendingPrivateHandoffs: {}, OpClaimPrivateHandoff: {}, OpPendingCommerceProfileEvents: {}, OpClaimCommerceProfileEvent: {}, OpComplete: {}, OpReject: {}, OpQueue: {}, OpCompose: {}, OpComposeProtocolResult: {},
		OpResolveContact: {}, OpEnsureDirectConversation: {},
		OpSendDirect: {}, OpSendDirectApplication: {}, OpEconomicSendDirect: {}, OpEconomicActionStatus: {}, OpReplyDirect: {},
		OpPendingAttachments: {}, OpClaimAttachment: {},
		OpBeginOutboundAttachment: {}, OpAppendOutboundAttachment: {}, OpCommitOutboundAttachment: {},
		OpRequestAction: {}, OpActionStatus: {}, OpClaimAction: {}, OpListMandates: {},
		OpVerifyAcceptedQuote: {},
	},
	PrincipalOwner: {
		OpAwaitingAdmission: {}, OpAdmit: {}, OpRefuse: {},
		OpApprove: {}, OpDeny: {},
		OpPendingActions: {}, OpGrantAction: {}, OpDenyAction: {},
		OpPlaceMandate: {}, OpRevokeMandate: {}, OpListMandates: {}, OpChallenge: {},
		OpCreateAdmissionInvite: {},
		OpRecordEscrowLocation:  {},
		OpExportDeviceHistory:   {},
		OpListDeviceHistory:     {},
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
	OpPending: {}, OpClaim: {}, OpPendingAgentGifts: {}, OpClaimAgentGift: {}, OpPendingAgreements: {}, OpClaimAgreement: {}, OpPendingPrivateHandoffs: {}, OpClaimPrivateHandoff: {}, OpPendingCommerceProfileEvents: {}, OpClaimCommerceProfileEvent: {}, OpComplete: {}, OpReject: {}, OpQueue: {}, OpCompose: {}, OpComposeProtocolResult: {},
	OpResolveContact: {}, OpEnsureDirectConversation: {},
	OpSendDirect: {}, OpSendDirectApplication: {}, OpEconomicSendDirect: {}, OpEconomicActionStatus: {}, OpReplyDirect: {},
	OpPendingAttachments: {}, OpClaimAttachment: {},
	OpBeginOutboundAttachment: {}, OpAppendOutboundAttachment: {}, OpCommitOutboundAttachment: {},
	OpAwaitingAdmission: {}, OpAdmit: {}, OpRefuse: {},
	OpApprove: {}, OpDeny: {},
	OpRequestAction: {}, OpActionStatus: {}, OpClaimAction: {}, OpPendingActions: {},
	OpGrantAction: {}, OpDenyAction: {},
	OpPlaceMandate: {}, OpRevokeMandate: {}, OpListMandates: {}, OpChallenge: {},
	OpCreateAdmissionInvite: {},
	OpRecordEscrowLocation:  {},
	OpVerifyAcceptedQuote:   {},
	OpExportDeviceHistory:   {},
	OpListDeviceHistory:     {},
}

var (
	eventPattern           = regexp.MustCompile(`^evt_[0-9a-f]{64}$`)
	leasePattern           = regexp.MustCompile(`^lease_[0-9a-f]{64}$`)
	sessionPattern         = regexp.MustCompile(`^ses_[0-9a-f]{64}$`)
	endpointPattern        = regexp.MustCompile(`^mep_[0-9a-f]{64}$`)
	actionPattern          = regexp.MustCompile(`^act_[0-9a-f]{64}$`)
	idempotencyPattern     = regexp.MustCompile(`^idem_[0-9a-f]{64}$`)
	conversationPattern    = regexp.MustCompile(`^conv_[0-9a-f]{64}$`)
	roomPattern            = regexp.MustCompile(`^room_[0-9a-f]{64}$`)
	mandatePattern         = regexp.MustCompile(`^mdt_[0-9a-f]{64}$`)
	agentPattern           = regexp.MustCompile(`^agent_[0-9a-f]{64}$`)
	devicePattern          = regexp.MustCompile(`^dev_[0-9a-f]{64}$`)
	challengePattern       = regexp.MustCompile(`^[0-9a-f]{64}$`)
	quotePattern           = regexp.MustCompile(`^tvm-cell-sha256:[0-9a-f]{64}$`)
	uploadPattern          = regexp.MustCompile(`^attup_[0-9a-f]{64}$`)
	capabilityPattern      = regexp.MustCompile(`^cap_[0-9a-f]{64}$`)
	physicalNamePattern    = regexp.MustCompile(`^[a-z][a-z0-9_-]{0,63}$`)
	canonicalDigestPattern = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
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
	// Recipient is a human input accepted only by contacts.resolve and
	// conversations.ensure-direct. It is either a canonical AgentID or a
	// canonical .tos alias and never carries endpoint, device, session, route,
	// or authorization data.
	Recipient string `json:"recipient,omitempty"`

	// Event is an encoded Messaging Event, for submission.
	Event               json.RawMessage `json:"event,omitempty"`
	SessionID           string          `json:"session_id,omitempty"`
	RecipientEndpointID string          `json:"recipient_endpoint_id,omitempty"`
	// RecipientAgentID is an optional canonical assertion on compose. When
	// present, the daemon re-verifies that the selected Endpoint belongs to
	// this exact Agent before queueing.
	RecipientAgentID string `json:"recipient_agent_id,omitempty"`
	ExpiresAtUnix    uint64 `json:"expires_at_unix,omitempty"`
	ConversationID   string `json:"conversation_id,omitempty"`
	RoomID           string `json:"room_id,omitempty"`
	ReplyToEventID   string `json:"reply_to_event_id,omitempty"`
	MembershipEpoch  uint64 `json:"membership_epoch,omitempty"`
	MediaType        string `json:"media_type,omitempty"`
	Body             string `json:"body,omitempty"`
	IdempotencyKey   string `json:"idempotency_key,omitempty"`
	ProtocolKind     string `json:"protocol_kind,omitempty"`
	Protocol         string `json:"protocol,omitempty"`
	ProtocolVersion  string `json:"protocol_version,omitempty"`
	ProtocolBody     []byte `json:"protocol_body_base64,omitempty"`
	ApplicationKind  string `json:"application_kind,omitempty"`
	ApplicationBody  []byte `json:"application_body_base64,omitempty"`

	// Economic fields exist only on the v13 economic operations. The daemon
	// derives the stable ID again and decodes ExactEconomicRequest to obtain the
	// actual message; none of these bytes are trusted as routing authority.
	EconomicAction        *commerce.AuthorizedAction    `json:"economic_action,omitempty"`
	EconomicWriterFence   *commerce.WriterFence         `json:"economic_writer_fence,omitempty"`
	EconomicFields        []commerce.SemanticFieldValue `json:"economic_semantic_fields,omitempty"`
	ExactEconomicRequest  []byte                        `json:"exact_economic_request_base64,omitempty"`
	EconomicStableID      string                        `json:"economic_stable_action_id,omitempty"`
	EconomicRequestDigest string                        `json:"economic_request_digest,omitempty"`

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

	// InvitedAgentID optionally scopes a new admission bearer to one Agent.
	// InviteExpiresAtUnix is always explicit and owner-signed.
	InvitedAgentID      string `json:"invited_agent_id,omitempty"`
	InviteExpiresAtUnix uint64 `json:"invite_expires_at_unix,omitempty"`

	QuoteCommitment    string         `json:"quote_commitment,omitempty"`
	EscrowAddress      string         `json:"escrow_address,omitempty"`
	CapabilityClass    string         `json:"capability_class,omitempty"`
	ExpectedQuoteTerms *PurchaseTerms `json:"expected_quote_terms,omitempty"`

	// Device-history export terms are all owner-signed. The source device,
	// recipient Endpoint and pair-session identifier are daemon-derived.
	TargetDeviceID        string `json:"target_device_id,omitempty"`
	HistorySequence       uint64 `json:"history_sequence,omitempty"`
	PreviousSegmentDigest string `json:"previous_segment_digest,omitempty"`
	AfterCreatedAtUnix    uint64 `json:"after_created_at_unix,omitempty"`
	AfterEventID          string `json:"after_event_id,omitempty"`

	// Outbound attachment fields carry plaintext evidence/stream bytes only.
	// Reference, keys, grants, storage authority, retention and Event identity
	// never cross from the runtime into the daemon.
	Filename        string `json:"filename,omitempty"`
	PlaintextDigest string `json:"plaintext_digest,omitempty"`
	PlaintextBytes  uint64 `json:"plaintext_bytes,omitempty"`
	UploadID        string `json:"upload_id,omitempty"`
	ChunkIndex      uint32 `json:"chunk_index,omitempty"`
	Chunk           []byte `json:"chunk_base64,omitempty"`
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
	// Physical is present only for physical-io. It binds the separately
	// configured local Capability and exact canonical argument digest that the
	// owner is being asked to authorize.
	Physical *PhysicalOperation `json:"physical,omitempty"`
}

type PhysicalOperation struct {
	CapabilityID    string `json:"capability_id"`
	Tool            string `json:"tool"`
	Operation       string `json:"operation"`
	ArgumentsDigest string `json:"arguments_digest"`
	ArgumentsJSON   string `json:"arguments_json"`
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

// PendingAttachment is deliberately less than a PendingEvent. In particular,
// it contains neither canonical Event bytes nor the v3 fetch capability key.
type PendingAttachment struct {
	EventID          string `json:"event_id"`
	SenderEndpointID string `json:"sender_messaging_endpoint_id"`
	ConversationID   string `json:"conversation_id"`
	ReceivedAtUnix   uint64 `json:"received_at_unix"`
}

type AttachmentScan struct {
	ScannerID     string                   `json:"scanner_id"`
	ScannerDigest string                   `json:"scanner_digest"`
	Resources     []AttachmentScanResource `json:"resources,omitempty"`
}

type AttachmentScanResource struct {
	Name   string `json:"name"`
	Digest string `json:"digest"`
}

// AdmittedAttachment is the only attachment shape released to the runtime.
// Its body has already passed exact AEAD/reference verification and every
// configured scanner; no decryption or capability material is present.
type AdmittedAttachment struct {
	EventID          string           `json:"event_id"`
	SenderAgentID    string           `json:"sender_agent_id"`
	SenderEndpointID string           `json:"sender_messaging_endpoint_id"`
	SenderDeviceID   string           `json:"sender_device_id"`
	ConversationID   string           `json:"conversation_id"`
	RoomID           string           `json:"room_id,omitempty"`
	ReplyToEventID   string           `json:"reply_to_event_id,omitempty"`
	ReceivedAtUnix   uint64           `json:"received_at_unix"`
	Filename         string           `json:"filename"`
	MediaType        string           `json:"media_type"`
	PlaintextDigest  string           `json:"plaintext_digest"`
	SizeBytes        uint64           `json:"size_bytes"`
	Body             string           `json:"body"`
	Scans            []AttachmentScan `json:"scans"`
}

// Response is one answer.
type Response struct {
	Schema string     `json:"schema"`
	OK     bool       `json:"ok"`
	Code   fault.Code `json:"code,omitempty"`
	Detail string     `json:"detail,omitempty"`

	Events      []PendingEvent      `json:"events,omitempty"`
	Event       *PendingEvent       `json:"claimed,omitempty"`
	Attachments []PendingAttachment `json:"attachments,omitempty"`
	Attachment  *AdmittedAttachment `json:"attachment,omitempty"`
	History     []json.RawMessage   `json:"history,omitempty"`
	Fresh       bool                `json:"fresh,omitempty"`
	EventID     string              `json:"event_id,omitempty"`
	UploadID    string              `json:"upload_id,omitempty"`
	NextChunk   uint32              `json:"next_chunk,omitempty"`
	Complete    bool                `json:"complete,omitempty"`
	// AgentID is the protocol identity returned by contacts.resolve.
	// CanonicalName is optional display metadata and MUST NOT be used as a key.
	AgentID       string `json:"agent_id,omitempty"`
	CanonicalName string `json:"canonical_name,omitempty"`
	// ConversationID and Readiness are returned only by the daemon-owned direct
	// conversation ensure operation. Readiness is not delivery confirmation.
	ConversationID     string                     `json:"conversation_id,omitempty"`
	Readiness          string                     `json:"readiness,omitempty"`
	EconomicResolution *commerce.ActionResolution `json:"economic_resolution,omitempty"`

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
	// AdmissionToken is returned exactly once when an owner creates an invite.
	AdmissionToken string `json:"admission_token,omitempty"`
	// FinalizedQuote is present only after the daemon resolved and exactly
	// matched a finalized Accepted Quote to the submitted terms and network.
	FinalizedQuote *FinalizedQuoteEvidence `json:"finalized_quote,omitempty"`
	// History export returns the committed page cursor and digest needed to
	// authorize the next segment without exposing the page body on this API.
	HistorySegmentDigest string `json:"history_segment_digest,omitempty"`
	LastEventCreatedAt   uint64 `json:"last_event_created_at_unix,omitempty"`
	LastEventID          string `json:"last_event_id,omitempty"`
}

type FinalizedQuoteEvidence struct {
	Commitment          string `json:"quote_commitment"`
	EscrowAccount       string `json:"escrow_account"`
	TransactionHash     string `json:"transaction_hash"`
	ContractCodeHash    string `json:"contract_code_hash"`
	FinalizedCheckpoint uint64 `json:"finalized_checkpoint"`
	FinalizedAtUnix     uint64 `json:"finalized_at_unix"`
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
	Physical    *PhysicalOperation `json:"physical,omitempty"`
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
	if request.Schema != RequestSchema && request.Schema != RequestSchemaV14 && request.Schema != RequestSchemaV13 && request.Schema != RequestSchemaV12 && request.Schema != RequestSchemaV11 && request.Schema != RequestSchemaV10 && request.Schema != RequestSchemaV9 && request.Schema != RequestSchemaV8 &&
		request.Schema != RequestSchemaV7 && request.Schema != RequestSchemaV6 {
		return Request{}, errors.New("unsupported request schema")
	}
	if request.Schema != RequestSchema && request.Schema != RequestSchemaV14 && request.Schema != RequestSchemaV13 && request.Schema != RequestSchemaV12 && request.Schema != RequestSchemaV11 && request.Op == OpSendDirectApplication {
		return Request{}, errors.New("direct application sending requires local request v11")
	}
	if request.Schema != RequestSchema && request.Schema != RequestSchemaV14 && request.Schema != RequestSchemaV13 && request.Schema != RequestSchemaV12 && (request.Op == OpPendingAgentGifts || request.Op == OpClaimAgentGift || request.Op == OpPendingAgreements || request.Op == OpClaimAgreement) {
		return Request{}, errors.New("typed economic inbox operations require local request v12")
	}
	if request.Schema != RequestSchema && request.Schema != RequestSchemaV14 && request.Schema != RequestSchemaV13 && (request.Op == OpEconomicSendDirect || request.Op == OpEconomicActionStatus) {
		return Request{}, errors.New("economic side-effect operations require local request v13")
	}
	if request.Schema != RequestSchema && request.Schema != RequestSchemaV14 && (request.Op == OpPendingPrivateHandoffs || request.Op == OpClaimPrivateHandoff) {
		return Request{}, errors.New("private handoff inbox operations require local request v14")
	}
	if request.Schema != RequestSchema && (request.Op == OpPendingCommerceProfileEvents || request.Op == OpClaimCommerceProfileEvent) {
		return Request{}, errors.New("commerce profile inbox operations require local request v15")
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
	if request.Op != OpEconomicSendDirect && request.Op != OpEconomicActionStatus &&
		(request.EconomicAction != nil || request.EconomicWriterFence != nil || len(request.EconomicFields) != 0 ||
			len(request.ExactEconomicRequest) != 0 || request.EconomicStableID != "" || request.EconomicRequestDigest != "") {
		return errors.New("only economic operations carry economic authorization")
	}
	if request.Op != OpCreateAdmissionInvite &&
		(request.InvitedAgentID != "" || request.InviteExpiresAtUnix != 0) {
		return errors.New("only admission invite creation carries invite terms")
	}
	if request.Op != OpResolveContact && request.Op != OpEnsureDirectConversation && request.Op != OpSendDirect && request.Op != OpSendDirectApplication && request.Recipient != "" {
		return errors.New("only contact or direct-conversation resolution carries a recipient input")
	}
	if request.Op != OpCompose && request.RecipientAgentID != "" {
		return errors.New("only message composition carries a recipient Agent assertion")
	}
	if request.Op != OpRecordEscrowLocation && request.Op != OpVerifyAcceptedQuote && request.QuoteCommitment != "" {
		return errors.New("only escrow recording or Quote verification carries a Quote commitment")
	}
	if request.Op != OpRecordEscrowLocation && request.Op != OpVerifyAcceptedQuote &&
		(request.EscrowAddress != "" || request.CapabilityClass != "") {
		return errors.New("only escrow recording or Quote verification carries funded escrow locators")
	}
	if request.Op != OpVerifyAcceptedQuote && request.ExpectedQuoteTerms != nil {
		return errors.New("only Quote verification carries expected Quote terms")
	}
	if request.Op != OpCompose && request.Op != OpSendDirect && request.Op != OpSendDirectApplication && request.Op != OpReplyDirect && request.Op != OpComposeProtocolResult && request.Op != OpBeginOutboundAttachment && request.Op != OpExportDeviceHistory && request.Op != OpListDeviceHistory &&
		(request.ConversationID != "" || request.IdempotencyKey != "") {
		return errors.New("only outbound composition carries message semantics")
	}
	if request.Op == OpListDeviceHistory && request.IdempotencyKey != "" {
		return errors.New("a history listing has no idempotency key")
	}
	if request.Op != OpCompose && request.Op != OpSendDirect && request.Op != OpReplyDirect && request.Op != OpComposeProtocolResult && request.Op != OpBeginOutboundAttachment && (request.RoomID != "" || request.ReplyToEventID != "" ||
		request.MembershipEpoch != 0 || request.MediaType != "" || request.Body != "") {
		return errors.New("only message composition carries message body semantics")
	}
	if request.Op == OpBeginOutboundAttachment && request.Body != "" {
		return errors.New("outbound attachment begin does not carry an inline body")
	}
	if request.Op != OpComposeProtocolResult && (request.ProtocolKind != "" || request.Protocol != "" ||
		request.ProtocolVersion != "" || len(request.ProtocolBody) != 0) {
		return errors.New("only protocol result composition carries protocol body semantics")
	}
	if request.Op != OpSendDirectApplication && (request.ApplicationKind != "" || len(request.ApplicationBody) != 0) {
		return errors.New("only direct application sending carries an application object")
	}
	if request.Op != OpBeginOutboundAttachment && (request.Filename != "" || request.PlaintextDigest != "" || request.PlaintextBytes != 0) {
		return errors.New("only outbound attachment begin carries plaintext metadata")
	}
	if request.Op != OpAppendOutboundAttachment && request.Op != OpCommitOutboundAttachment && request.UploadID != "" {
		return errors.New("only an outbound attachment transaction carries an upload identifier")
	}
	if request.Op != OpAppendOutboundAttachment && (request.ChunkIndex != 0 || len(request.Chunk) != 0) {
		return errors.New("only an outbound attachment chunk carries chunk bytes")
	}
	if request.Op != OpExportDeviceHistory && (request.TargetDeviceID != "" || request.HistorySequence != 0 ||
		request.PreviousSegmentDigest != "" || request.AfterCreatedAtUnix != 0 || request.AfterEventID != "") {
		return errors.New("only device-history export carries history terms")
	}
	switch request.Op {
	case OpEconomicSendDirect:
		if request.EconomicAction == nil || request.EconomicWriterFence == nil || len(request.EconomicFields) == 0 ||
			len(request.ExactEconomicRequest) == 0 || len(request.ExactEconomicRequest) > commerce.MaxActionRequestBytes ||
			request.EconomicStableID != "" || request.EconomicRequestDigest != "" {
			return errors.New("an economic send needs one complete authorization envelope")
		}
		if _, err := commerce.ImportSemanticFields(request.EconomicAction.ActionKind, request.EconomicFields); err != nil {
			return err
		}
		if _, err := commerce.DecodeMessengerEffectRequest(request.ExactEconomicRequest); err != nil {
			return err
		}
		return requireEmpty(request, "an economic send", request.EventID, request.LeaseID, request.SessionID,
			request.Recipient, request.MediaType, request.Body, request.ApplicationKind, request.IdempotencyKey)
	case OpEconomicActionStatus:
		if request.EconomicAction != nil || request.EconomicWriterFence != nil || len(request.EconomicFields) != 0 ||
			len(request.ExactEconomicRequest) != 0 || !canonicalDigestPattern.MatchString(request.EconomicStableID) ||
			!canonicalDigestPattern.MatchString(request.EconomicRequestDigest) {
			return errors.New("economic action status needs one stable ID and exact request digest")
		}
		return requireEmpty(request, "an economic action status", request.EventID, request.LeaseID, request.SessionID)
	case OpReplyDirect:
		if !eventPattern.MatchString(request.ReplyToEventID) || request.MediaType == "" || request.Body == "" ||
			!idempotencyPattern.MatchString(request.IdempotencyKey) || request.ExpiresAtUnix == 0 {
			return errors.New("a direct reply needs source Event, message, expiry and idempotency")
		}
		if request.Recipient != "" || request.Limit != 0 || request.Code != "" || request.SessionID != "" ||
			request.RecipientEndpointID != "" || request.RecipientAgentID != "" || request.ConversationID != "" ||
			request.RoomID != "" || request.MembershipEpoch != 0 {
			return errors.New("a direct reply cannot carry low-level routing authority")
		}
		return requireEmpty(request, "a direct reply", request.EventID, request.LeaseID)
	case OpSendDirect:
		if request.Recipient == "" || len(request.Recipient) > 255 || request.MediaType == "" || request.Body == "" ||
			!idempotencyPattern.MatchString(request.IdempotencyKey) || request.ExpiresAtUnix == 0 {
			return errors.New("a direct send needs recipient, message, expiry and idempotency")
		}
		if request.Limit != 0 || request.Code != "" || request.SessionID != "" ||
			request.RecipientEndpointID != "" || request.RecipientAgentID != "" || request.ConversationID != "" ||
			request.RoomID != "" || request.ReplyToEventID != "" || request.MembershipEpoch != 0 {
			return errors.New("a direct send cannot carry low-level routing authority")
		}
		return requireEmpty(request, "a direct send", request.EventID, request.LeaseID)
	case OpSendDirectApplication:
		if request.Recipient == "" || len(request.Recipient) > 255 ||
			!idempotencyPattern.MatchString(request.IdempotencyKey) || request.ExpiresAtUnix == 0 ||
			len(request.ApplicationBody) == 0 || len(request.ApplicationBody) > payload.MaxAgreementPromotionBytes {
			return errors.New("a direct application send needs recipient, bounded object, expiry and idempotency")
		}
		switch request.ApplicationKind {
		case "agent.gift.address-request", "agent.gift.address-response", "agent.gift.signed-boc-offer":
			if len(request.ApplicationBody) > payload.MaxGiftCanonicalBytes {
				return errors.New("Agent Gift application is oversized")
			}
		default:
			return errors.New("unsupported direct application kind")
		}
		if request.MediaType != "" || request.Body != "" || request.RoomID != "" || request.ReplyToEventID != "" || request.ConversationID != "" || request.SessionID != "" || request.RecipientEndpointID != "" || request.RecipientAgentID != "" {
			return errors.New("a direct application cannot carry text, room, or route authority")
		}
		return requireEmpty(request, "a direct application send", request.EventID, request.LeaseID)
	case OpResolveContact, OpEnsureDirectConversation:
		if request.Recipient == "" || len(request.Recipient) > 255 {
			return errors.New("recipient resolution needs one bounded input")
		}
		if request.Limit != 0 || request.Code != "" || request.RecipientEndpointID != "" ||
			request.ExpiresAtUnix != 0 || request.LeaseSeconds != 0 || request.Action != nil ||
			request.ActionID != "" || request.Reason != "" || request.Mandate != nil || request.MandateID != "" {
			return errors.New("recipient resolution cannot carry route or control fields")
		}
		return requireEmpty(request, "recipient resolution", request.EventID, request.LeaseID, request.SessionID)
	case OpPending, OpPendingAgentGifts, OpPendingAgreements, OpPendingPrivateHandoffs, OpPendingCommerceProfileEvents, OpAwaitingAdmission, OpPendingAttachments:
		if request.Limit < 0 || request.Limit > MaxEventsPerResponse {
			return errors.New("invalid pending limit")
		}
		return requireEmpty(request, "a listing", request.EventID, request.LeaseID, request.SessionID)
	case OpClaim, OpClaimAgentGift, OpClaimAgreement, OpClaimPrivateHandoff, OpClaimCommerceProfileEvent, OpClaimAttachment:
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
	case OpCompose:
		if !conversationPattern.MatchString(request.ConversationID) ||
			!sessionPattern.MatchString(request.SessionID) || !endpointPattern.MatchString(request.RecipientEndpointID) ||
			!idempotencyPattern.MatchString(request.IdempotencyKey) || request.ExpiresAtUnix == 0 {
			return errors.New("a composition needs canonical conversation, route, expiry and idempotency identifiers")
		}
		if request.RoomID == "" {
			if request.MembershipEpoch != 0 {
				return errors.New("a direct message has no membership epoch")
			}
		} else if !roomPattern.MatchString(request.RoomID) || request.MembershipEpoch == 0 {
			return errors.New("a room message needs a canonical room and membership epoch")
		}
		if request.ReplyToEventID != "" && !eventPattern.MatchString(request.ReplyToEventID) {
			return errors.New("invalid reply event identifier")
		}
		if request.MediaType == "" || request.Body == "" {
			return errors.New("a composition needs media type and body")
		}
		if request.RecipientAgentID != "" && !agentPattern.MatchString(request.RecipientAgentID) {
			return errors.New("a composition has an invalid recipient Agent assertion")
		}
		return nil
	case OpComposeProtocolResult:
		if !conversationPattern.MatchString(request.ConversationID) || !eventPattern.MatchString(request.ReplyToEventID) ||
			!sessionPattern.MatchString(request.SessionID) || !endpointPattern.MatchString(request.RecipientEndpointID) ||
			!idempotencyPattern.MatchString(request.IdempotencyKey) || request.ExpiresAtUnix == 0 || len(request.ProtocolBody) == 0 {
			return errors.New("a protocol result needs canonical source, route, expiry, idempotency and body")
		}
		if !((request.ProtocolKind == "a2a.message" && request.Protocol == "a2a") ||
			(request.ProtocolKind == "mcp.result" && request.Protocol == "mcp")) || request.ProtocolVersion != "1" {
			return errors.New("invalid protocol result profile")
		}
		if request.RoomID != "" || request.MembershipEpoch != 0 || request.MediaType != "" || request.Body != "" {
			return errors.New("a protocol result cannot carry text or room semantics")
		}
		return nil
	case OpBeginOutboundAttachment:
		if !conversationPattern.MatchString(request.ConversationID) || !sessionPattern.MatchString(request.SessionID) ||
			!endpointPattern.MatchString(request.RecipientEndpointID) || !idempotencyPattern.MatchString(request.IdempotencyKey) {
			return errors.New("an attachment begin needs canonical conversation, route and idempotency identifiers")
		}
		if request.RoomID == "" {
			if request.MembershipEpoch != 0 {
				return errors.New("a direct attachment has no membership epoch")
			}
		} else if !roomPattern.MatchString(request.RoomID) || request.MembershipEpoch == 0 {
			return errors.New("a room attachment needs a canonical room and membership epoch")
		}
		if request.ReplyToEventID != "" && !eventPattern.MatchString(request.ReplyToEventID) {
			return errors.New("invalid attachment reply event identifier")
		}
		if request.Filename == "" || request.MediaType == "" || !canon.ValidDigest(request.PlaintextDigest) || request.PlaintextBytes == 0 {
			return errors.New("an attachment begin needs filename, media type, digest and size")
		}
		if request.ExpiresAtUnix != 0 {
			return errors.New("attachment retention is daemon-owned")
		}
		return nil
	case OpAppendOutboundAttachment:
		if !uploadPattern.MatchString(request.UploadID) || len(request.Chunk) == 0 || len(request.Chunk) > 1<<20 {
			return errors.New("an attachment chunk needs a canonical upload and bounded bytes")
		}
		return nil
	case OpCommitOutboundAttachment:
		if !uploadPattern.MatchString(request.UploadID) {
			return errors.New("an attachment commit needs a canonical upload")
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
		oneShotTool := request.Action.Effect == "tool-call" || request.Action.Effect == "physical-io"
		if oneShotTool && !idempotencyPattern.MatchString(request.Action.IdempotencyKey) {
			return errors.New("a tool call needs a canonical idempotency key")
		}
		if !oneShotTool && request.Action.IdempotencyKey != "" {
			return errors.New("only a tool call carries an idempotency key")
		}
		if request.Action.Effect == "physical-io" {
			physical := request.Action.Physical
			if physical == nil || !capabilityPattern.MatchString(physical.CapabilityID) ||
				!physicalNamePattern.MatchString(physical.Tool) || !physicalNamePattern.MatchString(physical.Operation) ||
				!canon.ValidDigest(physical.ArgumentsDigest) || physical.ArgumentsJSON == "" ||
				len(physical.ArgumentsJSON) > firewall.MaxPhysicalArgumentsBytes {
				return errors.New("physical I/O needs a canonical local Capability, operation, and argument digest")
			}
		} else if request.Action.Physical != nil {
			return errors.New("only physical I/O carries a physical operation")
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
	case OpCreateAdmissionInvite:
		if request.InvitedAgentID != "" && !agentPattern.MatchString(request.InvitedAgentID) {
			return errors.New("an admission invite has an invalid Agent scope")
		}
		if request.InviteExpiresAtUnix == 0 {
			return errors.New("an admission invite needs an expiry")
		}
		return requireEmpty(request, "admission invite creation", request.EventID, request.LeaseID, request.SessionID)
	case OpRecordEscrowLocation:
		if !quotePattern.MatchString(request.QuoteCommitment) ||
			request.EscrowAddress == "" || len(request.EscrowAddress) > 80 || request.CapabilityClass == "" ||
			len(request.CapabilityClass) > 64 {
			return errors.New("recording an escrow location needs canonical funded escrow terms")
		}
		return requireEmpty(request, "escrow-location recording", request.EventID, request.LeaseID, request.SessionID)
	case OpVerifyAcceptedQuote:
		if !quotePattern.MatchString(request.QuoteCommitment) || request.EscrowAddress == "" ||
			len(request.EscrowAddress) > 80 || request.CapabilityClass == "" ||
			len(request.CapabilityClass) > 64 || request.ExpectedQuoteTerms == nil {
			return errors.New("Quote verification needs an escrow locator, commitment, and complete expected terms")
		}
		if terms := toTerms(request.ExpectedQuoteTerms); terms == nil || terms.Validate() != nil {
			return errors.New("Quote verification carries invalid expected terms")
		}
		return requireEmpty(request, "Quote verification", request.EventID, request.LeaseID, request.SessionID)
	case OpExportDeviceHistory:
		validCursor := (request.HistorySequence == 1 && request.PreviousSegmentDigest == "" &&
			request.AfterCreatedAtUnix == 0 && request.AfterEventID == "") ||
			(request.HistorySequence > 1 && canon.ValidDigest(request.PreviousSegmentDigest) &&
				request.AfterCreatedAtUnix > 0 && eventPattern.MatchString(request.AfterEventID))
		if !conversationPattern.MatchString(request.ConversationID) ||
			!devicePattern.MatchString(request.TargetDeviceID) || !idempotencyPattern.MatchString(request.IdempotencyKey) ||
			request.ExpiresAtUnix == 0 || request.Limit < 0 || request.Limit > payload.MaxHistoryEventsPerSegment || !validCursor {
			return errors.New("history export needs canonical target, cursor, expiry and idempotency terms")
		}
		return requireEmpty(request, "device-history export", request.EventID, request.LeaseID, request.SessionID)
	case OpListDeviceHistory:
		if !conversationPattern.MatchString(request.ConversationID) || request.Limit < 0 || request.Limit > MaxHistoryEventsPerResponse {
			return errors.New("history listing needs a canonical conversation and bounded limit")
		}
		return requireEmpty(request, "device-history listing", request.EventID, request.LeaseID, request.SessionID)
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
