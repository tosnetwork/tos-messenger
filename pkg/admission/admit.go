package admission

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"time"

	"github.com/tosnetwork/tos-messenger/internal/canon"
	"github.com/tosnetwork/tos-messenger/pkg/envelope"
	"github.com/tosnetwork/tos-messenger/pkg/eventlog"
	"github.com/tosnetwork/tos-messenger/pkg/fault"
	"github.com/tosnetwork/tos-messenger/pkg/identity"
	"github.com/tosnetwork/tos-messenger/pkg/payload"
	nativev1 "github.com/tosnetwork/tos-service-protocol/gen/tos/service/v1"
)

// RecordSchema is the strict schema of a decision record.
const RecordSchema = "tos.messaging.admission-record.v1"

// DefaultClockSkewSeconds bounds how far ahead of local time an event may be
// dated. Clocks differ; an event dated further ahead than this is not a clock
// difference.
const DefaultClockSkewSeconds = 300

// MinInstallSaltBytes bounds the salt that makes sender references local.
const MinInstallSaltBytes = 16

// Route is how an event arrived. It is recorded for diagnosis and has no
// bearing on the decision: a Relay path grants nothing a direct path does not.
type Route string

const (
	// RouteDirect is a direct session between endpoints.
	RouteDirect Route = "direct"
	// RouteTunnel is an approved proxy or tunnel.
	RouteTunnel Route = "tunnel"
	// RouteRelay is an encrypted offline Mailbox Relay.
	RouteRelay Route = "relay"
	// RouteHTTPS is the bounded bootstrap path.
	RouteHTTPS Route = "https"
)

var routes = map[Route]struct{}{RouteDirect: {}, RouteTunnel: {}, RouteRelay: {}, RouteHTTPS: {}}

// Outcome is what the caller should do with the event.
type Outcome string

const (
	// Accepted means the event is fresh and durably queued. It is what a
	// DeliveryAck reports.
	//
	// It does not mean the event has been handed to a runtime. Delivery is
	// driven from the journal, so that an event accepted just before a crash
	// is still delivered afterwards; a caller that treated this return value
	// as the delivery itself would lose exactly those events.
	Accepted Outcome = "accepted"
	// Duplicate means the event was already delivered. It is a successful
	// at-least-once delivery, not a failure: the peer is acknowledged and the
	// runtime is not told again.
	Duplicate Outcome = "duplicate"
	// Held means the event is waiting on an owner decision.
	Held Outcome = "held"
	// Rejected means the event does not enter.
	Rejected Outcome = "rejected"
)

// Record is the privacy-minimized decision record.
//
// It carries what an operator needs to diagnose a delivery and not what would
// reconstruct a social graph. The sender appears as a reference derived with a
// per-install salt, so the same sender is correlatable within one node's logs
// while the logs alone identify nobody.
type Record struct {
	Schema    string     `json:"schema"`
	EventID   string     `json:"event_id"`
	SenderRef string     `json:"sender_ref"`
	Class     string     `json:"class,omitempty"`
	Outcome   Outcome    `json:"outcome"`
	Code      fault.Code `json:"code,omitempty"`
	Route     Route      `json:"route"`
	AtUnix    uint64     `json:"at_unix"`
}

// Decision is the result of one admission run.
type Decision struct {
	Outcome    Outcome
	Code       fault.Code
	Response   fault.Response
	Delegation identity.Delegation
	Event      envelope.Event
	Record     Record
}

// Inbound is one decrypted event and the authority presented with it.
//
// The event is already decrypted, because decryption belongs to the session
// layer and its suite is not chosen. Everything here is about whether a
// decrypted event may proceed.
type Inbound struct {
	Event          envelope.Event
	DelegationJSON []byte
	Route          Route
	ReceivedAtUnix uint64
}

// Config wires one gate.
type Config struct {
	Network *nativev1.NetworkDomain
	// Chain is what this install accepts as finalized state: which registry
	// contract produced it, and how far back a checkpoint may be.
	Chain    identity.ChainPolicy
	Resolver identity.AgentResolver
	Journal  *eventlog.Journal
	Policy   ContactPolicy
	// LocalDelegationJSON is this installation's own published delegation, as
	// it was published. It is verified against finalized state at start, and
	// it names the inbox policy digest this endpoint told the network it
	// enforces.
	LocalDelegationJSON []byte
	// LocalAgentID and LocalEndpointID are who this installation is. The
	// delegation has to be theirs: another endpoint's, however valid, would
	// bind this gate to somebody else's published policy.
	LocalAgentID    string
	LocalEndpointID string
	// Now is the clock the start-up checks use.
	Now                 func() time.Time
	MaxContentBytes     int
	MaxClockSkewSeconds uint64
	InstallSalt         []byte
}

// Gate admits inbound events.
type Gate struct {
	config Config
}

// New builds a gate. Every dependency is required: a gate missing its resolver
// would be deciding authority from the sender's own claims, and one missing
// its policy would be an open inbox nobody chose.
func New(config Config) (*Gate, error) {
	if config.Now == nil {
		config.Now = time.Now
	}
	if config.Network == nil || config.Network.NetworkId == "" ||
		!canon.HashPattern.MatchString(config.Network.GenesisRootHash) ||
		!canon.HashPattern.MatchString(config.Network.GenesisFileHash) {
		return nil, errors.New("invalid admission network domain")
	}
	if config.Resolver == nil {
		return nil, errors.New("admission requires a finalized state resolver")
	}
	if err := config.Chain.Validate(); err != nil {
		return nil, err
	}
	if config.Journal == nil {
		return nil, errors.New("admission requires a durable journal")
	}
	if !config.Policy.Configured() {
		return nil, errors.New("admission requires an inbox policy")
	}
	// This endpoint's own delegation is not taken on the caller's word. It is
	// resolved against finalized state the same way a sender's is, because an
	// installation enforcing a delegation the Agent no longer commits would be
	// enforcing a permission that was withdrawn.
	local, err := identity.Verify(config.Resolver, config.Network, config.Chain,
		config.LocalDelegationJSON, config.Now())
	if err != nil {
		return nil, errors.New("this endpoint's own delegation does not verify: " + err.Error())
	}
	// And it must be this installation's, not some other endpoint's.
	if local.AgentID != config.LocalAgentID || local.EndpointID != config.LocalEndpointID {
		return nil, errors.New("this endpoint's delegation belongs to another endpoint")
	}
	// A published policy digest that nothing checks is a claim, not a
	// commitment. An installation that advertises one policy and enforces
	// another must not start.
	if config.Policy.Digest() != local.InboxAdmissionPolicyDigest {
		return nil, errors.New("the inbox policy in use is not the one this endpoint published")
	}
	if len(config.InstallSalt) < MinInstallSaltBytes {
		return nil, errors.New("admission requires a per-install salt")
	}
	// The bound a recipient publishes in its descriptor may be smaller than the
	// protocol maximum, and it is the smaller one that applies. An event above
	// the protocol maximum cannot be constructed at all, so this check exists
	// for the recipient's own limit.
	if config.MaxContentBytes <= 0 || config.MaxContentBytes > envelope.MaxContentBytes {
		config.MaxContentBytes = envelope.MaxContentBytes
	}
	if config.MaxClockSkewSeconds == 0 {
		config.MaxClockSkewSeconds = DefaultClockSkewSeconds
	}
	return &Gate{config: config}, nil
}

// Admit runs the ordered checks and returns a decision.
//
// An error is returned only for a local failure, never for a rejected event: a
// refusal is a result, and turning it into an error would tempt a caller into
// treating the two the same way.
func (g *Gate) Admit(inbound Inbound) (Decision, error) {
	if g == nil {
		return Decision{}, errors.New("no admission gate")
	}
	if _, known := routes[inbound.Route]; !known {
		return Decision{}, errors.New("invalid arrival route")
	}
	if inbound.ReceivedAtUnix == 0 {
		return Decision{}, errors.New("invalid arrival time")
	}

	// The caller decoded this event, but a gate that trusted its caller's
	// validation would be one bypass away from admitting anything.
	if err := envelope.ValidateEvent(inbound.Event); err != nil {
		return g.refuse(inbound, fault.CodeSenderMismatch, ""), nil
	}
	class, known := envelope.ClassOf(inbound.Event.Kind)
	if !known {
		return g.refuse(inbound, fault.CodeUnknownEventKind, ""), nil
	}
	// A local-only kind carries authority rather than information: it is this
	// owner authorising something here. Arriving from the network it is not a
	// request to evaluate, it is a kind that has no business being expressible
	// on the wire, and it is refused before anything else looks at it.
	if envelope.LocalOnly(inbound.Event.Kind) {
		return g.refuse(inbound, fault.CodeUnknownEventKind, class), nil
	}
	if !sameNetwork(inbound.Event.Network, g.config.Network) {
		return g.refuse(inbound, fault.CodeNetworkMismatch, class), nil
	}
	if !g.withinWindow(inbound) {
		return g.refuse(inbound, fault.CodeEventOutsideWindow, class), nil
	}
	if len(inbound.Event.Content) > g.config.MaxContentBytes {
		return g.refuse(inbound, fault.CodeContentTooLarge, class), nil
	}
	delegation, code := g.authority(inbound)
	if code != "" {
		return g.refuse(inbound, code, class), nil
	}
	if inbound.Event.SenderAgentID != delegation.AgentID ||
		inbound.Event.SenderEndpointID != delegation.EndpointID {
		return g.refuse(inbound, fault.CodeSenderMismatch, class), nil
	}
	if !identity.AllowsEventClass(delegation, class) {
		return g.refuse(inbound, fault.CodeClassNotDelegated, class), nil
	}

	// The inbox policy runs before anything is written down.
	//
	// A sender told to satisfy an admission policy will send the same event
	// again once they have. Event identifiers are content addressed, so that
	// resend is byte-identical, and a claim taken now would turn their
	// corrected attempt into a duplicate that is never delivered. Refusing
	// without claiming is what leaves the remedy usable. Denied senders are
	// not written down either, which keeps a stranger from filling the journal.
	admission := g.config.Policy.Admits(inbound.Event.SenderAgentID, inbound.Event.Kind)
	if admission != AdmitAllow && admission != AdmitHoldForApproval {
		code, err := codeFor(admission)
		if err != nil {
			return Decision{}, err
		}
		decision := g.refuse(inbound, code, class)
		decision.Delegation = delegation
		return decision, nil
	}

	// The kind names a payload contract, and a body that does not meet it is
	// not a weakly-typed message: it is a message whose kind is wrong about
	// itself. Admitting it would hand the runtime bytes it would have to guess
	// at, which is the guessing this layer exists to remove.
	//
	// It runs after admission on purpose. A sender who was never admitted must
	// not learn whether their body parsed, because that answer is a probe the
	// recipient would be answering for a stranger.
	if err := payload.Validate(inbound.Event.Kind, inbound.Event.Content); err != nil {
		decision := g.refuse(inbound, fault.CodePayloadMalformed, class)
		decision.Delegation = delegation
		return decision, nil
	}

	// The event itself is stored, not only its identity. A record that said
	// "seen" without saying what was seen would leave an event deduplicated
	// forever and delivered never, because the only copy was in the memory of
	// a process that may not survive the next second.
	stored, err := envelope.EncodeEventJSON(inbound.Event)
	if err != nil {
		return Decision{}, err
	}
	// A held event is stored as awaiting the owner, not as ordinary work with
	// a note attached. Recording the hold only in the return value left the
	// event queued, and a runtime draining its inbox would take it before the
	// owner ever saw the question.
	admitted := eventlog.AdmissionAdmitted
	if admission == AdmitHoldForApproval {
		admitted = eventlog.AdmissionPending
	}
	fresh, _, err := g.config.Journal.Accept(eventlog.Entry{
		EventID:          inbound.Event.EventID,
		SenderEndpointID: inbound.Event.SenderEndpointID,
		ConversationID:   inbound.Event.ConversationID,
		Payload:          stored,
		Admission:        admitted,
		ReceivedAtUnix:   inbound.ReceivedAtUnix,
		ExpiresAtUnix:    inbound.Event.ExpiresAtUnix,
	})
	if err != nil {
		if errors.Is(err, eventlog.ErrConflict) {
			// The same content-addressed identifier arrived bound to a
			// different sender or conversation. That is not a retry.
			return g.refuse(inbound, fault.CodeReplayed, class), nil
		}
		// The owner's queue is full. The sender is told, rather than the event
		// being dropped, so their retry later can succeed and so the events
		// already waiting keep their place.
		if errors.Is(err, eventlog.ErrPendingFull) {
			return g.refuse(inbound, fault.CodeQuotaExceeded, class), nil
		}
		return Decision{}, err
	}

	// A hold is claimed like an accepted event so the owner is asked once. A
	// resend finds the existing claim and reports a duplicate, which is what
	// keeps a sender from raising the same question again by retrying.
	if admission == AdmitHoldForApproval && fresh {
		decision := Decision{
			Outcome:    Held,
			Code:       fault.CodeApprovalRequired,
			Response:   fault.PeerCode(fault.CodeApprovalRequired, 0),
			Delegation: delegation,
			Event:      inbound.Event,
		}
		decision.Record = g.record(inbound, class, decision.Outcome, decision.Code)
		return decision, nil
	}

	outcome := Accepted
	if !fresh {
		outcome = Duplicate
	}
	decision := Decision{
		Outcome:    outcome,
		Delegation: delegation,
		Event:      inbound.Event,
	}
	decision.Record = g.record(inbound, class, outcome, "")
	return decision, nil
}

// authority resolves the sender's delegation from finalized state.
//
// The window is checked before the finalized read so that an expired
// delegation reports its own expiry, which the sender can fix, rather than the
// generic authority failure that a chain lookup would produce.
func (g *Gate) authority(inbound Inbound) (identity.Delegation, fault.Code) {
	delegation, err := identity.DecodeJSON(inbound.DelegationJSON)
	if err != nil {
		return identity.Delegation{}, fault.CodeDelegationUncommitted
	}
	now := time.Unix(int64(inbound.ReceivedAtUnix), 0)
	if err := identity.CheckWindow(delegation, now); err != nil {
		return identity.Delegation{}, fault.CodeDelegationExpired
	}
	verified, err := identity.Verify(g.config.Resolver, g.config.Network, g.config.Chain, inbound.DelegationJSON, now)
	if err != nil {
		return identity.Delegation{}, fault.CodeDelegationUncommitted
	}
	return verified, ""
}

func (g *Gate) withinWindow(inbound Inbound) bool {
	created := inbound.Event.CreatedAtUnix
	expires := inbound.Event.ExpiresAtUnix
	received := inbound.ReceivedAtUnix
	if created > received+g.config.MaxClockSkewSeconds {
		return false
	}
	if expires != 0 && expires <= received {
		return false
	}
	return true
}

func (g *Gate) refuse(inbound Inbound, code fault.Code, class string) Decision {
	decision := Decision{
		Outcome:  Rejected,
		Code:     code,
		Response: fault.PeerCode(code, 0),
	}
	decision.Record = g.record(inbound, class, Rejected, code)
	return decision
}

func (g *Gate) record(inbound Inbound, class string, outcome Outcome, code fault.Code) Record {
	return Record{
		Schema:    RecordSchema,
		EventID:   inbound.Event.EventID,
		SenderRef: g.senderRef(inbound.Event.SenderAgentID),
		Class:     class,
		Outcome:   outcome,
		Code:      code,
		Route:     inbound.Route,
		AtUnix:    inbound.ReceivedAtUnix,
	}
}

// senderRef derives a local reference to a sender.
//
// Logs outlive the incident they were kept for, and a log of Agent identifiers
// is a contact graph. Salting with a per-install value keeps the reference
// useful for correlating one node's own records and useless to anyone reading
// them elsewhere.
func (g *Gate) senderRef(agentID string) string {
	if agentID == "" {
		return ""
	}
	buffer := bytes.NewBuffer(nil)
	canon.Bytes(buffer, g.config.InstallSalt)
	canon.Text(buffer, agentID)
	sum := sha256.Sum256(buffer.Bytes())
	return "ref_" + hex.EncodeToString(sum[:8])
}

func sameNetwork(first, second *nativev1.NetworkDomain) bool {
	return first != nil && second != nil &&
		first.NetworkId == second.NetworkId &&
		first.GenesisRootHash == second.GenesisRootHash &&
		first.GenesisFileHash == second.GenesisFileHash
}

// EncodeRecordJSON returns the record as one log line.
func EncodeRecordJSON(record Record) ([]byte, error) {
	if record.Schema != RecordSchema || record.EventID == "" || record.SenderRef == "" {
		return nil, errors.New("invalid admission record")
	}
	if _, known := routes[record.Route]; !known {
		return nil, errors.New("invalid admission record route")
	}
	return json.Marshal(record)
}
