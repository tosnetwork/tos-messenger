// Package firewall is the upper half of the context firewall.
//
// Admission establishes that an event came from the party it claims, inside
// the scope that party was delegated. It deliberately stops there: a valid
// signature proves origin, not safety. This package is what stands between
// content that arrived and actions an Agent takes because of it.
//
// The defence is structural, not detective. This package contains no patterns
// for "ignore previous instructions" and no scoring of how manipulative a
// message looks, because a filter that tries to recognise an attack fails open
// on the attacks it has not seen while manufacturing confidence about the ones
// it has. What it does instead is make two things impossible to lose by
// accident: where a piece of content came from, and which actions may be
// reached from it without a person deciding.
//
// The boundary this package draws is honest about its limit. It governs
// proposals to act. It cannot govern what a model concludes from text it
// reads, and nothing here should be read as claiming otherwise.
package firewall

import (
	"bytes"
	"errors"
	"sort"

	"github.com/tosnetwork/tos-messenger/internal/canon"
	"github.com/tosnetwork/tos-messenger/internal/ids"
	"github.com/tosnetwork/tos-messenger/pkg/negotiation"
)

// Bounds on what one action may cite.
const (
	// MaxProvenance bounds how many origins one action may name. An approval
	// prompt an owner cannot read is not an approval, and an unbounded chain
	// is also an unbounded allocation.
	MaxProvenance = 32
	// MaxSummaryBytes bounds the human-readable description of an action.
	MaxSummaryBytes = 512
)

// Effect is what an action does that outlives the runtime's own memory.
//
// Effects are ordered, and the order is what the policy ceilings are stated
// in. An action with several effects is judged by its strongest one: an action
// that both reads a file and spends money is a spend.
type Effect string

const (
	// EffectNone changes nothing outside the runtime's own reasoning.
	EffectNone Effect = "none"
	// EffectLocalRead reads local state.
	EffectLocalRead Effect = "local-read"
	// EffectLocalWrite changes local state the runtime owns, such as its own
	// notes or memory.
	EffectLocalWrite Effect = "local-write"
	// EffectMessage sends a message to another party. This is ordinary Agent
	// work: an Agent that needed a human for every reply would not be an
	// Agent, and the delegation's outbound classes already bound it.
	EffectMessage Effect = "message"
	// EffectToolCall invokes something outside this installation.
	EffectToolCall Effect = "tool-call"
	// EffectSpend moves value or commits to terms that will.
	EffectSpend Effect = "spend"
	// EffectKeyUse uses an identity or signing key.
	EffectKeyUse Effect = "key-use"
	// EffectConfiguration changes what this installation is or what it will
	// allow, including this policy.
	EffectConfiguration Effect = "configuration"
)

// rank orders effects. It is not exported: the order is a property of the
// design, and letting callers compare effects numerically would invite them to
// invent effects between two of these.
var rank = map[Effect]int{
	EffectNone: 0, EffectLocalRead: 1, EffectLocalWrite: 2, EffectMessage: 3,
	EffectToolCall: 4, EffectSpend: 5, EffectKeyUse: 6, EffectConfiguration: 7,
}

// Known reports whether an effect is one this build recognises. An unknown
// effect is refused rather than treated as harmless.
func Known(effect Effect) bool {
	_, known := rank[effect]
	return known
}

// atLeast reports whether one effect is at least as strong as another.
func atLeast(effect, floor Effect) bool {
	return rank[effect] >= rank[floor]
}

// Origin is where one piece of content came from.
//
// It names the Agent, the endpoint, the device, and the event, because an
// approval an owner cannot trace back to a specific message is a rubber stamp.
type Origin struct {
	AgentID        string
	EndpointID     string
	DeviceID       string
	EventID        string
	ConversationID string
	Kind           string
	ReceivedAtUnix uint64
}

// Validate enforces that an origin identifies something.
func (o Origin) Validate() error {
	if !ids.Agent.MatchString(o.AgentID) {
		return errors.New("origin names no Agent")
	}
	if !ids.Endpoint.MatchString(o.EndpointID) {
		return errors.New("origin names no endpoint")
	}
	if !ids.Device.MatchString(o.DeviceID) {
		return errors.New("origin names no device")
	}
	if !ids.Event.MatchString(o.EventID) {
		return errors.New("origin names no event")
	}
	if !ids.Conversation.MatchString(o.ConversationID) {
		return errors.New("origin names no conversation")
	}
	if o.Kind == "" || len(o.Kind) > 128 {
		return errors.New("origin names no event kind")
	}
	if o.ReceivedAtUnix == 0 {
		return errors.New("origin has no arrival time")
	}
	return nil
}

// Policy is what an owner permits an Agent to reach unattended.
//
// Two ceilings rather than one, because the two cases differ in kind. An
// action the Agent reached on its own initiative is bounded by what the owner
// set up in advance. An action reached because of something a stranger sent is
// bounded more tightly, whatever the sender's standing: a known counterparty
// can still relay a document somebody else wrote.
type Policy struct {
	// UnattendedCeiling is the strongest effect an action derived from
	// received content may have without an owner decision.
	UnattendedCeiling Effect
	// OwnInitiativeCeiling is the same for an action no received content
	// contributed to.
	OwnInitiativeCeiling Effect
}

// Validate refuses policies that cannot be safe rather than trusting an
// operator to avoid them.
//
// Two ceilings are not configurable at all. Received content must never reach
// a signing key or this installation's own configuration without a person,
// because a key can authorise anything and a configuration change can remove
// this check. An operator who could raise those ceilings would be able to
// disable the firewall by configuring it.
func (p Policy) Validate() error {
	if !Known(p.UnattendedCeiling) || !Known(p.OwnInitiativeCeiling) {
		return errors.New("a firewall policy names an effect this build does not recognise")
	}
	if atLeast(p.UnattendedCeiling, EffectKeyUse) {
		return errors.New("received content may never reach a key or this installation's configuration unattended")
	}
	if atLeast(p.OwnInitiativeCeiling, EffectConfiguration) {
		return errors.New("only the owner changes this installation's configuration")
	}
	if rank[p.UnattendedCeiling] > rank[p.OwnInitiativeCeiling] {
		return errors.New("received content cannot be trusted further than the Agent's own initiative")
	}
	return nil
}

// Default is the policy an installation starts from.
//
// Received content may cause the Agent to reply and to keep its own notes, and
// nothing more, until an owner says otherwise. Replying is what a messenger
// is; a tool call or a payment is where a stranger's message stops being
// conversation and starts being instruction.
func Default() Policy {
	return Policy{
		UnattendedCeiling:    EffectMessage,
		OwnInitiativeCeiling: EffectToolCall,
	}
}

// Action is something the runtime proposes to do.
type Action struct {
	// Effect is the strongest effect this action has.
	Effect Effect
	// Summary is what the owner would be asked about. It is required even when
	// no approval is expected, because an action nobody can describe is one
	// nobody can review afterwards either.
	Summary string
	// DerivedFrom names the received content that contributed to this action.
	// An empty set is a claim that nothing received contributed, and it is the
	// runtime's claim to make honestly: this package cannot check it.
	DerivedFrom []Origin
	// Terms are the exact purchase, required when the effect is a spend and
	// refused otherwise. They are part of the action rather than an argument
	// beside it because the identifier commits them: without that, an approval
	// for one price could be spent on another that happened to be described
	// the same way.
	Terms *negotiation.Terms
}

// Validate enforces that an action can be judged.
func (a Action) Validate() error {
	if !Known(a.Effect) {
		return errors.New("action names an effect this build does not recognise")
	}
	if a.Summary == "" || len(a.Summary) > MaxSummaryBytes {
		return errors.New("an action must describe itself")
	}
	if len(a.DerivedFrom) > MaxProvenance {
		return errors.New("action cites more origins than an owner could review")
	}
	if a.Effect == EffectSpend && a.Terms == nil {
		return errors.New("a spend must say what it is buying")
	}
	if a.Effect != EffectSpend && a.Terms != nil {
		return errors.New("only a spend carries terms")
	}
	seen := make(map[string]struct{}, len(a.DerivedFrom))
	for _, origin := range a.DerivedFrom {
		if err := origin.Validate(); err != nil {
			return err
		}
		if _, duplicate := seen[origin.EventID]; duplicate {
			return errors.New("action cites one event twice")
		}
		seen[origin.EventID] = struct{}{}
	}
	return nil
}

// Untrusted reports whether any received content contributed to this action.
func (a Action) Untrusted() bool { return len(a.DerivedFrom) > 0 }

// Outcome is what the firewall decided.
type Outcome string

const (
	// Allow lets the runtime proceed unattended.
	Allow Outcome = "allow"
	// RequireOwnerApproval stops the action until a person decides. It is not
	// a refusal: the owner may still say yes, and the decision is theirs.
	RequireOwnerApproval Outcome = "require-owner-approval"
	// Refuse ends the action. It is used where the proposal is malformed or
	// where no owner decision could make it coherent.
	Refuse Outcome = "refuse"
)

// Decision is the answer, and everything an owner would need to review it.
type Decision struct {
	Outcome Outcome
	// Reason is stated plainly, for the owner rather than for a log parser.
	Reason string
	// Effect is the effect that was judged.
	Effect Effect
	// Ceiling is the ceiling that applied.
	Ceiling Effect
	// Provenance is the received content behind this action, in a stable
	// order, so two renderings of one approval prompt read the same way.
	Provenance []Origin
}

// Evaluate applies the policy to one proposed action.
//
// The order matters. Structural refusals come first, because a malformed
// action is not a policy question. Then the two ceilings that no policy may
// raise. Then the configured ceiling. An action only reaches Allow by passing
// all of them.
func Evaluate(policy Policy, action Action) (Decision, error) {
	if err := policy.Validate(); err != nil {
		return Decision{}, err
	}
	if err := action.Validate(); err != nil {
		return Decision{Outcome: Refuse, Reason: err.Error(), Effect: action.Effect}, nil
	}

	provenance := append([]Origin(nil), action.DerivedFrom...)
	sort.Slice(provenance, func(i, j int) bool { return provenance[i].EventID < provenance[j].EventID })

	ceiling := policy.OwnInitiativeCeiling
	if action.Untrusted() {
		ceiling = policy.UnattendedCeiling
	}
	decision := Decision{Effect: action.Effect, Ceiling: ceiling, Provenance: provenance}

	// Changing what this installation is, or what it will allow, is the
	// owner's. The runtime asking for it is not evidence that it should be
	// automatic; it is the case the separate sockets exist for.
	if action.Effect == EffectConfiguration {
		decision.Outcome = RequireOwnerApproval
		decision.Reason = "changing this installation's configuration is the owner's decision"
		return decision, nil
	}
	// A key authorises whatever it signs, so received content reaching one is
	// the case a ceiling must not be able to permit.
	if action.Untrusted() && atLeast(action.Effect, EffectKeyUse) {
		decision.Outcome = RequireOwnerApproval
		decision.Reason = "an action derived from received content would use a key"
		return decision, nil
	}
	if atLeast(action.Effect, ceiling) && action.Effect != ceiling {
		decision.Outcome = RequireOwnerApproval
		decision.Reason = "this action is stronger than what may happen unattended"
		return decision, nil
	}
	decision.Outcome = Allow
	decision.Reason = "within what the owner permitted unattended"
	return decision, nil
}

// ActionID is the content-addressed identifier of one proposed action.
//
// It commits the effect, the description, and every origin cited, so an
// approval is an approval of that action and nothing else. Without this an
// owner could approve a tool call and the runtime could perform a payment
// under the same permission: the approval would name a request rather than a
// deed.
func ActionID(action Action) (string, error) {
	if err := action.Validate(); err != nil {
		return "", err
	}
	origins := append([]Origin(nil), action.DerivedFrom...)
	sort.Slice(origins, func(i, j int) bool { return origins[i].EventID < origins[j].EventID })

	buffer := bytes.NewBufferString(canon.DomainAgentAction)
	canon.Text(buffer, string(action.Effect))
	canon.Text(buffer, action.Summary)
	canon.Uint32(buffer, uint32(len(origins)))
	for _, origin := range origins {
		canon.Text(buffer, origin.AgentID)
		canon.Text(buffer, origin.EndpointID)
		canon.Text(buffer, origin.DeviceID)
		canon.Text(buffer, origin.EventID)
		canon.Text(buffer, origin.ConversationID)
		canon.Text(buffer, origin.Kind)
		canon.Uint64(buffer, origin.ReceivedAtUnix)
	}
	// The terms are committed, so an approval for one price cannot be spent on
	// another. A spend with no terms never reaches here: it fails validation.
	if action.Terms != nil {
		canon.Text(buffer, action.Terms.CapabilityID)
		canon.Text(buffer, action.Terms.CapabilityVersion)
		canon.Text(buffer, action.Terms.CapabilityClass)
		canon.Text(buffer, action.Terms.Total.Asset)
		canon.Uint64(buffer, action.Terms.Total.Units)
		buffer.WriteByte(action.Terms.Total.Decimals)
		canon.Uint64(buffer, action.Terms.NotAfterUnix)
	}
	digest := canon.Digest(buffer.Bytes())
	return "act_" + digest[len("sha256:"):], nil
}
