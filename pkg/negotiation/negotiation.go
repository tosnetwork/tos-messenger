package negotiation

import (
	"errors"
	"time"

	"github.com/tosnetwork/tos-messenger/internal/ids"
	nativev1 "github.com/tosnetwork/tos-service-protocol/gen/tos/service/v1"
)

// State is where a negotiation stands.
//
// The states before finalisation describe a conversation. None of them means
// anything has been created, accepted, or funded, and the distance between
// intent-agreed and finalized is the distance between two parties saying yes
// and a commitment existing.
type State string

const (
	// StateDiscussing means the parties are talking with nothing on the table.
	StateDiscussing State = "discussing"
	// StateProposalPending means the counterparty has made an offer.
	StateProposalPending State = "proposal-pending"
	// StateCounterproposalPending means we have answered with one.
	StateCounterproposalPending State = "counterproposal-pending"
	// StateIntentAgreed means both sides said yes in conversation. Nothing is
	// committed and nothing is owed.
	StateIntentAgreed State = "intent-agreed"
	// StateCanonicalizationPending means the agreed terms are being turned
	// into a canonical action.
	StateCanonicalizationPending State = "canonicalization-pending"
	// StateFinalized means a canonical commitment exists and matches the terms.
	StateFinalized State = "finalized"
	// StateRejected means the exchange ended without agreement, including a
	// canonicalisation that did not reproduce the agreed terms.
	StateRejected State = "rejected"
	// StateWithdrawn means we ended it.
	StateWithdrawn State = "withdrawn"
	// StateExpired means the mandate or the terms ran out first.
	StateExpired State = "expired"
)

// Negotiation is one exchange under one mandate.
type Negotiation struct {
	ID                  string
	ConversationID      string
	CounterpartyAgentID string
	Mandate             Mandate

	state         State
	generation    uint64
	counteroffers uint32
	onTable       *Terms
	agreed        *Terms
	needsApproval bool
	// network is the TOS network this exchange is bound to. A finalized Accepted
	// Quote is accepted only if it was read from this network: the same
	// workchain, account and code hashes can exist on another network, so a
	// commitment from elsewhere with matching terms is a different purchase.
	network *nativev1.NetworkDomain
	// approval is the owner's decision, bound to exactly what they saw. A
	// boolean would survive a change of terms, and the change a counterparty
	// makes right after an approval is the one they have the most reason to
	// make.
	approval   *Approval
	commitment string
	quote      *VerifiedAcceptedQuote
	failure    string
	budget     *Budget
	store      Store
	// poisoned is set when a durable write failed after the in-memory state had
	// already moved. The two then disagree, and rather than let the caller act
	// on a transition the disk never recorded, every further operation is
	// refused until the negotiation is reloaded from what was actually written.
	poisoned bool
}

// ErrPoisoned reports a negotiation whose last write failed; it must be reloaded
// from its snapshot before it is used again.
var ErrPoisoned = errors.New("this negotiation's last write failed and it must be reloaded")

// Approval is an owner decision bound to what it was a decision about.
type Approval struct {
	// TermsDigest is what the owner approved.
	TermsDigest string
	// Generation is the version of the negotiation they approved it at, so an
	// approval cannot survive a reopening.
	Generation uint64
	// MandateDigest ties the approval to the authority it was given under.
	MandateDigest string
	AtUnix        uint64
}

// New starts a negotiation under a live mandate, drawing on an owner budget.
//
// A mandate that may commit needs a budget. Without one, several conversations
// each inside their own ceiling can agree to more than the owner has, and the
// shortfall only appears once every yes already exists.
func New(id, conversationID, counterpartyAgentID string, mandate Mandate,
	network *nativev1.NetworkDomain, budget *Budget, store Store, now time.Time) (*Negotiation, error) {
	if !ids.Conversation.MatchString(conversationID) {
		return nil, errors.New("invalid conversation identifier")
	}
	if !ids.Agent.MatchString(counterpartyAgentID) {
		return nil, errors.New("invalid counterparty identifier")
	}
	if id == "" || len(id) > 128 {
		return nil, errors.New("invalid negotiation identifier")
	}
	// The network is bound at the start, not inferred at finalisation, so the
	// exchange knows from the first transition which network a commitment must
	// have come from.
	if err := validateNetworkDomain(network); err != nil {
		return nil, err
	}
	if err := mandate.Live(now); err != nil {
		return nil, err
	}
	if mandate.Authority == AuthorityCommit && budget == nil {
		return nil, errors.New("a mandate that may commit needs a budget to commit against")
	}
	if store == nil {
		return nil, errors.New("a negotiation needs somewhere to survive a restart")
	}
	instance := &Negotiation{
		ID: id, ConversationID: conversationID, CounterpartyAgentID: counterpartyAgentID,
		Mandate: mandate, network: cloneNetwork(network), state: StateDiscussing,
		budget: budget, store: store,
	}
	// The first state is written before it is returned. A negotiation that
	// existed only after its first transition would leave a budget hold behind
	// with nothing to account for it.
	if err := instance.persist(); err != nil {
		return nil, err
	}
	return instance, nil
}

// persist writes the current state down. Every transition calls it, and a
// transition that could not be written is not a transition: the caller is told
// it failed rather than holding a negotiation the disk has never heard of.
func (n *Negotiation) persist() error {
	snapshot, err := n.Snapshot()
	if err != nil {
		return err
	}
	if err := n.store.Save(snapshot); err != nil {
		// The in-memory state moved and the disk did not. Poison the object so
		// nothing acts on the difference; a reload rebuilds it from the disk.
		n.poisoned = true
		return err
	}
	return nil
}

// State returns where the negotiation stands.
func (n *Negotiation) State() State { return n.state }

// Counteroffers returns how many we have made.
func (n *Negotiation) Counteroffers() uint32 { return n.counteroffers }

// NeedsOwnerApproval reports whether the agreed terms reached the point the
// owner decides personally.
func (n *Negotiation) NeedsOwnerApproval() bool { return n.needsApproval }

// Agreed returns the terms both sides accepted in conversation, if any.
//
// Holding these terms is not holding an agreement. Nothing is owed until
// Committed reports otherwise.
func (n *Negotiation) Agreed() (Terms, bool) {
	if n.agreed == nil {
		return Terms{}, false
	}
	return *n.agreed, true
}

// Committed reports whether a canonical commitment exists.
//
// This is the only method whose answer means value can move, and it means it
// because Finalize read the quote out of finalized state rather than being
// handed a digest. Every other signal in this package describes a
// conversation.
func (n *Negotiation) Committed() (string, bool) {
	if n.state != StateFinalized || n.commitment == "" {
		return "", false
	}
	return n.commitment, true
}

// Failure returns why the negotiation ended badly, for display.
func (n *Negotiation) Failure() string { return n.failure }

// bindsCounterparty refuses terms whose named provider is not the party this
// negotiation is with. A one-to-one service negotiation names one provider, and
// terms that quietly name another are a different purchase wearing this
// conversation's identity. Once the entry points enforce it, the finalised
// quote inherits it through the terms-equality check.
func (n *Negotiation) bindsCounterparty(terms Terms) error {
	if terms.ProviderAgentID != n.CounterpartyAgentID {
		return errors.New("these terms name a provider that is not the counterparty")
	}
	return nil
}

// ReceiveProposal records an offer from the counterparty.
//
// The offer is recorded whether or not it is inside the mandate. A proposal
// above the ceiling is a thing that was said, and refusing to record it would
// leave an Agent unable to counter it.
func (n *Negotiation) ReceiveProposal(terms Terms, now time.Time) error {
	if err := n.open(now); err != nil {
		return err
	}
	if err := terms.Validate(); err != nil {
		return err
	}
	if err := n.bindsCounterparty(terms); err != nil {
		return err
	}
	proposal := terms
	n.onTable = &proposal
	n.state = StateProposalPending
	return n.persist()
}

// Counter answers with our own offer.
//
// Our offer must be inside our own mandate. An Agent may counter an offer
// above its ceiling; it may not counter with one, because that would be the
// Agent proposing to exceed what it was permitted.
func (n *Negotiation) Counter(terms Terms, now time.Time) error {
	if err := n.open(now); err != nil {
		return err
	}
	if n.counteroffers >= n.Mandate.MaxCounteroffers {
		if err := n.settle(StateWithdrawn, "counteroffer budget exhausted"); err != nil {
			return err
		}
		return errors.New("the mandate's counteroffer budget is exhausted")
	}
	if _, err := n.Mandate.Permits(terms, now); err != nil {
		return err
	}
	if err := n.bindsCounterparty(terms); err != nil {
		return err
	}
	offer := terms
	n.onTable = &offer
	n.counteroffers++
	n.state = StateCounterproposalPending
	return n.persist()
}

// AcceptIntent agrees, in conversation, to the terms on the table.
//
// It is the step most likely to be mistaken for something else. What it
// establishes is that both parties said yes. It creates no Quote, funds no
// escrow, and obliges nobody.
func (n *Negotiation) AcceptIntent(now time.Time) error {
	if n.poisoned {
		return ErrPoisoned
	}
	if err := n.open(now); err != nil {
		return err
	}
	if n.onTable == nil {
		return errors.New("there is nothing on the table to accept")
	}
	needsApproval, err := n.Mandate.Permits(*n.onTable, now)
	if err != nil {
		return err
	}
	// The hold is taken at the moment of agreement. Waiting until money moves
	// would let several conversations each say yes inside their own ceiling
	// and discover the shortfall only once the yeses already exist.
	if n.budget != nil {
		if err := n.budget.Reserve(n.ID, n.onTable.Price); err != nil {
			return err
		}
	}
	agreed := *n.onTable
	n.agreed = &agreed
	n.needsApproval = needsApproval
	n.state = StateIntentAgreed
	return n.persist()
}

// Reopen returns an agreed negotiation to discussion.
//
// It is explicit, and it is the only way back. Terms freeze when both parties
// say yes, and continuing to bargain from that state without saying so would
// carry the owner's approval and the budget hold across a change they never
// saw. Reopening releases the hold, clears the approval, and moves the
// generation on, so anything bound to the old terms no longer matches.
func (n *Negotiation) Reopen(reason string, now time.Time) error {
	if n.state != StateIntentAgreed {
		return errors.New("only an agreed intent can be reopened")
	}
	if err := n.Mandate.Live(now); err != nil {
		return err
	}
	if reason == "" || len(reason) > 512 {
		return errors.New("reopening must say why")
	}
	// The reopened state is written before the hold is released. A crash
	// between the two leaves a discussing snapshot beside a hold, and a hold
	// whose exchange is back in discussion is released at start-up. The other
	// order would leave an agreed snapshot with no hold behind it.
	n.agreed = nil
	n.needsApproval = false
	n.approval = nil
	n.generation++
	n.state = StateDiscussing
	if err := n.persist(); err != nil {
		return err
	}
	if n.budget != nil {
		return n.budget.Release(n.ID)
	}
	return nil
}

// Generation is how many times this negotiation has been reopened. It is what
// an owner approval is bound to alongside the terms.
func (n *Negotiation) Generation() uint64 { return n.generation }

// Approval returns the owner's decision, if one stands.
func (n *Negotiation) Approval() (Approval, bool) {
	if n.approval == nil {
		return Approval{}, false
	}
	return *n.approval, true
}

// RejectIntent ends the exchange without agreement.
func (n *Negotiation) RejectIntent(reason string) error {
	if n.settled() {
		return errors.New("this negotiation has already ended")
	}
	return n.settle(StateRejected, reason)
}

// Withdraw ends the exchange from our side.
func (n *Negotiation) Withdraw(reason string) error {
	if n.settled() {
		return errors.New("this negotiation has already ended")
	}
	return n.settle(StateWithdrawn, reason)
}

// ApproveByOwner records the owner's decision.
//
// It exists here so the state machine can require it, and it is not something
// a counterparty can supply: the event kinds that carry an owner decision are
// refused on every network route, so this can only be reached through the
// owner's own local interface.
// ApproveByOwner takes the digest of the terms the owner was shown. It is not
// a confirmation that something was approved; it is a statement of what was.
// An approval that named only the negotiation could be carried across a change
// of terms, and a counterparty who wanted one number approved and another
// committed would only have to send the second one afterwards.
func (n *Negotiation) ApproveByOwner(termsDigest string, now time.Time) error {
	if n.state != StateIntentAgreed {
		return errors.New("there is no agreed intent to approve")
	}
	if err := n.Mandate.Live(now); err != nil {
		return err
	}
	if !n.needsApproval {
		return errors.New("these terms are inside what the owner already permitted")
	}
	if n.agreed == nil {
		return errors.New("there are no agreed terms to approve")
	}
	current, err := n.agreed.Digest()
	if err != nil {
		return err
	}
	if termsDigest != current {
		return errors.New("the owner approved terms other than the ones on the table")
	}
	mandateDigest, err := n.Mandate.Digest()
	if err != nil {
		return err
	}
	n.approval = &Approval{
		TermsDigest: current, Generation: n.generation,
		MandateDigest: mandateDigest, AtUnix: uint64(now.Unix()),
	}
	return n.persist()
}

// DenyByOwner records the owner refusing.
func (n *Negotiation) DenyByOwner(reason string) error {
	if n.state != StateIntentAgreed {
		return errors.New("there is no agreed intent to refuse")
	}
	return n.settle(StateRejected, reason)
}

// BeginCanonicalization moves from conversation towards a commitment.
func (n *Negotiation) BeginCanonicalization(now time.Time) error {
	if n.poisoned {
		return ErrPoisoned
	}
	if n.state != StateIntentAgreed {
		return errors.New("only an agreed intent can be canonicalised")
	}
	// Canonicalisation is where conversation becomes a commitment. A mandate
	// that may only propose stops here, and a commitment needs a durable budget
	// to reserve against -- without one there is nothing to hold the price.
	if n.Mandate.Authority != AuthorityCommit {
		return errors.New("only a mandate that may commit can canonicalise terms")
	}
	if n.budget == nil {
		return errors.New("canonicalisation needs a budget to commit against")
	}
	if err := n.Mandate.Live(now); err != nil {
		return err
	}
	if n.needsApproval {
		if err := n.approvalStands(); err != nil {
			return err
		}
	}
	n.state = StateCanonicalizationPending
	return n.persist()
}

// approvalStands checks that the owner's decision still describes this
// negotiation. Anything that changed since they made it invalidates it.
func (n *Negotiation) approvalStands() error {
	if n.approval == nil {
		return errors.New("these terms need the owner's decision first")
	}
	if n.agreed == nil {
		return errors.New("there are no agreed terms to act on")
	}
	current, err := n.agreed.Digest()
	if err != nil {
		return err
	}
	if n.approval.TermsDigest != current {
		return errors.New("the terms changed after the owner approved them")
	}
	if n.approval.Generation != n.generation {
		return errors.New("this negotiation was reopened after the owner approved it")
	}
	mandateDigest, err := n.Mandate.Digest()
	if err != nil {
		return err
	}
	if n.approval.MandateDigest != mandateDigest {
		return errors.New("the mandate changed after the owner approved these terms")
	}
	return nil
}

// Expire ends a negotiation whose mandate or terms ran out.
func (n *Negotiation) Expire(now time.Time) (bool, error) {
	if n.settled() {
		return false, nil
	}
	reason := ""
	if err := n.Mandate.Live(now); err != nil {
		reason = "the mandate expired"
	} else if n.agreed != nil && uint64(now.Unix()) >= n.agreed.NotAfterUnix {
		reason = "the agreed terms expired"
	}
	if reason == "" {
		return false, nil
	}
	return true, n.settle(StateExpired, reason)
}

// ActiveAgreement reports whether there is a commercial agreement in force.
//
// A caller displaying negotiation state uses this and not the state name. A
// person reading "intent agreed" will reasonably think something was agreed
// commercially, and until Committed says so, nothing was.
func (n *Negotiation) ActiveAgreement() bool {
	_, committed := n.Committed()
	return committed
}

func (n *Negotiation) open(now time.Time) error {
	if n.poisoned {
		return ErrPoisoned
	}
	if n.settled() {
		return errors.New("this negotiation has already ended")
	}
	if n.state == StateCanonicalizationPending {
		return errors.New("this negotiation is being canonicalised")
	}
	// Terms freeze when both parties say yes. Bargaining on from that state
	// would carry the owner's approval and the budget hold across a change
	// they never saw, so it takes an explicit Reopen, which drops both.
	if n.state == StateIntentAgreed {
		return errors.New("these terms are agreed; reopen the negotiation to change them")
	}
	return n.Mandate.Live(now)
}

func (n *Negotiation) settled() bool {
	switch n.state {
	case StateFinalized, StateRejected, StateWithdrawn, StateExpired:
		return true
	default:
		return false
	}
}

func (n *Negotiation) end(state State, reason string) {
	n.state = state
	n.failure = reason
	n.onTable = nil
}

// settle ends a negotiation durably, in the one order a crash cannot make
// ambiguous: the settled state is written first, and the budget hold is
// released second. A crash between the two leaves a settled snapshot beside a
// live hold, which is exactly the shape start-up reconciliation resolves --
// a hold whose exchange has ended goes back. The other order would leave an
// agreed snapshot with no hold, which is indistinguishable from money that was
// never reserved, and nothing could repair it safely.
func (n *Negotiation) settle(state State, reason string) error {
	n.end(state, reason)
	if err := n.persist(); err != nil {
		return err
	}
	// Anything held for an exchange that ended goes back, or a withdrawn
	// negotiation would keep the owner's budget out of reach forever. The
	// error is not swallowed: a release the ledger refused is a hold still on
	// the books, and the caller has to know.
	if n.budget != nil && state != StateFinalized {
		return n.budget.Release(n.ID)
	}
	return nil
}
