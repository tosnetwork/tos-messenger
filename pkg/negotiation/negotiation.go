package negotiation

import (
	"errors"
	"time"

	"github.com/tosnetwork/tos-messenger/internal/canon"
	"github.com/tosnetwork/tos-messenger/internal/ids"
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
	counteroffers uint32
	onTable       *Terms
	agreed        *Terms
	needsApproval bool
	ownerApproved bool
	commitment    string
	failure       string
	budget        *Budget
}

// New starts a negotiation under a live mandate.
// New starts a negotiation drawing on an owner budget.
//
// The budget may be nil for an exchange that spends nothing, and must not be
// nil for one that does: several conversations each inside their own ceiling
// can still agree to more than the owner has.
func New(id, conversationID, counterpartyAgentID string, mandate Mandate, budget *Budget, now time.Time) (*Negotiation, error) {
	if !ids.Conversation.MatchString(conversationID) {
		return nil, errors.New("invalid conversation identifier")
	}
	if !ids.Agent.MatchString(counterpartyAgentID) {
		return nil, errors.New("invalid counterparty identifier")
	}
	if id == "" || len(id) > 128 {
		return nil, errors.New("invalid negotiation identifier")
	}
	if err := mandate.Live(now); err != nil {
		return nil, err
	}
	return &Negotiation{
		ID: id, ConversationID: conversationID, CounterpartyAgentID: counterpartyAgentID,
		Mandate: mandate, state: StateDiscussing, budget: budget,
	}, nil
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
// This is the only method whose answer means value can move. Every other
// signal in this package describes a conversation.
func (n *Negotiation) Committed() (string, bool) {
	if n.state != StateFinalized || n.commitment == "" {
		return "", false
	}
	return n.commitment, true
}

// Failure returns why the negotiation ended badly, for display.
func (n *Negotiation) Failure() string { return n.failure }

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
	proposal := terms
	n.onTable = &proposal
	n.state = StateProposalPending
	return nil
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
		n.end(StateWithdrawn, "counteroffer budget exhausted")
		return errors.New("the mandate's counteroffer budget is exhausted")
	}
	if _, err := n.Mandate.Permits(terms, now); err != nil {
		return err
	}
	offer := terms
	n.onTable = &offer
	n.counteroffers++
	n.state = StateCounterproposalPending
	return nil
}

// AcceptIntent agrees, in conversation, to the terms on the table.
//
// It is the step most likely to be mistaken for something else. What it
// establishes is that both parties said yes. It creates no Quote, funds no
// escrow, and obliges nobody.
func (n *Negotiation) AcceptIntent(now time.Time) error {
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
		if err := n.budget.Reserve(n.ID, n.onTable.Total); err != nil {
			return err
		}
	}
	agreed := *n.onTable
	n.agreed = &agreed
	n.needsApproval = needsApproval
	n.state = StateIntentAgreed
	return nil
}

// RejectIntent ends the exchange without agreement.
func (n *Negotiation) RejectIntent(reason string) error {
	if n.settled() {
		return errors.New("this negotiation has already ended")
	}
	n.end(StateRejected, reason)
	return nil
}

// Withdraw ends the exchange from our side.
func (n *Negotiation) Withdraw(reason string) error {
	if n.settled() {
		return errors.New("this negotiation has already ended")
	}
	n.end(StateWithdrawn, reason)
	return nil
}

// ApproveByOwner records the owner's decision.
//
// It exists here so the state machine can require it, and it is not something
// a counterparty can supply: the event kinds that carry an owner decision are
// refused on every network route, so this can only be reached through the
// owner's own local interface.
func (n *Negotiation) ApproveByOwner(now time.Time) error {
	if n.state != StateIntentAgreed {
		return errors.New("there is no agreed intent to approve")
	}
	if err := n.Mandate.Live(now); err != nil {
		return err
	}
	if !n.needsApproval {
		return errors.New("these terms are inside what the owner already permitted")
	}
	n.ownerApproved = true
	return nil
}

// DenyByOwner records the owner refusing.
func (n *Negotiation) DenyByOwner(reason string) error {
	if n.state != StateIntentAgreed {
		return errors.New("there is no agreed intent to refuse")
	}
	n.end(StateRejected, reason)
	return nil
}

// BeginCanonicalization moves from conversation towards a commitment.
func (n *Negotiation) BeginCanonicalization(now time.Time) error {
	if n.state != StateIntentAgreed {
		return errors.New("only an agreed intent can be canonicalised")
	}
	if err := n.Mandate.Live(now); err != nil {
		return err
	}
	if n.needsApproval && !n.ownerApproved {
		return errors.New("these terms need the owner's decision first")
	}
	n.state = StateCanonicalizationPending
	return nil
}

// Finalize records a canonical commitment.
//
// The canonical terms must reproduce what was agreed in every field. If they
// do not, the negotiation ends rejected rather than finalising on whichever
// version arrived last: a conversation that agreed twelve and a commitment
// that says a hundred and twenty is not a rounding difference to reconcile.
func (n *Negotiation) Finalize(canonical Terms, commitment string, now time.Time) error {
	if n.state != StateCanonicalizationPending {
		return errors.New("nothing is being canonicalised")
	}
	if err := n.Mandate.Live(now); err != nil {
		n.end(StateExpired, "the mandate expired before the commitment existed")
		return err
	}
	if !canon.ValidDigest(commitment) {
		return errors.New("invalid commitment digest")
	}
	if err := canonical.Validate(); err != nil {
		return err
	}
	if n.agreed == nil || !n.agreed.Equal(canonical) {
		n.end(StateRejected, "the canonical terms do not match what was agreed")
		return errors.New("the canonical terms do not match what was agreed")
	}
	if _, err := n.Mandate.Permits(canonical, now); err != nil {
		n.end(StateRejected, "the canonical terms fall outside the mandate")
		return err
	}
	if n.budget != nil {
		if err := n.budget.Commit(n.ID); err != nil {
			n.end(StateRejected, "the owner's budget could not cover the commitment")
			return err
		}
	}
	n.commitment = commitment
	n.state = StateFinalized
	return nil
}

// Expire ends a negotiation whose mandate or terms ran out.
func (n *Negotiation) Expire(now time.Time) bool {
	if n.settled() {
		return false
	}
	if err := n.Mandate.Live(now); err != nil {
		n.end(StateExpired, "the mandate expired")
		return true
	}
	if n.agreed != nil && uint64(now.Unix()) >= n.agreed.NotAfterUnix {
		n.end(StateExpired, "the agreed terms expired")
		return true
	}
	return false
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
	if n.settled() {
		return errors.New("this negotiation has already ended")
	}
	if n.state == StateCanonicalizationPending {
		return errors.New("this negotiation is being canonicalised")
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
	// Anything held for an exchange that ended goes back, or a withdrawn
	// negotiation would keep the owner's budget out of reach forever.
	if n.budget != nil && state != StateFinalized {
		n.budget.Release(n.ID)
	}
}
