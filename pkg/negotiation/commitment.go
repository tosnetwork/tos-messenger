package negotiation

import (
	"errors"
	"time"

	nativev1 "github.com/tosnetwork/tos-service-protocol/gen/tos/service/v1"
)

// VerifiedAcceptedQuote is an Accepted Quote that has been read from finalized
// state and checked, not a string that looks like a digest.
//
// It exists as a distinct type so the state machine cannot be finalised
// without one. A commitment field that took any well-formed digest could only
// ever mean "the caller gave me something digest-shaped", which is not what
// anything downstream reads it as: it is read as "value may move".
type VerifiedAcceptedQuote struct {
	// Commitment is the quote commitment recorded on chain.
	Commitment string
	// Terms are what the finalized quote actually says, decoded from chain
	// state rather than restated by the caller.
	Terms Terms
	// Reference is where it was read from, so a caller can say which block and
	// which contract produced it.
	Reference *nativev1.ChainReference
	// Network is the network the state came from.
	Network *nativev1.NetworkDomain
	// FinalizedAtUnix is when the state it came from was final.
	FinalizedAtUnix uint64
}

// Validate enforces that a verified quote carries what it claims to.
func (q VerifiedAcceptedQuote) Validate() error {
	if !digestPattern.MatchString(q.Commitment) {
		return errors.New("verified quote carries no commitment")
	}
	if err := q.Terms.Validate(); err != nil {
		return err
	}
	if q.Reference == nil || q.Reference.FinalizedCheckpoint == 0 {
		return errors.New("verified quote was not read from finalized state")
	}
	if q.Network == nil || q.Network.NetworkId == "" {
		return errors.New("verified quote names no network")
	}
	if q.FinalizedAtUnix == 0 {
		return errors.New("verified quote has no finalization time")
	}
	return nil
}

// QuoteResolver reads an Accepted Quote from finalized state.
//
// The Messenger does not implement one. Resolving chain state is the service
// protocol's job, and a resolver written here would be a second opinion about
// what the chain says.
type QuoteResolver interface {
	// ResolveAcceptedQuote returns the finalized quote under one commitment.
	// A commitment that is not on chain is not found, never an empty success.
	ResolveAcceptedQuote(commitment string) (VerifiedAcceptedQuote, bool, error)
}

// Finalize records a canonical commitment, having verified it exists.
//
// The quote is resolved from finalized state through the caller's resolver and
// then compared, field by field, with what was agreed. Both halves matter: a
// resolver that returned something is not enough, because the something could
// be a different purchase, and matching terms are not enough, because a caller
// could restate the agreement without anything having been committed.
func (n *Negotiation) Finalize(resolver QuoteResolver, commitment string, now time.Time) error {
	if n.state != StateCanonicalizationPending {
		return errors.New("nothing is being canonicalised")
	}
	if resolver == nil {
		return errors.New("a commitment must be verified against finalized state")
	}
	if err := n.Mandate.Live(now); err != nil {
		n.end(StateExpired, "the mandate expired before the commitment existed")
		return err
	}
	if !digestPattern.MatchString(commitment) {
		return errors.New("invalid commitment digest")
	}

	quote, found, err := resolver.ResolveAcceptedQuote(commitment)
	if err != nil {
		return err
	}
	if !found {
		// Nothing was committed. The negotiation is not rejected for this: the
		// caller may simply have asked too early.
		return errors.New("no Accepted Quote exists under this commitment")
	}
	if err := quote.Validate(); err != nil {
		return err
	}
	if quote.Commitment != commitment {
		return errors.New("the resolver returned another commitment")
	}
	if n.agreed == nil || !n.agreed.Equal(quote.Terms) {
		n.end(StateRejected, "the finalized quote does not match what was agreed")
		return errors.New("the finalized quote does not match what was agreed")
	}
	// The owner's decision has to still describe this, and the terms have to
	// still be inside the authority they were agreed under.
	if n.needsApproval {
		if err := n.approvalStands(); err != nil {
			return err
		}
	}
	if _, err := n.Mandate.Permits(quote.Terms, now); err != nil {
		n.end(StateRejected, "the finalized quote falls outside the mandate")
		return err
	}
	if n.budget != nil {
		if err := n.budget.Commit(n.ID); err != nil {
			n.end(StateRejected, "the owner's budget could not cover the commitment")
			return err
		}
	}
	n.commitment = commitment
	n.quote = &quote
	n.state = StateFinalized
	return nil
}

// Quote returns the finalized Accepted Quote behind a commitment.
func (n *Negotiation) Quote() (VerifiedAcceptedQuote, bool) {
	if n.state != StateFinalized || n.quote == nil {
		return VerifiedAcceptedQuote{}, false
	}
	return *n.quote, true
}
