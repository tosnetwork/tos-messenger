package negotiation

import (
	"errors"
	"time"

	"github.com/tosnetwork/tos-messenger/internal/canon"
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
	// A network id alone is not identity: the same id can front different genesis
	// state, so a quote read from finalized state must carry a fully identified
	// network -- id and both genesis hashes -- for the finalisation-time network
	// check to compare against.
	if err := validateNetworkDomain(q.Network); err != nil {
		return errors.New("verified quote names no network")
	}
	// The terms' priced asset commits a network of its own, and it has to be
	// the network the state was read from. A resolver that decoded state on one
	// network into terms naming another would be internally contradictory, and
	// the terms digest it produced would commit the wrong network.
	read, err := NetworkFromDomain(q.Network)
	if err != nil {
		return errors.New("verified quote names no network")
	}
	if !q.Terms.Price.Asset.Network.Same(read) {
		return errors.New("verified quote's terms are priced on a network other than the one it was read from")
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

// ErrFinalizedQuoteMismatch reports a real finalized Quote that does not
// reproduce the commitment, complete expected terms, or network the caller
// supplied. It is distinct from temporary absence/resolver failure so a
// negotiation can durably reject substitution while retrying an early read.
var ErrFinalizedQuoteMismatch = errors.New("the finalized quote does not match the expected purchase")

// ResolveMatchingAcceptedQuote is the daemon/runtime verification boundary for
// one complete expected purchase. It returns chain-derived terms and evidence
// only after every field and the full network identity match.
func ResolveMatchingAcceptedQuote(resolver QuoteResolver, commitment string, expected Terms,
	network *nativev1.NetworkDomain) (VerifiedAcceptedQuote, error) {
	if resolver == nil {
		return VerifiedAcceptedQuote{}, errors.New("a commitment must be verified against finalized state")
	}
	if !digestPattern.MatchString(commitment) {
		return VerifiedAcceptedQuote{}, errors.New("invalid commitment digest")
	}
	if err := expected.Validate(); err != nil {
		return VerifiedAcceptedQuote{}, err
	}
	if err := validateNetworkDomain(network); err != nil {
		return VerifiedAcceptedQuote{}, err
	}
	quote, found, err := resolver.ResolveAcceptedQuote(commitment)
	if err != nil {
		return VerifiedAcceptedQuote{}, err
	}
	if !found {
		return VerifiedAcceptedQuote{}, errors.New("no Accepted Quote exists under this commitment")
	}
	return MatchAcceptedQuote(quote, commitment, expected, network)
}

// MatchAcceptedQuote applies the same complete-term and network check to a
// Quote already read from finalized state. Address-keyed chain adapters use it
// when the funded escrow address is known but no local commitment locator has
// been populated.
func MatchAcceptedQuote(quote VerifiedAcceptedQuote, commitment string, expected Terms,
	network *nativev1.NetworkDomain) (VerifiedAcceptedQuote, error) {
	if !digestPattern.MatchString(commitment) {
		return VerifiedAcceptedQuote{}, errors.New("invalid commitment digest")
	}
	if err := expected.Validate(); err != nil {
		return VerifiedAcceptedQuote{}, err
	}
	if err := validateNetworkDomain(network); err != nil {
		return VerifiedAcceptedQuote{}, err
	}
	if err := quote.Validate(); err != nil {
		return VerifiedAcceptedQuote{}, err
	}
	if quote.Commitment != commitment || !expected.Equal(quote.Terms) || !sameNetwork(network, quote.Network) {
		return VerifiedAcceptedQuote{}, ErrFinalizedQuoteMismatch
	}
	return quote, nil
}

// Finalize records a canonical commitment, having verified it exists.
//
// The quote is resolved from finalized state through the caller's resolver and
// then compared, field by field, with what was agreed. Both halves matter: a
// resolver that returned something is not enough, because the something could
// be a different purchase, and matching terms are not enough, because a caller
// could restate the agreement without anything having been committed.
func (n *Negotiation) Finalize(resolver QuoteResolver, commitment string, now time.Time) error {
	if n.poisoned {
		return ErrPoisoned
	}
	if n.state != StateCanonicalizationPending {
		return errors.New("nothing is being canonicalised")
	}
	if resolver == nil {
		return errors.New("a commitment must be verified against finalized state")
	}
	// Finalising is the commit boundary; a proposal authority or a budgetless
	// negotiation must not reach it, even though the state check above already
	// implies canonicalisation gated on both. This is the second lock on the
	// one door value moves through.
	if n.Mandate.Authority != AuthorityCommit {
		return errors.New("only a mandate that may commit can finalize")
	}
	if n.budget == nil {
		return errors.New("finalizing needs a budget to commit against")
	}
	if err := n.Mandate.Live(now); err != nil {
		// The mandate expired: end durably, so the budget hold is released and
		// the expired state survives a restart. Ending only in memory would
		// leave a canonicalisation-pending snapshot beside a live hold that
		// reconciliation would keep forever.
		if settleErr := n.settle(StateExpired, "the mandate expired before the commitment existed"); settleErr != nil {
			return settleErr
		}
		return err
	}
	if !digestPattern.MatchString(commitment) {
		return errors.New("invalid commitment digest")
	}

	if n.agreed == nil {
		return errors.New("canonicalization has no agreed terms")
	}
	quote, err := ResolveMatchingAcceptedQuote(resolver, commitment, *n.agreed, n.network)
	if errors.Is(err, ErrFinalizedQuoteMismatch) {
		if err := n.settle(StateRejected, "the finalized quote does not match what was agreed"); err != nil {
			return err
		}
		return ErrFinalizedQuoteMismatch
	}
	if err != nil {
		return err
	}
	// The finalized quote must have come from the network this negotiation was
	// bound to. A network id alone is not identity, so both genesis hashes must
	// agree too: a quote read from another network is a different commitment
	// wearing familiar terms, and accepting it would move value under a
	// purchase nobody here made.
	//
	// The network is now also committed inside the digests themselves -- the
	// asset carries it, so the terms and mandate preimages inherit it, and
	// identical terms on two networks no longer share a digest. The equality
	// comparison below is kept as the second, runtime layer: the digest
	// commitment makes a cross-network replay fail cryptographically, and this
	// check makes a resolver that answered from the wrong network fail loudly
	// even when nothing else differs.
	// The owner's decision has to still describe this, and the terms have to
	// still be inside the authority they were agreed under.
	if n.needsApproval {
		if err := n.approvalStands(); err != nil {
			return err
		}
	}
	if _, err := n.Mandate.PermitsCommit(quote.Terms, now); err != nil {
		if settleErr := n.settle(StateRejected, "the finalized quote falls outside the mandate"); settleErr != nil {
			return settleErr
		}
		return err
	}
	// The finalized state is written before the budget hold becomes a spend.
	// A crash between the two leaves a finalized snapshot beside a live hold,
	// and start-up reconciliation commits it: the reservation is keyed by this
	// negotiation, so the link survives. The other order turns the hold into
	// an anonymous spend first, and a crash then leaves money marked spent
	// with no finalized exchange to account for it -- nothing could tell that
	// apart from corruption. The commit itself cannot exceed the budget: the
	// reservation was bounded when it was taken.
	n.commitment = commitment
	n.quote = &quote
	n.state = StateFinalized
	if err := n.persist(); err != nil {
		return err
	}
	if n.budget != nil {
		return n.budget.Commit(n.ID)
	}
	return nil
}

// validateNetworkDomain enforces a fully identified TOS network, the way
// identity validation does: a named id and both genesis hashes carried as bare
// hex. A network id without its genesis hashes is not an identity -- the same id
// can front different genesis state -- so the binding a negotiation is checked
// against must carry all three.
func validateNetworkDomain(network *nativev1.NetworkDomain) error {
	if network == nil || network.NetworkId == "" || len(network.NetworkId) > 128 ||
		!canon.HashPattern.MatchString(network.GenesisRootHash) ||
		!canon.HashPattern.MatchString(network.GenesisFileHash) {
		return errors.New("invalid negotiation network domain")
	}
	return nil
}

// sameNetwork reports whether two domains name the same TOS network. Both the
// id and both genesis hashes must agree: a shared id over different genesis
// state is a different network.
func sameNetwork(expected, got *nativev1.NetworkDomain) bool {
	if expected == nil || got == nil {
		return false
	}
	return expected.NetworkId == got.NetworkId &&
		expected.GenesisRootHash == got.GenesisRootHash &&
		expected.GenesisFileHash == got.GenesisFileHash
}

// cloneNetwork copies the three identifying fields of a network domain, so a
// stored binding cannot be mutated through the caller's pointer. A nil input
// clones to nil; validation elsewhere refuses a negotiation with no network.
func cloneNetwork(network *nativev1.NetworkDomain) *nativev1.NetworkDomain {
	if network == nil {
		return nil
	}
	return &nativev1.NetworkDomain{
		NetworkId:       network.NetworkId,
		GenesisRootHash: network.GenesisRootHash,
		GenesisFileHash: network.GenesisFileHash,
	}
}

// Quote returns the finalized Accepted Quote behind a commitment.
func (n *Negotiation) Quote() (VerifiedAcceptedQuote, bool) {
	if n.state != StateFinalized || n.quote == nil {
		return VerifiedAcceptedQuote{}, false
	}
	return *n.quote, true
}
