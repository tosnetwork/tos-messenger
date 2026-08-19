// Package chainquote resolves finalized Accepted Quotes from TOS chain state
// and satisfies the Messenger's negotiation.QuoteResolver.
//
// It reimplements no chain logic. Reading finalized state under a strict
// endpoint majority, checkpoint and rollback protection all belong to
// tos-service-protocol's toschain; decoding a quote cell to its committed
// fields belongs to its nativecore. This package only locates the escrow that
// holds a commitment, checks the account it read carries the commitment it was
// asked for, and maps the decoded proposal onto the Messenger's own Terms. That
// is the boundary the Messenger's design draws: the finalized chain state is the
// authority, and a resolver written here consumes it rather than offering a
// second opinion about what it says.
//
// The chain is addressed by account, not by commitment, so a commitment cannot
// be resolved without first learning where its escrow lives. That mapping -- and
// the capability class, which the canonical quote omits because the capability
// identifier already determines it -- is produced when the escrow is prepared
// and funded, by the party that set it up. Both are therefore locally attested
// through an EscrowLocator, not read from the chain.
package chainquote

import (
	"context"
	"encoding/hex"
	"errors"

	"github.com/tosnetwork/tos-messenger/pkg/negotiation"
	nativev1 "github.com/tosnetwork/tos-service-protocol/gen/tos/service/v1"
	"github.com/tosnetwork/tos-service-protocol/pkg/nativecore"
	"github.com/tosnetwork/tos-service-protocol/pkg/toschain"
	"github.com/xssnick/tonutils-go/tvm/cell"
)

// EscrowReader reads a finalized escrow account by address. It is the narrow
// slice of toschain.EscrowResolver this bridge depends on, declared here so the
// resolver can be exercised without a live chain.
type EscrowReader interface {
	ResolveFinalized(ctx context.Context, escrowAddress string) (*toschain.FinalizedEscrowV1, bool, error)
}

// EscrowLocator maps a quote commitment to the escrow account that holds it and
// to the capability class the on-chain quote does not carry.
//
// A commitment that this installation has no escrow for is reported not-found,
// not as an error: the caller may simply have asked before the escrow was
// funded, which the negotiation state machine already tolerates.
type EscrowLocator interface {
	LocateEscrow(commitment string) (escrowAddress, capabilityClass string, found bool, err error)
}

// quoteDecoder is nativecore.DecodeAcceptedQuoteV1, made injectable so the
// resolver's orchestration can be tested without encoding a real quote cell.
type quoteDecoder func(*cell.Cell, *nativev1.NetworkDomain) (*nativecore.AcceptedQuoteTermsV1, error)

// Resolver reads finalized Accepted Quotes and satisfies
// negotiation.QuoteResolver.
type Resolver struct {
	reader  EscrowReader
	locator EscrowLocator
	network *nativev1.NetworkDomain
	decode  quoteDecoder
}

// New builds a resolver over a reader and a locator. The network is the domain
// the reader reads and the quote cell is bound to.
func New(reader EscrowReader, locator EscrowLocator, network *nativev1.NetworkDomain) (*Resolver, error) {
	if reader == nil {
		return nil, errors.New("a quote resolver needs a finalized escrow reader")
	}
	if locator == nil {
		return nil, errors.New("a quote resolver needs an escrow locator")
	}
	if network == nil || network.NetworkId == "" {
		return nil, errors.New("a quote resolver needs a network domain")
	}
	return &Resolver{reader: reader, locator: locator, network: network, decode: nativecore.DecodeAcceptedQuoteV1}, nil
}

// NewFromChain builds a resolver whose reader is a toschain escrow resolver over
// a configured chain adapter. The adapter, network, escrow code hash and
// checkpoint path are the service protocol's, unchanged.
func NewFromChain(adapter *toschain.Adapter, network *nativev1.NetworkDomain,
	escrowCodeHash, checkpointPath string, locator EscrowLocator) (*Resolver, error) {
	if adapter == nil {
		return nil, errors.New("a chain-backed resolver needs a chain adapter")
	}
	escrow, err := toschain.NewEscrowResolver(adapter, network, escrowCodeHash, checkpointPath)
	if err != nil {
		return nil, err
	}
	return New(escrow, locator, network)
}

// ResolveAcceptedQuote implements negotiation.QuoteResolver.
//
// The read is bounded by the reader's own per-query timeout, so it is issued
// against the background context: the interface carries none, and inventing a
// deadline here would second-guess the transport's.
func (r *Resolver) ResolveAcceptedQuote(commitment string) (negotiation.VerifiedAcceptedQuote, bool, error) {
	if r == nil {
		return negotiation.VerifiedAcceptedQuote{}, false, errors.New("no quote resolver")
	}
	if commitment == "" {
		return negotiation.VerifiedAcceptedQuote{}, false, errors.New("a commitment must be named")
	}
	address, capabilityClass, found, err := r.locator.LocateEscrow(commitment)
	if err != nil {
		return negotiation.VerifiedAcceptedQuote{}, false, err
	}
	if !found {
		// No escrow is known for this commitment yet. Not an error, and not a
		// false success: the caller may have asked before funding.
		return negotiation.VerifiedAcceptedQuote{}, false, nil
	}
	if address == "" {
		return negotiation.VerifiedAcceptedQuote{}, false, errors.New("the locator returned no escrow address")
	}

	escrow, found, err := r.reader.ResolveFinalized(context.Background(), address)
	if err != nil {
		return negotiation.VerifiedAcceptedQuote{}, false, err
	}
	if !found {
		// The escrow account is not finalized on chain yet.
		return negotiation.VerifiedAcceptedQuote{}, false, nil
	}
	if escrow == nil || escrow.State == nil || escrow.Reference == nil {
		return negotiation.VerifiedAcceptedQuote{}, false, errors.New("finalized escrow read returned an incomplete record")
	}
	// The located account must hold the commitment that was asked for. A
	// mismatch means the locator pointed at the wrong escrow; fail closed rather
	// than return a different purchase under this commitment.
	if escrow.State.QuoteCommitment != commitment {
		return negotiation.VerifiedAcceptedQuote{}, false, errors.New("the finalized escrow holds a different quote commitment")
	}
	if escrow.State.AcceptedQuote == nil {
		return negotiation.VerifiedAcceptedQuote{}, false, errors.New("the finalized escrow carries no accepted quote")
	}

	decoded, err := r.decode(escrow.State.AcceptedQuote, r.network)
	if err != nil {
		return negotiation.VerifiedAcceptedQuote{}, false, err
	}
	terms, err := mapTerms(decoded, capabilityClass)
	if err != nil {
		return negotiation.VerifiedAcceptedQuote{}, false, err
	}
	quote := negotiation.VerifiedAcceptedQuote{
		Commitment:      commitment,
		Terms:           terms,
		Reference:       escrow.Reference,
		Network:         r.network,
		FinalizedAtUnix: finalizedUnix(escrow),
	}
	// The Messenger's own invariants are enforced on the mapped result, so a
	// chain object that does not meet them is refused here rather than surfacing
	// as a malformed quote deeper in the state machine.
	if err := quote.Validate(); err != nil {
		return negotiation.VerifiedAcceptedQuote{}, false, err
	}
	return quote, true, nil
}

// finalizedUnix reads the finalization time as a non-negative Unix second.
func finalizedUnix(escrow *toschain.FinalizedEscrowV1) uint64 {
	seconds := escrow.FinalizedAt.Unix()
	if seconds < 0 {
		return 0
	}
	return uint64(seconds)
}

// mapTerms projects the decoded canonical quote onto the Messenger's Terms. The
// capability class is supplied by the locator, because the canonical quote does
// not carry it.
func mapTerms(decoded *nativecore.AcceptedQuoteTermsV1, capabilityClass string) (negotiation.Terms, error) {
	if decoded == nil || decoded.Proposal == nil {
		return negotiation.Terms{}, errors.New("the decoded quote carries no proposal")
	}
	proposal := decoded.Proposal
	price, err := mapMoney(proposal.MaximumPrice)
	if err != nil {
		return negotiation.Terms{}, err
	}
	return negotiation.Terms{
		CapabilityID:           proposal.CapabilityId,
		CapabilityVersion:      proposal.CapabilityVersion,
		CapabilityClass:        capabilityClass,
		ProviderAgentID:        proposal.ProviderAgentId,
		ManifestDigest:         proposal.ManifestDigest,
		TransportBindingDigest: proposal.TransportBindingDigest,
		Price:                  price,
		EscrowTermsDigest:      proposal.EscrowTermsDigest,
		DisputePolicyDigest:    proposal.DisputePolicyDigest,
		NotAfterUnix:           proposal.ExpiresAtUnixSeconds,
	}, nil
}

// mapMoney projects the on-chain money onto the Messenger's Money. Field
// validity is left to the Messenger's own Validate, so a malformed asset is
// refused by the same rules every other quote is.
func mapMoney(money *nativev1.MoneyV1) (negotiation.Money, error) {
	if money == nil || money.Asset == nil || money.Asset.Master == nil {
		return negotiation.Money{}, errors.New("the quote carries no priced asset")
	}
	return negotiation.Money{
		Asset: negotiation.Asset{
			Workchain:      money.Asset.Master.Workchain,
			AccountID:      hex.EncodeToString(money.Asset.Master.AccountId),
			MasterCodeHash: money.Asset.Master.CodeHash,
			WalletCodeHash: money.Asset.WalletCodeHash,
			Decimals:       money.Asset.Decimals,
		},
		Atomic: money.AtomicAmount,
	}, nil
}
