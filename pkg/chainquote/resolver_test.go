package chainquote

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/tosnetwork/tos-messenger/pkg/eventlog"
	"github.com/tosnetwork/tos-messenger/pkg/negotiation"
	nativev1 "github.com/tosnetwork/tos-service-protocol/gen/tos/service/v1"
	"github.com/tosnetwork/tos-service-protocol/pkg/nativecore"
	"github.com/tosnetwork/tos-service-protocol/pkg/toschain"
	"github.com/tosnetwork/tosutils-go/tvm/cell"
)

// The resolver satisfies the Messenger's own interface.
var _ negotiation.QuoteResolver = (*Resolver)(nil)
var _ EscrowLocator = (*eventlog.Journal)(nil)

const (
	testCommitment = "tvm-cell-sha256:" + "abababababababababababababababababababababababababababababababab"
	testAddress    = "0:" + "cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd"
	testClass      = "software.audit"
)

func testNetwork() *nativev1.NetworkDomain {
	return &nativev1.NetworkDomain{
		NetworkId:       "tos-local",
		GenesisRootHash: strings.Repeat("a", 64),
		GenesisFileHash: strings.Repeat("b", 64),
	}
}

type fakeReader struct {
	escrow *toschain.FinalizedEscrowV1
	found  bool
	err    error
}

type addressCheckingReader struct {
	want   string
	escrow *toschain.FinalizedEscrowV1
}

func (r addressCheckingReader) ResolveFinalized(
	_ context.Context,
	address string,
) (*toschain.FinalizedEscrowV1, bool, error) {
	if address != r.want {
		return nil, false, errors.New("unexpected escrow address")
	}
	return r.escrow, true, nil
}

func (f fakeReader) ResolveFinalized(context.Context, string) (*toschain.FinalizedEscrowV1, bool, error) {
	return f.escrow, f.found, f.err
}

// finalizedEscrow builds a finalized escrow record carrying a commitment and a
// non-nil quote cell. The cell's contents are irrelevant: the decode step is
// injected in tests, so what matters is that the field is present.
func finalizedEscrow(commitment string) *toschain.FinalizedEscrowV1 {
	return &toschain.FinalizedEscrowV1{
		State: &nativecore.EscrowStateV1{
			QuoteCommitment: commitment,
			AcceptedQuote:   cell.BeginCell().EndCell(),
		},
		Reference: &nativev1.ChainReference{
			Workchain: 0, Account: testAddress,
			LogicalTime: 42, TransactionHash: "sha256:" + strings.Repeat("e", 64),
			ContractCodeHash: "tvm-cell-sha256:" + strings.Repeat("f", 64), FinalizedCheckpoint: 100,
		},
		FinalizedAt: time.Unix(1_800_000_000, 0),
	}
}

// validProposal is a canonical quote whose mapped Terms pass the Messenger's own
// validation, so a test that gets a rejection learns it came from the behaviour
// under test and not a malformed fixture.
func validProposal() *nativev1.QuoteProposalV1 {
	return &nativev1.QuoteProposalV1{
		CapabilityId:           "cap_" + strings.Repeat("9", 64),
		CapabilityVersion:      "1.4.0",
		ProviderAgentId:        "agent_" + strings.Repeat("5", 64),
		ManifestDigest:         "sha256:" + strings.Repeat("d", 64),
		TransportBindingDigest: "sha256:" + strings.Repeat("e", 64),
		MaximumPrice: &nativev1.MoneyV1{
			Asset: &nativev1.TOSAssetIdentityV1{
				Master: &nativev1.TOSContractIdentityV1{
					Workchain: 0, AccountId: bytes.Repeat([]byte{0xaa}, 32),
					CodeHash: "tvm-cell-sha256:" + strings.Repeat("b", 64),
				},
				WalletCodeHash: "tvm-cell-sha256:" + strings.Repeat("c", 64),
				Decimals:       6,
			},
			AtomicAmount: "10000000",
		},
		EscrowTermsDigest:    "sha256:" + strings.Repeat("f", 64),
		DisputePolicyDigest:  "sha256:" + strings.Repeat("1", 64),
		ExpiresAtUnixSeconds: 1_800_000_000 + 3600,
	}
}

func decodeTo(proposal *nativev1.QuoteProposalV1) quoteDecoder {
	return func(*cell.Cell, *nativev1.NetworkDomain) (*nativecore.AcceptedQuoteTermsV1, error) {
		return &nativecore.AcceptedQuoteTermsV1{Network: testNetwork(), Proposal: proposal}, nil
	}
}

func newResolver(t *testing.T, reader EscrowReader, decode quoteDecoder) *Resolver {
	t.Helper()
	locator := NewMapLocator()
	if err := locator.Record(testCommitment, testAddress, testClass); err != nil {
		t.Fatalf("record locator: %v", err)
	}
	resolver, err := New(reader, locator, testNetwork())
	if err != nil {
		t.Fatalf("new resolver: %v", err)
	}
	if decode != nil {
		resolver.decode = decode
	}
	return resolver
}

// The whole chain: locate the escrow, read it finalized, confirm it holds the
// asked-for commitment, decode, and map onto Terms the Messenger accepts.
func TestResolveMapsAFinalizedQuote(t *testing.T) {
	reader := fakeReader{escrow: finalizedEscrow(testCommitment), found: true}
	resolver := newResolver(t, reader, decodeTo(validProposal()))

	quote, found, err := resolver.ResolveAcceptedQuote(testCommitment)
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if !found {
		t.Fatal("a finalized quote was reported not found")
	}
	if quote.Commitment != testCommitment {
		t.Fatalf("commitment not carried through: %q", quote.Commitment)
	}
	if quote.Terms.CapabilityClass != testClass {
		t.Fatalf("class was not taken from the locator: %q", quote.Terms.CapabilityClass)
	}
	if quote.Terms.Price.Asset.AccountID != strings.Repeat("aa", 32) {
		t.Fatalf("asset account was not hex-encoded from the chain bytes: %q", quote.Terms.Price.Asset.AccountID)
	}
	if quote.Terms.Price.Atomic != "10000000" || quote.Terms.ProviderAgentID != "agent_"+strings.Repeat("5", 64) {
		t.Fatalf("terms were not mapped from the proposal: %+v", quote.Terms)
	}
	if quote.Reference == nil || quote.Reference.FinalizedCheckpoint != 100 {
		t.Fatal("the finalized reference was not carried through")
	}
	if err := quote.Validate(); err != nil {
		t.Fatalf("a mapped quote failed the Messenger's own validation: %v", err)
	}
}

func TestResolveAtVerifiesFinalizedEscrowWithoutLocalLocator(t *testing.T) {
	resolver, err := New(
		addressCheckingReader{want: testAddress, escrow: finalizedEscrow(testCommitment)},
		NewMapLocator(), testNetwork())
	if err != nil {
		t.Fatal(err)
	}
	resolver.decode = decodeTo(validProposal())
	if _, found, err := resolver.ResolveAcceptedQuote(testCommitment); err != nil || found {
		t.Fatalf("digest lookup unexpectedly had a locator: found=%v err=%v", found, err)
	}
	quote, found, err := resolver.ResolveAcceptedQuoteAt(
		context.Background(), testCommitment, testAddress, testClass)
	if err != nil || !found || quote.Reference.Account != testAddress || quote.Terms.CapabilityClass != testClass {
		t.Fatalf("addressed finalized read: quote=%+v found=%v err=%v", quote, found, err)
	}
	if _, _, err := resolver.ResolveAcceptedQuoteAt(
		context.Background(), testCommitment, "0:"+strings.Repeat("1", 64), testClass); err == nil {
		t.Fatal("an escrow-address substitution was not sent through the finalized reader")
	}
}

// A commitment with no known escrow is not found, not an error: the caller may
// have asked before funding.
func TestResolveUnknownCommitmentIsNotFound(t *testing.T) {
	reader := fakeReader{escrow: finalizedEscrow(testCommitment), found: true}
	resolver := newResolver(t, reader, decodeTo(validProposal()))

	_, found, err := resolver.ResolveAcceptedQuote("tvm-cell-sha256:" + strings.Repeat("0", 64))
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if found {
		t.Fatal("a commitment with no escrow was reported found")
	}
}

// An escrow account not yet finalized is not found, not an error.
func TestResolveUnfinalizedEscrowIsNotFound(t *testing.T) {
	resolver := newResolver(t, fakeReader{found: false}, decodeTo(validProposal()))
	_, found, err := resolver.ResolveAcceptedQuote(testCommitment)
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if found {
		t.Fatal("an unfinalized escrow was reported found")
	}
}

// The located escrow must hold the commitment that was asked for; an account
// carrying a different one is refused rather than returned as this purchase.
func TestResolveRefusesAMismatchedCommitment(t *testing.T) {
	other := "tvm-cell-sha256:" + strings.Repeat("2", 64)
	reader := fakeReader{escrow: finalizedEscrow(other), found: true}
	resolver := newResolver(t, reader, decodeTo(validProposal()))

	if _, _, err := resolver.ResolveAcceptedQuote(testCommitment); err == nil {
		t.Fatal("an escrow holding another commitment was accepted")
	}
}

// A reader error is propagated, not swallowed into a not-found.
func TestResolvePropagatesAReaderError(t *testing.T) {
	reader := fakeReader{err: errors.New("chain is unreachable")}
	resolver := newResolver(t, reader, decodeTo(validProposal()))
	if _, found, err := resolver.ResolveAcceptedQuote(testCommitment); err == nil || found {
		t.Fatalf("a reader error was not propagated: found=%v err=%v", found, err)
	}
}

// A decode failure is refused, not returned as a partial quote.
func TestResolveRefusesAnUndecodableQuote(t *testing.T) {
	reader := fakeReader{escrow: finalizedEscrow(testCommitment), found: true}
	failing := func(*cell.Cell, *nativev1.NetworkDomain) (*nativecore.AcceptedQuoteTermsV1, error) {
		return nil, errors.New("non-canonical quote cell")
	}
	resolver := newResolver(t, reader, failing)
	if _, _, err := resolver.ResolveAcceptedQuote(testCommitment); err == nil {
		t.Fatal("an undecodable quote was accepted")
	}
}

// A mapped quote that a foreign asset makes invalid is refused by the
// Messenger's own rules, exercised here through a proposal with an empty asset.
func TestResolveRefusesAnInvalidMappedQuote(t *testing.T) {
	reader := fakeReader{escrow: finalizedEscrow(testCommitment), found: true}
	broken := validProposal()
	broken.MaximumPrice = &nativev1.MoneyV1{Asset: nil, AtomicAmount: "1"}
	resolver := newResolver(t, reader, decodeTo(broken))
	if _, _, err := resolver.ResolveAcceptedQuote(testCommitment); err == nil {
		t.Fatal("a quote with no priced asset was accepted")
	}
}

// The locator refuses a second, conflicting binding for one commitment.
func TestLocatorRefusesConflictingRebind(t *testing.T) {
	locator := NewMapLocator()
	if err := locator.Record(testCommitment, testAddress, testClass); err != nil {
		t.Fatalf("record: %v", err)
	}
	if err := locator.Record(testCommitment, testAddress, testClass); err != nil {
		t.Fatalf("an identical re-record was refused: %v", err)
	}
	if err := locator.Record(testCommitment, "0:"+strings.Repeat("1", 64), testClass); err == nil {
		t.Fatal("a commitment was silently redirected to another escrow")
	}
}
