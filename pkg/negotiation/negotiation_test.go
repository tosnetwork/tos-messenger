package negotiation

import (
	"errors"
	"strings"
	"testing"
	"time"

	nativev1 "github.com/tosnetwork/tos-service-protocol/gen/tos/service/v1"
)

const (
	baseUnix     = uint64(1_800_000_000)
	conversation = "conv_" + "1111111111111111111111111111111111111111111111111111111111111111"
	counterparty = "agent_" + "5555555555555555555555555555555555555555555555555555555555555555"
	capabilityID = "cap_" + "9999999999999999999999999999999999999999999999999999999999999999"
	commitment   = "sha256:" + "abababababababababababababababababababababababababababababababab"
)

// testAsset is an asset identified the way the chain identifies one. There is
// no ticker: two contracts may both answer to "USDT", and a test that used one
// would be testing an identity the code no longer accepts.
func testAsset() Asset {
	return Asset{
		Workchain:      0,
		AccountID:      strings.Repeat("a", 64),
		MasterCodeHash: "tvm-cell-sha256:" + strings.Repeat("b", 64),
		WalletCodeHash: "tvm-cell-sha256:" + strings.Repeat("c", 64),
		Decimals:       6,
	}
}

func usdt(atomic string) Money {
	return Money{Asset: testAsset(), Atomic: atomic}
}

func testMandate() Mandate {
	return Mandate{
		Objective:        "audit one smart contract",
		Authority:        AuthorityCommit,
		CapabilityClass:  "software.audit",
		MaxTotal:         usdt("120000000"),
		ApprovalAbove:    usdt("100000000"),
		MaxCounteroffers: 3,
		ExpiresAtUnix:    baseUnix + 86_400,
	}
}

func terms(atomic string) Terms {
	return Terms{
		CapabilityID:           capabilityID,
		CapabilityVersion:      "1.4.0",
		CapabilityClass:        "software.audit",
		ProviderAgentID:        counterparty,
		ManifestDigest:         "sha256:" + strings.Repeat("d", 64),
		TransportBindingDigest: "sha256:" + strings.Repeat("e", 64),
		Price:                  usdt(atomic),
		EscrowTermsDigest:      "sha256:" + strings.Repeat("f", 64),
		DisputePolicyDigest:    "sha256:" + strings.Repeat("1", 64),
		NotAfterUnix:           baseUnix + 3600,
	}
}

// memoryLedger is a budget ledger for tests. A budget with nowhere to survive
// a restart is one the code refuses to open.
type memoryLedger struct {
	state BudgetState
	held  bool
}

func (m *memoryLedger) Load() (BudgetState, bool, error) { return m.state, m.held, nil }

func (m *memoryLedger) Record(state BudgetState) error {
	reserved := make(map[string]Money, len(state.Reserved))
	for id, amount := range state.Reserved {
		reserved[id] = amount
	}
	m.state = BudgetState{Total: state.Total, Spent: state.Spent, Reserved: reserved}
	m.held = true
	return nil
}

func testBudget(t *testing.T, total string) *Budget {
	t.Helper()
	budget, err := OpenBudget(usdt(total), &memoryLedger{})
	if err != nil {
		t.Fatalf("budget: %v", err)
	}
	return budget
}

// memoryStore is a negotiation store for tests. A negotiation with nowhere to
// survive a restart is one the code refuses to start.
type memoryStore struct {
	saved Snapshot
	held  bool
}

func (m *memoryStore) Save(snapshot Snapshot) error {
	m.saved = snapshot
	m.held = true
	return nil
}

// stubResolver stands in for reading a finalized Accepted Quote off the chain.
type stubResolver struct {
	quote VerifiedAcceptedQuote
	found bool
	err   error
}

func (s stubResolver) ResolveAcceptedQuote(string) (VerifiedAcceptedQuote, bool, error) {
	return s.quote, s.found, s.err
}

func finalizedQuote(agreed Terms) VerifiedAcceptedQuote {
	return VerifiedAcceptedQuote{
		Commitment: commitment,
		Terms:      agreed,
		Reference: &nativev1.ChainReference{
			Workchain: 0, Account: "0:" + strings.Repeat("d", 64),
			LogicalTime: 42, TransactionHash: "sha256:" + strings.Repeat("e", 64),
			ContractCodeHash:    "tvm-cell-sha256:" + strings.Repeat("f", 64),
			FinalizedCheckpoint: 100,
		},
		Network:         &nativev1.NetworkDomain{NetworkId: "tos-local"},
		FinalizedAtUnix: baseUnix + 10,
	}
}

// approvedDigest is what the owner saw. An approval names the terms it was a
// decision about, so a test that passed a bare confirmation would be
// exercising the binding it is meant to check.
func approvedDigest(t *testing.T, instance *Negotiation) string {
	t.Helper()
	agreed, ok := instance.Agreed()
	if !ok {
		t.Fatal("nothing has been agreed")
	}
	digest, err := agreed.Digest()
	if err != nil {
		t.Fatalf("digest: %v", err)
	}
	return digest
}

// testCandidate is a complete candidate: every field a canonical quote carries
// is named rather than inferred.
func testCandidate() Candidate {
	return Candidate{
		CapabilityID:           capabilityID,
		CapabilityVersion:      "1.4.0",
		CapabilityClass:        "software.audit",
		ProviderAgentID:        counterparty,
		ManifestDigest:         "sha256:" + strings.Repeat("d", 64),
		TransportBindingDigest: "sha256:" + strings.Repeat("e", 64),
		Price:                  usdt("10000000"),
		EscrowTermsDigest:      "sha256:" + strings.Repeat("f", 64),
		DisputePolicyDigest:    "sha256:" + strings.Repeat("1", 64),
		NotAfterUnix:           baseUnix + 3600,
	}
}

func withCapability(t Terms, id string) Terms     { t.CapabilityID = id; return t }
func withVersion(t Terms, version string) Terms   { t.CapabilityVersion = version; return t }
func withExpiry(t Terms, expiry uint64) Terms     { t.NotAfterUnix = expiry; return t }
func withProvider(t Terms, provider string) Terms { t.ProviderAgentID = provider; return t }
func withManifest(t Terms, digest string) Terms   { t.ManifestDigest = digest; return t }
func withEscrow(t Terms, digest string) Terms     { t.EscrowTermsDigest = digest; return t }

// otherMoney is an amount of a different asset.
func otherMoney(atomic string) Money {
	asset := testAsset()
	asset.AccountID = strings.Repeat("9", 64)
	return Money{Asset: asset, Atomic: atomic}
}

// left is what a budget has remaining.
func left(t *testing.T, budget *Budget) Money {
	t.Helper()
	remaining, err := budget.Remaining()
	if err != nil {
		t.Fatalf("remaining: %v", err)
	}
	return remaining
}

func at(offset uint64) time.Time { return time.Unix(int64(baseUnix+offset), 0) }

func start(t *testing.T, budget *Budget) *Negotiation {
	t.Helper()
	instance, err := New("neg-1", conversation, counterparty, testMandate(), budget, &memoryStore{}, at(0))
	if err != nil {
		t.Fatalf("new: %v", err)
	}
	return instance
}

// The exchange the design describes: an offer, a counter, agreement in
// conversation, and only then a commitment.
func TestNegotiationReachesACommitment(t *testing.T) {
	instance := start(t, testBudget(t, "1000000000"))
	if err := instance.ReceiveProposal(terms("126000000"), at(1)); err != nil {
		t.Fatalf("proposal: %v", err)
	}
	if err := instance.Counter(terms("118000000"), at(2)); err != nil {
		t.Fatalf("counter: %v", err)
	}
	if err := instance.AcceptIntent(at(3)); err != nil {
		t.Fatalf("accept: %v", err)
	}
	if instance.State() != StateIntentAgreed {
		t.Fatalf("unexpected state: %q", instance.State())
	}
	// Saying yes is not owing anything.
	if instance.ActiveAgreement() {
		t.Fatal("agreeing in conversation reported a commercial agreement")
	}
	// The deal is above the point the owner decides personally, which is the
	// case the design's own example describes.
	if !instance.NeedsOwnerApproval() {
		t.Fatal("a deal above the approval point did not ask for the owner")
	}
	if err := instance.ApproveByOwner(approvedDigest(t, instance), at(4)); err != nil {
		t.Fatalf("approve: %v", err)
	}
	if err := instance.BeginCanonicalization(at(4)); err != nil {
		t.Fatalf("canonicalise: %v", err)
	}
	if err := instance.Finalize(stubResolver{quote: finalizedQuote(terms("118000000")), found: true}, commitment, at(5)); err != nil {
		t.Fatalf("finalize: %v", err)
	}
	if !instance.ActiveAgreement() {
		t.Fatal("a finalised negotiation reports no agreement")
	}
	digest, committed := instance.Committed()
	if !committed || digest != commitment {
		t.Fatalf("unexpected commitment: %q %v", digest, committed)
	}
}

// "I accept" is a sentence. It creates no Quote, funds no escrow, and obliges
// nobody.
func TestAcceptingIntentCreatesNothing(t *testing.T) {
	instance := start(t, testBudget(t, "1000000000"))
	if err := instance.ReceiveProposal(terms("50000000"), at(1)); err != nil {
		t.Fatalf("proposal: %v", err)
	}
	if err := instance.AcceptIntent(at(2)); err != nil {
		t.Fatalf("accept: %v", err)
	}
	if _, committed := instance.Committed(); committed {
		t.Fatal("accepting an intent produced a commitment")
	}
	if instance.ActiveAgreement() {
		t.Fatal("accepting an intent produced an active agreement")
	}
}

// An Agent may counter an offer above its ceiling. It may not counter with
// one, and it cannot move the ceiling by arguing.
func TestTheCeilingIsNotPartOfTheNegotiation(t *testing.T) {
	instance := start(t, testBudget(t, "1000000000"))
	if err := instance.ReceiveProposal(terms("126000000"), at(1)); err != nil {
		t.Fatalf("an offer above the ceiling could not even be recorded: %v", err)
	}
	if err := instance.Counter(terms("126000000"), at(2)); err == nil {
		t.Fatal("an Agent countered with terms beyond its own mandate")
	}
	if err := instance.AcceptIntent(at(3)); err == nil {
		t.Fatal("an Agent accepted terms beyond its own mandate")
	}
	// And the mandate is unchanged by any of it.
	if instance.Mandate.MaxTotal.Atomic != "120000000" {
		t.Fatalf("the ceiling moved: %v", instance.Mandate.MaxTotal)
	}
}

// The compiler refuses to fill in what the text did not say, including taking
// the asset from the budget.
func TestNothingIsInferredFromContext(t *testing.T) {
	mandate := testMandate()
	complete := testCandidate()
	if _, _, err := Compile(complete, mandate, at(1)); err != nil {
		t.Fatalf("a complete candidate was refused: %v", err)
	}
	for name, mutate := range map[string]func(*Candidate){
		"no asset":             func(c *Candidate) { c.Price.Asset = Asset{} },
		"no amount":            func(c *Candidate) { c.Price.Atomic = "0" },
		"no capability":        func(c *Candidate) { c.CapabilityID = "" },
		"no version":           func(c *Candidate) { c.CapabilityVersion = "" },
		"no class":             func(c *Candidate) { c.CapabilityClass = "" },
		"no provider":          func(c *Candidate) { c.ProviderAgentID = "" },
		"no manifest":          func(c *Candidate) { c.ManifestDigest = "" },
		"no transport binding": func(c *Candidate) { c.TransportBindingDigest = "" },
		"no escrow terms":      func(c *Candidate) { c.EscrowTermsDigest = "" },
		"no dispute policy":    func(c *Candidate) { c.DisputePolicyDigest = "" },
		"no expiry":            func(c *Candidate) { c.NotAfterUnix = 0 },
	} {
		t.Run(name, func(t *testing.T) {
			candidate := complete
			mutate(&candidate)
			if _, _, err := Compile(candidate, mandate, at(1)); err == nil {
				t.Fatalf("expected %q to be refused rather than filled in", name)
			}
		})
	}
}

// Where the structured amount and the sentence disagree, the difference is not
// a preference to resolve.
func TestRenderingConflictFailsClosed(t *testing.T) {
	mandate := testMandate()
	rendered := usdt("120000000")
	candidate := testCandidate()
	candidate.Price = usdt("12000000")
	candidate.RenderedPrice = &rendered
	if _, _, err := Compile(candidate, mandate, at(1)); !errors.Is(err, ErrRenderingConflict) {
		t.Fatalf("expected a rendering conflict, got %v", err)
	}
	// The same number in another asset is also a conflict, not a conversion.
	other := testAsset()
	other.AccountID = strings.Repeat("9", 64)
	otherAsset := Money{Asset: other, Atomic: "12000000"}
	candidate.RenderedPrice = &otherAsset
	if _, _, err := Compile(candidate, mandate, at(1)); !errors.Is(err, ErrRenderingConflict) {
		t.Fatalf("expected an asset conflict, got %v", err)
	}
	agreeing := usdt("12000000")
	candidate.RenderedPrice = &agreeing
	if _, _, err := Compile(candidate, mandate, at(1)); err != nil {
		t.Fatalf("agreeing representations were refused: %v", err)
	}
}

// A commitment that does not reproduce the agreed terms ends the negotiation
// rather than finalising on whichever version arrived last.
func TestCanonicalTermsMustMatchWhatWasAgreed(t *testing.T) {
	cases := map[string]Terms{
		"another amount":     terms("120000000"),
		"another version":    withVersion(terms("50000000"), "2.0.0"),
		"another expiry":     withExpiry(terms("50000000"), baseUnix+7200),
		"another provider":   withProvider(terms("50000000"), "agent_"+strings.Repeat("7", 64)),
		"another manifest":   withManifest(terms("50000000"), "sha256:"+strings.Repeat("2", 64)),
		"another escrow":     withEscrow(terms("50000000"), "sha256:"+strings.Repeat("3", 64)),
		"another capability": withCapability(terms("50000000"), "cap_"+strings.Repeat("1", 64)),
	}
	for name, canonical := range cases {
		t.Run(name, func(t *testing.T) {
			instance := start(t, testBudget(t, "1000000000"))
			if err := instance.ReceiveProposal(terms("50000000"), at(1)); err != nil {
				t.Fatalf("proposal: %v", err)
			}
			if err := instance.AcceptIntent(at(2)); err != nil {
				t.Fatalf("accept: %v", err)
			}
			if err := instance.BeginCanonicalization(at(3)); err != nil {
				t.Fatalf("canonicalise: %v", err)
			}
			if err := instance.Finalize(stubResolver{quote: finalizedQuote(canonical), found: true}, commitment, at(4)); err == nil {
				t.Fatalf("a commitment differing in %q was accepted", name)
			}
			if instance.State() != StateRejected {
				t.Fatalf("a failed canonicalisation left state %q", instance.State())
			}
			// The person looking at this must not see an agreement.
			if instance.ActiveAgreement() {
				t.Fatal("a failed canonicalisation reported an active agreement")
			}
			if instance.Failure() == "" {
				t.Fatal("a failed canonicalisation gave no reason")
			}
		})
	}
}

// A finalized quote naming a different asset at the same nominal amount is not
// the agreement. Money is the asset and the amount together; matching the
// amount while the asset differs would let a settlement move a different token
// than the one that was agreed, at a number that looks right.
func TestFinalizeRejectsAForeignAsset(t *testing.T) {
	instance := start(t, testBudget(t, "1000000000"))
	if err := instance.ReceiveProposal(terms("50000000"), at(1)); err != nil {
		t.Fatalf("proposal: %v", err)
	}
	if err := instance.AcceptIntent(at(2)); err != nil {
		t.Fatalf("accept: %v", err)
	}
	if err := instance.BeginCanonicalization(at(3)); err != nil {
		t.Fatalf("canonicalise: %v", err)
	}

	foreign := terms("50000000")
	foreign.Price = otherMoney("50000000")
	if err := instance.Finalize(stubResolver{quote: finalizedQuote(foreign), found: true}, commitment, at(4)); err == nil {
		t.Fatal("a quote in a different asset at the same amount was accepted")
	}
	if instance.State() != StateRejected {
		t.Fatalf("a foreign-asset quote left state %q", instance.State())
	}
	if instance.ActiveAgreement() {
		t.Fatal("a rejected finalisation reported an active agreement")
	}
}

// A resolver that cannot read finalized state has not said the quote is absent
// or wrong; it has said nothing. The negotiation stays where it was, to be
// retried, rather than being rejected for the chain's unavailability -- a
// rejection would throw away an agreement over a transient read failure, and
// the budget hold stays held rather than becoming an unaccountable spend.
func TestFinalizePropagatesAResolverError(t *testing.T) {
	instance := start(t, testBudget(t, "1000000000"))
	if err := instance.ReceiveProposal(terms("50000000"), at(1)); err != nil {
		t.Fatalf("proposal: %v", err)
	}
	if err := instance.AcceptIntent(at(2)); err != nil {
		t.Fatalf("accept: %v", err)
	}
	if err := instance.BeginCanonicalization(at(3)); err != nil {
		t.Fatalf("canonicalise: %v", err)
	}

	readErr := errors.New("finalized state is temporarily unreadable")
	if err := instance.Finalize(stubResolver{err: readErr}, commitment, at(4)); err == nil {
		t.Fatal("a resolver read error was swallowed")
	}
	if instance.State() != StateCanonicalizationPending {
		t.Fatalf("a transient resolver error moved the state to %q", instance.State())
	}
	if instance.ActiveAgreement() {
		t.Fatal("a pending canonicalisation reported an active agreement")
	}

	// The read can be retried, and a good resolver then finalises the same
	// agreement: the transient error cost nothing.
	if err := instance.Finalize(stubResolver{quote: finalizedQuote(terms("50000000")), found: true}, commitment, at(5)); err != nil {
		t.Fatalf("retry after a transient error failed: %v", err)
	}
	if instance.State() != StateFinalized {
		t.Fatalf("a retry after a transient error did not finalise: state %q", instance.State())
	}
}

func proposalMandate() Mandate {
	m := testMandate()
	m.Authority = AuthorityPropose
	return m
}

// A proposal authority may agree in conversation but must never walk that
// agreement up into a commitment. This is the escalation the review found:
// propose -> accept -> canonicalise -> finalise, with no budget. Agreeing is
// allowed; canonicalising is refused, and the state does not advance.
func TestProposalAuthorityCannotCommit(t *testing.T) {
	// A proposal mandate is created with no budget: New demands a budget only of
	// a committing mandate, which is the budgetless path the review flagged.
	instance, err := New("neg-propose", conversation, counterparty, proposalMandate(), nil, &memoryStore{}, at(0))
	if err != nil {
		t.Fatalf("new: %v", err)
	}
	if err := instance.ReceiveProposal(terms("50000000"), at(1)); err != nil {
		t.Fatalf("proposal: %v", err)
	}
	if err := instance.AcceptIntent(at(2)); err != nil {
		t.Fatalf("a proposal authority could not agree in conversation: %v", err)
	}
	if instance.ActiveAgreement() {
		t.Fatal("agreeing in conversation reported a commercial agreement")
	}
	if err := instance.BeginCanonicalization(at(3)); err == nil {
		t.Fatal("a proposal authority canonicalised terms into a commitment")
	}
	if instance.State() == StateCanonicalizationPending {
		t.Fatal("a proposal authority reached canonicalisation-pending")
	}
}

// A mandate that expires between canonicalisation and finalisation must release
// its budget hold durably, so a restart does not find the hold still on the
// books with an expired negotiation behind it.
func TestFinalizeReleasesBudgetOnMandateExpiry(t *testing.T) {
	budget := testBudget(t, "1000000000")
	instance := start(t, budget)
	if err := instance.ReceiveProposal(terms("50000000"), at(1)); err != nil {
		t.Fatalf("proposal: %v", err)
	}
	if err := instance.AcceptIntent(at(2)); err != nil {
		t.Fatalf("accept: %v", err)
	}
	if err := instance.BeginCanonicalization(at(3)); err != nil {
		t.Fatalf("canonicalise: %v", err)
	}
	if remaining := left(t, budget); remaining.Atomic != "950000000" {
		t.Fatalf("the hold was not taken at agreement: remaining %q, want 950000000", remaining.Atomic)
	}

	// The mandate expires (ExpiresAtUnix = baseUnix+86400) before finalisation.
	past := time.Unix(int64(baseUnix)+86_400+10, 0)
	if err := instance.Finalize(stubResolver{quote: finalizedQuote(terms("50000000")), found: true}, commitment, past); err == nil {
		t.Fatal("finalize succeeded past the mandate's expiry")
	}
	if instance.State() != StateExpired {
		t.Fatalf("state after expiry = %q, want expired", instance.State())
	}
	// The hold is released, not leaked into a canonicalisation-pending snapshot.
	if remaining := left(t, budget); remaining.Atomic != "1000000000" {
		t.Fatalf("budget hold leaked on expiry: remaining %q, want the full 1000000000", remaining.Atomic)
	}
}

// One commitment per negotiation. A repeated event does not produce a second.
func TestFinalizingTwiceIsRefused(t *testing.T) {
	instance := start(t, testBudget(t, "1000000000"))
	if err := instance.ReceiveProposal(terms("50000000"), at(1)); err != nil {
		t.Fatalf("proposal: %v", err)
	}
	if err := instance.AcceptIntent(at(2)); err != nil {
		t.Fatalf("accept: %v", err)
	}
	if err := instance.BeginCanonicalization(at(3)); err != nil {
		t.Fatalf("canonicalise: %v", err)
	}
	if err := instance.Finalize(stubResolver{quote: finalizedQuote(terms("50000000")), found: true}, commitment, at(4)); err != nil {
		t.Fatalf("finalize: %v", err)
	}
	if err := instance.Finalize(stubResolver{quote: finalizedQuote(terms("50000000")), found: true}, commitment, at(5)); err == nil {
		t.Fatal("a second commitment was accepted")
	}
}

// Terms above the owner's approval point wait for the owner, and the owner's
// decision is not something the counterparty can supply.
func TestApprovalPointRequiresTheOwner(t *testing.T) {
	instance := start(t, testBudget(t, "1000000000"))
	if err := instance.ReceiveProposal(terms("110000000"), at(1)); err != nil {
		t.Fatalf("proposal: %v", err)
	}
	if err := instance.AcceptIntent(at(2)); err != nil {
		t.Fatalf("accept: %v", err)
	}
	if !instance.NeedsOwnerApproval() {
		t.Fatal("terms above the approval point did not ask for the owner")
	}
	if err := instance.BeginCanonicalization(at(3)); err == nil {
		t.Fatal("terms above the approval point were canonicalised without the owner")
	}
	if err := instance.ApproveByOwner(approvedDigest(t, instance), at(4)); err != nil {
		t.Fatalf("approve: %v", err)
	}
	if err := instance.BeginCanonicalization(at(5)); err != nil {
		t.Fatalf("canonicalise after approval: %v", err)
	}

	// Below the point the owner is not asked, and approving is meaningless.
	small := start(t, testBudget(t, "1000000000"))
	if err := small.ReceiveProposal(terms("10000000"), at(1)); err != nil {
		t.Fatalf("proposal: %v", err)
	}
	if err := small.AcceptIntent(at(2)); err != nil {
		t.Fatalf("accept: %v", err)
	}
	if small.NeedsOwnerApproval() {
		t.Fatal("terms inside the mandate asked for the owner anyway")
	}
	if err := small.ApproveByOwner(approvedDigest(t, small), at(3)); err == nil {
		t.Fatal("an unnecessary approval was recorded")
	}
}

func TestOwnerCanRefuse(t *testing.T) {
	instance := start(t, testBudget(t, "1000000000"))
	if err := instance.ReceiveProposal(terms("110000000"), at(1)); err != nil {
		t.Fatalf("proposal: %v", err)
	}
	if err := instance.AcceptIntent(at(2)); err != nil {
		t.Fatalf("accept: %v", err)
	}
	if err := instance.DenyByOwner("too expensive"); err != nil {
		t.Fatalf("deny: %v", err)
	}
	if instance.State() != StateRejected || instance.ActiveAgreement() {
		t.Fatalf("a refused intent survived: %q", instance.State())
	}
	if err := instance.BeginCanonicalization(at(3)); err == nil {
		t.Fatal("a refused intent was canonicalised")
	}
}

// A negotiation that can run forever is one an unattended Agent can be kept in
// indefinitely.
func TestCounteroffersAreBounded(t *testing.T) {
	instance := start(t, testBudget(t, "1000000000"))
	for round := uint64(0); round < 3; round++ {
		if err := instance.ReceiveProposal(terms("100000000"), at(round*2+1)); err != nil {
			t.Fatalf("proposal: %v", err)
		}
		if err := instance.Counter(terms("90000000"), at(round*2+2)); err != nil {
			t.Fatalf("counter %d: %v", round, err)
		}
	}
	if err := instance.ReceiveProposal(terms("100000000"), at(10)); err != nil {
		t.Fatalf("proposal: %v", err)
	}
	if err := instance.Counter(terms("90000000"), at(11)); err == nil {
		t.Fatal("the counteroffer budget was exceeded")
	}
	if instance.State() != StateWithdrawn {
		t.Fatalf("an exhausted negotiation stayed open: %q", instance.State())
	}
}

// An expired mandate or expired terms end the exchange rather than letting it
// finalise late.
func TestExpiryEndsTheExchange(t *testing.T) {
	instance := start(t, testBudget(t, "1000000000"))
	if err := instance.ReceiveProposal(terms("50000000"), at(1)); err != nil {
		t.Fatalf("proposal: %v", err)
	}
	if err := instance.AcceptIntent(at(2)); err != nil {
		t.Fatalf("accept: %v", err)
	}
	if err := instance.BeginCanonicalization(at(3)); err != nil {
		t.Fatalf("canonicalise: %v", err)
	}
	late := time.Unix(int64(testMandate().ExpiresAtUnix)+1, 0)
	if err := instance.Finalize(stubResolver{quote: finalizedQuote(terms("50000000")), found: true}, commitment, late); err == nil {
		t.Fatal("a commitment was accepted after the mandate expired")
	}
	if instance.State() != StateExpired || instance.ActiveAgreement() {
		t.Fatalf("an expired negotiation reported %q", instance.State())
	}

	// Agreed terms expire on their own too.
	second := start(t, testBudget(t, "1000000000"))
	if err := second.ReceiveProposal(terms("50000000"), at(1)); err != nil {
		t.Fatalf("proposal: %v", err)
	}
	if err := second.AcceptIntent(at(2)); err != nil {
		t.Fatalf("accept: %v", err)
	}
	ended, err := second.Expire(time.Unix(int64(baseUnix+3600), 0))
	if err != nil {
		t.Fatalf("expire: %v", err)
	}
	if !ended {
		t.Fatal("expired terms did not end the negotiation")
	}
	if second.State() != StateExpired {
		t.Fatalf("unexpected state: %q", second.State())
	}
}

// Several conversations, each inside its own ceiling, must not together agree
// to more than the owner has.
func TestConcurrentNegotiationsShareOneBudget(t *testing.T) {
	budget, err := OpenBudget(usdt("150000000"), &memoryLedger{})
	if err != nil {
		t.Fatalf("budget: %v", err)
	}
	first, err := New("neg-1", conversation, counterparty, testMandate(), budget, &memoryStore{}, at(0))
	if err != nil {
		t.Fatalf("new: %v", err)
	}
	second, err := New("neg-2", conversation, counterparty, testMandate(), budget, &memoryStore{}, at(0))
	if err != nil {
		t.Fatalf("new: %v", err)
	}

	for _, instance := range []*Negotiation{first, second} {
		if err := instance.ReceiveProposal(terms("100000000"), at(1)); err != nil {
			t.Fatalf("proposal: %v", err)
		}
	}
	if err := first.AcceptIntent(at(2)); err != nil {
		t.Fatalf("first accept: %v", err)
	}
	// Each is inside its own ceiling of 120; together they are not inside 150.
	if err := second.AcceptIntent(at(3)); err == nil {
		t.Fatal("two negotiations together agreed beyond the owner's budget")
	}
	if remaining := left(t, budget); remaining.Atomic != "50000000" {
		t.Fatalf("unexpected remaining budget: %v", remaining)
	}

	// A withdrawn negotiation gives its hold back.
	if err := first.Withdraw("changed our mind"); err != nil {
		t.Fatalf("withdraw: %v", err)
	}
	if remaining := left(t, budget); remaining.Atomic != "150000000" {
		t.Fatalf("a withdrawn negotiation kept the budget: %v", remaining)
	}
	if err := second.AcceptIntent(at(4)); err != nil {
		t.Fatalf("second accept after release: %v", err)
	}
}

func TestBudgetCommitsOnlyWhatWasHeld(t *testing.T) {
	budget, err := OpenBudget(usdt("150000000"), &memoryLedger{})
	if err != nil {
		t.Fatalf("budget: %v", err)
	}
	instance, err := New("neg-1", conversation, counterparty, testMandate(), budget, &memoryStore{}, at(0))
	if err != nil {
		t.Fatalf("new: %v", err)
	}
	if err := instance.ReceiveProposal(terms("90000000"), at(1)); err != nil {
		t.Fatalf("proposal: %v", err)
	}
	if err := instance.AcceptIntent(at(2)); err != nil {
		t.Fatalf("accept: %v", err)
	}
	if err := instance.BeginCanonicalization(at(3)); err != nil {
		t.Fatalf("canonicalise: %v", err)
	}
	if err := instance.Finalize(stubResolver{quote: finalizedQuote(terms("90000000")), found: true}, commitment, at(4)); err != nil {
		t.Fatalf("finalize: %v", err)
	}
	if spent := budget.Spent(); spent.Atomic != "90000000" {
		t.Fatalf("unexpected spend: %v", spent)
	}
	if remaining := left(t, budget); remaining.Atomic != "60000000" {
		t.Fatalf("unexpected remaining: %v", remaining)
	}
	if err := budget.Commit("neg-1"); err == nil {
		t.Fatal("a committed hold was committed twice")
	}
	if err := budget.Reserve("neg-2", usdt("70000000")); err == nil {
		t.Fatal("a reservation beyond what is left was accepted")
	}
	if err := budget.Reserve("neg-2", Money{Asset: Asset{Workchain: 0, AccountID: strings.Repeat("9", 64), MasterCodeHash: "tvm-cell-sha256:" + strings.Repeat("8", 64), WalletCodeHash: "tvm-cell-sha256:" + strings.Repeat("7", 64), Decimals: 6}, Atomic: "1"}); err == nil {
		t.Fatal("a reservation in another asset was drawn on this budget")
	}
}

// A commitment digest stands on its own: verifying settlement never needs the
// conversation that produced it.
func TestCommitmentDoesNotDependOnTheConversation(t *testing.T) {
	instance := start(t, testBudget(t, "1000000000"))
	if err := instance.ReceiveProposal(terms("50000000"), at(1)); err != nil {
		t.Fatalf("proposal: %v", err)
	}
	if err := instance.AcceptIntent(at(2)); err != nil {
		t.Fatalf("accept: %v", err)
	}
	if err := instance.BeginCanonicalization(at(3)); err != nil {
		t.Fatalf("canonicalise: %v", err)
	}
	if err := instance.Finalize(stubResolver{quote: finalizedQuote(terms("50000000")), found: true}, commitment, at(4)); err != nil {
		t.Fatalf("finalize: %v", err)
	}
	digest, committed := instance.Committed()
	if !committed {
		t.Fatal("no commitment")
	}
	// Discarding every local record leaves the digest meaning exactly what it
	// meant, which is what a third resolver checks.
	instance = nil
	if digest != commitment {
		t.Fatal("the commitment depended on the negotiation that produced it")
	}
}

func TestMandateMustBeUsable(t *testing.T) {
	cases := map[string]func(*Mandate){
		"no objective":       func(m *Mandate) { m.Objective = "" },
		"no authority":       func(m *Mandate) { m.Authority = "" },
		"conversation only":  func(m *Mandate) { m.Authority = AuthorityConverse },
		"bad class":          func(m *Mandate) { m.CapabilityClass = "Software.Audit" },
		"mixed assets":       func(m *Mandate) { m.ApprovalAbove = otherMoney("1") },
		"approval above cap": func(m *Mandate) { m.ApprovalAbove = usdt("130000000") },
		"no counteroffers":   func(m *Mandate) { m.MaxCounteroffers = 0 },
		"endless":            func(m *Mandate) { m.ExpiresAtUnix = 0 },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			mandate := testMandate()
			mutate(&mandate)
			if name == "conversation only" {
				// A converse-only mandate is valid; it simply permits nothing.
				if err := mandate.Validate(); err != nil {
					t.Fatalf("a conversation mandate was refused: %v", err)
				}
				if _, err := mandate.Permits(terms("1"), at(1)); err == nil {
					t.Fatal("a conversation mandate permitted terms")
				}
				return
			}
			if err := mandate.Validate(); err == nil {
				t.Fatalf("expected %q to be refused", name)
			}
		})
	}
}

func TestAmountsAreExactAndTyped(t *testing.T) {
	// The rendering shows the amount and enough of the asset to tell two
	// tokens apart. It is presentation, and nothing parses it back.
	if rendered := usdt("1500000").String(); !strings.HasPrefix(rendered, "1.5 (") {
		t.Fatalf("unexpected rendering: %s", rendered)
	}
	if _, err := usdt("1").AtMost(otherMoney("1")); err == nil {
		t.Fatal("amounts of different assets were compared")
	}
	// Same contract, different precision, is a different asset: a count of
	// atomic units means nothing without the scale it is counted in.
	shifted := testAsset()
	shifted.Decimals = 2
	if _, err := usdt("1").AtMost(Money{Asset: shifted, Atomic: "1"}); err == nil {
		t.Fatal("amounts at different precisions were compared")
	}

	// The count is arbitrary precision, so an amount no fixed-width integer
	// could hold is an ordinary amount here rather than an overflow.
	huge := strings.Repeat("9", 40)
	sum, err := (Money{Asset: testAsset(), Atomic: huge}).Add(usdt("1"))
	if err != nil {
		t.Fatalf("a large sum failed: %v", err)
	}
	if len(sum.Atomic) != 41 {
		t.Fatalf("a large sum was truncated: %s", sum.Atomic)
	}

	for name, invalid := range map[string]Money{
		"no asset":            {Atomic: "1"},
		"non-canonical count": {Asset: testAsset(), Atomic: "007"},
		"negative":            {Asset: testAsset(), Atomic: "-1"},
		"unbounded":           {Asset: testAsset(), Atomic: strings.Repeat("9", MaxAtomicDigits+1)},
		"empty count":         {Asset: testAsset()},
	} {
		if err := invalid.Validate(); err == nil {
			t.Fatalf("expected %q to be refused", name)
		}
	}
	for name, invalid := range map[string]Asset{
		"no account":     {MasterCodeHash: "tvm-cell-sha256:" + strings.Repeat("b", 64), WalletCodeHash: "tvm-cell-sha256:" + strings.Repeat("c", 64)},
		"no master code": {AccountID: strings.Repeat("a", 64), WalletCodeHash: "tvm-cell-sha256:" + strings.Repeat("c", 64)},
		"no wallet code": {AccountID: strings.Repeat("a", 64), MasterCodeHash: "tvm-cell-sha256:" + strings.Repeat("b", 64)},
		"too precise": {AccountID: strings.Repeat("a", 64),
			MasterCodeHash: "tvm-cell-sha256:" + strings.Repeat("b", 64),
			WalletCodeHash: "tvm-cell-sha256:" + strings.Repeat("c", 64), Decimals: MaxDecimals + 1},
	} {
		if err := invalid.Validate(); err == nil {
			t.Fatalf("expected asset %q to be refused", name)
		}
	}
}

// Two contracts may both call themselves USDT. What identifies an asset is the
// contract, not the label, and there is no label to confuse.
func TestAssetsAreIdentifiedByContract(t *testing.T) {
	first := testAsset()
	second := testAsset()
	second.AccountID = strings.Repeat("9", 64)
	if first.Same(second) {
		t.Fatal("two different master contracts were treated as one asset")
	}
	wallet := testAsset()
	wallet.WalletCodeHash = "tvm-cell-sha256:" + strings.Repeat("5", 64)
	if first.Same(wallet) {
		t.Fatal("two different wallet implementations were treated as one asset")
	}
	if _, err := first.Proto(); err != nil {
		t.Fatalf("an asset could not be expressed in protocol form: %v", err)
	}
}

func TestNegotiationRefusesUnusableInput(t *testing.T) {
	mandate := testMandate()
	if _, err := New("", conversation, counterparty, mandate, nil, &memoryStore{}, at(0)); err == nil {
		t.Fatal("a negotiation without an identifier was started")
	}
	if _, err := New("neg-1", "conv_bad", counterparty, mandate, nil, &memoryStore{}, at(0)); err == nil {
		t.Fatal("an invalid conversation was accepted")
	}
	if _, err := New("neg-1", conversation, "agent_bad", mandate, nil, &memoryStore{}, at(0)); err == nil {
		t.Fatal("an invalid counterparty was accepted")
	}
	expired := mandate
	expired.ExpiresAtUnix = baseUnix
	if _, err := New("neg-1", conversation, counterparty, expired, nil, &memoryStore{}, at(0)); err == nil {
		t.Fatal("a negotiation started under an expired mandate")
	}
}

// The exact case an owner would never expect: they approve one number, the
// counterparty sends another, and the Agent accepts again. The old approval
// must not carry.
func TestApprovalDoesNotSurviveAChangeOfTerms(t *testing.T) {
	instance := start(t, testBudget(t, "1000000000"))
	if err := instance.ReceiveProposal(terms("110000000"), at(1)); err != nil {
		t.Fatalf("proposal: %v", err)
	}
	if err := instance.AcceptIntent(at(2)); err != nil {
		t.Fatalf("accept: %v", err)
	}
	if !instance.NeedsOwnerApproval() {
		t.Fatal("terms above the approval point did not need the owner")
	}
	if err := instance.ApproveByOwner(approvedDigest(t, instance), at(3)); err != nil {
		t.Fatalf("approve: %v", err)
	}

	// Continuing to bargain from an agreed state is refused outright: terms
	// freeze when both parties say yes.
	if err := instance.ReceiveProposal(terms("119000000"), at(4)); err == nil {
		t.Fatal("an agreed negotiation silently returned to bargaining")
	}
	if err := instance.AcceptIntent(at(4)); err == nil {
		t.Fatal("an agreed negotiation was accepted a second time")
	}

	// Reopening is explicit, and it takes the approval and the hold with it.
	if err := instance.Reopen("the counterparty came back with a new price", at(4)); err != nil {
		t.Fatalf("reopen: %v", err)
	}
	if _, held := instance.Approval(); held {
		t.Fatal("the owner's approval survived a reopening")
	}
	if err := instance.ReceiveProposal(terms("119000000"), at(5)); err != nil {
		t.Fatalf("proposal: %v", err)
	}
	if err := instance.AcceptIntent(at(6)); err != nil {
		t.Fatalf("accept: %v", err)
	}
	if err := instance.BeginCanonicalization(at(7)); err == nil {
		t.Fatal("the higher price proceeded on the earlier approval")
	}
}

// An approval names the terms it was a decision about.
func TestApprovalMustNameWhatWasApproved(t *testing.T) {
	instance := start(t, testBudget(t, "1000000000"))
	if err := instance.ReceiveProposal(terms("110000000"), at(1)); err != nil {
		t.Fatalf("proposal: %v", err)
	}
	if err := instance.AcceptIntent(at(2)); err != nil {
		t.Fatalf("accept: %v", err)
	}
	other, err := terms("119000000").Digest()
	if err != nil {
		t.Fatalf("digest: %v", err)
	}
	if err := instance.ApproveByOwner(other, at(3)); err == nil {
		t.Fatal("an approval for other terms was accepted")
	}
	if err := instance.BeginCanonicalization(at(4)); err == nil {
		t.Fatal("a negotiation proceeded with no approval at all")
	}
}

// A commitment is not a string that looks like a digest.
func TestFinalizeNeedsAQuoteThatExists(t *testing.T) {
	prepare := func(t *testing.T) *Negotiation {
		t.Helper()
		instance := start(t, testBudget(t, "1000000000"))
		if err := instance.ReceiveProposal(terms("50000000"), at(1)); err != nil {
			t.Fatalf("proposal: %v", err)
		}
		if err := instance.AcceptIntent(at(2)); err != nil {
			t.Fatalf("accept: %v", err)
		}
		if err := instance.BeginCanonicalization(at(3)); err != nil {
			t.Fatalf("canonicalise: %v", err)
		}
		return instance
	}

	absent := prepare(t)
	if err := absent.Finalize(stubResolver{}, commitment, at(4)); err == nil {
		t.Fatal("a commitment nothing on chain backs was accepted")
	}
	if _, committed := absent.Committed(); committed {
		t.Fatal("an unbacked commitment was reported as committed")
	}

	if err := prepare(t).Finalize(nil, commitment, at(4)); err == nil {
		t.Fatal("a commitment was accepted with nothing to verify it against")
	}

	unfinalized := prepare(t)
	quote := finalizedQuote(terms("50000000"))
	quote.Reference.FinalizedCheckpoint = 0
	if err := unfinalized.Finalize(stubResolver{quote: quote, found: true}, commitment, at(4)); err == nil {
		t.Fatal("a quote that was never final was accepted")
	}

	mismatched := prepare(t)
	other := finalizedQuote(terms("50000000"))
	other.Commitment = "sha256:" + strings.Repeat("1", 64)
	if err := mismatched.Finalize(stubResolver{quote: other, found: true}, commitment, at(4)); err == nil {
		t.Fatal("a resolver returned another commitment and it was accepted")
	}

	good := prepare(t)
	if err := good.Finalize(stubResolver{quote: finalizedQuote(terms("50000000")), found: true},
		commitment, at(4)); err != nil {
		t.Fatalf("a verified quote was refused: %v", err)
	}
	if _, committed := good.Committed(); !committed {
		t.Fatal("a verified quote did not commit")
	}
	if _, held := good.Quote(); !held {
		t.Fatal("the finalized quote was not kept")
	}
}

// A mandate that may commit needs somewhere to commit against.
func TestCommitAuthorityNeedsABudget(t *testing.T) {
	if _, err := New("neg-1", conversation, counterparty, testMandate(), nil, &memoryStore{}, at(0)); err == nil {
		t.Fatal("a commit mandate was started with no budget")
	}
	converse := testMandate()
	converse.Authority = AuthorityConverse
	if _, err := New("neg-1", conversation, counterparty, converse, nil, &memoryStore{}, at(0)); err != nil {
		t.Fatalf("a conversation mandate needed a budget: %v", err)
	}
}

// Reservations that lived only in memory would return to zero on a restart,
// and several negotiations could commit against the same money again.
func TestBudgetSurvivesARestart(t *testing.T) {
	ledger := &memoryLedger{}
	budget, err := OpenBudget(usdt("150000000"), ledger)
	if err != nil {
		t.Fatalf("budget: %v", err)
	}
	if err := budget.Reserve("neg-1", usdt("100000000")); err != nil {
		t.Fatalf("reserve: %v", err)
	}

	// The process ends here. Everything below is what comes back.
	restored, err := OpenBudget(usdt("150000000"), ledger)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	if held, found := restored.Reserved("neg-1"); !found || held.Atomic != "100000000" {
		t.Fatalf("a reservation did not survive: %v %v", held, found)
	}
	if remaining := left(t, restored); remaining.Atomic != "50000000" {
		t.Fatalf("the budget forgot what was held: %v", remaining)
	}
	if err := restored.Reserve("neg-2", usdt("100000000")); err == nil {
		t.Fatal("a restart let the same money back a second commitment")
	}

	// A spend survives too.
	if err := restored.Commit("neg-1"); err != nil {
		t.Fatalf("commit: %v", err)
	}
	again, err := OpenBudget(usdt("150000000"), ledger)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	if spent := again.Spent(); spent.Atomic != "100000000" {
		t.Fatalf("a spend did not survive: %v", spent)
	}

	// Reopening with a different ceiling is refused rather than resolved.
	if _, err := OpenBudget(usdt("200000000"), ledger); err == nil {
		t.Fatal("a budget was reopened with a different total")
	}
	if _, err := OpenBudget(usdt("150000000"), nil); err == nil {
		t.Fatal("a budget was opened with nowhere to survive")
	}
}

// A negotiation that lived only in memory would lose its state when a process
// ended while its budget hold stayed on the books: the money would be spoken
// for by an exchange nobody could find, and the approval that took a person
// would have to be asked for again.
func TestNegotiationSurvivesARestart(t *testing.T) {
	ledger := &memoryLedger{}
	budget, err := OpenBudget(usdt("1000000000"), ledger)
	if err != nil {
		t.Fatalf("budget: %v", err)
	}
	store := &memoryStore{}
	instance, err := New("neg-1", conversation, counterparty, testMandate(), budget, store, at(0))
	if err != nil {
		t.Fatalf("new: %v", err)
	}
	if err := instance.ReceiveProposal(terms("110000000"), at(1)); err != nil {
		t.Fatalf("proposal: %v", err)
	}
	if err := instance.AcceptIntent(at(2)); err != nil {
		t.Fatalf("accept: %v", err)
	}
	if err := instance.ApproveByOwner(approvedDigest(t, instance), at(3)); err != nil {
		t.Fatalf("approve: %v", err)
	}

	// The process ends here.
	if !store.held {
		t.Fatal("nothing was written down")
	}
	restoredBudget, err := OpenBudget(usdt("1000000000"), ledger)
	if err != nil {
		t.Fatalf("reopen budget: %v", err)
	}
	restored, err := Restore(store.saved, testMandate(), restoredBudget, store)
	if err != nil {
		t.Fatalf("restore: %v", err)
	}
	if restored.State() != StateIntentAgreed {
		t.Fatalf("unexpected restored state: %q", restored.State())
	}
	agreed, ok := restored.Agreed()
	if !ok || agreed.Price.Atomic != "110000000" {
		t.Fatalf("the agreed terms did not survive: %+v", agreed)
	}
	// The owner's decision survived, and it still describes these terms.
	if _, held := restored.Approval(); !held {
		t.Fatal("the owner's approval did not survive")
	}
	if err := restored.BeginCanonicalization(at(4)); err != nil {
		t.Fatalf("the restored approval was not honoured: %v", err)
	}
	// And the hold it took is still on the books.
	if held, found := restoredBudget.Reserved("neg-1"); !found || held.Atomic != "110000000" {
		t.Fatalf("the budget hold did not survive: %v %v", held, found)
	}
}

// The mandate is referenced rather than copied, so an exchange does not resume
// under an authority that was withdrawn or replaced.
func TestRestoreRefusesAMandateThatMoved(t *testing.T) {
	store := &memoryStore{}
	instance, err := New("neg-1", conversation, counterparty, testMandate(),
		testBudget(t, "1000000000"), store, at(0))
	if err != nil {
		t.Fatalf("new: %v", err)
	}
	if err := instance.ReceiveProposal(terms("50000000"), at(1)); err != nil {
		t.Fatalf("proposal: %v", err)
	}

	raised := testMandate()
	raised.MaxTotal = usdt("900000000")
	if _, err := Restore(store.saved, raised, testBudget(t, "1000000000"), store); err == nil {
		t.Fatal("an exchange resumed under a mandate that had changed")
	}
	if _, err := Restore(store.saved, testMandate(), testBudget(t, "1000000000"), nil); err == nil {
		t.Fatal("a restored negotiation was given nowhere to survive")
	}
	if _, err := Restore(store.saved, testMandate(), nil, store); err == nil {
		t.Fatal("a commit mandate was restored with no budget")
	}
}

// A snapshot that does not describe a negotiation this build knows is refused
// rather than half-understood.
func TestSnapshotsAreStrict(t *testing.T) {
	store := &memoryStore{}
	if _, err := New("neg-1", conversation, counterparty, testMandate(),
		testBudget(t, "1000000000"), store, at(0)); err != nil {
		t.Fatalf("new: %v", err)
	}
	encoded, err := EncodeSnapshotJSON(store.saved)
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	if _, err := DecodeSnapshotJSON(encoded); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if _, err := DecodeSnapshotJSON(append(encoded, '{')); err == nil {
		t.Fatal("a snapshot with trailing JSON was accepted")
	}
	if _, err := DecodeSnapshotJSON([]byte(`{"schema":"other"}`)); err == nil {
		t.Fatal("a snapshot of another schema was accepted")
	}

	for name, mutate := range map[string]func(*Snapshot){
		"unknown state":  func(s *Snapshot) { s.State = "haggling" },
		"no negotiation": func(s *Snapshot) { s.ID = "" },
		"no mandate":     func(s *Snapshot) { s.MandateDigest = "" },
		"finalized with no commitment": func(s *Snapshot) {
			s.State = string(StateFinalized)
			s.Commitment = ""
		},
		"approval from the future": func(s *Snapshot) {
			s.Approval = &Approval{TermsDigest: "x", Generation: s.Generation + 1}
		},
	} {
		t.Run(name, func(t *testing.T) {
			snapshot := store.saved
			mutate(&snapshot)
			if err := snapshot.Validate(); err == nil {
				t.Fatalf("expected %q to be refused", name)
			}
		})
	}
}

// Every transition is durable, including the first inbound one. A proposal
// that survived only in memory would vanish on restart while the counterparty
// believes it is on the table.
func TestEveryTransitionIsWrittenDown(t *testing.T) {
	store := &memoryStore{}
	instance, err := New("neg-1", conversation, counterparty, testMandate(),
		testBudget(t, "1000000000"), store, at(0))
	if err != nil {
		t.Fatalf("new: %v", err)
	}
	if store.saved.State != string(StateDiscussing) {
		t.Fatalf("the opening state was not written: %+v", store.saved)
	}
	if err := instance.ReceiveProposal(terms("50000000"), at(1)); err != nil {
		t.Fatalf("proposal: %v", err)
	}
	if store.saved.State != string(StateProposalPending) || store.saved.OnTable == nil {
		t.Fatalf("a received proposal was not written: %+v", store.saved)
	}
	if err := instance.AcceptIntent(at(2)); err != nil {
		t.Fatalf("accept: %v", err)
	}
	if store.saved.State != string(StateIntentAgreed) || store.saved.Agreed == nil {
		t.Fatalf("the agreement was not written: %+v", store.saved)
	}
	if err := instance.Withdraw("done"); err != nil {
		t.Fatalf("withdraw: %v", err)
	}
	if store.saved.State != string(StateWithdrawn) {
		t.Fatalf("the ending was not written: %+v", store.saved)
	}
}

// A store that refuses the write refuses the transition: the caller must not
// end up holding a state the disk has never heard of.
func TestAFailedWriteIsAFailedTransition(t *testing.T) {
	store := &failingStore{}
	if _, err := New("neg-1", conversation, counterparty, testMandate(),
		testBudget(t, "1000000000"), store, at(0)); err == nil {
		t.Fatal("a negotiation started with nowhere to live")
	}
}

type failingStore struct{}

func (failingStore) Save(Snapshot) error { return errors.New("disk says no") }
