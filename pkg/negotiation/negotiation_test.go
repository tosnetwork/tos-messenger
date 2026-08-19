package negotiation

import (
	"errors"
	"strings"
	"testing"
	"time"
)

const (
	baseUnix     = uint64(1_800_000_000)
	conversation = "conv_" + "1111111111111111111111111111111111111111111111111111111111111111"
	counterparty = "agent_" + "5555555555555555555555555555555555555555555555555555555555555555"
	capabilityID = "cap_" + "9999999999999999999999999999999999999999999999999999999999999999"
	commitment   = "sha256:" + "abababababababababababababababababababababababababababababababab"
)

func usdt(units uint64) Amount {
	return Amount{Asset: "USDT", Units: units, Decimals: 6}
}

func testMandate() Mandate {
	return Mandate{
		Objective:        "audit one smart contract",
		Authority:        AuthorityCommit,
		CapabilityClass:  "software.audit",
		MaxTotal:         usdt(120_000_000),
		ApprovalAbove:    usdt(100_000_000),
		MaxCounteroffers: 3,
		ExpiresAtUnix:    baseUnix + 86_400,
	}
}

func terms(units uint64) Terms {
	return Terms{
		CapabilityID:      capabilityID,
		CapabilityVersion: "1.4.0",
		CapabilityClass:   "software.audit",
		Total:             usdt(units),
		NotAfterUnix:      baseUnix + 3600,
	}
}

func at(offset uint64) time.Time { return time.Unix(int64(baseUnix+offset), 0) }

func start(t *testing.T, budget *Budget) *Negotiation {
	t.Helper()
	instance, err := New("neg-1", conversation, counterparty, testMandate(), budget, at(0))
	if err != nil {
		t.Fatalf("new: %v", err)
	}
	return instance
}

// The exchange the design describes: an offer, a counter, agreement in
// conversation, and only then a commitment.
func TestNegotiationReachesACommitment(t *testing.T) {
	instance := start(t, nil)
	if err := instance.ReceiveProposal(terms(126_000_000), at(1)); err != nil {
		t.Fatalf("proposal: %v", err)
	}
	if err := instance.Counter(terms(118_000_000), at(2)); err != nil {
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
	if err := instance.ApproveByOwner(at(4)); err != nil {
		t.Fatalf("approve: %v", err)
	}
	if err := instance.BeginCanonicalization(at(4)); err != nil {
		t.Fatalf("canonicalise: %v", err)
	}
	if err := instance.Finalize(terms(118_000_000), commitment, at(5)); err != nil {
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
	instance := start(t, nil)
	if err := instance.ReceiveProposal(terms(50_000_000), at(1)); err != nil {
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
	instance := start(t, nil)
	if err := instance.ReceiveProposal(terms(126_000_000), at(1)); err != nil {
		t.Fatalf("an offer above the ceiling could not even be recorded: %v", err)
	}
	if err := instance.Counter(terms(126_000_000), at(2)); err == nil {
		t.Fatal("an Agent countered with terms beyond its own mandate")
	}
	if err := instance.AcceptIntent(at(3)); err == nil {
		t.Fatal("an Agent accepted terms beyond its own mandate")
	}
	// And the mandate is unchanged by any of it.
	if instance.Mandate.MaxTotal.Units != 120_000_000 {
		t.Fatalf("the ceiling moved: %v", instance.Mandate.MaxTotal)
	}
}

// The compiler refuses to fill in what the text did not say, including taking
// the asset from the budget.
func TestNothingIsInferredFromContext(t *testing.T) {
	mandate := testMandate()
	complete := Candidate{
		CapabilityID: capabilityID, CapabilityVersion: "1.4.0", CapabilityClass: "software.audit",
		Asset: "USDT", Units: 10_000_000, Decimals: 6, NotAfterUnix: baseUnix + 3600,
	}
	if _, _, err := Compile(complete, mandate, at(1)); err != nil {
		t.Fatalf("a complete candidate was refused: %v", err)
	}
	for name, mutate := range map[string]func(*Candidate){
		"no asset":      func(c *Candidate) { c.Asset = "" },
		"no amount":     func(c *Candidate) { c.Units = 0 },
		"no capability": func(c *Candidate) { c.CapabilityID = "" },
		"no version":    func(c *Candidate) { c.CapabilityVersion = "" },
		"no class":      func(c *Candidate) { c.CapabilityClass = "" },
		"no expiry":     func(c *Candidate) { c.NotAfterUnix = 0 },
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
	rendered := usdt(120_000_000)
	candidate := Candidate{
		CapabilityID: capabilityID, CapabilityVersion: "1.4.0", CapabilityClass: "software.audit",
		Asset: "USDT", Units: 12_000_000, Decimals: 6, NotAfterUnix: baseUnix + 3600,
		RenderedTotal: &rendered,
	}
	if _, _, err := Compile(candidate, mandate, at(1)); !errors.Is(err, ErrRenderingConflict) {
		t.Fatalf("expected a rendering conflict, got %v", err)
	}
	// The same number in another asset is also a conflict, not a conversion.
	otherAsset := Amount{Asset: "TOS", Units: 12_000_000, Decimals: 6}
	candidate.RenderedTotal = &otherAsset
	if _, _, err := Compile(candidate, mandate, at(1)); !errors.Is(err, ErrRenderingConflict) {
		t.Fatalf("expected an asset conflict, got %v", err)
	}
	agreeing := usdt(12_000_000)
	candidate.RenderedTotal = &agreeing
	if _, _, err := Compile(candidate, mandate, at(1)); err != nil {
		t.Fatalf("agreeing representations were refused: %v", err)
	}
}

// A commitment that does not reproduce the agreed terms ends the negotiation
// rather than finalising on whichever version arrived last.
func TestCanonicalTermsMustMatchWhatWasAgreed(t *testing.T) {
	cases := map[string]Terms{
		"another amount":  terms(120_000_000),
		"another version": {CapabilityID: capabilityID, CapabilityVersion: "2.0.0", CapabilityClass: "software.audit", Total: usdt(50_000_000), NotAfterUnix: baseUnix + 3600},
		"another expiry":  {CapabilityID: capabilityID, CapabilityVersion: "1.4.0", CapabilityClass: "software.audit", Total: usdt(50_000_000), NotAfterUnix: baseUnix + 7200},
		"another capability": {CapabilityID: "cap_" + strings.Repeat("1", 64), CapabilityVersion: "1.4.0",
			CapabilityClass: "software.audit", Total: usdt(50_000_000), NotAfterUnix: baseUnix + 3600},
	}
	for name, canonical := range cases {
		t.Run(name, func(t *testing.T) {
			instance := start(t, nil)
			if err := instance.ReceiveProposal(terms(50_000_000), at(1)); err != nil {
				t.Fatalf("proposal: %v", err)
			}
			if err := instance.AcceptIntent(at(2)); err != nil {
				t.Fatalf("accept: %v", err)
			}
			if err := instance.BeginCanonicalization(at(3)); err != nil {
				t.Fatalf("canonicalise: %v", err)
			}
			if err := instance.Finalize(canonical, commitment, at(4)); err == nil {
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

// One commitment per negotiation. A repeated event does not produce a second.
func TestFinalizingTwiceIsRefused(t *testing.T) {
	instance := start(t, nil)
	if err := instance.ReceiveProposal(terms(50_000_000), at(1)); err != nil {
		t.Fatalf("proposal: %v", err)
	}
	if err := instance.AcceptIntent(at(2)); err != nil {
		t.Fatalf("accept: %v", err)
	}
	if err := instance.BeginCanonicalization(at(3)); err != nil {
		t.Fatalf("canonicalise: %v", err)
	}
	if err := instance.Finalize(terms(50_000_000), commitment, at(4)); err != nil {
		t.Fatalf("finalize: %v", err)
	}
	if err := instance.Finalize(terms(50_000_000), commitment, at(5)); err == nil {
		t.Fatal("a second commitment was accepted")
	}
}

// Terms above the owner's approval point wait for the owner, and the owner's
// decision is not something the counterparty can supply.
func TestApprovalPointRequiresTheOwner(t *testing.T) {
	instance := start(t, nil)
	if err := instance.ReceiveProposal(terms(110_000_000), at(1)); err != nil {
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
	if err := instance.ApproveByOwner(at(4)); err != nil {
		t.Fatalf("approve: %v", err)
	}
	if err := instance.BeginCanonicalization(at(5)); err != nil {
		t.Fatalf("canonicalise after approval: %v", err)
	}

	// Below the point the owner is not asked, and approving is meaningless.
	small := start(t, nil)
	if err := small.ReceiveProposal(terms(10_000_000), at(1)); err != nil {
		t.Fatalf("proposal: %v", err)
	}
	if err := small.AcceptIntent(at(2)); err != nil {
		t.Fatalf("accept: %v", err)
	}
	if small.NeedsOwnerApproval() {
		t.Fatal("terms inside the mandate asked for the owner anyway")
	}
	if err := small.ApproveByOwner(at(3)); err == nil {
		t.Fatal("an unnecessary approval was recorded")
	}
}

func TestOwnerCanRefuse(t *testing.T) {
	instance := start(t, nil)
	if err := instance.ReceiveProposal(terms(110_000_000), at(1)); err != nil {
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
	instance := start(t, nil)
	for round := uint64(0); round < 3; round++ {
		if err := instance.ReceiveProposal(terms(100_000_000), at(round*2+1)); err != nil {
			t.Fatalf("proposal: %v", err)
		}
		if err := instance.Counter(terms(90_000_000), at(round*2+2)); err != nil {
			t.Fatalf("counter %d: %v", round, err)
		}
	}
	if err := instance.ReceiveProposal(terms(100_000_000), at(10)); err != nil {
		t.Fatalf("proposal: %v", err)
	}
	if err := instance.Counter(terms(90_000_000), at(11)); err == nil {
		t.Fatal("the counteroffer budget was exceeded")
	}
	if instance.State() != StateWithdrawn {
		t.Fatalf("an exhausted negotiation stayed open: %q", instance.State())
	}
}

// An expired mandate or expired terms end the exchange rather than letting it
// finalise late.
func TestExpiryEndsTheExchange(t *testing.T) {
	instance := start(t, nil)
	if err := instance.ReceiveProposal(terms(50_000_000), at(1)); err != nil {
		t.Fatalf("proposal: %v", err)
	}
	if err := instance.AcceptIntent(at(2)); err != nil {
		t.Fatalf("accept: %v", err)
	}
	if err := instance.BeginCanonicalization(at(3)); err != nil {
		t.Fatalf("canonicalise: %v", err)
	}
	late := time.Unix(int64(testMandate().ExpiresAtUnix)+1, 0)
	if err := instance.Finalize(terms(50_000_000), commitment, late); err == nil {
		t.Fatal("a commitment was accepted after the mandate expired")
	}
	if instance.State() != StateExpired || instance.ActiveAgreement() {
		t.Fatalf("an expired negotiation reported %q", instance.State())
	}

	// Agreed terms expire on their own too.
	second := start(t, nil)
	if err := second.ReceiveProposal(terms(50_000_000), at(1)); err != nil {
		t.Fatalf("proposal: %v", err)
	}
	if err := second.AcceptIntent(at(2)); err != nil {
		t.Fatalf("accept: %v", err)
	}
	if !second.Expire(time.Unix(int64(baseUnix+3600), 0)) {
		t.Fatal("expired terms did not end the negotiation")
	}
	if second.State() != StateExpired {
		t.Fatalf("unexpected state: %q", second.State())
	}
}

// Several conversations, each inside its own ceiling, must not together agree
// to more than the owner has.
func TestConcurrentNegotiationsShareOneBudget(t *testing.T) {
	budget, err := NewBudget(usdt(150_000_000))
	if err != nil {
		t.Fatalf("budget: %v", err)
	}
	first, err := New("neg-1", conversation, counterparty, testMandate(), budget, at(0))
	if err != nil {
		t.Fatalf("new: %v", err)
	}
	second, err := New("neg-2", conversation, counterparty, testMandate(), budget, at(0))
	if err != nil {
		t.Fatalf("new: %v", err)
	}

	for _, instance := range []*Negotiation{first, second} {
		if err := instance.ReceiveProposal(terms(100_000_000), at(1)); err != nil {
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
	if remaining := budget.Remaining(); remaining.Units != 50_000_000 {
		t.Fatalf("unexpected remaining budget: %v", remaining)
	}

	// A withdrawn negotiation gives its hold back.
	if err := first.Withdraw("changed our mind"); err != nil {
		t.Fatalf("withdraw: %v", err)
	}
	if remaining := budget.Remaining(); remaining.Units != 150_000_000 {
		t.Fatalf("a withdrawn negotiation kept the budget: %v", remaining)
	}
	if err := second.AcceptIntent(at(4)); err != nil {
		t.Fatalf("second accept after release: %v", err)
	}
}

func TestBudgetCommitsOnlyWhatWasHeld(t *testing.T) {
	budget, err := NewBudget(usdt(150_000_000))
	if err != nil {
		t.Fatalf("budget: %v", err)
	}
	instance, err := New("neg-1", conversation, counterparty, testMandate(), budget, at(0))
	if err != nil {
		t.Fatalf("new: %v", err)
	}
	if err := instance.ReceiveProposal(terms(90_000_000), at(1)); err != nil {
		t.Fatalf("proposal: %v", err)
	}
	if err := instance.AcceptIntent(at(2)); err != nil {
		t.Fatalf("accept: %v", err)
	}
	if err := instance.BeginCanonicalization(at(3)); err != nil {
		t.Fatalf("canonicalise: %v", err)
	}
	if err := instance.Finalize(terms(90_000_000), commitment, at(4)); err != nil {
		t.Fatalf("finalize: %v", err)
	}
	if spent := budget.Spent(); spent.Units != 90_000_000 {
		t.Fatalf("unexpected spend: %v", spent)
	}
	if remaining := budget.Remaining(); remaining.Units != 60_000_000 {
		t.Fatalf("unexpected remaining: %v", remaining)
	}
	if err := budget.Commit("neg-1"); err == nil {
		t.Fatal("a committed hold was committed twice")
	}
	if err := budget.Reserve("neg-2", usdt(70_000_000)); err == nil {
		t.Fatal("a reservation beyond what is left was accepted")
	}
	if err := budget.Reserve("neg-2", Amount{Asset: "TOS", Units: 1, Decimals: 6}); err == nil {
		t.Fatal("a reservation in another asset was drawn on this budget")
	}
}

// A commitment digest stands on its own: verifying settlement never needs the
// conversation that produced it.
func TestCommitmentDoesNotDependOnTheConversation(t *testing.T) {
	instance := start(t, nil)
	if err := instance.ReceiveProposal(terms(50_000_000), at(1)); err != nil {
		t.Fatalf("proposal: %v", err)
	}
	if err := instance.AcceptIntent(at(2)); err != nil {
		t.Fatalf("accept: %v", err)
	}
	if err := instance.BeginCanonicalization(at(3)); err != nil {
		t.Fatalf("canonicalise: %v", err)
	}
	if err := instance.Finalize(terms(50_000_000), commitment, at(4)); err != nil {
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
		"mixed assets":       func(m *Mandate) { m.ApprovalAbove = Amount{Asset: "TOS", Units: 1, Decimals: 6} },
		"approval above cap": func(m *Mandate) { m.ApprovalAbove = usdt(130_000_000) },
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
				if _, err := mandate.Permits(terms(1), at(1)); err == nil {
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
	if usdt(1_500_000).String() != "1.5 USDT" {
		t.Fatalf("unexpected rendering: %s", usdt(1_500_000).String())
	}
	if _, err := usdt(1).AtMost(Amount{Asset: "TOS", Units: 1, Decimals: 6}); err == nil {
		t.Fatal("amounts in different assets were compared")
	}
	if _, err := usdt(1).AtMost(Amount{Asset: "USDT", Units: 1, Decimals: 2}); err == nil {
		t.Fatal("amounts at different precisions were compared")
	}
	if _, err := (Amount{Asset: "USDT", Units: ^uint64(0), Decimals: 6}).Add(usdt(1)); err == nil {
		t.Fatal("an overflowing sum wrapped instead of failing")
	}
	for _, invalid := range []Amount{
		{Asset: "", Units: 1}, {Asset: "usdt", Units: 1}, {Asset: "USDT", Units: 1, Decimals: MaxDecimals + 1},
	} {
		if err := invalid.Validate(); err == nil {
			t.Fatalf("expected %+v to be refused", invalid)
		}
	}
}

func TestNegotiationRefusesUnusableInput(t *testing.T) {
	mandate := testMandate()
	if _, err := New("", conversation, counterparty, mandate, nil, at(0)); err == nil {
		t.Fatal("a negotiation without an identifier was started")
	}
	if _, err := New("neg-1", "conv_bad", counterparty, mandate, nil, at(0)); err == nil {
		t.Fatal("an invalid conversation was accepted")
	}
	if _, err := New("neg-1", conversation, "agent_bad", mandate, nil, at(0)); err == nil {
		t.Fatal("an invalid counterparty was accepted")
	}
	expired := mandate
	expired.ExpiresAtUnix = baseUnix
	if _, err := New("neg-1", conversation, counterparty, expired, nil, at(0)); err == nil {
		t.Fatal("a negotiation started under an expired mandate")
	}
}
