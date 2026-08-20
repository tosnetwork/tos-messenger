package firewall

import (
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/tosnetwork/tos-messenger/pkg/negotiation"
)

const baseUnix = uint64(1_800_000_000)

func testOrigin(seed string) Origin {
	return Origin{
		AgentID:        "agent_" + strings.Repeat(seed, 64),
		EndpointID:     "mep_" + strings.Repeat(seed, 64),
		DeviceID:       "dev_" + strings.Repeat(seed, 64),
		EventID:        "evt_" + strings.Repeat(seed, 64),
		ConversationID: "conv_" + strings.Repeat(seed, 64),
		Kind:           "text",
		ReceivedAtUnix: baseUnix,
	}
}

func testAction(effect Effect, origins ...Origin) Action {
	action := Action{Effect: effect, Summary: "do the thing", DerivedFrom: origins}
	if effect == EffectSpend {
		terms := testTerms(200)
		action.Terms = &terms
	}
	return action
}

func spendAction(units uint64, origins ...Origin) Action {
	terms := testTerms(units)
	return Action{Effect: EffectSpend, Summary: "buy the transcription",
		DerivedFrom: origins, Terms: &terms}
}

// The same action is judged differently depending on whether something a
// stranger sent contributed to it. That difference is the whole point.
func TestReceivedContentIsHeldToATighterCeiling(t *testing.T) {
	policy := Default()

	ownWork, err := Evaluate(policy, testAction(EffectToolCall))
	if err != nil {
		t.Fatalf("evaluate: %v", err)
	}
	if ownWork.Outcome != Allow {
		t.Fatalf("the Agent's own tool call was stopped: %+v", ownWork)
	}

	prompted, err := Evaluate(policy, testAction(EffectToolCall, testOrigin("1")))
	if err != nil {
		t.Fatalf("evaluate: %v", err)
	}
	if prompted.Outcome != RequireOwnerApproval {
		t.Fatalf("a tool call a stranger's message led to ran unattended: %+v", prompted)
	}
	if len(prompted.Provenance) != 1 {
		t.Fatalf("the owner would not be told what caused it: %+v", prompted)
	}
}

// Replying is what a messenger is. An Agent that needed a person for every
// answer would not be an Agent.
func TestRepliesRunUnattended(t *testing.T) {
	decision, err := Evaluate(Default(), testAction(EffectMessage, testOrigin("2")))
	if err != nil {
		t.Fatalf("evaluate: %v", err)
	}
	if decision.Outcome != Allow {
		t.Fatalf("answering a message required a person: %+v", decision)
	}
}

// A key authorises whatever it signs, and a configuration change can remove
// this check. No policy may permit either unattended.
func TestNoPolicyCanReachAKeyOrTheConfiguration(t *testing.T) {
	for _, ceiling := range []Effect{EffectKeyUse, EffectConfiguration} {
		policy := Policy{UnattendedCeiling: ceiling, OwnInitiativeCeiling: EffectConfiguration}
		if err := policy.Validate(); err == nil {
			t.Fatalf("a policy raised the unattended ceiling to %q", ceiling)
		}
	}
	if err := (Policy{UnattendedCeiling: EffectMessage, OwnInitiativeCeiling: EffectConfiguration}).Validate(); err == nil {
		t.Fatal("a policy let the runtime reconfigure the installation")
	}
	// Even own-initiative configuration goes to the owner.
	decision, err := Evaluate(Default(), testAction(EffectConfiguration))
	if err != nil {
		t.Fatalf("evaluate: %v", err)
	}
	if decision.Outcome != RequireOwnerApproval {
		t.Fatalf("the runtime reconfigured the installation: %+v", decision)
	}
}

// Received content cannot be trusted further than the Agent's own initiative.
func TestUnattendedCeilingCannotExceedOwnInitiative(t *testing.T) {
	policy := Policy{UnattendedCeiling: EffectToolCall, OwnInitiativeCeiling: EffectMessage}
	if err := policy.Validate(); err == nil {
		t.Fatal("received content was trusted further than the Agent itself")
	}
}

func TestMalformedActionsAreRefused(t *testing.T) {
	duplicate := testOrigin("3")
	cases := map[string]Action{
		"unknown effect":   {Effect: "delete-everything", Summary: "x"},
		"no summary":       {Effect: EffectMessage},
		"summary too long": {Effect: EffectMessage, Summary: strings.Repeat("x", MaxSummaryBytes+1)},
		"broken origin":    {Effect: EffectMessage, Summary: "x", DerivedFrom: []Origin{{}}},
		"same event twice": {Effect: EffectMessage, Summary: "x", DerivedFrom: []Origin{duplicate, duplicate}},
		"too much lineage": {Effect: EffectMessage, Summary: "x", DerivedFrom: tooManyOrigins()},
	}
	for name, action := range cases {
		t.Run(name, func(t *testing.T) {
			decision, err := Evaluate(Default(), action)
			if err != nil {
				t.Fatalf("evaluate: %v", err)
			}
			if decision.Outcome != Refuse {
				t.Fatalf("expected %q to be refused, got %+v", name, decision)
			}
		})
	}
}

func tooManyOrigins() []Origin {
	origins := make([]Origin, 0, MaxProvenance+1)
	for index := 0; index <= MaxProvenance; index++ {
		origin := testOrigin("1")
		origin.EventID = "evt_" + strings.Repeat("0", 62) + string([]byte{
			"0123456789abcdef"[index>>4], "0123456789abcdef"[index&0xf],
		})
		origins = append(origins, origin)
	}
	return origins
}

// Two renderings of one approval prompt must read the same way, or an owner
// comparing them would see a difference that is not there.
func TestProvenanceIsOrderedStably(t *testing.T) {
	first, second := testOrigin("1"), testOrigin("2")
	forward, err := Evaluate(Default(), testAction(EffectToolCall, first, second))
	if err != nil {
		t.Fatalf("evaluate: %v", err)
	}
	backward, err := Evaluate(Default(), testAction(EffectToolCall, second, first))
	if err != nil {
		t.Fatalf("evaluate: %v", err)
	}
	for index := range forward.Provenance {
		if forward.Provenance[index].EventID != backward.Provenance[index].EventID {
			t.Fatal("the approval prompt depended on the order the runtime listed its sources")
		}
	}
}

func testMandate() negotiation.Mandate {
	return negotiation.Mandate{
		Objective:        "buy transcription",
		Authority:        negotiation.AuthorityCommit,
		CapabilityClass:  "transcription.audio",
		MaxTotal:         negotiation.Money{Asset: testAsset(), Atomic: "1000"},
		ApprovalAbove:    negotiation.Money{Asset: testAsset(), Atomic: "500"},
		MaxCounteroffers: 4,
		ExpiresAtUnix:    baseUnix + 3600,
	}
}

func testTerms(units uint64) negotiation.Terms {
	return negotiation.Terms{
		CapabilityID:           "cap_" + strings.Repeat("2", 64),
		CapabilityVersion:      "1.0.0",
		CapabilityClass:        "transcription.audio",
		ProviderAgentID:        "agent_" + strings.Repeat("3", 64),
		ManifestDigest:         "sha256:" + strings.Repeat("4", 64),
		TransportBindingDigest: "sha256:" + strings.Repeat("5", 64),
		Price:                  negotiation.Money{Asset: testAsset(), Atomic: strconv.FormatUint(units, 10)},
		EscrowTermsDigest:      "sha256:" + strings.Repeat("6", 64),
		DisputePolicyDigest:    "sha256:" + strings.Repeat("7", 64),
		NotAfterUnix:           baseUnix + 600,
	}
}

// testAsset identifies an asset the way the chain does: by contract, not by
// ticker.
func testAsset() negotiation.Asset {
	return negotiation.Asset{
		Network: negotiation.Network{
			ID:              "tos-local",
			GenesisRootHash: strings.Repeat("1", 64),
			GenesisFileHash: strings.Repeat("2", 64),
		},
		Workchain:      0,
		AccountID:      strings.Repeat("a", 64),
		MasterCodeHash: "tvm-cell-sha256:" + strings.Repeat("b", 64),
		WalletCodeHash: "tvm-cell-sha256:" + strings.Repeat("c", 64),
		Decimals:       6,
	}
}

// A spend commits value, so a mandate that may only propose cannot
// pre-authorise one, even for terms that fit its class, asset, and ceiling. The
// owner may still say yes; what a proposal authority cannot do is have said yes
// in advance.
func TestProposalAuthorityCannotPreAuthoriseASpend(t *testing.T) {
	now := time.Unix(int64(baseUnix)+60, 0)
	permissive := Policy{UnattendedCeiling: EffectSpend, OwnInitiativeCeiling: EffectSpend}

	proposal := testMandate()
	proposal.Authority = negotiation.AuthorityPropose
	decision, err := EvaluateSpend(permissive, proposal, spendAction(200, testOrigin("1")), now)
	if err != nil {
		t.Fatalf("evaluate: %v", err)
	}
	if decision.Outcome != RequireOwnerApproval {
		t.Fatalf("a proposal authority pre-authorised a spend: %+v", decision)
	}

	// The same terms under a committing mandate are allowed, so the refusal is
	// the authority and not the terms.
	allowed, err := EvaluateSpend(permissive, testMandate(), spendAction(200, testOrigin("1")), now)
	if err != nil {
		t.Fatalf("evaluate: %v", err)
	}
	if allowed.Outcome != Allow {
		t.Fatalf("a committing authority was refused the same terms: %+v", allowed)
	}
}

// The mandate and the ceiling are independent, and neither substitutes for the
// other. A spend the owner authorised in advance is still stopped when a
// stranger's message drove it, and a spend inside the ceiling is still stopped
// when it is outside the mandate.
func TestSpendNeedsBothTheMandateAndTheCeiling(t *testing.T) {
	now := time.Unix(int64(baseUnix)+60, 0)
	permissive := Policy{UnattendedCeiling: EffectSpend, OwnInitiativeCeiling: EffectSpend}

	within, err := EvaluateSpend(permissive, testMandate(), spendAction(200, testOrigin("1")), now)
	if err != nil {
		t.Fatalf("evaluate: %v", err)
	}
	if within.Outcome != Allow {
		t.Fatalf("a spend inside both bounds was stopped: %+v", within)
	}

	// Inside the ceiling, above the amount the owner reserved for themselves.
	above, err := EvaluateSpend(permissive, testMandate(), spendAction(800, testOrigin("1")), now)
	if err != nil {
		t.Fatalf("evaluate: %v", err)
	}
	if above.Outcome != RequireOwnerApproval {
		t.Fatalf("a spend above the approval threshold ran unattended: %+v", above)
	}

	// Inside the mandate, but the default ceiling does not let received
	// content reach a spend at all.
	ceilinged, err := EvaluateSpend(Default(), testMandate(), spendAction(200, testOrigin("1")), now)
	if err != nil {
		t.Fatalf("evaluate: %v", err)
	}
	if ceilinged.Outcome != RequireOwnerApproval {
		t.Fatalf("the mandate alone authorised a spend a stranger's message drove: %+v", ceilinged)
	}

	// Outside the mandate entirely.
	outside, err := EvaluateSpend(permissive, testMandate(), spendAction(5000, testOrigin("1")), now)
	if err != nil {
		t.Fatalf("evaluate: %v", err)
	}
	if outside.Outcome != RequireOwnerApproval {
		t.Fatalf("a spend above the ceiling the owner set was allowed: %+v", outside)
	}

	// Terms that do not describe a purchase are refused, not escalated: no
	// owner decision makes them coherent.
	brokenTerms := negotiation.Terms{}
	broken, err := EvaluateSpend(permissive, testMandate(), Action{
		Effect: EffectSpend, Summary: "buy nothing in particular",
		DerivedFrom: []Origin{testOrigin("1")}, Terms: &brokenTerms,
	}, now)
	if err != nil {
		t.Fatalf("evaluate: %v", err)
	}
	if broken.Outcome != Refuse {
		t.Fatalf("incoherent terms were put to the owner: %+v", broken)
	}

	if _, err := EvaluateSpend(permissive, testMandate(), testAction(EffectMessage), now); err == nil {
		t.Fatal("a non-spend was judged as a spend")
	}
}

// An expired mandate is not a smaller mandate. The owner may still say yes;
// what they cannot do is have said yes in advance.
func TestExpiredMandateGoesToTheOwner(t *testing.T) {
	late := time.Unix(int64(baseUnix)+7200, 0)
	decision, err := EvaluateSpend(
		Policy{UnattendedCeiling: EffectSpend, OwnInitiativeCeiling: EffectSpend},
		testMandate(), spendAction(100), late)
	if err != nil {
		t.Fatalf("evaluate: %v", err)
	}
	if decision.Outcome != RequireOwnerApproval {
		t.Fatalf("an expired mandate still authorised a spend: %+v", decision)
	}
}

// Where the number and the words disagree, both are returned and neither is
// chosen. Picking the text would make prose authoritative through a side door.
func TestAmountRenderingDisagreementIsSurfacedNotResolved(t *testing.T) {
	amount := negotiation.Money{Asset: testAsset(), Atomic: "250"}
	agreeing, err := CheckAmountRendering(amount, "the price is "+amount.String()+" total")
	if err != nil {
		t.Fatalf("check: %v", err)
	}
	if !agreeing.Agrees {
		t.Fatalf("a rendering containing the exact amount was reported as disagreeing: %+v", agreeing)
	}

	lying, err := CheckAmountRendering(amount, "the price is 0.01 TOS, a bargain")
	if err != nil {
		t.Fatalf("check: %v", err)
	}
	if lying.Agrees {
		t.Fatal("a rendering that showed another number was accepted")
	}
	if lying.Structured != amount.String() || lying.Rendered == "" {
		t.Fatalf("the disagreement did not carry both sides: %+v", lying)
	}
}

// An approval names a price as well as a deed. Two spends described the same
// way but for different amounts are different actions.
func TestApprovalCannotMoveBetweenPrices(t *testing.T) {
	cheap, err := ActionID(spendAction(100, testOrigin("1")))
	if err != nil {
		t.Fatalf("identify: %v", err)
	}
	dear, err := ActionID(spendAction(9000, testOrigin("1")))
	if err != nil {
		t.Fatalf("identify: %v", err)
	}
	if cheap == dear {
		t.Fatal("two prices shared one action identifier")
	}

	// A spend must say what it is buying, and nothing else may carry terms.
	if err := (Action{Effect: EffectSpend, Summary: "buy something"}).Validate(); err == nil {
		t.Fatal("a spend with no terms was accepted")
	}
	terms := testTerms(100)
	if err := (Action{Effect: EffectMessage, Summary: "say hello", Terms: &terms}).Validate(); err == nil {
		t.Fatal("a message carried purchase terms")
	}
}
