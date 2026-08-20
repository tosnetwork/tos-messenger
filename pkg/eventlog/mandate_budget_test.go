package eventlog

import (
	"strings"
	"testing"

	"github.com/tosnetwork/tos-messenger/pkg/negotiation"
)

func mandateBudgetAsset() negotiation.Asset {
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

// A per-mandate budget is keyed by the mandate, so two mandates over the same
// asset never draw on one total: a hold placed under one leaves the other's
// ceiling untouched.
func TestMandateBudgetsDoNotShareOneTotal(t *testing.T) {
	journal := approvalJournal(t)
	asset := mandateBudgetAsset()
	money := func(atomic string) negotiation.Money {
		return negotiation.Money{Asset: asset, Atomic: atomic}
	}
	first := "mdt_" + strings.Repeat("1", 64)
	second := "mdt_" + strings.Repeat("2", 64)

	firstID, err := MandateBudgetID(first, asset)
	if err != nil {
		t.Fatalf("first id: %v", err)
	}
	secondID, err := MandateBudgetID(second, asset)
	if err != nil {
		t.Fatalf("second id: %v", err)
	}
	if firstID == secondID {
		t.Fatal("two mandates derived the same budget over one asset")
	}

	openBudget := func(mandateID string) *negotiation.Budget {
		ledger, err := journal.OpenMandateBudgetLedger(mandateID, asset)
		if err != nil {
			t.Fatalf("ledger: %v", err)
		}
		budget, err := negotiation.OpenBudget(money("100"), ledger)
		if err != nil {
			t.Fatalf("budget: %v", err)
		}
		return budget
	}

	// The first mandate reserves almost all of its own ceiling.
	if err := openBudget(first).Reserve("eex_"+strings.Repeat("d", 64), money("90")); err != nil {
		t.Fatalf("first reserve: %v", err)
	}
	// The second mandate's budget is untouched: its full ceiling is still free,
	// which it would not be if the two shared one total.
	secondBudget := openBudget(second)
	remaining, err := secondBudget.Remaining()
	if err != nil {
		t.Fatalf("remaining: %v", err)
	}
	if remaining.Atomic != "100" {
		t.Fatalf("the second mandate's budget was drawn down by the first: %s", remaining.Atomic)
	}
	if err := secondBudget.Reserve("eex_"+strings.Repeat("e", 64), money("90")); err != nil {
		t.Fatalf("the second mandate could not spend its own budget: %v", err)
	}
}

// A per-mandate budget enforces its MaxTotal across distinct executions: holds
// accumulate, and the one that would push the sum past the total is refused.
func TestMandateBudgetEnforcesMaxTotal(t *testing.T) {
	journal := approvalJournal(t)
	asset := mandateBudgetAsset()
	money := func(atomic string) negotiation.Money {
		return negotiation.Money{Asset: asset, Atomic: atomic}
	}
	mandateID := "mdt_" + strings.Repeat("7", 64)

	open := func() *negotiation.Budget {
		ledger, err := journal.OpenMandateBudgetLedger(mandateID, asset)
		if err != nil {
			t.Fatalf("ledger: %v", err)
		}
		budget, err := negotiation.OpenBudget(money("100"), ledger)
		if err != nil {
			t.Fatalf("budget: %v", err)
		}
		return budget
	}

	first := "eex_" + strings.Repeat("1", 64)
	second := "eex_" + strings.Repeat("2", 64)
	if err := open().Reserve(first, money("90")); err != nil {
		t.Fatalf("first reserve: %v", err)
	}
	// 90 + 90 = 180 is past the 100 ceiling, so the second distinct execution is
	// refused rather than accepted the way a per-spend-only check would.
	if err := open().Reserve(second, money("90")); err == nil {
		t.Fatal("a per-mandate budget authorised more than its total")
	}
	// The refused hold left nothing behind: the survivor is still just the first.
	remaining, err := open().Remaining()
	if err != nil {
		t.Fatalf("remaining: %v", err)
	}
	if remaining.Atomic != "10" {
		t.Fatalf("the refused reservation was not rolled back: %s", remaining.Atomic)
	}

	// The same execution re-reserving its own amount is idempotent, not additive.
	if err := open().Reserve(first, money("90")); err != nil {
		t.Fatalf("idempotent reserve: %v", err)
	}
	if remaining, err := open().Remaining(); err != nil || remaining.Atomic != "10" {
		t.Fatalf("a repeated reservation double-counted: %s err=%v", remaining.Atomic, err)
	}
}

// A mandate budget refuses a missing or over-long mandate identifier and an
// invalid asset rather than deriving a budget for it.
func TestMandateBudgetIDValidatesInput(t *testing.T) {
	asset := mandateBudgetAsset()
	if _, err := MandateBudgetID("", asset); err == nil {
		t.Fatal("an empty mandate identifier derived a budget")
	}
	if _, err := MandateBudgetID(strings.Repeat("m", 129), asset); err == nil {
		t.Fatal("an over-long mandate identifier derived a budget")
	}
	if _, err := MandateBudgetID("mdt_"+strings.Repeat("1", 64), negotiation.Asset{}); err == nil {
		t.Fatal("an invalid asset derived a budget")
	}
}

// A per-mandate budget's holds survive a restart, keyed by the mandate that
// took them, so a spend total is not forgotten when the process ends.
func TestMandateBudgetSurvivesRestart(t *testing.T) {
	root := t.TempDir() + "/state"
	journal, err := Open(root)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	asset := mandateBudgetAsset()
	money := func(atomic string) negotiation.Money {
		return negotiation.Money{Asset: asset, Atomic: atomic}
	}
	mandateID := "mdt_" + strings.Repeat("9", 64)

	ledger, err := journal.OpenMandateBudgetLedger(mandateID, asset)
	if err != nil {
		t.Fatalf("ledger: %v", err)
	}
	budget, err := negotiation.OpenBudget(money("100"), ledger)
	if err != nil {
		t.Fatalf("budget: %v", err)
	}
	if err := budget.Reserve("eex_"+strings.Repeat("1", 64), money("90")); err != nil {
		t.Fatalf("reserve: %v", err)
	}
	if err := journal.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}

	reopened, err := Open(root)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	defer reopened.Close()
	restoredLedger, err := reopened.OpenMandateBudgetLedger(mandateID, asset)
	if err != nil {
		t.Fatalf("ledger: %v", err)
	}
	restored, err := negotiation.OpenBudget(money("100"), restoredLedger)
	if err != nil {
		t.Fatalf("budget: %v", err)
	}
	remaining, err := restored.Remaining()
	if err != nil {
		t.Fatalf("remaining: %v", err)
	}
	if remaining.Atomic != "10" {
		t.Fatalf("a mandate's spend total was forgotten across a restart: %s", remaining.Atomic)
	}
}
