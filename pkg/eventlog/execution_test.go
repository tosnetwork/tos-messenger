package eventlog

import (
	"strings"
	"testing"
	"time"
)

// An economic execution is bound to the first action that authorised it. The
// same action re-claims itself (crash recovery), and a different action for the
// same purchase finds the first bound rather than taking a second claim -- which
// is what stops a re-described replay of one purchase being authorised twice.
func TestEconomicExecutionIsClaimedOnce(t *testing.T) {
	journal := approvalJournal(t)
	now := time.Unix(1_800_000_000, 0)
	exec := "eex_" + strings.Repeat("a", 64)
	first := "act_" + strings.Repeat("1", 64)
	second := "act_" + strings.Repeat("2", 64)

	bound, fresh, err := journal.ClaimEconomicExecution(exec, first, now)
	if err != nil || !fresh || bound != first {
		t.Fatalf("first claim: bound=%q fresh=%v err=%v", bound, fresh, err)
	}
	bound, fresh, err = journal.ClaimEconomicExecution(exec, first, now)
	if err != nil || fresh || bound != first {
		t.Fatalf("re-claim by the same action: bound=%q fresh=%v err=%v", bound, fresh, err)
	}
	bound, fresh, err = journal.ClaimEconomicExecution(exec, second, now)
	if err != nil || fresh || bound != first {
		t.Fatalf("a re-described purchase took a second claim: bound=%q fresh=%v err=%v", bound, fresh, err)
	}

	claim, found, err := journal.LookupEconomicExecution(exec)
	if err != nil || !found || claim.ActionID != first {
		t.Fatalf("lookup: claim=%+v found=%v err=%v", claim, found, err)
	}
}
