package eventlog

import (
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func approvalJournal(t *testing.T) *Journal {
	t.Helper()
	journal, err := Open(filepath.Join(t.TempDir(), "state"))
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	t.Cleanup(func() { _ = journal.Close() })
	return journal
}

func testRequest(seed string) ApprovalRequest {
	return ApprovalRequest{
		ActionID: "act_" + strings.Repeat(seed, 64),
		Effect:   "tool-call",
		Summary:  "call the payments tool",
		Reason:   "this action is stronger than what may happen unattended",
		Origins: []ApprovalOrigin{{
			AgentID:        "agent_" + strings.Repeat("2", 64),
			EndpointID:     "mep_" + strings.Repeat("3", 64),
			EventID:        "evt_" + strings.Repeat("4", 64),
			ConversationID: "conv_" + strings.Repeat("5", 64),
			Kind:           "text",
		}},
		AskedAt: 1_800_000_000,
	}
}

func TestApprovalSurvivesAndIsDecidedOnce(t *testing.T) {
	journal := approvalJournal(t)
	request := testRequest("a")
	now := time.Unix(1_800_000_060, 0)

	approval, err := journal.RequestApproval(request)
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	if approval.State != ApprovalPending {
		t.Fatalf("a new request was not pending: %+v", approval)
	}

	waiting, err := journal.ListPendingApprovals(0)
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(waiting) != 1 || waiting[0].ActionID != request.ActionID {
		t.Fatalf("the owner would not see the request: %+v", waiting)
	}
	// The owner is shown what caused it, stored with the question rather than
	// looked up afterwards.
	if len(waiting[0].Origins) != 1 || waiting[0].Origins[0].EventID != request.Origins[0].EventID {
		t.Fatalf("the provenance was not kept with the question: %+v", waiting[0])
	}

	granted, err := journal.GrantAction(request.ActionID, now)
	if err != nil {
		t.Fatalf("grant: %v", err)
	}
	if granted.State != ApprovalGranted || granted.DecidedAtUnix == 0 {
		t.Fatalf("the grant was not recorded: %+v", granted)
	}
	if _, err := journal.DenyAction(request.ActionID, "changed my mind", now); err == nil {
		t.Fatal("a settled decision was revisited by whoever asked for it")
	}
	if waiting, err := journal.ListPendingApprovals(0); err != nil {
		t.Fatalf("list: %v", err)
	} else if len(waiting) != 0 {
		t.Fatalf("a decided request stayed in the owner's queue: %+v", waiting)
	}
}

// An approval that could be presented twice would authorise the second
// occurrence of an action the owner saw once.
func TestGrantedApprovalIsSpentOnce(t *testing.T) {
	journal := approvalJournal(t)
	request := testRequest("b")
	now := time.Unix(1_800_000_060, 0)

	if _, err := journal.RequestApproval(request); err != nil {
		t.Fatalf("request: %v", err)
	}
	if _, err := journal.SpendApproval(request.ActionID, now); err == nil {
		t.Fatal("an undecided action was performed")
	}
	if _, err := journal.GrantAction(request.ActionID, now); err != nil {
		t.Fatalf("grant: %v", err)
	}
	spent, err := journal.SpendApproval(request.ActionID, now)
	if err != nil {
		t.Fatalf("spend: %v", err)
	}
	if spent.State != ApprovalSpent || spent.SpentAtUnix == 0 {
		t.Fatalf("spending was not recorded: %+v", spent)
	}
	if _, err := journal.SpendApproval(request.ActionID, now); err == nil {
		t.Fatal("one approval authorised the same action twice")
	}
}

// A runtime that retried must not be able to clear a refusal by asking again.
func TestAskingAgainDoesNotClearARefusal(t *testing.T) {
	journal := approvalJournal(t)
	request := testRequest("c")
	now := time.Unix(1_800_000_060, 0)

	if _, err := journal.RequestApproval(request); err != nil {
		t.Fatalf("request: %v", err)
	}
	if _, err := journal.DenyAction(request.ActionID, "not this one", now); err != nil {
		t.Fatalf("deny: %v", err)
	}
	again, err := journal.RequestApproval(request)
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	if again.State != ApprovalDenied {
		t.Fatalf("asking again reopened a refusal: %+v", again)
	}
	if _, err := journal.SpendApproval(request.ActionID, now); err == nil {
		t.Fatal("a refused action was performed")
	}
}

func TestApprovalInputsAreValidated(t *testing.T) {
	journal := approvalJournal(t)
	cases := map[string]func(*ApprovalRequest){
		"no action":   func(r *ApprovalRequest) { r.ActionID = "" },
		"bad action":  func(r *ApprovalRequest) { r.ActionID = "act_short" },
		"no effect":   func(r *ApprovalRequest) { r.Effect = "" },
		"no summary":  func(r *ApprovalRequest) { r.Summary = "" },
		"no reason":   func(r *ApprovalRequest) { r.Reason = "" },
		"no time":     func(r *ApprovalRequest) { r.AskedAt = 0 },
		"bad origin":  func(r *ApprovalRequest) { r.Origins[0].EventID = "evt_short" },
		"no kind":     func(r *ApprovalRequest) { r.Origins[0].Kind = "" },
		"too much":    func(r *ApprovalRequest) { r.Origins = make([]ApprovalOrigin, MaxApprovalOrigins+1) },
		"long reason": func(r *ApprovalRequest) { r.Reason = strings.Repeat("x", MaxApprovalSummaryBytes+1) },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			request := testRequest("d")
			request.Origins = append([]ApprovalOrigin(nil), request.Origins...)
			mutate(&request)
			if _, err := journal.RequestApproval(request); err == nil {
				t.Fatalf("expected %q to be refused", name)
			}
		})
	}
	if _, err := journal.GrantAction("act_"+strings.Repeat("e", 64), time.Unix(1, 0)); err == nil {
		t.Fatal("an action nobody asked about was granted")
	}
	if _, err := journal.DenyAction(testRequest("f").ActionID, "", time.Unix(1, 0)); err == nil {
		t.Fatal("a refusal with no reason was accepted")
	}
	if _, _, err := journal.LookupApproval("nonsense"); err == nil {
		t.Fatal("an invalid action identifier was looked up")
	}
}
