package eventlog

import (
	"errors"
	"strings"
	"testing"
	"time"
)

func boundedJournal(t *testing.T, quota Quota) *Journal {
	t.Helper()
	journal, err := OpenWith(t.TempDir()+"/state", quota)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	t.Cleanup(func() { _ = journal.Close() })
	return journal
}

func heldEntry(eventID, sender string, at uint64) Entry {
	held := entry(eventID, sender)
	held.Admission = AdmissionPending
	held.ReceivedAtUnix = at
	return held
}

func eventNamed(index int) string {
	return "evt_" + strings.Repeat("0", 62) + string([]byte{
		"0123456789abcdef"[index>>4], "0123456789abcdef"[index&0xf],
	})
}

// A delegated sender inside its own scope can still send a new
// content-addressed identifier every second. Without a bound, the owner's
// queue and the disk behind it are theirs to fill.
func TestOneSenderCannotFillTheOwnersQueue(t *testing.T) {
	quota := DefaultQuota()
	quota.MaxPendingPerSender = 3
	journal := boundedJournal(t, quota)
	at := uint64(1_800_000_000)

	for index := 0; index < 3; index++ {
		if _, _, err := journal.Accept(heldEntry(eventNamed(index), endpoint, at)); err != nil {
			t.Fatalf("accept %d: %v", index, err)
		}
	}
	if _, _, err := journal.Accept(heldEntry(eventNamed(3), endpoint, at)); !errors.Is(err, ErrPendingFull) {
		t.Fatalf("a sender filled the queue past its bound: %v", err)
	}
	// Another sender still gets in: the bound is per sender, not a shared
	// queue one party can close.
	other := "mep_" + strings.Repeat("7", 64)
	if _, _, err := journal.Accept(heldEntry(eventNamed(4), other, at)); err != nil {
		t.Fatalf("a second sender was refused: %v", err)
	}
}

func TestTheOwnersQueueHasATotalBound(t *testing.T) {
	quota := DefaultQuota()
	quota.MaxPendingAdmissions = 2
	quota.MaxPendingPerSender = 2
	journal := boundedJournal(t, quota)
	at := uint64(1_800_000_000)

	for index := 0; index < 2; index++ {
		if _, _, err := journal.Accept(heldEntry(eventNamed(index), endpoint, at)); err != nil {
			t.Fatalf("accept %d: %v", index, err)
		}
	}
	other := "mep_" + strings.Repeat("7", 64)
	if _, _, err := journal.Accept(heldEntry(eventNamed(2), other, at)); !errors.Is(err, ErrPendingFull) {
		t.Fatalf("the total bound did not apply: %v", err)
	}
}

// An event nobody decided about is retired, and the space it held comes back.
func TestUndecidedEventsAreRetired(t *testing.T) {
	quota := DefaultQuota()
	quota.MaxPendingPerSender = 1
	quota.MaxPendingAge = time.Hour
	journal := boundedJournal(t, quota)
	at := uint64(1_800_000_000)

	if _, _, err := journal.Accept(heldEntry(eventNamed(0), endpoint, at)); err != nil {
		t.Fatalf("accept: %v", err)
	}
	later := time.Unix(int64(at)+7200, 0)
	// It is no longer offered to the owner before anything sweeps.
	if waiting, err := journal.ListAwaitingAdmission(later, 10); err != nil {
		t.Fatalf("list: %v", err)
	} else if len(waiting) != 0 {
		t.Fatalf("an expired question was still put to the owner: %+v", waiting)
	}

	count, err := journal.ExpirePendingAdmissions(later)
	if err != nil {
		t.Fatalf("expire: %v", err)
	}
	if count != 1 {
		t.Fatalf("expected one retirement, got %d", count)
	}
	// Recorded, not deleted: an owner returning to an empty queue can still
	// see that something arrived and was never decided.
	record, found, err := journal.Lookup(eventNamed(0))
	if err != nil || !found {
		t.Fatalf("lookup: found=%v err=%v", found, err)
	}
	if record.Admission != AdmissionDenied || record.Application != StateRejected {
		t.Fatalf("an expired question was not settled: %+v", record)
	}
	// And the space it held is available again.
	if _, _, err := journal.Accept(heldEntry(eventNamed(1), endpoint, uint64(later.Unix()))); err != nil {
		t.Fatalf("the bound counted a retired question: %v", err)
	}
}

// An event's own expiry retires it too, whatever the installation's window.
func TestAnEventPastItsOwnExpiryIsRetired(t *testing.T) {
	journal := boundedJournal(t, DefaultQuota())
	at := uint64(1_800_000_000)
	held := heldEntry(eventNamed(0), endpoint, at)
	held.ExpiresAtUnix = at + 60
	if _, _, err := journal.Accept(held); err != nil {
		t.Fatalf("accept: %v", err)
	}
	later := time.Unix(int64(at)+120, 0)
	if waiting, err := journal.ListAwaitingAdmission(later, 10); err != nil {
		t.Fatalf("list: %v", err)
	} else if len(waiting) != 0 {
		t.Fatalf("an event past its own expiry was put to the owner: %+v", waiting)
	}
	if count, err := journal.ExpirePendingAdmissions(later); err != nil || count != 1 {
		t.Fatalf("expire: count=%d err=%v", count, err)
	}
}

// The runtime's own queue of questions is bounded for the same reason.
func TestPendingApprovalsAreBoundedAndRetired(t *testing.T) {
	quota := DefaultQuota()
	quota.MaxPendingAge = time.Hour
	journal := boundedJournal(t, quota)
	at := uint64(1_800_000_000)

	request := testRequest("a")
	request.AskedAt = at
	if _, err := journal.RequestApproval(request); err != nil {
		t.Fatalf("request: %v", err)
	}
	later := time.Unix(int64(at)+7200, 0)
	if waiting, err := journal.ListPendingApprovals(later, 10); err != nil {
		t.Fatalf("list: %v", err)
	} else if len(waiting) != 0 {
		t.Fatalf("an expired question was still put to the owner: %+v", waiting)
	}
	if count, err := journal.ExpirePendingApprovals(later); err != nil || count != 1 {
		t.Fatalf("expire: count=%d err=%v", count, err)
	}
	approval, found, err := journal.LookupApproval(request.ActionID)
	if err != nil || !found {
		t.Fatalf("lookup: found=%v err=%v", found, err)
	}
	if approval.State != ApprovalDenied || approval.DenialReason == "" {
		t.Fatalf("an unanswered question was not settled: %+v", approval)
	}
	// And it cannot be performed afterwards.
	if _, err := journal.SpendApproval(request.ActionID, later); err == nil {
		t.Fatal("an expired request authorised an action")
	}
}

func TestQuotaMustBoundSomething(t *testing.T) {
	cases := map[string]func(*Quota){
		"no total":      func(q *Quota) { q.MaxPendingAdmissions = 0 },
		"no per sender": func(q *Quota) { q.MaxPendingPerSender = 0 },
		"sender above total": func(q *Quota) {
			q.MaxPendingPerSender = q.MaxPendingAdmissions + 1
		},
		"no bytes": func(q *Quota) { q.MaxPendingBytes = 0 },
		"no age":   func(q *Quota) { q.MaxPendingAge = 0 },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			quota := DefaultQuota()
			mutate(&quota)
			if err := quota.Validate(); err == nil {
				t.Fatalf("expected %q to be refused", name)
			}
			if _, err := OpenWith(t.TempDir()+"/state", quota); err == nil {
				t.Fatalf("a journal opened under %q", name)
			}
		})
	}
}
