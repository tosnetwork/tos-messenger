package eventlog

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/tosnetwork/tos-messenger/internal/dirlock"
	"github.com/tosnetwork/tos-messenger/pkg/fault"
)

const (
	eventA   = "evt_" + "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	eventB   = "evt_" + "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	endpoint = "mep_" + "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
	other    = "mep_" + "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"
	convo    = "conv_" + "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"
	acceptAt = uint64(1_800_000_000)
)

func openJournal(t *testing.T) (*Journal, string) {
	t.Helper()
	root := filepath.Join(t.TempDir(), "state")
	journal, err := Open(root)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	t.Cleanup(func() { _ = journal.Close() })
	return journal, root
}

func entry(eventID, senderEndpoint string) Entry {
	return Entry{
		EventID:          eventID,
		SenderEndpointID: senderEndpoint,
		ConversationID:   convo,
		AcceptedAtUnix:   acceptAt,
	}
}

func TestAcceptClaimsOnce(t *testing.T) {
	journal, _ := openJournal(t)

	fresh, record, err := journal.Accept(entry(eventA, endpoint))
	if err != nil {
		t.Fatalf("accept: %v", err)
	}
	if !fresh || record.State != StateAccepted {
		t.Fatalf("first claim should be fresh and accepted, got fresh=%v state=%q", fresh, record.State)
	}

	// Every later presentation of the same event is a duplicate, whatever
	// route it arrived by.
	for attempt := 0; attempt < 3; attempt++ {
		fresh, duplicate, err := journal.Accept(entry(eventA, endpoint))
		if err != nil {
			t.Fatalf("duplicate accept: %v", err)
		}
		if fresh {
			t.Fatal("a duplicate was reported as a fresh application event")
		}
		if duplicate.EventID != record.EventID || duplicate.State != StateAccepted {
			t.Fatal("duplicate returned a different record")
		}
	}
}

func TestClaimSurvivesRestart(t *testing.T) {
	root := filepath.Join(t.TempDir(), "state")
	journal, err := Open(root)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if fresh, _, err := journal.Accept(entry(eventA, endpoint)); err != nil || !fresh {
		t.Fatalf("first claim: fresh=%v err=%v", fresh, err)
	}
	if _, err := journal.MarkApplied(eventA, acceptAt+5); err != nil {
		t.Fatalf("mark applied: %v", err)
	}
	if err := journal.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}

	// A process restart must not erase replay protection.
	reopened, err := Open(root)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	defer reopened.Close()

	fresh, record, err := reopened.Accept(entry(eventA, endpoint))
	if err != nil {
		t.Fatalf("accept after restart: %v", err)
	}
	if fresh {
		t.Fatal("replay protection did not survive a restart")
	}
	if record.State != StateApplied || record.AppliedAtUnix != acceptAt+5 {
		t.Fatalf("state did not survive a restart: %+v", record)
	}
}

func TestConflictingSenderIsRefused(t *testing.T) {
	journal, _ := openJournal(t)
	if _, _, err := journal.Accept(entry(eventA, endpoint)); err != nil {
		t.Fatalf("accept: %v", err)
	}
	if _, _, err := journal.Accept(entry(eventA, other)); !errors.Is(err, ErrConflict) {
		t.Fatalf("expected a conflicting sender to be refused, got %v", err)
	}
	conflicting := entry(eventA, endpoint)
	conflicting.ConversationID = "conv_" + strings.Repeat("1", 64)
	if _, _, err := journal.Accept(conflicting); !errors.Is(err, ErrConflict) {
		t.Fatalf("expected a conflicting conversation to be refused, got %v", err)
	}
}

func TestStateMachineOnlyMovesForward(t *testing.T) {
	journal, _ := openJournal(t)
	if _, _, err := journal.Accept(entry(eventA, endpoint)); err != nil {
		t.Fatalf("accept: %v", err)
	}
	if _, err := journal.MarkApplied(eventA, acceptAt+1); err != nil {
		t.Fatalf("apply: %v", err)
	}
	if _, err := journal.MarkApplied(eventA, acceptAt+2); err == nil {
		t.Fatal("expected a repeated application transition to be refused")
	}
	if _, err := journal.MarkRead(eventA, acceptAt+3); err != nil {
		t.Fatalf("read: %v", err)
	}
	if _, err := journal.MarkApplied(eventA, acceptAt+4); err == nil {
		t.Fatal("expected a regression from read to applied to be refused")
	}
	if _, err := journal.MarkRead(eventA, acceptAt+5); err == nil {
		t.Fatal("expected a repeated read transition to be refused")
	}
}

func TestReadMayFollowAcceptance(t *testing.T) {
	journal, _ := openJournal(t)
	if _, _, err := journal.Accept(entry(eventA, endpoint)); err != nil {
		t.Fatalf("accept: %v", err)
	}
	if _, err := journal.MarkRead(eventA, acceptAt+1); err != nil {
		t.Fatalf("expected a read indication without an application ack: %v", err)
	}
}

func TestTransitionsRejectImpossibleTimes(t *testing.T) {
	journal, _ := openJournal(t)
	if _, _, err := journal.Accept(entry(eventA, endpoint)); err != nil {
		t.Fatalf("accept: %v", err)
	}
	if _, err := journal.MarkApplied(eventA, acceptAt-1); err == nil {
		t.Fatal("expected an application before acceptance to be refused")
	}
	if _, err := journal.MarkApplied(eventA, 0); err == nil {
		t.Fatal("expected a zero transition time to be refused")
	}
}

func TestUnknownEventTransitions(t *testing.T) {
	journal, _ := openJournal(t)
	if _, err := journal.MarkApplied(eventB, acceptAt+1); !errors.Is(err, ErrUnknown) {
		t.Fatalf("expected an unclaimed event to be unknown, got %v", err)
	}
	record, found, err := journal.Lookup(eventB)
	if err != nil {
		t.Fatalf("lookup: %v", err)
	}
	if found || record.EventID != "" {
		t.Fatal("expected no record for an unclaimed event")
	}
}

func TestInvalidInputIsRejected(t *testing.T) {
	journal, _ := openJournal(t)
	cases := map[string]Entry{
		"bad event":        entry("evt_bad", endpoint),
		"bad endpoint":     entry(eventA, "mep_bad"),
		"empty event":      entry("", endpoint),
		"zero accept time": {EventID: eventA, SenderEndpointID: endpoint, ConversationID: convo},
	}
	for name, candidate := range cases {
		t.Run(name, func(t *testing.T) {
			if _, _, err := journal.Accept(candidate); err == nil {
				t.Fatalf("expected %q to be rejected", name)
			}
		})
	}
	badConversation := entry(eventA, endpoint)
	badConversation.ConversationID = "conv_bad"
	if _, _, err := journal.Accept(badConversation); err == nil {
		t.Fatal("expected an invalid conversation identifier to be rejected")
	}
	if _, _, err := journal.Lookup("evt_bad"); err == nil {
		t.Fatal("expected an invalid lookup identifier to be rejected")
	}
}

func TestSecondWriterIsRefused(t *testing.T) {
	journal, root := openJournal(t)
	if _, err := Open(root); !errors.Is(err, dirlock.ErrHeld) {
		t.Fatalf("expected a second writer to be refused, got %v", err)
	}
	if err := journal.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	// Ownership is released on close, so a replacement process can take over.
	replacement, err := Open(root)
	if err != nil {
		t.Fatalf("expected ownership to be released on close: %v", err)
	}
	defer replacement.Close()
}

func TestClosedJournalRefusesWork(t *testing.T) {
	journal, _ := openJournal(t)
	if err := journal.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	if _, _, err := journal.Accept(entry(eventA, endpoint)); err == nil {
		t.Fatal("expected a closed journal to refuse claims")
	}
	if _, err := journal.MarkApplied(eventA, acceptAt+1); err == nil {
		t.Fatal("expected a closed journal to refuse transitions")
	}
	if _, _, err := journal.Lookup(eventA); err == nil {
		t.Fatal("expected a closed journal to refuse lookups")
	}
	if err := journal.Close(); err != nil {
		t.Fatalf("expected a repeated close to be safe: %v", err)
	}
}

func TestCorruptRecordIsRefused(t *testing.T) {
	journal, root := openJournal(t)
	if _, _, err := journal.Accept(entry(eventA, endpoint)); err != nil {
		t.Fatalf("accept: %v", err)
	}
	path := filepath.Join(root, "inbound", eventA[len("evt_"):]+".json")
	if err := os.WriteFile(path, []byte("{not json"), 0o600); err != nil {
		t.Fatalf("corrupt record: %v", err)
	}
	if _, _, err := journal.Accept(entry(eventA, endpoint)); err == nil {
		t.Fatal("expected a corrupt record to fail closed instead of granting a fresh claim")
	}
	if _, _, err := journal.Lookup(eventA); err == nil {
		t.Fatal("expected a corrupt record to fail closed on lookup")
	}
}

func TestOpenRejectsUnsafeRoots(t *testing.T) {
	if _, err := Open("relative/path"); err == nil {
		t.Fatal("expected a relative root to be rejected")
	}
	if _, err := Open("/tmp/../tmp/state/"); err == nil {
		t.Fatal("expected an uncleaned root to be rejected")
	}
	shared := filepath.Join(t.TempDir(), "shared")
	if err := os.MkdirAll(shared, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if _, err := Open(shared); err == nil {
		t.Fatal("expected a world-readable root to be rejected")
	}
}

func TestRecordsArePrivate(t *testing.T) {
	journal, root := openJournal(t)
	if _, _, err := journal.Accept(entry(eventA, endpoint)); err != nil {
		t.Fatalf("accept: %v", err)
	}
	if _, _, err := journal.Enqueue(outbound(eventB)); err != nil {
		t.Fatalf("enqueue: %v", err)
	}
	err := filepath.WalkDir(root, func(path string, item os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		info, err := item.Info()
		if err != nil {
			return err
		}
		expected := os.FileMode(0o600)
		if item.IsDir() {
			expected = 0o700
		}
		if info.Mode().Perm() != expected {
			t.Fatalf("%s has mode %v, expected %v", path, info.Mode().Perm(), expected)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walk: %v", err)
	}
}

func outbound(eventID string) Outbound {
	return Outbound{
		EventID:             eventID,
		RecipientEndpointID: endpoint,
		ConversationID:      convo,
		CreatedAtUnix:       acceptAt,
		ExpiresAtUnix:       acceptAt + 86_400,
	}
}

func TestEnqueueClaimsOnceAndKeepsItsBackoff(t *testing.T) {
	journal, _ := openJournal(t)

	fresh, delivery, err := journal.Enqueue(outbound(eventA))
	if err != nil {
		t.Fatalf("enqueue: %v", err)
	}
	if !fresh || delivery.State != StatePending || delivery.Attempts != 0 {
		t.Fatalf("unexpected first enqueue: %+v", delivery)
	}
	if _, err := journal.Failed(eventA, fault.CodeUnreachable, time.Unix(int64(acceptAt), 0)); err != nil {
		t.Fatalf("failed: %v", err)
	}
	// Re-submitting after a crash must not reset a backoff that exists to
	// protect the recipient.
	fresh, again, err := journal.Enqueue(outbound(eventA))
	if err != nil {
		t.Fatalf("re-enqueue: %v", err)
	}
	if fresh {
		t.Fatal("a duplicate enqueue was reported as fresh")
	}
	if again.Attempts != 1 {
		t.Fatalf("re-enqueue reset the attempt count: %+v", again)
	}
	conflicting := outbound(eventA)
	conflicting.RecipientEndpointID = other
	if _, _, err := journal.Enqueue(conflicting); !errors.Is(err, ErrConflict) {
		t.Fatalf("expected a conflicting recipient to be refused, got %v", err)
	}
}

func TestRetryScheduleFollowsTheDisposition(t *testing.T) {
	journal, _ := openJournal(t)
	if _, _, err := journal.Enqueue(outbound(eventA)); err != nil {
		t.Fatalf("enqueue: %v", err)
	}
	now := time.Unix(int64(acceptAt), 0)

	delivery, err := journal.Failed(eventA, fault.CodeUnreachable, now)
	if err != nil {
		t.Fatalf("failed: %v", err)
	}
	if delivery.State != StatePending || delivery.NextAttemptAtUnix <= acceptAt {
		t.Fatalf("a transient failure did not back off: %+v", delivery)
	}
	if delivery.LastCode != fault.CodeUnreachable {
		t.Fatalf("the failure code was not recorded: %+v", delivery)
	}

	// A permanent code ends the delivery immediately.
	if _, _, err := journal.Enqueue(outbound(eventB)); err != nil {
		t.Fatalf("enqueue: %v", err)
	}
	permanent, err := journal.Failed(eventB, fault.CodeOversized, now)
	if err != nil {
		t.Fatalf("failed: %v", err)
	}
	if permanent.State != StateAbandoned || permanent.NextAttemptAtUnix != 0 {
		t.Fatalf("a permanent failure stayed queued: %+v", permanent)
	}
	if _, err := journal.Failed(eventB, fault.CodeUnreachable, now); !errors.Is(err, ErrNotPending) {
		t.Fatalf("an abandoned delivery accepted another attempt: %v", err)
	}
}

// An approval hold must leave the timer entirely, or the owner is asked the
// same question on every sweep.
func TestApprovalHoldLeavesTheQueue(t *testing.T) {
	journal, _ := openJournal(t)
	if _, _, err := journal.Enqueue(outbound(eventA)); err != nil {
		t.Fatalf("enqueue: %v", err)
	}
	now := time.Unix(int64(acceptAt), 0)
	held, err := journal.Failed(eventA, fault.CodeApprovalRequired, now)
	if err != nil {
		t.Fatalf("failed: %v", err)
	}
	if held.State != StateHeld || held.NextAttemptAtUnix != 0 {
		t.Fatalf("an approval hold stayed on a timer: %+v", held)
	}
	due, err := journal.Due(time.Unix(int64(acceptAt)+86_000, 0))
	if err != nil {
		t.Fatalf("due: %v", err)
	}
	if len(due) != 0 {
		t.Fatalf("a held delivery was swept: %+v", due)
	}
	resumed, err := journal.Resume(eventA, now)
	if err != nil {
		t.Fatalf("resume: %v", err)
	}
	if resumed.State != StatePending {
		t.Fatalf("resume did not requeue: %+v", resumed)
	}
	if _, err := journal.Resume(eventA, now); !errors.Is(err, ErrNotPending) {
		t.Fatalf("a pending delivery was resumed again: %v", err)
	}
}

func TestDueSelectsOnlyWhatIsReady(t *testing.T) {
	journal, _ := openJournal(t)
	for _, eventID := range []string{eventA, eventB} {
		if _, _, err := journal.Enqueue(outbound(eventID)); err != nil {
			t.Fatalf("enqueue: %v", err)
		}
	}
	now := time.Unix(int64(acceptAt), 0)
	due, err := journal.Due(now)
	if err != nil {
		t.Fatalf("due: %v", err)
	}
	if len(due) != 2 {
		t.Fatalf("expected both deliveries, got %d", len(due))
	}
	if _, err := journal.Failed(eventA, fault.CodeUnreachable, now); err != nil {
		t.Fatalf("failed: %v", err)
	}
	due, err = journal.Due(now)
	if err != nil {
		t.Fatalf("due: %v", err)
	}
	if len(due) != 1 || due[0].EventID != eventB {
		t.Fatalf("a backed-off delivery was swept again: %+v", due)
	}
	if _, err := journal.Delivered(eventB, now); err != nil {
		t.Fatalf("delivered: %v", err)
	}
	due, err = journal.Due(now)
	if err != nil {
		t.Fatalf("due: %v", err)
	}
	if len(due) != 0 {
		t.Fatalf("a settled delivery was swept: %+v", due)
	}
}

func TestExpiredDeliveryIsAbandoned(t *testing.T) {
	journal, _ := openJournal(t)
	request := outbound(eventA)
	request.ExpiresAtUnix = acceptAt + 60
	if _, _, err := journal.Enqueue(request); err != nil {
		t.Fatalf("enqueue: %v", err)
	}
	past := time.Unix(int64(request.ExpiresAtUnix)+1, 0)
	delivery, err := journal.Failed(eventA, fault.CodeUnreachable, past)
	if err != nil {
		t.Fatalf("failed: %v", err)
	}
	if delivery.State != StateAbandoned {
		t.Fatalf("an expired delivery stayed queued: %+v", delivery)
	}

	// A backoff that would land at or past the expiry is pointless, so it
	// settles now rather than waking up only to give up.
	second := outbound(eventB)
	second.ExpiresAtUnix = acceptAt + 1
	if _, _, err := journal.Enqueue(second); err != nil {
		t.Fatalf("enqueue: %v", err)
	}
	settled, err := journal.Failed(eventB, fault.CodeUnreachable, time.Unix(int64(acceptAt), 0))
	if err != nil {
		t.Fatalf("failed: %v", err)
	}
	if settled.State != StateAbandoned {
		t.Fatalf("a delivery whose retry falls past its expiry stayed queued: %+v", settled)
	}
}

func TestDeliveryTransitionsRejectUnknownEvents(t *testing.T) {
	journal, _ := openJournal(t)
	now := time.Unix(int64(acceptAt), 0)
	if _, err := journal.Failed(eventA, fault.CodeUnreachable, now); !errors.Is(err, ErrUnknown) {
		t.Fatalf("expected an unknown delivery, got %v", err)
	}
	if _, err := journal.Delivered(eventA, now); !errors.Is(err, ErrUnknown) {
		t.Fatalf("expected an unknown delivery, got %v", err)
	}
	if _, err := journal.Resume(eventA, now); !errors.Is(err, ErrUnknown) {
		t.Fatalf("expected an unknown delivery, got %v", err)
	}
	if _, found, err := journal.LookupDelivery(eventA); err != nil || found {
		t.Fatalf("expected no record: found=%v err=%v", found, err)
	}
	bad := outbound(eventA)
	bad.RecipientEndpointID = "mep_bad"
	if _, _, err := journal.Enqueue(bad); err == nil {
		t.Fatal("an invalid recipient was accepted")
	}
	inverted := outbound(eventA)
	inverted.ExpiresAtUnix = inverted.CreatedAtUnix
	if _, _, err := journal.Enqueue(inverted); err == nil {
		t.Fatal("an inverted validity window was accepted")
	}
}

// Retention shorter than the window a Relay may hold ciphertext would reopen
// the replay window the journal exists to close.
func TestPruneRefusesRetentionShorterThanTheReplayWindow(t *testing.T) {
	journal, _ := openJournal(t)
	if _, err := journal.Prune(time.Unix(int64(acceptAt), 0), MinClaimRetention-time.Second); err == nil {
		t.Fatal("a retention shorter than the replay window was accepted")
	}
	if _, err := journal.Prune(time.Time{}, MinClaimRetention); err == nil {
		t.Fatal("a zero clock was accepted")
	}
}

func TestPruneRemovesOnlyClosedRecords(t *testing.T) {
	journal, _ := openJournal(t)
	now := time.Unix(int64(acceptAt), 0)
	if _, _, err := journal.Accept(entry(eventA, endpoint)); err != nil {
		t.Fatalf("accept: %v", err)
	}
	if _, _, err := journal.Enqueue(outbound(eventA)); err != nil {
		t.Fatalf("enqueue: %v", err)
	}
	if _, _, err := journal.Enqueue(outbound(eventB)); err != nil {
		t.Fatalf("enqueue: %v", err)
	}
	if _, err := journal.Delivered(eventB, now); err != nil {
		t.Fatalf("delivered: %v", err)
	}

	// Nothing has aged out yet.
	report, err := journal.Prune(now, MinClaimRetention)
	if err != nil {
		t.Fatalf("prune: %v", err)
	}
	if report.ClaimsRemoved != 0 || report.DeliveriesRemoved != 0 {
		t.Fatalf("a live record was pruned: %+v", report)
	}

	after := now.Add(MinClaimRetention + time.Hour)
	report, err = journal.Prune(after, MinClaimRetention)
	if err != nil {
		t.Fatalf("prune: %v", err)
	}
	if report.ClaimsRemoved != 1 {
		t.Fatalf("the closed claim was not pruned: %+v", report)
	}
	if report.DeliveriesRemoved != 1 {
		t.Fatalf("the settled delivery was not pruned: %+v", report)
	}
	// The pending delivery is live work, not history.
	if _, found, err := journal.LookupDelivery(eventA); err != nil || !found {
		t.Fatalf("a pending delivery was pruned: found=%v err=%v", found, err)
	}
	if _, found, err := journal.Lookup(eventA); err != nil || found {
		t.Fatalf("the claim survived its retention: found=%v err=%v", found, err)
	}
}

// Deleting a damaged record would turn "corrupt the file" into "replay the
// event", so a sweep reports damage and leaves it alone.
func TestPruneKeepsUnreadableRecords(t *testing.T) {
	journal, root := openJournal(t)
	if _, _, err := journal.Accept(entry(eventA, endpoint)); err != nil {
		t.Fatalf("accept: %v", err)
	}
	path := filepath.Join(root, "inbound", eventA[len("evt_"):]+".json")
	if err := os.WriteFile(path, []byte("{corrupt"), 0o600); err != nil {
		t.Fatalf("corrupt: %v", err)
	}
	report, err := journal.Prune(time.Unix(int64(acceptAt), 0).Add(2*MinClaimRetention), MinClaimRetention)
	if err != nil {
		t.Fatalf("prune: %v", err)
	}
	if report.ClaimsRemoved != 0 {
		t.Fatalf("a damaged record was removed: %+v", report)
	}
	if len(report.Unreadable) != 1 {
		t.Fatalf("the damage was not reported: %+v", report)
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("the damaged record was deleted: %v", err)
	}
	if _, _, err := journal.Accept(entry(eventA, endpoint)); err == nil {
		t.Fatal("a damaged claim granted a fresh claim after a sweep")
	}
}

func TestDeliveryStateSurvivesRestart(t *testing.T) {
	root := filepath.Join(t.TempDir(), "state")
	journal, err := Open(root)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if _, _, err := journal.Enqueue(outbound(eventA)); err != nil {
		t.Fatalf("enqueue: %v", err)
	}
	if _, err := journal.Failed(eventA, fault.CodeRateLimited, time.Unix(int64(acceptAt), 0)); err != nil {
		t.Fatalf("failed: %v", err)
	}
	if err := journal.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}

	reopened, err := Open(root)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	defer reopened.Close()
	delivery, found, err := reopened.LookupDelivery(eventA)
	if err != nil || !found {
		t.Fatalf("lookup after restart: found=%v err=%v", found, err)
	}
	if delivery.Attempts != 1 || delivery.LastCode != fault.CodeRateLimited {
		t.Fatalf("delivery state did not survive a restart: %+v", delivery)
	}
}

func TestClosedJournalRefusesDeliveryWork(t *testing.T) {
	journal, _ := openJournal(t)
	if err := journal.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	now := time.Unix(int64(acceptAt), 0)
	if _, _, err := journal.Enqueue(outbound(eventA)); err == nil {
		t.Fatal("a closed journal accepted an enqueue")
	}
	if _, err := journal.Due(now); err == nil {
		t.Fatal("a closed journal swept deliveries")
	}
	if _, err := journal.Prune(now, MinClaimRetention); err == nil {
		t.Fatal("a closed journal pruned records")
	}
}
