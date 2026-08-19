package eventlog

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/tosnetwork/tos-messenger/internal/dirlock"
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
	path := filepath.Join(root, eventA[len("evt_"):]+".json")
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
	entries, err := os.ReadDir(root)
	if err != nil {
		t.Fatalf("read dir: %v", err)
	}
	for _, item := range entries {
		info, err := item.Info()
		if err != nil {
			t.Fatalf("stat: %v", err)
		}
		if info.Mode().Perm() != 0o600 {
			t.Fatalf("%s is not private: %v", item.Name(), info.Mode().Perm())
		}
	}
}
