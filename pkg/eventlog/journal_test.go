package eventlog

import (
	"bytes"
	"encoding/base64"
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
		Payload:          []byte(`{"event":"` + eventID + `"}`),
		Admission:        AdmissionAdmitted,
		ReceivedAtUnix:   acceptAt,
	}
}

func attempt(seed byte) string {
	id, err := NewAttemptID(bytes.Repeat([]byte{seed}, 32))
	if err != nil {
		panic(err)
	}
	return id
}

// claim takes the send attempt a settlement needs, so tests exercise the same
// path a sweep does.
func claim(t *testing.T, journal *Journal, eventID string, seed byte, now time.Time) string {
	t.Helper()
	id := attempt(seed)
	if _, err := journal.ClaimForSend(eventID, id, now, time.Minute); err != nil {
		t.Fatalf("claim for send: %v", err)
	}
	return id
}

func lease(seed byte) string {
	id, err := NewLeaseID(bytes.Repeat([]byte{seed}, 32))
	if err != nil {
		panic(err)
	}
	return id
}

func TestAcceptRecordsOnceAndKeepsTheEvent(t *testing.T) {
	journal, _ := openJournal(t)

	fresh, record, err := journal.Accept(entry(eventA, endpoint))
	if err != nil {
		t.Fatalf("accept: %v", err)
	}
	if !fresh || record.Application != StateQueued {
		t.Fatalf("first receipt should be fresh and queued: fresh=%v state=%q", fresh, record.Application)
	}
	stored, err := record.Payload()
	if err != nil {
		t.Fatalf("payload: %v", err)
	}
	if string(stored) != `{"event":"`+eventA+`"}` {
		t.Fatalf("the event was not stored: %s", stored)
	}
	for attempt := 0; attempt < 3; attempt++ {
		fresh, duplicate, err := journal.Accept(entry(eventA, endpoint))
		if err != nil {
			t.Fatalf("duplicate accept: %v", err)
		}
		if fresh {
			t.Fatal("a duplicate was reported as a fresh event")
		}
		if duplicate.EventID != record.EventID {
			t.Fatal("duplicate returned a different record")
		}
	}
}

// The failure this journal exists to prevent: an event accepted and fsynced,
// then a crash before any runtime saw it. Deduplication must not swallow it.
func TestEventAcceptedBeforeACrashIsStillDelivered(t *testing.T) {
	root := filepath.Join(t.TempDir(), "state")
	journal, err := Open(root)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if fresh, _, err := journal.Accept(entry(eventA, endpoint)); err != nil || !fresh {
		t.Fatalf("accept: fresh=%v err=%v", fresh, err)
	}
	// The process dies here, before the event reaches a runtime.
	if err := journal.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}

	reopened, err := Open(root)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	defer reopened.Close()

	now := time.Unix(int64(acceptAt)+10, 0)
	pending, err := reopened.ListPending(now, 0)
	if err != nil {
		t.Fatalf("pending: %v", err)
	}
	if len(pending) != 1 || pending[0].EventID != eventA {
		t.Fatalf("the accepted event was not recovered: %+v", pending)
	}
	payload, err := pending[0].Payload()
	if err != nil || len(payload) == 0 {
		t.Fatalf("the recovered event carries no content: %v", err)
	}

	// And it is processed exactly once.
	if _, err := reopened.ClaimForApplication(eventA, lease(0x11), now, time.Minute); err != nil {
		t.Fatalf("claim: %v", err)
	}
	if _, err := reopened.CompleteApplication(eventA, lease(0x11), now); err != nil {
		t.Fatalf("complete: %v", err)
	}
	pending, err = reopened.ListPending(now, 0)
	if err != nil {
		t.Fatalf("pending: %v", err)
	}
	if len(pending) != 0 {
		t.Fatalf("an applied event was offered again: %+v", pending)
	}
	// A later redelivery from the network is a duplicate and stays one.
	if fresh, _, err := reopened.Accept(entry(eventA, endpoint)); err != nil || fresh {
		t.Fatalf("a redelivery was treated as new: fresh=%v err=%v", fresh, err)
	}
}

// A worker that dies holding a lease must not strand the event.
func TestExpiredLeaseReturnsWorkToTheQueue(t *testing.T) {
	journal, _ := openJournal(t)
	if _, _, err := journal.Accept(entry(eventA, endpoint)); err != nil {
		t.Fatalf("accept: %v", err)
	}
	now := time.Unix(int64(acceptAt), 0)
	if _, err := journal.ClaimForApplication(eventA, lease(0x11), now, time.Minute); err != nil {
		t.Fatalf("claim: %v", err)
	}
	// While the lease is live nobody else may take the work, or a tool call or
	// an approval request would happen twice.
	if _, err := journal.ClaimForApplication(eventA, lease(0x22), now, time.Minute); !errors.Is(err, ErrLeaseMismatch) {
		t.Fatalf("a live lease was taken over: %v", err)
	}
	if pending, err := journal.ListPending(now, 0); err != nil || len(pending) != 0 {
		t.Fatalf("a leased event was offered again: %+v %v", pending, err)
	}

	expired := now.Add(2 * time.Minute)
	pending, err := journal.ListPending(expired, 0)
	if err != nil {
		t.Fatalf("pending: %v", err)
	}
	if len(pending) != 1 {
		t.Fatalf("an expired lease did not return its work: %+v", pending)
	}
	if _, err := journal.ClaimForApplication(eventA, lease(0x22), expired, time.Minute); err != nil {
		t.Fatalf("reclaim: %v", err)
	}
	// The original worker coming back must not be able to complete it.
	if _, err := journal.CompleteApplication(eventA, lease(0x11), expired); !errors.Is(err, ErrLeaseMismatch) {
		t.Fatalf("a superseded lease completed the work: %v", err)
	}
	if _, err := journal.CompleteApplication(eventA, lease(0x22), expired); err != nil {
		t.Fatalf("complete: %v", err)
	}
}

// Reading is a separate dimension. A person marking a message read must not
// stop a runtime from ever receiving it.
func TestReadingDoesNotBlockApplication(t *testing.T) {
	journal, _ := openJournal(t)
	if _, _, err := journal.Accept(entry(eventA, endpoint)); err != nil {
		t.Fatalf("accept: %v", err)
	}
	now := time.Unix(int64(acceptAt), 0)
	read, err := journal.MarkRead(eventA, now)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if read.ReadAtUnix == 0 || read.Application != StateQueued {
		t.Fatalf("unexpected record after reading: %+v", read)
	}
	pending, err := journal.ListPending(now, 0)
	if err != nil || len(pending) != 1 {
		t.Fatalf("a read event left the queue: %+v %v", pending, err)
	}
	if _, err := journal.ClaimForApplication(eventA, lease(0x11), now, time.Minute); err != nil {
		t.Fatalf("claim after reading: %v", err)
	}
	applied, err := journal.CompleteApplication(eventA, lease(0x11), now)
	if err != nil {
		t.Fatalf("complete after reading: %v", err)
	}
	if applied.Application != StateApplied || applied.ReadAtUnix == 0 {
		t.Fatalf("the two dimensions interfered: %+v", applied)
	}
	// Reading twice is not an error and changes nothing.
	again, err := journal.MarkRead(eventA, now.Add(time.Hour))
	if err != nil {
		t.Fatalf("second read: %v", err)
	}
	if again.ReadAtUnix != applied.ReadAtUnix {
		t.Fatal("a second read moved the timestamp")
	}
}

func TestRejectedEventIsNotOfferedAgain(t *testing.T) {
	journal, _ := openJournal(t)
	if _, _, err := journal.Accept(entry(eventA, endpoint)); err != nil {
		t.Fatalf("accept: %v", err)
	}
	now := time.Unix(int64(acceptAt), 0)
	if _, err := journal.ClaimForApplication(eventA, lease(0x11), now, time.Minute); err != nil {
		t.Fatalf("claim: %v", err)
	}
	rejected, err := journal.RejectApplication(eventA, lease(0x11), fault.CodeContentTooLarge, now)
	if err != nil {
		t.Fatalf("reject: %v", err)
	}
	if rejected.Application != StateRejected || rejected.RejectionCode != fault.CodeContentTooLarge {
		t.Fatalf("unexpected rejection: %+v", rejected)
	}
	if pending, err := journal.ListPending(now.Add(time.Hour), 0); err != nil || len(pending) != 0 {
		t.Fatalf("a rejected event was offered again: %+v %v", pending, err)
	}
	if _, err := journal.RejectApplication(eventA, lease(0x11), fault.CodeInternal, now); !errors.Is(err, ErrNotPending) {
		t.Fatalf("a settled event accepted another outcome: %v", err)
	}
	if _, err := journal.RejectApplication(eventA, lease(0x11), "invented", now); err == nil {
		t.Fatal("an unclassified rejection code was accepted")
	}
}

func TestConflictingRecordIsRefused(t *testing.T) {
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
	// The same identity with different content is a forgery, not a retry.
	substituted := entry(eventA, endpoint)
	substituted.Payload = []byte("different content under the same identifier")
	if _, _, err := journal.Accept(substituted); !errors.Is(err, ErrConflict) {
		t.Fatalf("expected substituted content to be refused, got %v", err)
	}
}

func TestApplicationTransitionsRejectUnusableInput(t *testing.T) {
	journal, _ := openJournal(t)
	now := time.Unix(int64(acceptAt), 0)
	if _, err := journal.ClaimForApplication(eventB, lease(0x11), now, time.Minute); !errors.Is(err, ErrUnknown) {
		t.Fatalf("expected an unknown event, got %v", err)
	}
	if _, err := journal.MarkRead(eventB, now); !errors.Is(err, ErrUnknown) {
		t.Fatalf("expected an unknown event, got %v", err)
	}
	if _, _, err := journal.Accept(entry(eventA, endpoint)); err != nil {
		t.Fatalf("accept: %v", err)
	}
	if _, err := journal.ClaimForApplication(eventA, "lease_bad", now, time.Minute); err == nil {
		t.Fatal("an invalid lease identifier was accepted")
	}
	if _, err := journal.ClaimForApplication(eventA, lease(0x11), now, 0); err == nil {
		t.Fatal("a zero lease was accepted")
	}
	if _, err := journal.ClaimForApplication(eventA, lease(0x11), now, 2*time.Hour); err == nil {
		t.Fatal("an unbounded lease was accepted")
	}
	if _, err := journal.CompleteApplication(eventA, lease(0x11), now); !errors.Is(err, ErrNotPending) {
		t.Fatalf("an unclaimed event was completed: %v", err)
	}
}

func TestInvalidEntriesAreRejected(t *testing.T) {
	journal, _ := openJournal(t)
	cases := map[string]func(*Entry){
		"bad event":     func(e *Entry) { e.EventID = "evt_bad" },
		"bad endpoint":  func(e *Entry) { e.SenderEndpointID = "mep_bad" },
		"bad conv":      func(e *Entry) { e.ConversationID = "conv_bad" },
		"no payload":    func(e *Entry) { e.Payload = nil },
		"huge payload":  func(e *Entry) { e.Payload = bytes.Repeat([]byte{1}, MaxPayloadBytes+1) },
		"zero received": func(e *Entry) { e.ReceivedAtUnix = 0 },
		"no admission":  func(e *Entry) { e.Admission = "" },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			candidate := entry(eventA, endpoint)
			mutate(&candidate)
			if _, _, err := journal.Accept(candidate); err == nil {
				t.Fatalf("expected %q to be rejected", name)
			}
		})
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
	replacement, err := Open(root)
	if err != nil {
		t.Fatalf("expected ownership to be released on close: %v", err)
	}
	defer replacement.Close()
}

func TestCanonicalStateMarkerIsPrivateAndRestartStable(t *testing.T) {
	root := filepath.Join(t.TempDir(), "state")
	journal, err := Open(root)
	if err != nil {
		t.Fatal(err)
	}
	if err := journal.Close(); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(root, canonicalStateMarkerName)
	raw, err := os.ReadFile(path)
	if err != nil || string(raw) != canonicalStateMarker {
		t.Fatalf("unexpected canonical state marker: %q %v", raw, err)
	}
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0o600 {
		t.Fatalf("canonical state marker is not a private regular file: %v %v", info, err)
	}
	reopened, err := Open(root)
	if err != nil {
		t.Fatalf("reopen marked state: %v", err)
	}
	defer reopened.Close()
}

func TestUnmarkedOrSubstitutedStateIsRefusedWithoutMutation(t *testing.T) {
	t.Run("legacy nonempty root", func(t *testing.T) {
		root := filepath.Join(t.TempDir(), "state")
		if err := os.Mkdir(root, 0o700); err != nil {
			t.Fatal(err)
		}
		legacy := filepath.Join(root, "legacy.json")
		if err := os.WriteFile(legacy, []byte("legacy\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := Open(root); err == nil || !strings.Contains(err.Error(), "explicit state migration") {
			t.Fatalf("unmarked state was not refused: %v", err)
		}
		if raw, err := os.ReadFile(legacy); err != nil || string(raw) != "legacy\n" {
			t.Fatalf("legacy state was changed: %q %v", raw, err)
		}
		if _, err := os.Lstat(filepath.Join(root, canonicalStateMarkerName)); !errors.Is(err, os.ErrNotExist) {
			t.Fatal("a failed open marked legacy state as migrated")
		}
	})

	for name, setup := range map[string]func(string) error{
		"future generation": func(path string) error {
			return os.WriteFile(path, []byte("tos.messaging.canonical-network-preimages.v999\n"), 0o600)
		},
		"public marker": func(path string) error {
			if err := os.WriteFile(path, []byte(canonicalStateMarker), 0o600); err != nil {
				return err
			}
			return os.Chmod(path, 0o644)
		},
		"symlink": func(path string) error {
			return os.Symlink("missing", path)
		},
	} {
		t.Run(name, func(t *testing.T) {
			root := filepath.Join(t.TempDir(), "state")
			if err := os.Mkdir(root, 0o700); err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(root, canonicalStateMarkerName)
			if err := setup(path); err != nil {
				t.Fatal(err)
			}
			if _, err := Open(root); err == nil {
				t.Fatal("substituted canonical state marker was accepted")
			}
		})
	}
}

func TestClosedJournalRefusesWork(t *testing.T) {
	journal, _ := openJournal(t)
	if err := journal.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	now := time.Unix(int64(acceptAt), 0)
	if _, _, err := journal.Accept(entry(eventA, endpoint)); err == nil {
		t.Fatal("expected a closed journal to refuse records")
	}
	if _, err := journal.ListPending(now, 0); err == nil {
		t.Fatal("expected a closed journal to refuse a sweep")
	}
	if _, err := journal.ClaimForApplication(eventA, lease(0x11), now, time.Minute); err == nil {
		t.Fatal("expected a closed journal to refuse a claim")
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
		t.Fatal("expected a corrupt record to fail closed instead of granting a fresh record")
	}
	if _, _, err := journal.Lookup(eventA); err == nil {
		t.Fatal("expected a corrupt record to fail closed on lookup")
	}
}

// Content that no longer matches its stored digest is not usable, whatever the
// rest of the record says.
func TestTamperedPayloadIsRefused(t *testing.T) {
	journal, root := openJournal(t)
	if _, _, err := journal.Accept(entry(eventA, endpoint)); err != nil {
		t.Fatalf("accept: %v", err)
	}
	path := filepath.Join(root, "inbound", eventA[len("evt_"):]+".json")
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	tampered := strings.Replace(string(raw), base64.StdEncoding.EncodeToString([]byte(`{"event":"`+eventA+`"}`)),
		base64.StdEncoding.EncodeToString([]byte(`{"event":"substituted"}`)), 1)
	if tampered == string(raw) {
		t.Fatal("the test did not modify the payload")
	}
	if err := os.WriteFile(path, []byte(tampered), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	if _, _, err := journal.Lookup(eventA); err == nil {
		t.Fatal("a payload that no longer matches its digest was accepted")
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
		SessionID:           session(0x11),
		RecipientEndpointID: endpoint,
		ConversationID:      convo,
		Payload:             []byte(`{"outbound":"` + eventID + `"}`),
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
	if _, err := journal.Failed(eventA, claim(t, journal, eventA, 0x40, time.Unix(int64(acceptAt), 0)), fault.CodeUnreachable, time.Unix(int64(acceptAt), 0)); err != nil {
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

	delivery, err := journal.Failed(eventA, claim(t, journal, eventA, 0x40, now), fault.CodeUnreachable, now)
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
	permanent, err := journal.Failed(eventB, claim(t, journal, eventB, 0x40, now), fault.CodeOversized, now)
	if err != nil {
		t.Fatalf("failed: %v", err)
	}
	if permanent.State != StateAbandoned || permanent.NextAttemptAtUnix != 0 {
		t.Fatalf("a permanent failure stayed queued: %+v", permanent)
	}
	// An abandoned delivery cannot even be claimed, let alone settled again.
	if _, err := journal.ClaimForSend(eventB, attempt(0x44), now, time.Minute); !errors.Is(err, ErrNotPending) {
		t.Fatalf("an abandoned delivery was claimed: %v", err)
	}
	if _, err := journal.Failed(eventB, attempt(0x40), fault.CodeUnreachable, now); !errors.Is(err, ErrNotPending) {
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
	held, err := journal.Failed(eventA, claim(t, journal, eventA, 0x40, now), fault.CodeApprovalRequired, now)
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
	if _, err := journal.Failed(eventA, claim(t, journal, eventA, 0x40, now), fault.CodeUnreachable, now); err != nil {
		t.Fatalf("failed: %v", err)
	}
	due, err = journal.Due(now)
	if err != nil {
		t.Fatalf("due: %v", err)
	}
	if len(due) != 1 || due[0].EventID != eventB {
		t.Fatalf("a backed-off delivery was swept again: %+v", due)
	}
	if _, err := journal.Delivered(eventB, claim(t, journal, eventB, 0x41, now), now); err != nil {
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
	delivery, err := journal.Failed(eventA, claim(t, journal, eventA, 0x40, past), fault.CodeUnreachable, past)
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
	settled, err := journal.Failed(eventB, claim(t, journal, eventB, 0x42, time.Unix(int64(acceptAt), 0)), fault.CodeUnreachable, time.Unix(int64(acceptAt), 0))
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
	if _, err := journal.ClaimForSend(eventA, attempt(0x40), now, time.Minute); !errors.Is(err, ErrUnknown) {
		t.Fatalf("expected an unknown delivery, got %v", err)
	}
	if _, err := journal.Failed(eventA, attempt(0x40), fault.CodeUnreachable, now); !errors.Is(err, ErrUnknown) {
		t.Fatalf("expected an unknown delivery, got %v", err)
	}
	if _, err := journal.Delivered(eventA, attempt(0x41), now); !errors.Is(err, ErrUnknown) {
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
	if _, err := journal.ClaimForApplication(eventA, lease(0x11), now, time.Minute); err != nil {
		t.Fatalf("claim: %v", err)
	}
	if _, err := journal.CompleteApplication(eventA, lease(0x11), now); err != nil {
		t.Fatalf("complete: %v", err)
	}
	if _, _, err := journal.Enqueue(outbound(eventA)); err != nil {
		t.Fatalf("enqueue: %v", err)
	}
	if _, _, err := journal.Enqueue(outbound(eventB)); err != nil {
		t.Fatalf("enqueue: %v", err)
	}
	if _, err := journal.Delivered(eventB, claim(t, journal, eventB, 0x41, now), now); err != nil {
		t.Fatalf("delivered: %v", err)
	}

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
		t.Fatalf("the finished event was not pruned: %+v", report)
	}
	if report.DeliveriesRemoved != 1 {
		t.Fatalf("the settled delivery was not pruned: %+v", report)
	}
	if _, found, err := journal.LookupDelivery(eventA); err != nil || !found {
		t.Fatalf("a pending delivery was pruned: found=%v err=%v", found, err)
	}
	if _, found, err := journal.Lookup(eventA); err != nil || found {
		t.Fatalf("the finished record survived its retention: found=%v err=%v", found, err)
	}
}

// An event nobody has processed is not history, however old it is. Pruning it
// would delete a message that was accepted and never delivered, which is the
// failure the journal exists to prevent.
func TestPruneNeverRemovesUnprocessedEvents(t *testing.T) {
	journal, _ := openJournal(t)
	now := time.Unix(int64(acceptAt), 0)
	if _, _, err := journal.Accept(entry(eventA, endpoint)); err != nil {
		t.Fatalf("accept: %v", err)
	}
	if _, _, err := journal.Accept(entry(eventB, endpoint)); err != nil {
		t.Fatalf("accept: %v", err)
	}
	if _, err := journal.ClaimForApplication(eventB, lease(0x11), now, time.Minute); err != nil {
		t.Fatalf("claim: %v", err)
	}

	long := now.Add(10 * MinClaimRetention)
	report, err := journal.Prune(long, MinClaimRetention)
	if err != nil {
		t.Fatalf("prune: %v", err)
	}
	if report.ClaimsRemoved != 0 {
		t.Fatalf("unprocessed events were pruned: %+v", report)
	}
	pending, err := journal.ListPending(long, 0)
	if err != nil {
		t.Fatalf("pending: %v", err)
	}
	if len(pending) != 2 {
		t.Fatalf("expected both events to still be deliverable, got %d", len(pending))
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
	if _, err := journal.Failed(eventA, claim(t, journal, eventA, 0x43, time.Unix(int64(acceptAt), 0)), fault.CodeRateLimited, time.Unix(int64(acceptAt), 0)); err != nil {
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

// Without an attempt nothing settles an outbound event, so an install with no
// transport would accumulate records past their expiry that are never swept
// and never pruned.
func TestExpiredDeliveriesAreSettledWithoutAnAttempt(t *testing.T) {
	journal, _ := openJournal(t)
	now := time.Unix(int64(acceptAt), 0)

	short := outbound(eventA)
	short.ExpiresAtUnix = acceptAt + 60
	if _, _, err := journal.Enqueue(short); err != nil {
		t.Fatalf("enqueue: %v", err)
	}
	long := outbound(eventB)
	if _, _, err := journal.Enqueue(long); err != nil {
		t.Fatalf("enqueue: %v", err)
	}

	if expired, err := journal.ExpireDeliveries(now); err != nil || expired != 0 {
		t.Fatalf("a live delivery was expired: %d %v", expired, err)
	}

	past := time.Unix(int64(short.ExpiresAtUnix)+1, 0)
	expired, err := journal.ExpireDeliveries(past)
	if err != nil {
		t.Fatalf("expire: %v", err)
	}
	if expired != 1 {
		t.Fatalf("expected one expiry, got %d", expired)
	}
	settled, found, err := journal.LookupDelivery(eventA)
	if err != nil || !found {
		t.Fatalf("lookup: found=%v err=%v", found, err)
	}
	if settled.State != StateAbandoned || settled.SettledAtUnix == 0 || settled.LastCode == "" {
		t.Fatalf("an expired delivery was not settled with a reason: %+v", settled)
	}
	if live, _, err := journal.LookupDelivery(eventB); err != nil || live.State != StatePending {
		t.Fatalf("a live delivery was settled: %+v %v", live, err)
	}

	// And it can now be pruned, which it could not be while it sat pending.
	report, err := journal.Prune(past.Add(MinClaimRetention+time.Hour), MinClaimRetention)
	if err != nil {
		t.Fatalf("prune: %v", err)
	}
	if report.DeliveriesRemoved != 1 {
		t.Fatalf("the settled delivery was not pruned: %+v", report)
	}
}

// A held delivery expires too. Waiting on a person is not a reason to wait
// past the point the event itself said it stops mattering.
func TestHeldDeliveriesAlsoExpire(t *testing.T) {
	journal, _ := openJournal(t)
	now := time.Unix(int64(acceptAt), 0)
	request := outbound(eventA)
	request.ExpiresAtUnix = acceptAt + 60
	if _, _, err := journal.Enqueue(request); err != nil {
		t.Fatalf("enqueue: %v", err)
	}
	if _, err := journal.Failed(eventA, claim(t, journal, eventA, 0x40, now), fault.CodeApprovalRequired, now); err != nil {
		t.Fatalf("hold: %v", err)
	}
	if expired, err := journal.ExpireDeliveries(time.Unix(int64(request.ExpiresAtUnix)+1, 0)); err != nil || expired != 1 {
		t.Fatalf("a held delivery outlived its expiry: %d %v", expired, err)
	}
}
