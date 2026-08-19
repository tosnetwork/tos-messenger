package eventlog

import (
	"strings"
	"testing"
	"time"

	"github.com/tosnetwork/tos-messenger/pkg/room"
)

var ledgerRoom = "room_" + strings.Repeat("e", 64)

func roomAgent(seed byte) string {
	return "agent_" + strings.Repeat(string("0123456789abcdef"[seed%16]), 64)
}

func openRoomLedger(t *testing.T) (*RoomLedger, *Journal, string) {
	t.Helper()
	root := t.TempDir() + "/state"
	journal, err := Open(root)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	ledger, err := journal.OpenRooms()
	if err != nil {
		t.Fatalf("rooms: %v", err)
	}
	return ledger, journal, root
}

func mustFound(t *testing.T, members ...string) room.Membership {
	t.Helper()
	m, err := room.Found(ledgerRoom, members)
	if err != nil {
		t.Fatalf("found: %v", err)
	}
	return m
}

// The ledger records a first epoch, reports joins and departures across a
// transition, and answers membership queries at the recorded epoch.
func TestRoomLedgerAdvancesAndJudges(t *testing.T) {
	ledger, journal, _ := openRoomLedger(t)
	defer journal.Close()
	now := time.Unix(1_800_000_000, 0)

	founded := mustFound(t, roomAgent(1), roomAgent(2))
	transition, err := ledger.Advance(founded, now)
	if err != nil {
		t.Fatalf("found: %v", err)
	}
	if len(transition.Joined) != 2 || len(transition.Departed) != 0 {
		t.Fatalf("founding join/departure wrong: %+v", transition)
	}

	added, err := founded.Add([]string{roomAgent(3)})
	if err != nil {
		t.Fatalf("add: %v", err)
	}
	transition, err = ledger.Advance(added, now)
	if err != nil {
		t.Fatalf("advance add: %v", err)
	}
	if len(transition.Joined) != 1 || transition.Joined[0] != roomAgent(3) {
		t.Fatalf("join not reported: %+v", transition.Joined)
	}

	standing, err := ledger.Judge(ledgerRoom, 2, roomAgent(3))
	if err != nil {
		t.Fatalf("judge: %v", err)
	}
	if standing != RoomMember {
		t.Fatalf("added member judged %q, want member", standing)
	}
	standing, err = ledger.Judge(ledgerRoom, 2, roomAgent(9))
	if err != nil {
		t.Fatalf("judge: %v", err)
	}
	if standing != RoomNotMember {
		t.Fatalf("outsider judged %q, want not-member", standing)
	}
}

// A rollback -- replaying an old epoch to reinstate a removed member -- is
// refused against the durable record, and it survives a restart.
func TestRoomLedgerRefusesRollbackAcrossRestart(t *testing.T) {
	ledger, journal, root := openRoomLedger(t)
	now := time.Unix(1_800_000_000, 0)

	founded := mustFound(t, roomAgent(1), roomAgent(2), roomAgent(3))
	if _, err := ledger.Advance(founded, now); err != nil {
		t.Fatalf("found: %v", err)
	}
	removed, err := founded.Remove([]string{roomAgent(2)})
	if err != nil {
		t.Fatalf("remove: %v", err)
	}
	transition, err := ledger.Advance(removed, now)
	if err != nil {
		t.Fatalf("advance remove: %v", err)
	}
	if len(transition.Departed) != 1 || transition.Departed[0] != roomAgent(2) {
		t.Fatalf("departure not reported: %+v", transition.Departed)
	}

	if err := journal.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	reopened, err := Open(root)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	defer reopened.Close()
	ledger2, err := reopened.OpenRooms()
	if err != nil {
		t.Fatalf("rooms: %v", err)
	}

	// Replaying the founding epoch would bring roomAgent(2) back. It is refused
	// as a rollback because its epoch is at or below the record.
	if _, err := ledger2.Advance(founded, now); err != ErrRoomRollback {
		t.Fatalf("rollback returned %v, want ErrRoomRollback", err)
	}
	// The removed member is still gone at the recorded epoch.
	standing, err := ledger2.Judge(ledgerRoom, 2, roomAgent(2))
	if err != nil {
		t.Fatalf("judge: %v", err)
	}
	if standing != RoomNotMember {
		t.Fatalf("removed member judged %q after restart, want not-member", standing)
	}
}

// A gap -- an epoch beyond the next -- is refused, because the ledger derives
// each successor from the member set of the epoch before it and cannot verify a
// jump it never saw.
func TestRoomLedgerRefusesGap(t *testing.T) {
	ledger, journal, _ := openRoomLedger(t)
	defer journal.Close()
	now := time.Unix(1_800_000_000, 0)

	founded := mustFound(t, roomAgent(1), roomAgent(2))
	if _, err := ledger.Advance(founded, now); err != nil {
		t.Fatalf("found: %v", err)
	}
	added, err := founded.Add([]string{roomAgent(3)})
	if err != nil {
		t.Fatalf("add: %v", err)
	}
	jumped, err := added.Add([]string{roomAgent(4)}) // epoch 3, skipping 2
	if err != nil {
		t.Fatalf("second add: %v", err)
	}
	if _, err := ledger.Advance(jumped, now); err != ErrRoomGap {
		t.Fatalf("gap returned %v, want ErrRoomGap", err)
	}
}

// A first sight at an epoch other than 1 is refused.
func TestRoomLedgerFirstEpochMustBeOne(t *testing.T) {
	ledger, journal, _ := openRoomLedger(t)
	defer journal.Close()
	now := time.Unix(1_800_000_000, 0)

	founded := mustFound(t, roomAgent(1), roomAgent(2))
	added, err := founded.Add([]string{roomAgent(3)}) // epoch 2
	if err != nil {
		t.Fatalf("add: %v", err)
	}
	if _, err := ledger.Advance(added, now); err == nil {
		t.Fatal("a first sight at epoch 2 was accepted")
	}
}

// Judge reports stale for an epoch behind the record and ahead for one past it;
// both mean "resynchronise" rather than a membership guess.
func TestRoomLedgerJudgeStaleAndAhead(t *testing.T) {
	ledger, journal, _ := openRoomLedger(t)
	defer journal.Close()
	now := time.Unix(1_800_000_000, 0)

	founded := mustFound(t, roomAgent(1), roomAgent(2))
	if _, err := ledger.Advance(founded, now); err != nil {
		t.Fatalf("found: %v", err)
	}
	added, err := founded.Add([]string{roomAgent(3)})
	if err != nil {
		t.Fatalf("add: %v", err)
	}
	if _, err := ledger.Advance(added, now); err != nil {
		t.Fatalf("advance: %v", err)
	}
	// Record is at epoch 2.
	stale, err := ledger.Judge(ledgerRoom, 1, roomAgent(1))
	if err != nil {
		t.Fatalf("judge: %v", err)
	}
	if stale != RoomStale {
		t.Fatalf("epoch 1 judged %q, want stale", stale)
	}
	ahead, err := ledger.Judge(ledgerRoom, 3, roomAgent(1))
	if err != nil {
		t.Fatalf("judge: %v", err)
	}
	if ahead != RoomAhead {
		t.Fatalf("epoch 3 judged %q, want ahead", ahead)
	}
	unknown, err := ledger.Judge("room_"+strings.Repeat("f", 64), 1, roomAgent(1))
	if err != nil {
		t.Fatalf("judge: %v", err)
	}
	if unknown != RoomUnknown {
		t.Fatalf("unknown room judged %q, want unknown", unknown)
	}
}

// Current reconstructs a membership the caller can derive the next epoch from.
func TestRoomLedgerCurrentDrivesNextEpoch(t *testing.T) {
	ledger, journal, _ := openRoomLedger(t)
	defer journal.Close()
	now := time.Unix(1_800_000_000, 0)

	founded := mustFound(t, roomAgent(1), roomAgent(2))
	if _, err := ledger.Advance(founded, now); err != nil {
		t.Fatalf("found: %v", err)
	}
	current, found, err := ledger.Current(ledgerRoom)
	if err != nil || !found {
		t.Fatalf("current: found=%v err=%v", found, err)
	}
	next, err := current.Add([]string{roomAgent(3)})
	if err != nil {
		t.Fatalf("add from current: %v", err)
	}
	if _, err := ledger.Advance(next, now); err != nil {
		t.Fatalf("advance derived successor: %v", err)
	}
}
