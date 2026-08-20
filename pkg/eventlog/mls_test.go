package eventlog

import (
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/tosnetwork/tos-messenger/internal/canon"
	"github.com/tosnetwork/tos-messenger/pkg/group"
	"github.com/tosnetwork/tos-messenger/pkg/room"
)

func mlsLedgerBinding(t *testing.T) group.State {
	t.Helper()
	m, err := room.Found("room_"+strings.Repeat("a", 64), []string{"agent_" + strings.Repeat("1", 64), "agent_" + strings.Repeat("2", 64)})
	if err != nil {
		t.Fatal(err)
	}
	return group.State{RoomID: m.RoomID, Clock: group.Clock{RoomEpoch: 1, MLSEpoch: 0}, MembershipDigest: m.Digest}
}

func TestMLSLedgerWelcomeAndCommitSurviveRestart(t *testing.T) {
	root := t.TempDir() + "/state"
	j, err := Open(root)
	if err != nil {
		t.Fatal(err)
	}
	ledger, err := j.OpenMLS()
	if err != nil {
		t.Fatal(err)
	}
	binding := mlsLedgerBinding(t)
	kp, welcome := canon.Digest([]byte("kp")), canon.Digest([]byte("welcome"))
	if err := ledger.InstallWelcome(binding, []byte("joined opaque state"), kp, welcome, time.Unix(500, 0)); err != nil {
		t.Fatal(err)
	}
	if err := j.Close(); err != nil {
		t.Fatal(err)
	}

	j, err = Open(root)
	if err != nil {
		t.Fatal(err)
	}
	defer j.Close()
	ledger, _ = j.OpenMLS()
	record, found, err := ledger.Current(binding.RoomID)
	if err != nil || !found {
		t.Fatalf("current: %v %v", found, err)
	}
	if state, err := record.State(); err != nil || string(state) != "joined opaque state" {
		t.Fatalf("state: %q %v", state, err)
	}
	if err := ledger.InstallWelcome(binding, []byte("replacement"), kp, canon.Digest([]byte("other-welcome")), time.Unix(501, 0)); !errors.Is(err, ErrKeyPackageConsumed) {
		t.Fatalf("KeyPackage replay: %v", err)
	}
	if err := ledger.InstallWelcome(binding, []byte("replacement"), canon.Digest([]byte("other-kp")), welcome, time.Unix(501, 0)); !errors.Is(err, ErrWelcomeReplay) {
		t.Fatalf("Welcome replay: %v", err)
	}
}

func TestMLSLedgerKeyPackageIsOneTimeAcrossRooms(t *testing.T) {
	j, err := Open(t.TempDir() + "/state")
	if err != nil {
		t.Fatal(err)
	}
	defer j.Close()
	ledger, _ := j.OpenMLS()
	first := mlsLedgerBinding(t)
	kp := canon.Digest([]byte("global-one-time-kp"))
	if err := ledger.InstallWelcome(first, []byte("first room state"), kp, canon.Digest([]byte("welcome-1")), time.Unix(500, 0)); err != nil {
		t.Fatal(err)
	}
	second := first
	second.RoomID = "room_" + strings.Repeat("b", 64)
	m, err := room.Found(second.RoomID, []string{"agent_" + strings.Repeat("1", 64), "agent_" + strings.Repeat("2", 64)})
	if err != nil {
		t.Fatal(err)
	}
	second.MembershipDigest = m.Digest
	if err := ledger.InstallWelcome(second, []byte("second room state"), kp, canon.Digest([]byte("welcome-2")), time.Unix(501, 0)); !errors.Is(err, ErrKeyPackageConsumed) {
		t.Fatalf("cross-room KeyPackage reuse: %v", err)
	}
}

func TestMLSLedgerRejectsGapRollbackAndCompetingChild(t *testing.T) {
	j, err := Open(t.TempDir() + "/state")
	if err != nil {
		t.Fatal(err)
	}
	defer j.Close()
	ledger, _ := j.OpenMLS()
	initial := mlsLedgerBinding(t)
	if err := ledger.InstallWelcome(initial, []byte("epoch zero"), canon.Digest([]byte("kp")), canon.Digest([]byte("welcome")), time.Unix(500, 0)); err != nil {
		t.Fatal(err)
	}
	commit1 := canon.Digest([]byte("commit-1"))
	next := group.State{RoomID: initial.RoomID, Clock: group.Clock{RoomEpoch: 1, MLSEpoch: 1}, MembershipDigest: initial.MembershipDigest, AcceptedCommitRef: commit1}
	transition := group.Transition{Prior: initial, Next: next, CommitRef: commit1}
	if fresh, err := ledger.Advance(transition, []byte("epoch one"), time.Unix(501, 0)); err != nil || !fresh {
		t.Fatalf("advance: %v %v", fresh, err)
	}
	if fresh, err := ledger.Advance(transition, []byte("epoch one"), time.Unix(502, 0)); err != nil || fresh {
		t.Fatalf("idempotent replay: %v %v", fresh, err)
	}
	if _, err := ledger.Advance(transition, []byte("different state"), time.Unix(502, 0)); !errors.Is(err, ErrMLSFork) {
		t.Fatalf("conflicting replay: %v", err)
	}

	competingRef := canon.Digest([]byte("competing"))
	competing := group.Transition{Prior: initial, Next: group.State{RoomID: initial.RoomID, Clock: group.Clock{RoomEpoch: 1, MLSEpoch: 1}, MembershipDigest: initial.MembershipDigest, AcceptedCommitRef: competingRef}, CommitRef: competingRef}
	if _, err := ledger.Advance(competing, []byte("other child"), time.Unix(503, 0)); !errors.Is(err, ErrMLSFork) {
		t.Fatalf("competing child: %v", err)
	}
	gapRef := canon.Digest([]byte("gap"))
	gap := group.Transition{Prior: next, Next: group.State{RoomID: initial.RoomID, Clock: group.Clock{RoomEpoch: 1, MLSEpoch: 3}, MembershipDigest: initial.MembershipDigest, AcceptedCommitRef: gapRef}, CommitRef: gapRef}
	// The application validator catches the gap before storage.
	if _, err := ledger.Advance(gap, []byte("epoch three"), time.Unix(504, 0)); err == nil {
		t.Fatal("epoch gap accepted")
	}
}

func TestMLSLedgerDetectsStateTampering(t *testing.T) {
	root := t.TempDir() + "/state"
	j, err := Open(root)
	if err != nil {
		t.Fatal(err)
	}
	ledger, _ := j.OpenMLS()
	binding := mlsLedgerBinding(t)
	if err := ledger.InstallWelcome(binding, []byte("authentic"), canon.Digest([]byte("kp")), canon.Digest([]byte("welcome")), time.Unix(500, 0)); err != nil {
		t.Fatal(err)
	}
	path := ledger.path(binding.RoomID)
	if err := j.Close(); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	mutated := strings.Replace(string(raw), "YXV0aGVudGlj", "Zm9yZ2VyeSE=", 1)
	if err := os.WriteFile(path, []byte(mutated), 0o600); err != nil {
		t.Fatal(err)
	}
	j, err = Open(root)
	if err != nil {
		t.Fatal(err)
	}
	defer j.Close()
	ledger, _ = j.OpenMLS()
	if _, _, err := ledger.Current(binding.RoomID); err == nil {
		t.Fatal("tampered MLS state accepted")
	}
}
