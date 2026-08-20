package eventlog

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/tosnetwork/tos-messenger/pkg/identity"
	"github.com/tosnetwork/tos-messenger/pkg/room"
	nativev1 "github.com/tosnetwork/tos-service-protocol/gen/tos/service/v1"
)

func TestRoomAuthorityDelegationSurvivesRestartAndDamageFailsClosed(t *testing.T) {
	ledger, journal, root := openRoomLedger(t)
	now := time.Unix(1_800_000_000, 0)
	delegation, _ := roomDelegation(t, roomAgent(1), 0x51)
	founded := mustFound(t, roomAgent(1), roomAgent(2))
	if _, err := advanceRoom(t, ledger, founded, 1, now); err != nil {
		t.Fatal(err)
	}
	if err := journal.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := Open(root)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	ledger, _ = reopened.OpenRooms()
	stored, found, err := ledger.CurrentAuthorityDelegation(ledgerRoom)
	if err != nil || !found || stored.AgentID != delegation.AgentID ||
		stored.EndpointID != delegation.EndpointID || !bytes.Equal(stored.IdentityPublicKey, delegation.IdentityPublicKey) {
		t.Fatalf("authority delegation: found=%v stored=%+v err=%v", found, stored, err)
	}
	record, _, err := ledger.read(ledgerRoom)
	if err != nil {
		t.Fatal(err)
	}
	record.AuthorityDelegationJSON = []byte(`{}`)
	raw, _ := json.Marshal(record)
	if err := os.WriteFile(ledger.path(ledgerRoom), raw, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := ledger.CurrentAuthorityDelegation(ledgerRoom); err == nil {
		t.Fatal("damaged authority delegation remained usable")
	}
}

var ledgerRoom = "room_" + strings.Repeat("e", 64)

func roomAgent(seed byte) string {
	return "agent_" + strings.Repeat(string("0123456789abcdef"[seed%16]), 64)
}

func membershipAuthorization(t *testing.T, membership room.Membership, delegation identity.Delegation, key ed25519.PrivateKey, now time.Time) room.MembershipAuthorization {
	t.Helper()
	value, err := room.SignMembershipAuthorization(room.MembershipAuthorization{
		Network: delegation.Network, RoomID: membership.RoomID, Epoch: membership.Epoch,
		MembershipDigest: membership.Digest,
		Authority:        room.Authority{AgentID: delegation.AgentID, EndpointID: delegation.EndpointID},
		IssuedAtUnix:     uint64(now.Unix() - 1), ExpiresAtUnix: uint64(now.Unix() + 60),
	}, key)
	if err != nil {
		t.Fatal(err)
	}
	return value
}

func advanceRoom(t *testing.T, ledger *RoomLedger, membership room.Membership, authoritySeed byte, now time.Time) (RoomTransition, error) {
	t.Helper()
	delegation, key := roomDelegation(t, roomAgent(authoritySeed), 0x50+authoritySeed)
	return ledger.Advance(membership, membershipAuthorization(t, membership, delegation, key, now), delegation, now)
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
	transition, err := advanceRoom(t, ledger, founded, 1, now)
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
	transition, err = advanceRoom(t, ledger, added, 1, now)
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
	if _, err := advanceRoom(t, ledger, founded, 1, now); err != nil {
		t.Fatalf("found: %v", err)
	}
	removed, err := founded.Remove([]string{roomAgent(2)})
	if err != nil {
		t.Fatalf("remove: %v", err)
	}
	transition, err := advanceRoom(t, ledger, removed, 1, now)
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
	if _, err := advanceRoom(t, ledger2, founded, 1, now); err != ErrRoomRollback {
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
	if _, err := advanceRoom(t, ledger, founded, 1, now); err != nil {
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
	if _, err := advanceRoom(t, ledger, jumped, 1, now); err != ErrRoomGap {
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
	if _, err := advanceRoom(t, ledger, added, 1, now); err == nil {
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
	if _, err := advanceRoom(t, ledger, founded, 1, now); err != nil {
		t.Fatalf("found: %v", err)
	}
	added, err := founded.Add([]string{roomAgent(3)})
	if err != nil {
		t.Fatalf("add: %v", err)
	}
	if _, err := advanceRoom(t, ledger, added, 1, now); err != nil {
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
	if _, err := advanceRoom(t, ledger, founded, 1, now); err != nil {
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
	if _, err := advanceRoom(t, ledger, next, 1, now); err != nil {
		t.Fatalf("advance derived successor: %v", err)
	}
}

func roomDelegation(t *testing.T, agentID string, seed byte) (identity.Delegation, ed25519.PrivateKey) {
	t.Helper()
	network := &nativev1.NetworkDomain{NetworkId: "tos-local", GenesisRootHash: strings.Repeat("a", 64), GenesisFileHash: strings.Repeat("b", 64)}
	key := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{seed}, ed25519.SeedSize))
	endpointID, err := identity.DeriveEndpointID(network, agentID, key.Public().(ed25519.PublicKey))
	if err != nil {
		t.Fatal(err)
	}
	return identity.Delegation{Network: network, AgentID: agentID, EndpointID: endpointID,
		IdentityPublicKey: key.Public().(ed25519.PublicKey), AllowedProtocolVersions: []uint32{1},
		AllowedOutboundEventClasses: []string{"room"}, NotBeforeUnix: 1, ExpiresAtUnix: 2_000_000_000,
		MaximumSessionLifetimeSeconds: 3600, ContactDescriptorPolicyDigest: "sha256:" + strings.Repeat("c", 64),
		InboxAdmissionPolicyDigest: "sha256:" + strings.Repeat("d", 64)}, key
}

func TestRoomLedgerEnforcesAndPersistsSignedAuthorityTransfer(t *testing.T) {
	ledger, journal, root := openRoomLedger(t)
	now := time.Unix(250, 0)
	fromDelegation, fromKey := roomDelegation(t, roomAgent(1), 0x51)
	toDelegation, _ := roomDelegation(t, roomAgent(2), 0x52)
	from := room.Authority{AgentID: fromDelegation.AgentID, EndpointID: fromDelegation.EndpointID}
	to := room.Authority{AgentID: toDelegation.AgentID, EndpointID: toDelegation.EndpointID}
	founded := mustFound(t, from.AgentID, to.AgentID)
	if _, err := ledger.Advance(founded, membershipAuthorization(t, founded, fromDelegation, fromKey, now), fromDelegation, now); err != nil {
		t.Fatal(err)
	}
	added, err := founded.Add([]string{roomAgent(3)})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ledger.Advance(added, membershipAuthorization(t, added, toDelegation, ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x52}, ed25519.SeedSize)), now), toDelegation, now); err == nil {
		t.Fatal("non-authority advanced membership")
	}
	removedAuthority, err := founded.Remove([]string{from.AgentID})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ledger.Advance(removedAuthority, membershipAuthorization(t, removedAuthority, fromDelegation, fromKey, now), fromDelegation, now); err == nil {
		t.Fatal("authority removed itself without transferring authority")
	}

	next, err := founded.AdvanceForAuthorityTransfer()
	if err != nil {
		t.Fatal(err)
	}
	transfer, err := room.SignAuthorityTransfer(room.AuthorityTransfer{
		Network: fromDelegation.Network, RoomID: founded.RoomID,
		PriorEpoch: founded.Epoch, NextEpoch: next.Epoch,
		PriorMembershipDigest: founded.Digest, NextMembershipDigest: next.Digest,
		From: from, To: to, IssuedAtUnix: 200, ExpiresAtUnix: 300,
	}, fromKey)
	if err != nil {
		t.Fatal(err)
	}
	result, err := ledger.TransferAuthority(next, transfer, fromDelegation, toDelegation, now)
	if err != nil || result.Authority != to || len(result.Joined) != 0 || len(result.Departed) != 0 {
		t.Fatalf("transfer=%+v err=%v", result, err)
	}
	if err := journal.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := Open(root)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	ledger, err = reopened.OpenRooms()
	if err != nil {
		t.Fatal(err)
	}
	current, found, err := ledger.CurrentAuthority(ledgerRoom)
	if err != nil || !found || current != to {
		t.Fatalf("current authority=%+v found=%v err=%v", current, found, err)
	}
	after, err := next.Add([]string{roomAgent(3)})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ledger.Advance(after, membershipAuthorization(t, after, fromDelegation, fromKey, now), fromDelegation, now); err == nil {
		t.Fatal("old authority advanced after restart")
	}
	toKey := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x52}, ed25519.SeedSize))
	if _, err := ledger.Advance(after, membershipAuthorization(t, after, toDelegation, toKey, now), toDelegation, now); err != nil {
		t.Fatalf("new authority could not advance: %v", err)
	}
}
