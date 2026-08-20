package eventlog

import (
	"errors"
	"testing"
	"time"

	"github.com/tosnetwork/tos-messenger/pkg/identity"
	"github.com/tosnetwork/tos-messenger/pkg/room"
)

func rolePolicy(t *testing.T, membership room.Membership, delegation identity.Delegation, revision uint64, assignments []room.RoleAssignment, now time.Time) room.RolePolicy {
	t.Helper()
	_, key := roomDelegation(t, delegation.AgentID, 0x51)
	policy, err := room.SignRolePolicy(room.RolePolicy{
		Network: delegation.Network, RoomID: membership.RoomID, MembershipEpoch: membership.Epoch,
		MembershipDigest: membership.Digest, Revision: revision, Assignments: assignments,
		Authority:    room.Authority{AgentID: delegation.AgentID, EndpointID: delegation.EndpointID},
		IssuedAtUnix: uint64(now.Unix() - 1), ExpiresAtUnix: uint64(now.Unix() + 60),
	}, key)
	if err != nil {
		t.Fatal(err)
	}
	return policy
}

func TestRoomRoleLedgerPersistsAndInvalidatesRolesOnMembershipChange(t *testing.T) {
	rooms, journal, root := openRoomLedger(t)
	now := time.Unix(1_800_000_000, 0)
	delegation, _ := roomDelegation(t, roomAgent(1), 0x51)
	founded := mustFound(t, roomAgent(1), roomAgent(2), roomAgent(3))
	if _, err := advanceRoom(t, rooms, founded, 1, now); err != nil {
		t.Fatal(err)
	}
	roles, err := journal.OpenRoomRoles()
	if err != nil {
		t.Fatal(err)
	}
	first := rolePolicy(t, founded, delegation, 1, []room.RoleAssignment{
		{AgentID: roomAgent(1), Role: room.RoleAdministrator},
		{AgentID: roomAgent(2), Role: room.RoleModerator},
	}, now)
	if _, err := roles.Advance(first, delegation, now); err != nil {
		t.Fatal(err)
	}
	allowed, err := roles.AllowsCurrent(ledgerRoom, roomAgent(2), room.ActionModerate, delegation, now)
	if err != nil || !allowed {
		t.Fatalf("moderator permission: allowed=%v err=%v", allowed, err)
	}
	if err := journal.Close(); err != nil {
		t.Fatal(err)
	}

	reopened, err := Open(root)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	rooms, err = reopened.OpenRooms()
	if err != nil {
		t.Fatal(err)
	}
	roles, err = reopened.OpenRoomRoles()
	if err != nil {
		t.Fatal(err)
	}
	allowed, err = roles.AllowsCurrent(ledgerRoom, roomAgent(2), room.ActionModerate, delegation, now)
	if err != nil || !allowed {
		t.Fatalf("permission after restart: allowed=%v err=%v", allowed, err)
	}

	removed, err := founded.Remove([]string{roomAgent(2)})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := advanceRoom(t, rooms, removed, 1, now); err != nil {
		t.Fatal(err)
	}
	if allowed, err = roles.AllowsCurrent(ledgerRoom, roomAgent(2), room.ActionModerate, delegation, now); err == nil || allowed {
		t.Fatalf("stale role survived removal: allowed=%v err=%v", allowed, err)
	}
	second := rolePolicy(t, removed, delegation, 2, []room.RoleAssignment{{AgentID: roomAgent(1), Role: room.RoleAdministrator}}, now)
	if _, err := roles.Advance(second, delegation, now); err != nil {
		t.Fatal(err)
	}
	if allowed, err = roles.AllowsCurrent(ledgerRoom, roomAgent(2), room.ActionPost, delegation, now); err != nil || allowed {
		t.Fatalf("removed member authorization: allowed=%v err=%v", allowed, err)
	}
	if allowed, err = roles.AllowsCurrent(ledgerRoom, roomAgent(3), room.ActionPost, delegation, now); err != nil || !allowed {
		t.Fatalf("remaining member authorization: allowed=%v err=%v", allowed, err)
	}
}

func TestRoomRoleLedgerRefusesRevisionRollbackAndGap(t *testing.T) {
	rooms, journal, _ := openRoomLedger(t)
	defer journal.Close()
	now := time.Unix(1_800_000_000, 0)
	delegation, _ := roomDelegation(t, roomAgent(1), 0x51)
	founded := mustFound(t, roomAgent(1), roomAgent(2))
	if _, err := advanceRoom(t, rooms, founded, 1, now); err != nil {
		t.Fatal(err)
	}
	roles, err := journal.OpenRoomRoles()
	if err != nil {
		t.Fatal(err)
	}
	assignments := []room.RoleAssignment{{AgentID: roomAgent(1), Role: room.RoleAdministrator}}
	first := rolePolicy(t, founded, delegation, 1, assignments, now)
	if _, err := roles.Advance(first, delegation, now); err != nil {
		t.Fatal(err)
	}
	if _, err := roles.Advance(first, delegation, now); !errors.Is(err, ErrRoomRoleRollback) {
		t.Fatalf("rollback returned %v", err)
	}
	gap := rolePolicy(t, founded, delegation, 3, assignments, now)
	if _, err := roles.Advance(gap, delegation, now); !errors.Is(err, ErrRoomRoleGap) {
		t.Fatalf("gap returned %v", err)
	}
}
