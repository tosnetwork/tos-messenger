package eventlog

import (
	"errors"
	"os"
	"path/filepath"
	"time"

	"github.com/tosnetwork/tos-messenger/internal/ids"
	"github.com/tosnetwork/tos-messenger/pkg/identity"
	"github.com/tosnetwork/tos-messenger/pkg/room"
)

var (
	ErrRoomRoleRollback = errors.New("the room role-policy revision regressed")
	ErrRoomRoleGap      = errors.New("the room role-policy revision skipped an unseen transition")
)

// RoomRoleLedger persists the authority-signed elevated powers for each room.
// It shares the Journal's sole writer and lock with membership: readers can
// never obtain a role policy from a different process racing the room epoch.
type RoomRoleLedger struct{ journal *Journal }

func (j *Journal) OpenRoomRoles() (*RoomRoleLedger, error) {
	if err := j.usable(); err != nil {
		return nil, err
	}
	return &RoomRoleLedger{journal: j}, nil
}

// Advance verifies and durably records exactly the next role revision. A
// membership transition does not copy roles forward; the last policy remains
// readable as evidence but fails current-membership verification until the
// authority signs a fresh revision for the new epoch.
func (l *RoomRoleLedger) Advance(policy room.RolePolicy, delegation identity.Delegation, now time.Time) (room.RolePolicy, error) {
	if l == nil || l.journal == nil {
		return room.RolePolicy{}, errors.New("no room role ledger")
	}
	if err := l.journal.usable(); err != nil {
		return room.RolePolicy{}, err
	}
	if now.IsZero() || now.Unix() < 0 {
		return room.RolePolicy{}, errors.New("invalid room role-policy time")
	}
	l.journal.mutex.Lock()
	defer l.journal.mutex.Unlock()

	record, found, err := (&RoomLedger{journal: l.journal}).read(policy.RoomID)
	if err != nil {
		return room.RolePolicy{}, err
	}
	if !found {
		return room.RolePolicy{}, errors.New("cannot assign roles for an unknown room")
	}
	membership := room.Membership{RoomID: record.RoomID, Epoch: record.Epoch, Members: record.Members, Digest: record.MembershipDigest}
	authority := room.Authority{AgentID: record.AuthorityAgentID, EndpointID: record.AuthorityEndpointID}
	if err := room.VerifyRolePolicy(policy, membership, authority, delegation, now); err != nil {
		return room.RolePolicy{}, err
	}

	prior, priorFound, err := l.read(policy.RoomID)
	if err != nil {
		return room.RolePolicy{}, err
	}
	if !priorFound {
		if policy.Revision != 1 {
			return room.RolePolicy{}, errors.New("a room's first role-policy revision must be 1")
		}
	} else {
		if policy.Revision <= prior.Revision {
			return room.RolePolicy{}, ErrRoomRoleRollback
		}
		if policy.Revision != prior.Revision+1 {
			return room.RolePolicy{}, ErrRoomRoleGap
		}
	}
	raw, err := room.EncodeRolePolicyJSON(policy)
	if err != nil {
		return room.RolePolicy{}, err
	}
	if err := l.journal.replace(l.path(policy.RoomID), raw); err != nil {
		return room.RolePolicy{}, err
	}
	return policy, nil
}

// Current returns the last signed policy, including a now-stale one. Callers
// making an authorization decision use AllowsCurrent, which rebinds it to the
// current room membership and live delegation.
func (l *RoomRoleLedger) Current(roomID string) (room.RolePolicy, bool, error) {
	if l == nil || l.journal == nil {
		return room.RolePolicy{}, false, errors.New("no room role ledger")
	}
	if err := l.journal.usable(); err != nil {
		return room.RolePolicy{}, false, err
	}
	if !ids.Room.MatchString(roomID) {
		return room.RolePolicy{}, false, errors.New("invalid room identifier")
	}
	l.journal.mutex.Lock()
	defer l.journal.mutex.Unlock()
	return l.read(roomID)
}

// AllowsCurrent fails closed when membership advanced, authority changed,
// finality/delegation is stale, the signature is damaged, or the role expired.
func (l *RoomRoleLedger) AllowsCurrent(roomID, agentID string, action room.Action, delegation identity.Delegation, now time.Time) (bool, error) {
	if l == nil || l.journal == nil {
		return false, errors.New("no room role ledger")
	}
	if err := l.journal.usable(); err != nil {
		return false, err
	}
	if !ids.Room.MatchString(roomID) || !ids.Agent.MatchString(agentID) {
		return false, errors.New("invalid room role authorization subject")
	}
	l.journal.mutex.Lock()
	defer l.journal.mutex.Unlock()
	policy, found, err := l.read(roomID)
	if err != nil || !found {
		return false, err
	}
	record, found, err := (&RoomLedger{journal: l.journal}).read(roomID)
	if err != nil || !found {
		return false, err
	}
	membership := room.Membership{RoomID: record.RoomID, Epoch: record.Epoch, Members: record.Members, Digest: record.MembershipDigest}
	authority := room.Authority{AgentID: record.AuthorityAgentID, EndpointID: record.AuthorityEndpointID}
	if err := room.VerifyRolePolicy(policy, membership, authority, delegation, now); err != nil {
		return false, err
	}
	return policy.Allows(membership, agentID, action), nil
}

func (l *RoomRoleLedger) read(roomID string) (room.RolePolicy, bool, error) {
	raw, err := os.ReadFile(l.path(roomID))
	if errors.Is(err, os.ErrNotExist) {
		return room.RolePolicy{}, false, nil
	}
	if err != nil {
		return room.RolePolicy{}, false, errors.New("read room role policy")
	}
	policy, err := room.DecodeRolePolicyJSON(raw)
	if err != nil {
		return room.RolePolicy{}, false, err
	}
	if policy.RoomID != roomID {
		return room.RolePolicy{}, false, errors.New("room role policy is stored under another room")
	}
	return policy, true, nil
}

func (l *RoomRoleLedger) path(roomID string) string {
	return filepath.Join(l.journal.root, roomDir, roomID[len("room_"):]+".roles.json")
}
