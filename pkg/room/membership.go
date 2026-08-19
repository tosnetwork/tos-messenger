// Package room is the membership state machine for a private group.
//
// A room's membership is a set of Agents that changes over time. The problem
// the state machine solves is not "who is in the room" -- a set answers that --
// but "which membership is current" when two members may hold different views
// after a network partition, and when an old membership can be replayed to
// reinstate someone who was removed. The answer is the epoch: every change
// advances a monotonic counter, and a commitment binds the counter to the
// member set it describes. A membership without its epoch is unordered; an
// epoch without its digest is unverifiable.
//
// The package is pure and holds no state of its own. A Membership is an
// immutable value; a transition returns the successor rather than mutating the
// receiver, so a rejected transition leaves the caller's membership untouched.
// Durability, rollback across restarts, and the single-authority question all
// live above this package, in the room ledger.
package room

import (
	"bytes"
	"errors"
	"sort"

	"github.com/tosnetwork/tos-messenger/internal/canon"
	"github.com/tosnetwork/tos-messenger/internal/ids"
	"github.com/tosnetwork/tos-messenger/pkg/payload"
)

// MaxMembers bounds a room's membership.
//
// A group whose membership no participant can review is not a group anyone can
// reason about, and an unbounded member set is an unbounded fan-out for every
// message. The bound is deliberately generous; the point is that one exists.
const MaxMembers = 1024

var (
	// ErrEmptyRoom reports a transition that would leave a room with no
	// members. A room with no members has no one to commit its next epoch, so
	// emptying it is refused rather than silently producing a terminal state.
	ErrEmptyRoom = errors.New("a room with no members is not a room")

	// ErrRoomFull reports a membership over the bound.
	ErrRoomFull = errors.New("a room may not hold this many members")

	// ErrEpochExhausted reports that the epoch counter cannot advance further.
	ErrEpochExhausted = errors.New("a room has exhausted its epoch counter")

	// ErrNoChange reports a transition that would commit an identical member
	// set. An epoch that changes nothing is two epochs claiming the same
	// membership, and the digest could not tell them apart.
	ErrNoChange = errors.New("a membership transition must change the member set")
)

// Membership is the committed state of one room at one epoch.
//
// Members is always sorted and free of duplicates once a Membership leaves this
// package, so the digest does not depend on the order members were named in.
// Digest is derived, not supplied: it is recomputed on every transition and is
// the value a room-membership-commit carries on the wire.
type Membership struct {
	RoomID  string
	Epoch   uint64
	Members []string
	Digest  string
}

// Found creates a room's first epoch from its founding members.
//
// The first epoch is 1, never 0: an epoch of 0 is the zero value of an
// uninitialised field, and a membership that cannot be told apart from an
// uninitialised one fails closed everywhere it is checked.
func Found(roomID string, founders []string) (Membership, error) {
	if !ids.Room.MatchString(roomID) {
		return Membership{}, errors.New("invalid room identifier")
	}
	members, err := normalize(founders)
	if err != nil {
		return Membership{}, err
	}
	if len(members) == 0 {
		return Membership{}, ErrEmptyRoom
	}
	return commit(roomID, 1, members)
}

// Add returns the successor membership with newMembers added.
//
// Adding a member already present is refused rather than ignored: a caller that
// believes it added someone who was already there has a different view of the
// room than the state machine, and hiding that behind a no-op would let the two
// drift. Re-adding a member who was previously removed is not this case -- a
// removed member is simply absent, so adding them again is an ordinary add at a
// fresh epoch. Membership here is an Agent, not a key; unlike a revoked device,
// an Agent legitimately returns.
func (m Membership) Add(newMembers []string) (Membership, error) {
	if err := m.usable(); err != nil {
		return Membership{}, err
	}
	incoming, err := normalize(newMembers)
	if err != nil {
		return Membership{}, err
	}
	if len(incoming) == 0 {
		return Membership{}, ErrNoChange
	}
	present := asSet(m.Members)
	for _, member := range incoming {
		if _, found := present[member]; found {
			return Membership{}, errors.New("a member cannot be added twice")
		}
	}
	combined := append(append([]string{}, m.Members...), incoming...)
	next, err := normalize(combined)
	if err != nil {
		return Membership{}, err
	}
	if len(next) > MaxMembers {
		return Membership{}, ErrRoomFull
	}
	epoch, err := nextEpoch(m.Epoch)
	if err != nil {
		return Membership{}, err
	}
	return commit(m.RoomID, epoch, next)
}

// Remove returns the successor membership with leaving members removed.
//
// Removing a member who is not present is refused: there is nothing to reverse,
// and accepting it would advance the epoch without a corresponding change,
// which the digest could not distinguish from the prior epoch. Removing the
// last member is refused as an empty room; dissolving a room is a distinct act,
// not the tail of a removal.
func (m Membership) Remove(leaving []string) (Membership, error) {
	if err := m.usable(); err != nil {
		return Membership{}, err
	}
	departing, err := normalize(leaving)
	if err != nil {
		return Membership{}, err
	}
	if len(departing) == 0 {
		return Membership{}, ErrNoChange
	}
	present := asSet(m.Members)
	remove := make(map[string]struct{}, len(departing))
	for _, member := range departing {
		if _, found := present[member]; !found {
			return Membership{}, errors.New("a member who is not present cannot be removed")
		}
		remove[member] = struct{}{}
	}
	next := make([]string, 0, len(m.Members))
	for _, member := range m.Members {
		if _, gone := remove[member]; gone {
			continue
		}
		next = append(next, member)
	}
	if len(next) == 0 {
		return Membership{}, ErrEmptyRoom
	}
	epoch, err := nextEpoch(m.Epoch)
	if err != nil {
		return Membership{}, err
	}
	return commit(m.RoomID, epoch, next)
}

// Contains reports whether an Agent is a member at this epoch.
func (m Membership) Contains(agentID string) bool {
	for _, member := range m.Members {
		if member == agentID {
			return true
		}
	}
	return false
}

// Announce projects a Membership onto the wire commit a room broadcasts.
//
// The commit carries the digest and the count, not the member list, because the
// list is what the digest commits to: a recipient who holds the members can
// recompute the digest and check it, and a recipient who does not learns only
// the size, which is all a digest is meant to reveal.
func (m Membership) Announce() (payload.RoomMembershipCommit, error) {
	if err := m.usable(); err != nil {
		return payload.RoomMembershipCommit{}, err
	}
	if len(m.Members) > MaxMembers {
		return payload.RoomMembershipCommit{}, ErrRoomFull
	}
	commitment := payload.RoomMembershipCommit{
		RoomID:           m.RoomID,
		Epoch:            m.Epoch,
		MembershipDigest: m.Digest,
		MemberCount:      uint32(len(m.Members)),
	}
	if err := commitment.Validate(); err != nil {
		return payload.RoomMembershipCommit{}, err
	}
	return commitment, nil
}

// VerifyCommit reports whether a wire commit describes this membership.
//
// It is the inverse of Announce: a recipient that has independently learned the
// member set for an epoch confirms that a broadcast commit matches, so a room
// authority cannot announce a digest that its stated members do not produce.
func (m Membership) VerifyCommit(commitment payload.RoomMembershipCommit) error {
	if err := m.usable(); err != nil {
		return err
	}
	if commitment.RoomID != m.RoomID {
		return errors.New("the commit names another room")
	}
	if commitment.Epoch != m.Epoch {
		return errors.New("the commit names another epoch")
	}
	if commitment.MemberCount != uint32(len(m.Members)) {
		return errors.New("the commit states a different member count")
	}
	if commitment.MembershipDigest != m.Digest {
		return errors.New("the commit's digest does not match the members")
	}
	return nil
}

func (m Membership) usable() error {
	if !ids.Room.MatchString(m.RoomID) {
		return errors.New("invalid room identifier")
	}
	if m.Epoch == 0 {
		return errors.New("a membership has no epoch")
	}
	if len(m.Members) == 0 {
		return ErrEmptyRoom
	}
	recomputed, err := Digest(m.RoomID, m.Epoch, m.Members)
	if err != nil {
		return err
	}
	if recomputed != m.Digest {
		return errors.New("the membership's digest does not match its members")
	}
	return nil
}

// ValidRoomID reports whether an identifier is a well-formed room identifier.
// It lets a package that only needs to check a room reference do so without
// reaching for the identifier patterns directly.
func ValidRoomID(roomID string) bool {
	return ids.Room.MatchString(roomID)
}

// Digest is the commitment a room publishes for one epoch's membership.
//
// The preimage is domain-separated and binds the room, the epoch, the count,
// and every member in sorted order. Binding the epoch is what stops an old
// membership being replayed as a current one; binding the count stops a
// truncated member list from colliding with a shorter genuine one.
func Digest(roomID string, epoch uint64, members []string) (string, error) {
	if !ids.Room.MatchString(roomID) {
		return "", errors.New("invalid room identifier")
	}
	if epoch == 0 {
		return "", errors.New("a membership digest has no epoch")
	}
	sorted, err := normalize(members)
	if err != nil {
		return "", err
	}
	if len(sorted) == 0 {
		return "", ErrEmptyRoom
	}
	if len(sorted) > MaxMembers {
		return "", ErrRoomFull
	}
	buffer := bytes.NewBufferString(canon.DomainRoomMembership)
	canon.Text(buffer, roomID)
	canon.Uint64(buffer, epoch)
	canon.Uint32(buffer, uint32(len(sorted)))
	for _, member := range sorted {
		canon.Text(buffer, member)
	}
	return canon.Digest(buffer.Bytes()), nil
}

// commit builds a Membership over an already-normalized member set.
func commit(roomID string, epoch uint64, members []string) (Membership, error) {
	digest, err := Digest(roomID, epoch, members)
	if err != nil {
		return Membership{}, err
	}
	return Membership{RoomID: roomID, Epoch: epoch, Members: members, Digest: digest}, nil
}

// nextEpoch advances the counter, refusing to wrap. Overflow of the epoch would
// let a far-future membership collide with epoch 0 or 1, so it fails closed.
func nextEpoch(current uint64) (uint64, error) {
	next := current + 1
	if next <= current {
		return 0, ErrEpochExhausted
	}
	return next, nil
}

// normalize validates every member, sorts them, and rejects duplicates.
//
// A duplicate in the input is not silently collapsed: the caller who listed a
// member twice has a mistaken view of the set, and the digest is defined over a
// set, so admitting the input as-is would let two different inputs commit the
// same digest.
func normalize(members []string) ([]string, error) {
	sorted := make([]string, 0, len(members))
	seen := make(map[string]struct{}, len(members))
	for _, member := range members {
		if !ids.Agent.MatchString(member) {
			return nil, errors.New("a room member must be an Agent identifier")
		}
		if _, duplicate := seen[member]; duplicate {
			return nil, errors.New("a member was listed twice")
		}
		seen[member] = struct{}{}
		sorted = append(sorted, member)
	}
	sort.Strings(sorted)
	return sorted, nil
}

func asSet(members []string) map[string]struct{} {
	set := make(map[string]struct{}, len(members))
	for _, member := range members {
		set[member] = struct{}{}
	}
	return set
}
