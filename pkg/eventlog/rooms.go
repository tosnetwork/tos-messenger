package eventlog

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"time"

	"github.com/tosnetwork/tos-messenger/internal/ids"
	"github.com/tosnetwork/tos-messenger/pkg/room"
)

const (
	roomDir = "rooms"

	// RoomRecordSchema is the on-disk schema of one room's current epoch.
	RoomRecordSchema = "tos.messaging.room-ledger.v1"
)

var (
	// ErrRoomRollback reports an epoch at or below the recorded one. Accepting
	// it would reinstate a membership the room has already moved past -- exactly
	// the replay the epoch counter exists to defeat.
	ErrRoomRollback = errors.New("the room's epoch regressed")

	// ErrRoomGap reports an epoch beyond the next one. This installation records
	// the full member set for each epoch it accepts, so it can only accept the
	// epoch that follows the one it holds; a jump means a transition it never
	// saw, whose member set it cannot verify.
	ErrRoomGap = errors.New("the room's epoch skipped an unseen transition")
)

// RoomRecord is what this installation holds for one room's membership.
//
// It carries the full member set, not only the digest, because the membership
// state machine advances one epoch at a time and each successor is derived from
// the members of the epoch before it. The digest is stored alongside so a query
// can be answered without recomputing it, and is checked against the members on
// read so a tampered record fails closed rather than answering from a set its
// own commitment disowns.
type RoomRecord struct {
	Schema           string   `json:"schema"`
	RoomID           string   `json:"room_id"`
	Epoch            uint64   `json:"epoch"`
	MembershipDigest string   `json:"membership_digest"`
	Members          []string `json:"members"`
	UpdatedAtUnix    uint64   `json:"updated_at_unix"`
}

// RoomLedger records room membership epochs, one record per room.
type RoomLedger struct{ journal *Journal }

// OpenRooms returns the ledger for this installation.
func (j *Journal) OpenRooms() (*RoomLedger, error) {
	if err := j.usable(); err != nil {
		return nil, err
	}
	return &RoomLedger{journal: j}, nil
}

// RoomTransition is the outcome of advancing a room.
type RoomTransition struct {
	// Membership is what is now on record.
	Membership room.Membership
	// Joined are members present now that were absent at the prior epoch.
	Joined []string
	// Departed are members absent now that were present at the prior epoch.
	Departed []string
}

// Advance judges a successor membership against the record and, when it
// succeeds, records it durably.
//
// The judgement and the write are one operation for the same reason the device
// ledger fuses them: a caller that judged first and recorded later could act on
// an epoch a crash then forgot, and re-advancing would re-run the join and
// departure side effects the caller already performed.
//
// The rule is strict succession. A first sight must be epoch 1; every later
// membership must be exactly one epoch past the record and name the same room.
// An epoch at or below the record is a rollback; an epoch beyond the next is a
// gap this installation cannot verify, because it holds only the current member
// set and derives each successor from it.
func (l *RoomLedger) Advance(next room.Membership, now time.Time) (RoomTransition, error) {
	if l == nil {
		return RoomTransition{}, errors.New("no room ledger")
	}
	if err := l.journal.usable(); err != nil {
		return RoomTransition{}, err
	}
	if now.IsZero() || now.Unix() < 0 {
		return RoomTransition{}, errors.New("invalid time")
	}
	// A membership whose digest does not match its members is rejected before
	// anything is compared, so a forged successor cannot be measured against the
	// record at all.
	commitment, err := next.Announce()
	if err != nil {
		return RoomTransition{}, err
	}
	l.journal.mutex.Lock()
	defer l.journal.mutex.Unlock()

	record, found, err := l.read(next.RoomID)
	if err != nil {
		return RoomTransition{}, err
	}
	var prior []string
	if !found {
		if next.Epoch != 1 {
			return RoomTransition{}, errors.New("a room's first epoch must be epoch 1")
		}
	} else {
		if next.RoomID != record.RoomID {
			return RoomTransition{}, errors.New("the successor names another room")
		}
		if next.Epoch <= record.Epoch {
			return RoomTransition{}, ErrRoomRollback
		}
		if next.Epoch != record.Epoch+1 {
			return RoomTransition{}, ErrRoomGap
		}
		prior = record.Members
	}

	joined, departed := diffMembers(prior, next.Members)
	if found && len(joined) == 0 && len(departed) == 0 {
		// Same members at a higher epoch: an epoch that changed nothing. The
		// state machine refuses to produce one, so seeing it here means the
		// successor was assembled by hand around an unchanged set.
		return RoomTransition{}, errors.New("a room epoch must change its membership")
	}

	record = RoomRecord{
		Schema:           RoomRecordSchema,
		RoomID:           next.RoomID,
		Epoch:            next.Epoch,
		MembershipDigest: commitment.MembershipDigest,
		Members:          next.Members,
		UpdatedAtUnix:    uint64(now.Unix()),
	}
	encoded, err := json.Marshal(record)
	if err != nil {
		return RoomTransition{}, err
	}
	if err := l.journal.replace(l.path(next.RoomID), encoded); err != nil {
		return RoomTransition{}, err
	}
	return RoomTransition{Membership: next, Joined: joined, Departed: departed}, nil
}

// RoomStanding reports how a claim of (room, epoch, member) stands against the
// record.
type RoomStanding string

const (
	// RoomMember is a member at the recorded epoch.
	RoomMember RoomStanding = "member"
	// RoomNotMember is not a member at the recorded epoch.
	RoomNotMember RoomStanding = "not-member"
	// RoomStale names an epoch older than the record: the claimant is behind,
	// and this installation no longer holds that epoch's member set to judge
	// against, so the remedy is for the claimant to catch up.
	RoomStale RoomStanding = "stale"
	// RoomAhead names an epoch newer than the record: this installation is
	// behind, and the remedy is to receive the intervening commits.
	RoomAhead RoomStanding = "ahead"
	// RoomUnknown names a room this installation holds nothing for.
	RoomUnknown RoomStanding = "unknown"
)

// Judge classifies one membership claim at a stated epoch.
//
// A claim is answerable only at the epoch on record, because that is the only
// member set this installation holds. An older epoch is stale and a newer one
// is ahead; both say "resynchronise" rather than guessing membership from a set
// that describes a different epoch.
func (l *RoomLedger) Judge(roomID string, epoch uint64, agentID string) (RoomStanding, error) {
	if l == nil {
		return "", errors.New("no room ledger")
	}
	if err := l.journal.usable(); err != nil {
		return "", err
	}
	if !ids.Room.MatchString(roomID) {
		return "", errors.New("invalid room identifier")
	}
	if !ids.Agent.MatchString(agentID) {
		return "", errors.New("invalid member identifier")
	}
	if epoch == 0 {
		return "", errors.New("a membership claim has no epoch")
	}
	l.journal.mutex.Lock()
	defer l.journal.mutex.Unlock()

	record, found, err := l.read(roomID)
	if err != nil {
		return "", err
	}
	if !found {
		return RoomUnknown, nil
	}
	switch {
	case epoch < record.Epoch:
		return RoomStale, nil
	case epoch > record.Epoch:
		return RoomAhead, nil
	}
	for _, member := range record.Members {
		if member == agentID {
			return RoomMember, nil
		}
	}
	return RoomNotMember, nil
}

// Current returns the membership on record for one room, reconstructed as a
// room.Membership so a caller can derive the next epoch from it.
func (l *RoomLedger) Current(roomID string) (room.Membership, bool, error) {
	if l == nil {
		return room.Membership{}, false, errors.New("no room ledger")
	}
	if err := l.journal.usable(); err != nil {
		return room.Membership{}, false, err
	}
	if !ids.Room.MatchString(roomID) {
		return room.Membership{}, false, errors.New("invalid room identifier")
	}
	l.journal.mutex.Lock()
	defer l.journal.mutex.Unlock()

	record, found, err := l.read(roomID)
	if err != nil || !found {
		return room.Membership{}, found, err
	}
	membership := room.Membership{
		RoomID:  record.RoomID,
		Epoch:   record.Epoch,
		Members: record.Members,
		Digest:  record.MembershipDigest,
	}
	return membership, true, nil
}

func (l *RoomLedger) read(roomID string) (RoomRecord, bool, error) {
	raw, err := os.ReadFile(l.path(roomID))
	if errors.Is(err, os.ErrNotExist) {
		return RoomRecord{}, false, nil
	}
	if err != nil {
		return RoomRecord{}, false, errors.New("read room record")
	}
	if len(raw) > MaxRecordBytes {
		return RoomRecord{}, false, errors.New("room record exceeds its bound")
	}
	var record RoomRecord
	if err := json.Unmarshal(raw, &record); err != nil {
		return RoomRecord{}, false, errors.New("invalid room record")
	}
	if record.Schema != RoomRecordSchema || record.RoomID != roomID {
		return RoomRecord{}, false, errors.New("room record describes another room")
	}
	// The digest is recomputed from the stored members on every read, so a
	// record edited underneath this process to swap a member without updating
	// the commitment is refused rather than answered from.
	digest, err := room.Digest(record.RoomID, record.Epoch, record.Members)
	if err != nil {
		return RoomRecord{}, false, err
	}
	if digest != record.MembershipDigest {
		return RoomRecord{}, false, errors.New("room record's digest does not match its members")
	}
	return record, true, nil
}

func (l *RoomLedger) path(roomID string) string {
	return filepath.Join(l.journal.root, roomDir, roomID[len("room_"):]+".json")
}

// diffMembers reports who joined and who departed between two sorted,
// duplicate-free member sets.
func diffMembers(prior, next []string) (joined, departed []string) {
	priorSet := make(map[string]struct{}, len(prior))
	for _, member := range prior {
		priorSet[member] = struct{}{}
	}
	nextSet := make(map[string]struct{}, len(next))
	for _, member := range next {
		nextSet[member] = struct{}{}
	}
	for _, member := range next {
		if _, was := priorSet[member]; !was {
			joined = append(joined, member)
		}
	}
	for _, member := range prior {
		if _, still := nextSet[member]; !still {
			departed = append(departed, member)
		}
	}
	return joined, departed
}
