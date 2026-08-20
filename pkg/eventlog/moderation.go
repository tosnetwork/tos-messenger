package eventlog

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"time"

	"github.com/tosnetwork/tos-messenger/internal/ids"
	"github.com/tosnetwork/tos-messenger/pkg/envelope"
	"github.com/tosnetwork/tos-messenger/pkg/identity"
	"github.com/tosnetwork/tos-messenger/pkg/payload"
	"github.com/tosnetwork/tos-messenger/pkg/room"
)

const ModerationRecordSchema = "tos.messaging.room-moderation-record.v1"

var (
	ErrModerationTargetMissing = errors.New("room moderation target is not present")
	ErrModerationRollback      = errors.New("room moderation decision revision regressed")
	ErrModerationGap           = errors.New("room moderation decision skipped an unseen revision")
)

// ModerationDecision is an auditable presentation overlay. The target Event
// remains immutable in the journal; hide and restore only change whether a
// client should present it.
type ModerationDecision struct {
	Schema             string `json:"schema"`
	RoomID             string `json:"room_id"`
	TargetEventID      string `json:"target_event_id"`
	DecisionEventID    string `json:"decision_event_id"`
	DecisionRevision   uint64 `json:"decision_revision"`
	MembershipEpoch    uint64 `json:"membership_epoch"`
	RolePolicyRevision uint64 `json:"role_policy_revision"`
	ActorAgentID       string `json:"actor_agent_id"`
	Action             string `json:"action"`
	Reason             string `json:"reason"`
	DecidedAtUnix      uint64 `json:"decided_at_unix"`
}

type ModerationLedger struct{ journal *Journal }

func (j *Journal) OpenModeration() (*ModerationLedger, error) {
	if err := j.usable(); err != nil {
		return nil, err
	}
	return &ModerationLedger{journal: j}, nil
}

// Apply authenticates the moderation Event's sender delegation, checks the
// current epoch-bound role policy, requires the immutable target room.message
// to be present, then commits exactly the next per-target decision revision.
func (l *ModerationLedger) Apply(event envelope.Event, senderDelegation, authorityDelegation identity.Delegation, now time.Time) (bool, ModerationDecision, error) {
	if l == nil || l.journal == nil {
		return false, ModerationDecision{}, errors.New("no moderation ledger")
	}
	if err := l.journal.usable(); err != nil {
		return false, ModerationDecision{}, err
	}
	if now.IsZero() || now.Unix() < 0 {
		return false, ModerationDecision{}, errors.New("invalid moderation time")
	}
	if event.Kind != "room.moderation" {
		return false, ModerationDecision{}, errors.New("event is not room moderation")
	}
	if err := identity.CheckWindow(senderDelegation, now); err != nil {
		return false, ModerationDecision{}, err
	}
	if err := envelope.AdmittedBy(senderDelegation, event); err != nil {
		return false, ModerationDecision{}, err
	}
	decoded, err := payload.Decode(event.Kind, event.Content)
	if err != nil {
		return false, ModerationDecision{}, err
	}
	body, ok := decoded.(payload.RoomModeration)
	if !ok {
		return false, ModerationDecision{}, errors.New("invalid room moderation body")
	}
	if event.RoomID != body.RoomID {
		return false, ModerationDecision{}, errors.New("moderation Event names another room")
	}
	l.journal.mutex.Lock()
	defer l.journal.mutex.Unlock()
	roomRecord, found, err := (&RoomLedger{journal: l.journal}).read(body.RoomID)
	if err != nil {
		return false, ModerationDecision{}, err
	}
	if !found {
		return false, ModerationDecision{}, errors.New("moderation room is unknown")
	}
	membership := room.Membership{RoomID: roomRecord.RoomID, Epoch: roomRecord.Epoch, Members: roomRecord.Members, Digest: roomRecord.MembershipDigest}
	authority := room.Authority{AgentID: roomRecord.AuthorityAgentID, EndpointID: roomRecord.AuthorityEndpointID}
	policy, found, err := (&RoomRoleLedger{journal: l.journal}).read(body.RoomID)
	if err != nil {
		return false, ModerationDecision{}, err
	}
	if !found {
		return false, ModerationDecision{}, errors.New("room has no role policy")
	}
	if body.MembershipEpoch != membership.Epoch || body.RolePolicyRevision != policy.Revision {
		return false, ModerationDecision{}, errors.New("moderation names stale room authority")
	}
	if err := room.VerifyRolePolicy(policy, membership, authority, authorityDelegation, now); err != nil {
		return false, ModerationDecision{}, err
	}
	if !policy.Allows(membership, event.SenderAgentID, room.ActionModerate) {
		return false, ModerationDecision{}, errors.New("sender has no room moderation role")
	}
	targetRecord, err := readRecord(l.journal.path(body.TargetEventID))
	if errors.Is(err, os.ErrNotExist) {
		return false, ModerationDecision{}, ErrModerationTargetMissing
	}
	if err != nil {
		return false, ModerationDecision{}, err
	}
	targetRaw, err := targetRecord.Payload()
	if err != nil {
		return false, ModerationDecision{}, err
	}
	target, err := envelope.DecodeEventJSON(targetRaw)
	if err != nil {
		return false, ModerationDecision{}, err
	}
	if target.EventID != body.TargetEventID || target.RoomID != body.RoomID || target.Kind != "room.message" {
		return false, ModerationDecision{}, errors.New("moderation target is not a message in this room")
	}
	decision := ModerationDecision{Schema: ModerationRecordSchema, RoomID: body.RoomID, TargetEventID: body.TargetEventID, DecisionEventID: event.EventID, DecisionRevision: body.DecisionRevision, MembershipEpoch: body.MembershipEpoch, RolePolicyRevision: body.RolePolicyRevision, ActorAgentID: event.SenderAgentID, Action: body.Action, Reason: body.Reason, DecidedAtUnix: uint64(now.Unix())}
	prior, priorFound, err := l.read(body.TargetEventID)
	if err != nil {
		return false, ModerationDecision{}, err
	}
	if priorFound {
		if prior.DecisionEventID == decision.DecisionEventID {
			return false, prior, nil
		}
		if decision.DecisionRevision <= prior.DecisionRevision {
			return false, ModerationDecision{}, ErrModerationRollback
		}
		if decision.DecisionRevision != prior.DecisionRevision+1 {
			return false, ModerationDecision{}, ErrModerationGap
		}
	} else if decision.DecisionRevision != 1 {
		return false, ModerationDecision{}, errors.New("first moderation decision revision must be 1")
	}
	raw, err := json.Marshal(decision)
	if err != nil {
		return false, ModerationDecision{}, err
	}
	if err := l.journal.replace(l.path(body.TargetEventID), raw); err != nil {
		return false, ModerationDecision{}, err
	}
	return true, decision, nil
}

// Visibility returns the durable presentation result without deleting or
// mutating the target Event. Absence means visible; hide means hidden; restore
// makes it visible again.
func (l *ModerationLedger) Visibility(targetEventID string) (bool, ModerationDecision, bool, error) {
	if l == nil || l.journal == nil {
		return false, ModerationDecision{}, false, errors.New("no moderation ledger")
	}
	if err := l.journal.usable(); err != nil {
		return false, ModerationDecision{}, false, err
	}
	if !ids.Event.MatchString(targetEventID) {
		return false, ModerationDecision{}, false, errors.New("invalid moderation target")
	}
	l.journal.mutex.Lock()
	defer l.journal.mutex.Unlock()
	decision, found, err := l.read(targetEventID)
	if err != nil || !found {
		return true, ModerationDecision{}, found, err
	}
	return decision.Action == "restore", decision, true, nil
}

func (l *ModerationLedger) read(targetEventID string) (ModerationDecision, bool, error) {
	raw, err := readRecordBytes(l.path(targetEventID))
	if errors.Is(err, os.ErrNotExist) {
		return ModerationDecision{}, false, nil
	}
	if err != nil {
		return ModerationDecision{}, false, err
	}
	var d ModerationDecision
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&d); err != nil {
		return ModerationDecision{}, false, errors.New("invalid moderation record")
	}
	if err := decoder.Decode(new(any)); !errors.Is(err, io.EOF) {
		return ModerationDecision{}, false, errors.New("invalid moderation record")
	}
	body := payload.RoomModeration{RoomID: d.RoomID, MembershipEpoch: d.MembershipEpoch,
		RolePolicyRevision: d.RolePolicyRevision, TargetEventID: d.TargetEventID,
		DecisionRevision: d.DecisionRevision, Action: d.Action, Reason: d.Reason}
	if d.Schema != ModerationRecordSchema || d.TargetEventID != targetEventID ||
		!ids.Event.MatchString(d.DecisionEventID) || !ids.Agent.MatchString(d.ActorAgentID) ||
		d.DecidedAtUnix == 0 || body.Validate() != nil {
		return ModerationDecision{}, false, errors.New("invalid moderation record")
	}
	return d, true, nil
}
func (l *ModerationLedger) path(targetEventID string) string {
	return filepath.Join(l.journal.root, moderationDir, targetEventID[len("evt_"):]+".json")
}
