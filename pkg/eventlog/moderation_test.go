package eventlog

import (
	"encoding/json"
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/tosnetwork/tos-messenger/pkg/envelope"
	"github.com/tosnetwork/tos-messenger/pkg/identity"
	"github.com/tosnetwork/tos-messenger/pkg/payload"
	"github.com/tosnetwork/tos-messenger/pkg/room"
)

func roomEvent(t *testing.T, delegation identity.Delegation, roomID, kind string, body payload.Payload, now time.Time) envelope.Event {
	t.Helper()
	content, err := payload.Encode(body)
	if err != nil {
		t.Fatal(err)
	}
	delegation.AllowedOutboundEventClasses = []string{"room"}
	event, err := envelope.NewEvent(envelope.Event{Network: delegation.Network, ConversationID: "conv_" + strings.Repeat("a", 64),
		SenderAgentID: delegation.AgentID, SenderEndpointID: delegation.EndpointID, SenderDeviceID: "dev_" + strings.Repeat("b", 64),
		RoomID: roomID, CreatedAtUnix: uint64(now.Unix()), Kind: kind, Content: content})
	if err != nil {
		t.Fatal(err)
	}
	return event
}

func acceptEvent(t *testing.T, journal *Journal, event envelope.Event, now time.Time) {
	t.Helper()
	raw, err := envelope.EncodeEventJSON(event)
	if err != nil {
		t.Fatal(err)
	}
	if fresh, _, err := journal.Accept(Entry{EventID: event.EventID, SenderEndpointID: event.SenderEndpointID, ConversationID: event.ConversationID, Payload: raw, Admission: AdmissionAdmitted, ReceivedAtUnix: uint64(now.Unix())}); err != nil || !fresh {
		t.Fatalf("accept: fresh=%v err=%v", fresh, err)
	}
}

func moderationBody(target envelope.Event, epoch, policyRevision, decisionRevision uint64, action string) payload.RoomModeration {
	return payload.RoomModeration{RoomID: target.RoomID, MembershipEpoch: epoch, RolePolicyRevision: policyRevision, TargetEventID: target.EventID, DecisionRevision: decisionRevision, Action: action, Reason: "room policy"}
}

func TestModerationEffectsAreAuthorizedAuditableAndRestartSafe(t *testing.T) {
	rooms, journal, root := openRoomLedger(t)
	now := time.Unix(1_800_000_000, 0)
	authorityDelegation, _ := roomDelegation(t, roomAgent(1), 0x51)
	moderatorDelegation, _ := roomDelegation(t, roomAgent(2), 0x52)
	memberDelegation, _ := roomDelegation(t, roomAgent(3), 0x53)
	founded := mustFound(t, roomAgent(1), roomAgent(2), roomAgent(3))
	if _, err := advanceRoom(t, rooms, founded, 1, now); err != nil {
		t.Fatal(err)
	}
	roles, _ := journal.OpenRoomRoles()
	policy := rolePolicy(t, founded, authorityDelegation, 1, []room.RoleAssignment{{AgentID: roomAgent(1), Role: room.RoleAdministrator}, {AgentID: roomAgent(2), Role: room.RoleModerator}}, now)
	if _, err := roles.Advance(policy, authorityDelegation, now); err != nil {
		t.Fatal(err)
	}
	target := roomEvent(t, memberDelegation, ledgerRoom, "room.message", payload.RoomMessage{RoomID: ledgerRoom, Epoch: 1, MediaType: "text/plain; charset=utf-8", Body: "hide me"}, now)
	acceptEvent(t, journal, target, now)
	ledger, _ := journal.OpenModeration()
	hide := roomEvent(t, moderatorDelegation, ledgerRoom, "room.moderation", moderationBody(target, 1, 1, 1, "hide"), now)
	fresh, decision, err := ledger.Apply(hide, withRoomClass(moderatorDelegation), authorityDelegation, now)
	if err != nil || !fresh || decision.Action != "hide" {
		t.Fatalf("hide: fresh=%v decision=%+v err=%v", fresh, decision, err)
	}
	visible, _, found, err := ledger.Visibility(target.EventID)
	if err != nil || !found || visible {
		t.Fatalf("visibility after hide: visible=%v found=%v err=%v", visible, found, err)
	}
	if fresh, _, err := ledger.Apply(hide, withRoomClass(moderatorDelegation), authorityDelegation, now); err != nil || fresh {
		t.Fatalf("exact replay: fresh=%v err=%v", fresh, err)
	}
	if pending, err := journal.ListPending(now, 0); err != nil || len(pending) != 0 {
		t.Fatalf("hidden target reached runtime queue: pending=%d err=%v", len(pending), err)
	}
	unauthorized := roomEvent(t, memberDelegation, ledgerRoom, "room.moderation", moderationBody(target, 1, 1, 2, "restore"), now)
	if _, _, err := ledger.Apply(unauthorized, withRoomClass(memberDelegation), authorityDelegation, now); err == nil {
		t.Fatal("ordinary member moderated a message")
	}
	if err := journal.Close(); err != nil {
		t.Fatal(err)
	}
	journal, err = Open(root)
	if err != nil {
		t.Fatal(err)
	}
	defer journal.Close()
	ledger, _ = journal.OpenModeration()
	visible, decision, found, err = ledger.Visibility(target.EventID)
	if err != nil || !found || visible || decision.DecisionEventID != hide.EventID {
		t.Fatalf("restart visibility: visible=%v decision=%+v found=%v err=%v", visible, decision, found, err)
	}
	restore := roomEvent(t, authorityDelegation, ledgerRoom, "room.moderation", moderationBody(target, 1, 1, 2, "restore"), now)
	fresh, decision, err = ledger.Apply(restore, withRoomClass(authorityDelegation), authorityDelegation, now)
	if err != nil || !fresh || decision.Action != "restore" {
		t.Fatalf("restore: %+v %v", decision, err)
	}
	visible, _, _, err = ledger.Visibility(target.EventID)
	if err != nil || !visible {
		t.Fatalf("visibility after restore: %v %v", visible, err)
	}
	if pending, err := journal.ListPending(now, 0); err != nil || len(pending) != 1 || pending[0].EventID != target.EventID {
		t.Fatalf("restored target absent from runtime queue: %+v err=%v", pending, err)
	}
	path := ledger.path(target.EventID)
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var object map[string]any
	if err := json.Unmarshal(raw, &object); err != nil {
		t.Fatal(err)
	}
	object["unexpected"] = true
	raw, _ = json.Marshal(object)
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, _, err := ledger.Visibility(target.EventID); err == nil {
		t.Fatal("damaged moderation record remained authoritative")
	}
}

func TestModerationRefusesRevisionAttacksAndStaleRoles(t *testing.T) {
	rooms, journal, _ := openRoomLedger(t)
	defer journal.Close()
	now := time.Unix(1_800_000_000, 0)
	authorityDelegation, _ := roomDelegation(t, roomAgent(1), 0x51)
	moderatorDelegation, _ := roomDelegation(t, roomAgent(2), 0x52)
	memberDelegation, _ := roomDelegation(t, roomAgent(3), 0x53)
	founded := mustFound(t, roomAgent(1), roomAgent(2), roomAgent(3))
	if _, err := advanceRoom(t, rooms, founded, 1, now); err != nil {
		t.Fatal(err)
	}
	roles, _ := journal.OpenRoomRoles()
	policy := rolePolicy(t, founded, authorityDelegation, 1, []room.RoleAssignment{{AgentID: roomAgent(1), Role: room.RoleAdministrator}, {AgentID: roomAgent(2), Role: room.RoleModerator}}, now)
	if _, err := roles.Advance(policy, authorityDelegation, now); err != nil {
		t.Fatal(err)
	}
	target := roomEvent(t, memberDelegation, ledgerRoom, "room.message", payload.RoomMessage{RoomID: ledgerRoom, Epoch: 1, MediaType: "text/plain; charset=utf-8", Body: "target"}, now)
	acceptEvent(t, journal, target, now)
	ledger, _ := journal.OpenModeration()
	first := roomEvent(t, moderatorDelegation, ledgerRoom, "room.moderation", moderationBody(target, 1, 1, 1, "hide"), now)
	if _, _, err := ledger.Apply(first, withRoomClass(moderatorDelegation), authorityDelegation, now); err != nil {
		t.Fatal(err)
	}
	rollback := roomEvent(t, moderatorDelegation, ledgerRoom, "room.moderation", moderationBody(target, 1, 1, 1, "restore"), now)
	if _, _, err := ledger.Apply(rollback, withRoomClass(moderatorDelegation), authorityDelegation, now); !errors.Is(err, ErrModerationRollback) {
		t.Fatalf("rollback: %v", err)
	}
	gap := roomEvent(t, moderatorDelegation, ledgerRoom, "room.moderation", moderationBody(target, 1, 1, 3, "restore"), now)
	if _, _, err := ledger.Apply(gap, withRoomClass(moderatorDelegation), authorityDelegation, now); !errors.Is(err, ErrModerationGap) {
		t.Fatalf("gap: %v", err)
	}
	removed, err := founded.Remove([]string{roomAgent(2)})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := advanceRoom(t, rooms, removed, 1, now); err != nil {
		t.Fatal(err)
	}
	stale := roomEvent(t, moderatorDelegation, ledgerRoom, "room.moderation", moderationBody(target, 1, 1, 2, "restore"), now)
	if _, _, err := ledger.Apply(stale, withRoomClass(moderatorDelegation), authorityDelegation, now); err == nil {
		t.Fatal("removed moderator retained stale power")
	}
}

func withRoomClass(delegation identity.Delegation) identity.Delegation {
	delegation.AllowedOutboundEventClasses = []string{"room"}
	return delegation
}
