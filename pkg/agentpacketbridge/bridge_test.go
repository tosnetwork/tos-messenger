package agentpacketbridge

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/tosnetwork/tos-messenger/pkg/eventlog"
	"github.com/tosnetwork/tos-messenger/pkg/payload"
	nativev1 "github.com/tosnetwork/tos-service-protocol/gen/tos/service/v1"
	"github.com/tosnetwork/tos-service-protocol/pkg/agentpacket"
	"github.com/tosnetwork/tos-service-protocol/pkg/mldsa44"
	"github.com/tosnetwork/tos-service-protocol/pkg/mldsa44/mldsa44test"
)

type states map[string]*nativev1.AgentStateV1

func (s states) ResolveAgent(id string) (*nativev1.AgentStateV1, bool, error) {
	state, ok := s[id]
	return state, ok, nil
}

type receiver struct {
	calls int
	fail  bool
}

func (r *receiver) Receive(context.Context, agentpacket.Packet) error {
	r.calls++
	if r.fail {
		return errors.New("retry")
	}
	return nil
}

// packetKeys stands in for the ML-DSA-44 helper in pure-logic tests; it is
// not ML-DSA-44.
var packetKeys = &mldsa44test.Fake{}

func packetPolicy(controller string) *nativev1.ControllerPolicyV1 {
	return &nativev1.ControllerPolicyV1{Threshold: 1, RecoveryThreshold: 1, Controllers: []*nativev1.ControllerV1{{
		KeyId: packetKeys.KeyID(controller), Mldsa44PublicKey: packetKeys.PublicKey(controller), Weight: 1, PurposeMask: 15, Recovery: true}}}
}

func bridgePacket(t *testing.T, key string, sender, recipient string, nonce byte, created uint64, body string) agentpacket.Packet {
	t.Helper()
	var n [32]byte
	for i := range n {
		n[i] = nonce
	}
	keyID, err := mldsa44.ParseKeyIDText(packetKeys.KeyID(key))
	if err != nil {
		t.Fatal(err)
	}
	p, err := agentpacket.Sign(context.Background(), packetKeys, key, agentpacket.Packet{SenderAgentID: sender, RecipientAgentID: recipient,
		SenderKeyID: keyID, CapabilityID: "cap_" + strings.Repeat("3", 64), Sequence: 1, Nonce: n, Payload: []byte(body), CreatedAtUnix: created})
	if err != nil {
		t.Fatal(err)
	}
	return p
}
func carried(t *testing.T, packet agentpacket.Packet) payload.AgentPacketMessage {
	t.Helper()
	raw, err := agentpacket.EncodeJSON(packet)
	if err != nil {
		t.Fatal(err)
	}
	return payload.AgentPacketMessage{Foreign: payload.Foreign{Protocol: "agentpacket", Version: "1", Body: raw}}
}

func TestBridgeDurablyDeduplicatesAndRecoversPending(t *testing.T) {
	sender, recipient := "agent_"+strings.Repeat("1", 64), "agent_"+strings.Repeat("2", 64)
	key := "sender"
	resolver := states{sender: {AgentId: sender, Policy: packetPolicy(key)}, recipient: {AgentId: recipient}}
	root := t.TempDir() + "/state"
	journal, err := eventlog.Open(root)
	if err != nil {
		t.Fatal(err)
	}
	receive := &receiver{fail: true}
	bridge, err := New(Config{Resolver: resolver, Verifier: packetKeys, Journal: journal, Receiver: receive, RecipientAgentID: recipient})
	if err != nil {
		t.Fatal(err)
	}
	packet := bridgePacket(t, key, sender, recipient, 7, 1_800_000_000, "work")
	if err := bridge.Handle(context.Background(), sender, carried(t, packet), time.Unix(1_800_000_001, 0)); err == nil {
		t.Fatal("receiver failure hidden")
	}
	receive.fail = false
	if err := bridge.Handle(context.Background(), sender, carried(t, packet), time.Unix(1_800_000_002, 0)); err != nil {
		t.Fatal(err)
	}
	if err := bridge.Handle(context.Background(), sender, carried(t, packet), time.Unix(1_800_000_003, 0)); err != nil {
		t.Fatal(err)
	}
	if receive.calls != 2 {
		t.Fatalf("receiver calls=%d, want failed attempt plus one recovery", receive.calls)
	}
	if err := journal.Close(); err != nil {
		t.Fatal(err)
	}
	journal, err = eventlog.Open(root)
	if err != nil {
		t.Fatal(err)
	}
	defer journal.Close()
	afterRestart := &receiver{}
	bridge, _ = New(Config{Resolver: resolver, Verifier: packetKeys, Journal: journal, Receiver: afterRestart, RecipientAgentID: recipient})
	if err := bridge.Handle(context.Background(), sender, carried(t, packet), time.Unix(1_800_000_004, 0)); err != nil {
		t.Fatal(err)
	}
	if afterRestart.calls != 0 {
		t.Fatal("completed packet redelivered after restart")
	}
}

func TestBridgeRejectsConflictStaleAndRevokedRecipient(t *testing.T) {
	sender, recipient := "agent_"+strings.Repeat("1", 64), "agent_"+strings.Repeat("2", 64)
	key := "sender"
	resolver := states{sender: {AgentId: sender, Policy: packetPolicy(key)}, recipient: {AgentId: recipient}}
	journal, _ := eventlog.Open(t.TempDir() + "/state")
	defer journal.Close()
	receive := &receiver{}
	bridge, _ := New(Config{Resolver: resolver, Verifier: packetKeys, Journal: journal, Receiver: receive, RecipientAgentID: recipient})
	packet := bridgePacket(t, key, sender, recipient, 9, 1_800_000_000, "first")
	now := time.Unix(1_800_000_001, 0)
	if err := bridge.Handle(context.Background(), sender, carried(t, packet), now); err != nil {
		t.Fatal(err)
	}
	conflict := bridgePacket(t, key, sender, recipient, 9, 1_800_000_000, "different")
	if err := bridge.Handle(context.Background(), sender, carried(t, conflict), now); !errors.Is(err, eventlog.ErrConflict) {
		t.Fatalf("nonce conflict: %v", err)
	}
	stale := bridgePacket(t, key, sender, recipient, 10, 1_700_000_000, "old")
	if err := bridge.Handle(context.Background(), sender, carried(t, stale), now); err == nil {
		t.Fatal("stale packet accepted")
	}
	resolver[recipient].Tombstoned = true
	fresh := bridgePacket(t, key, sender, recipient, 11, 1_800_000_000, "fresh")
	if err := bridge.Handle(context.Background(), sender, carried(t, fresh), now); err == nil {
		t.Fatal("tombstoned recipient accepted")
	}
	resolver[recipient].Tombstoned = false
	if err := bridge.Handle(context.Background(), "agent_"+strings.Repeat("f", 64), carried(t, fresh), now); err == nil {
		t.Fatal("forwarded packet with a mismatched Event sender accepted")
	}
}
