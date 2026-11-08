package daemon

import (
	"bytes"
	"context"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/tosnetwork/tos-messenger/pkg/agentpacketbridge"
	"github.com/tosnetwork/tos-messenger/pkg/dispatch"
	"github.com/tosnetwork/tos-messenger/pkg/e2ee"
	nativev1 "github.com/tosnetwork/tos-service-protocol/gen/tos/service/v1"
	"github.com/tosnetwork/tos-service-protocol/pkg/agentpacket"
	"github.com/tosnetwork/tos-service-protocol/pkg/mldsa44"
	"github.com/tosnetwork/tos-service-protocol/pkg/mldsa44/mldsa44test"
)

// sendKeys stands in for the ML-DSA-44 helper; it is not ML-DSA-44.
var sendKeys = &mldsa44test.Fake{}

type capturedPackets struct {
	mutex  sync.Mutex
	bodies [][]byte
}

func (c *capturedPackets) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	if err != nil || r.URL.Path != "/v1/agent-packet" {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	c.mutex.Lock()
	c.bodies = append(c.bodies, body)
	c.mutex.Unlock()
	w.WriteHeader(http.StatusAccepted)
}

func (c *capturedPackets) received() [][]byte {
	c.mutex.Lock()
	defer c.mutex.Unlock()
	return append([][]byte(nil), c.bodies...)
}

func installPacketTransport(t *testing.T, now time.Time, sender, recipient *Daemon) {
	t.Helper()
	dispatcher, err := dispatch.New(dispatch.Config{Journal: sender.journal, Suite: e2ee.NewDefaultSuite(),
		Sender: phaseALoopSender{recipient: recipient}, Bindings: dispatch.SessionBindings{Journal: sender.journal,
			Identity: sender.config.Identity(), Network: sender.config.Network()},
		Now: func() time.Time { return now }, Identity: sender.config.Identity(), Network: sender.config.Network(),
		AllowedEventClasses: []string{"agent.packet", "text"}})
	if err != nil {
		t.Fatalf("transport: %v", err)
	}
	sender.dispatch = dispatcher
}

func packetFrom(t *testing.T, sender, recipient string, created uint64, payloadBytes int) []byte {
	t.Helper()
	keyID, err := mldsa44.ParseKeyIDText(sendKeys.KeyID(sender))
	if err != nil {
		t.Fatal(err)
	}
	var nonce [32]byte
	nonce[0] = 7
	packet, err := agentpacket.Sign(context.Background(), sendKeys, sender, agentpacket.Packet{SenderAgentID: sender,
		RecipientAgentID: recipient, CapabilityID: "cap_" + strings.Repeat("3", 64), Sequence: 1, Nonce: nonce,
		Payload: bytes.Repeat([]byte{0x5a}, payloadBytes), CreatedAtUnix: created, SenderKeyID: keyID})
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := agentpacket.EncodeJSON(packet)
	if err != nil {
		t.Fatal(err)
	}
	return encoded
}

func agentPolicy(agentID string) *nativev1.AgentStateV1 {
	return &nativev1.AgentStateV1{AgentId: agentID, Policy: &nativev1.ControllerPolicyV1{Threshold: 1, RecoveryThreshold: 1,
		Controllers: []*nativev1.ControllerV1{{KeyId: sendKeys.KeyID(agentID), Mldsa44PublicKey: sendKeys.PublicKey(agentID),
			Weight: 1, PurposeMask: 15, Recovery: true}}}}
}

// TestEstablishedDaemonsCarryTheLargestAgentPacketToTheReceiver drives the
// whole outbound path: the sender daemon wraps the exact canonical packet,
// E2EE dispatch delivers it, and the recipient's bridge verifies it and posts
// the same bytes to the provider's Unix socket.
func TestEstablishedDaemonsCarryTheLargestAgentPacketToTheReceiver(t *testing.T) {
	now := time.Unix(1_900_000_000, 0)
	a := newPhaseADaemon(t, now, "2", "4")
	b := newPhaseADaemon(t, now, "7", "9")
	connectPhaseADirectories(a, b, now)
	connectPhaseADirectories(b, a, now)
	installPhaseAAdmission(t, now, a, b)
	installPhaseAAdmission(t, now, b, a)
	installPacketTransport(t, now, a, b)
	installPacketTransport(t, now, b, a)
	first, err := a.SendDirectMessage(context.Background(), b.config.AgentID,
		"text/plain; charset=utf-8", "establish", "idem_"+strings.Repeat("1", 64), uint64(now.Add(time.Hour).Unix()))
	if err != nil {
		t.Fatal(err)
	}
	if summary, err := a.dispatch.Sweep(context.Background(), 0); err != nil || summary.Sent != 1 {
		t.Fatalf("establish direct: %+v %v", summary, err)
	}
	assertPhaseAPendingText(t, b, first.EventID, "establish", now)

	// The largest packet the direct-application bound admits.
	payloadBytes := 0
	var canonical []byte
	for size := 70_000; size > 0; size -= 64 {
		candidate := packetFrom(t, a.config.AgentID, b.config.AgentID, uint64(now.Unix()), size)
		if len(candidate) <= 96<<10 {
			payloadBytes, canonical = size, candidate
			break
		}
	}
	if payloadBytes < 60<<10 {
		t.Fatalf("a 60 KiB frame does not fit the direct-application bound: %d", payloadBytes)
	}
	sent, err := a.SendDirectApplication(context.Background(), b.config.AgentID, "agent.packet", canonical,
		"idem_"+strings.Repeat("5", 64), uint64(now.Add(time.Hour).Unix()))
	if err != nil {
		t.Fatalf("send Agent Packet: %v", err)
	}
	if summary, err := a.dispatch.Sweep(context.Background(), 0); err != nil || summary.Sent != 1 {
		t.Fatalf("deliver Agent Packet: %+v %v", summary, err)
	}

	directory, err := os.MkdirTemp("", "apkt")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(directory) })
	socket := filepath.Join(directory, "r.sock")
	listener, err := net.Listen("unix", socket)
	if err != nil {
		t.Fatal(err)
	}
	captured := &capturedPackets{}
	server := &http.Server{Handler: captured, ReadHeaderTimeout: time.Second}
	go func() { _ = server.Serve(listener) }()
	t.Cleanup(func() { _ = server.Close() })
	receiver, err := agentpacketbridge.NewUnixReceiver(socket, 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	bridge, err := agentpacketbridge.New(agentpacketbridge.Config{Resolver: packetStates{
		a.config.AgentID: agentPolicy(a.config.AgentID), b.config.AgentID: agentPolicy(b.config.AgentID)},
		Verifier: sendKeys, Journal: b.journal, Receiver: receiver, RecipientAgentID: b.config.AgentID})
	if err != nil {
		t.Fatal(err)
	}
	b.agentPackets = bridge
	b.sweepAgentPackets(context.Background())
	bodies := captured.received()
	if len(bodies) != 1 || !bytes.Equal(bodies[0], canonical) {
		t.Fatalf("the receiver got %d bodies; want the exact %d-byte packet (event %s)", len(bodies), len(canonical), sent.EventID)
	}
	if pending, err := b.journal.ListPending(now, 10); err != nil || len(pending) != 1 {
		t.Fatalf("the delivered packet is still pending: %d %v", len(pending), err)
	}
}

func TestSendDirectApplicationRefusesAForeignOrNonCanonicalAgentPacket(t *testing.T) {
	now := time.Unix(1_900_000_000, 0)
	a := newPhaseADaemon(t, now, "2", "4")
	b := newPhaseADaemon(t, now, "7", "9")
	connectPhaseADirectories(a, b, now)
	installPhaseAAdmission(t, now, a, b)
	installPacketTransport(t, now, a, b)
	expires := uint64(now.Add(time.Hour).Unix())
	foreign := packetFrom(t, b.config.AgentID, a.config.AgentID, uint64(now.Unix()), 128)
	if _, err := a.SendDirectApplication(context.Background(), b.config.AgentID, "agent.packet", foreign,
		"idem_"+strings.Repeat("6", 64), expires); err == nil || !strings.Contains(err.Error(), "sending Agent") {
		t.Fatalf("a packet from another Agent: %v", err)
	}
	own := packetFrom(t, a.config.AgentID, b.config.AgentID, uint64(now.Unix()), 128)
	spaced := append([]byte(" "), own...)
	if _, err := a.SendDirectApplication(context.Background(), b.config.AgentID, "agent.packet", spaced,
		"idem_"+strings.Repeat("7", 64), expires); err == nil {
		t.Fatal("non-canonical packet JSON was accepted")
	}
	if _, err := a.SendDirectApplication(context.Background(), b.config.AgentID, "agent.packet", []byte("{}"),
		"idem_"+strings.Repeat("8", 64), expires); err == nil {
		t.Fatal("a body that is not an Agent Packet was accepted")
	}
}
