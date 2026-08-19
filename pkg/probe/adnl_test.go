package probe

import (
	"context"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/tosnetwork/tos-messenger/pkg/reachability"
)

// The route decision turns on whether a real ADNL session comes up, not on
// whether datagrams pass. This runs two endpoints against a live coordinator,
// hands each rendezvous port to a real gateway, and requires a completed
// handshake and round trip in both directions.
func TestEndToEndADNLEstablishment(t *testing.T) {
	skipUnderRace(t)
	coordinator := testCoordinator(t)
	listener, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer listener.Close()
	go func() { _ = coordinator.Serve(listener) }()

	session, err := NewSessionID()
	if err != nil {
		t.Fatalf("session: %v", err)
	}
	config := Config{
		EndpointKeyHex: testEndpointKey(RoleA), Probe: reachability.ProbeADNL,
		Coordinators: []string{listener.LocalAddr().String()},
		SessionID:    session,
		ListenAddr:   "127.0.0.1:0",
		BindTimeout:  3 * time.Second,
		PairTimeout:  8 * time.Second,
		PunchTimeout: 10 * time.Second,
		PollInterval: 50 * time.Millisecond,
		LingerWindow: 500 * time.Millisecond,
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	type outcome struct {
		result Result
		err    error
	}
	results := make(chan outcome, 2)
	for _, role := range []Role{RoleA, RoleB} {
		go func(role Role) {
			local := config
			local.Role = role
			local.EndpointKeyHex = testEndpointKey(role)
			result, err := RunADNL(ctx, local)
			results <- outcome{result: result, err: err}
		}(role)
	}
	for index := 0; index < 2; index++ {
		received := <-results
		if received.err != nil {
			t.Fatalf("probe returned an error: %v", received.err)
		}
		if !received.result.Established {
			t.Fatalf("no ADNL session was established: failure=%q", received.result.Failure)
		}
		if received.result.Failure != reachability.FailureNone {
			t.Fatalf("an established session reported a failure: %q", received.result.Failure)
		}
		if received.result.EstablishMillis == 0 {
			t.Fatal("an established session reported no latency")
		}
		// The attestation names this probe, so the trial built from this
		// result files under adnl and nowhere else.
		if received.result.Observation.Probe != string(reachability.ProbeADNL) {
			t.Fatalf("the coordinator attested to %q", received.result.Observation.Probe)
		}
		if err := reachability.VerifyObservation(received.result.Observation); err != nil {
			t.Fatalf("the observation does not verify: %v", err)
		}
	}
}

// Each runner measures exactly the probe it implements. Running one under the
// other's name would have the coordinator attest to a measurement that never
// happened.
func TestRunnersRefuseTheWrongProbe(t *testing.T) {
	config := Config{
		EndpointKeyHex: testEndpointKey(RoleA),
		Coordinators:   []string{"127.0.0.1:9"},
		SessionID:      "ses_00000000000000000000000000000000",
		Role:           RoleA,
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	config.Probe = reachability.ProbeADNL
	if _, err := Run(ctx, config); err == nil {
		t.Fatal("the udp runner accepted the adnl probe's name")
	}
	config.Probe = reachability.ProbeUDP
	if _, err := RunADNL(ctx, config); err == nil {
		t.Fatal("the adnl runner accepted the udp probe's name")
	}
}

// An ADNL pairing without a transport key would pair two endpoints that can
// never build a handshake toward each other.
func TestADNLPairingRequiresATransportKey(t *testing.T) {
	if _, err := EncodeRequest(Message{
		Kind: KindPair, SessionID: "ses_00000000000000000000000000000000",
		Role: RoleA, Nonce: testNonce, Candidates: []string{"127.0.0.1:1"},
		EndpointKey: testEndpointKey(RoleA), Probe: string(reachability.ProbeADNL),
	}); err == nil {
		t.Fatal("an adnl pairing without a transport key was accepted")
	}
	if _, err := EncodeRequest(Message{
		Kind: KindPair, SessionID: "ses_00000000000000000000000000000000",
		Role: RoleA, Nonce: testNonce, Candidates: []string{"127.0.0.1:1"},
		EndpointKey: testEndpointKey(RoleA), Probe: string(reachability.ProbeUDP),
	}); err != nil {
		t.Fatalf("a udp pairing was refused: %v", err)
	}
}

// Two halves measuring different probes are not one measurement, and the
// coordinator says so at pairing time rather than leaving it for the report.
func TestCoordinatorRefusesMismatchedProbes(t *testing.T) {
	coordinator := testCoordinator(t)
	listener, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer listener.Close()
	go func() { _ = coordinator.Serve(listener) }()
	address := listener.LocalAddr().String()

	session, err := NewSessionID()
	if err != nil {
		t.Fatalf("session: %v", err)
	}
	// Role A pairs for udp; role B pairs for adnl.
	sendPair := func(role Role, probe reachability.ProbeKind, transportKey string) Message {
		t.Helper()
		conn, err := net.Dial("udp", address)
		if err != nil {
			t.Fatalf("dial: %v", err)
		}
		defer conn.Close()
		request, err := EncodeRequest(Message{
			Kind: KindPair, SessionID: session, Role: role, Nonce: testNonce,
			Candidates: []string{"127.0.0.1:1"}, Commit: strings.Repeat("a", 40),
			EndpointKey: testEndpointKey(role), Probe: string(probe),
			TransportKey: transportKey,
		})
		if err != nil {
			t.Fatalf("encode: %v", err)
		}
		if _, err := conn.Write(request); err != nil {
			t.Fatalf("write: %v", err)
		}
		_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
		buffer := make([]byte, 2048)
		read, err := conn.Read(buffer)
		if err != nil {
			t.Fatalf("read: %v", err)
		}
		reply, err := Decode(buffer[:read])
		if err != nil {
			t.Fatalf("decode: %v", err)
		}
		return reply
	}

	first := sendPair(RoleA, reachability.ProbeUDP, "")
	if first.Kind == KindError {
		t.Fatalf("the first half was refused: %s", first.Reason)
	}
	second := sendPair(RoleB, reachability.ProbeADNL, testEndpointKey(RoleB))
	if second.Kind != KindError {
		t.Fatalf("mismatched probes were paired: %+v", second)
	}
}

// skipUnderRace names the reason once. The Makefile's verify target runs these
// tests in a dedicated non-race pass, so the skip is a relocation, not a loss.
func skipUnderRace(t *testing.T) {
	t.Helper()
	if RaceEnabled {
		t.Skip("tonutils-go's TL serializer trips checkptr; the ADNL gateway cannot run under -race")
	}
}
