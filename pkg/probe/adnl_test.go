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
	establishOverLoopback(t, "127.0.0.1")
}

// The reachability policy includes IPv6 endpoints, so the collector has to
// establish over IPv6 and not merely IPv4. This is the IPv4 test's mirror on
// the ::1 loopback; it skips cleanly where the host offers no usable IPv6
// loopback rather than failing on the environment.
func TestEndToEndADNLEstablishmentIPv6(t *testing.T) {
	if !hasIPv6Loopback() {
		t.Skip("no usable IPv6 loopback on this host; ADNL IPv6 establishment cannot be exercised")
	}
	establishOverLoopback(t, "::1")
}

// establishOverLoopback runs the two-endpoint establishment on one loopback
// host, so the IPv4 and IPv6 cases share exactly the same assertions and only
// the address family differs.
func establishOverLoopback(t *testing.T, host string) {
	t.Helper()
	results := runADNLPair(t, host, nil)
	for role, result := range results {
		if !result.Established {
			t.Fatalf("no ADNL session was established for role %s: failure=%q", role, result.Failure)
		}
		if result.Failure != reachability.FailureNone {
			t.Fatalf("an established session reported a failure: %q", result.Failure)
		}
		if result.EstablishMillis == 0 {
			t.Fatal("an established session reported no latency")
		}
		// Without a hold window the run measures establishment only, exactly
		// as before: the survival and reconnect fields must keep their
		// unmeasured zeros rather than invent a measurement.
		if result.SurvivalSeconds != 0 {
			t.Fatalf("survival was recorded without a hold window: %d", result.SurvivalSeconds)
		}
		if result.ReconnectMillis != 0 {
			t.Fatalf("a reconnect was recorded without being requested: %d", result.ReconnectMillis)
		}
		// The attestation names this probe, so the trial built from this
		// result files under adnl and nowhere else.
		if result.Observation.Probe != string(reachability.ProbeADNL) {
			t.Fatalf("the coordinator attested to %q", result.Observation.Probe)
		}
		if err := reachability.VerifyObservation(result.Observation); err != nil {
			t.Fatalf("the observation does not verify: %v", err)
		}
	}
}

// The route decision reads more than the first round trip: whether a session
// stays alive under keepalives, and how quickly the initiator re-establishes
// after a deliberate drop. On loopback the session must survive its whole
// hold window on both ends, and only the initiating role may carry a
// reconnect number, because pair joining takes the max of the two halves.
func TestEndToEndADNLHoldSurvivalAndReconnect(t *testing.T) {
	hold := 3 * time.Second
	results := runADNLPair(t, "127.0.0.1", func(config *Config) {
		config.HoldWindow = hold
		config.KeepaliveInterval = 300 * time.Millisecond
		config.MeasureReconnect = true
	})
	for role, result := range results {
		if !result.Established {
			t.Fatalf("no ADNL session was established for role %s: failure=%q", role, result.Failure)
		}
		if result.SurvivalSeconds < 1 {
			t.Fatalf("role %s measured no survival", role)
		}
		if result.SurvivalSeconds != uint64(hold/time.Second) {
			t.Fatalf("role %s did not survive its full loopback hold window: %d", role, result.SurvivalSeconds)
		}
	}
	if results[RoleA].ReconnectMillis == 0 {
		t.Fatal("the initiator measured no reconnect")
	}
	if results[RoleB].ReconnectMillis != 0 {
		t.Fatalf("the responder invented a reconnect: %d", results[RoleB].ReconnectMillis)
	}
}

// runADNLPair runs both endpoints of one ADNL attempt against a live
// coordinator on the given loopback host, applies the same configuration
// adjustment to both, and returns each role's result.
func runADNLPair(t *testing.T, host string, adjust func(*Config)) map[Role]Result {
	t.Helper()
	skipUnderRace(t)
	loopback := net.JoinHostPort(host, "0")
	coordinator := testCoordinator(t)
	listener, err := net.ListenPacket("udp", loopback)
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
		ListenAddr:   loopback,
		BindTimeout:  3 * time.Second,
		PairTimeout:  8 * time.Second,
		PunchTimeout: 10 * time.Second,
		PollInterval: 50 * time.Millisecond,
		LingerWindow: 500 * time.Millisecond,
	}
	if adjust != nil {
		adjust(&config)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	type outcome struct {
		role   Role
		result Result
		err    error
	}
	outcomes := make(chan outcome, 2)
	for _, role := range []Role{RoleA, RoleB} {
		go func(role Role) {
			local := config
			local.Role = role
			local.EndpointKeyHex = testEndpointKey(role)
			result, err := RunADNL(ctx, local)
			outcomes <- outcome{role: role, result: result, err: err}
		}(role)
	}
	results := make(map[Role]Result, 2)
	for index := 0; index < 2; index++ {
		received := <-outcomes
		if received.err != nil {
			t.Fatalf("probe returned an error: %v", received.err)
		}
		results[received.role] = received.result
	}
	return results
}

// hasIPv6Loopback reports whether ::1 can actually be bound here, so the IPv6
// test skips on hosts with IPv6 disabled instead of failing on them.
func hasIPv6Loopback() bool {
	conn, err := net.ListenPacket("udp", "[::1]:0")
	if err != nil {
		return false
	}
	_ = conn.Close()
	return true
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

// A measurement window that cannot work is refused rather than silently
// ignored: a run that recorded "not measured" for something the operator asked
// to measure would look like evidence of nothing when it is actually a
// misconfiguration.
func TestConfigRefusesUnusableMeasurementWindows(t *testing.T) {
	base := Config{
		EndpointKeyHex: testEndpointKey(RoleA), Probe: reachability.ProbeADNL,
		Coordinators: []string{"127.0.0.1:9"},
		SessionID:    "ses_00000000000000000000000000000000",
		Role:         RoleA,
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	negative := base
	negative.HoldWindow = -time.Second
	if _, err := RunADNL(ctx, negative); err == nil {
		t.Fatal("a negative hold window was accepted")
	}
	tooSlow := base
	tooSlow.HoldWindow = time.Second
	tooSlow.KeepaliveInterval = 2 * time.Second
	if _, err := RunADNL(ctx, tooSlow); err == nil {
		t.Fatal("a keepalive interval larger than its hold window was accepted")
	}
	unheld := base
	unheld.MeasureReconnect = true
	if _, err := RunADNL(ctx, unheld); err == nil {
		t.Fatal("reconnect measurement without a hold window was accepted")
	}
	wrongProbe := base
	wrongProbe.Probe = reachability.ProbeUDP
	wrongProbe.HoldWindow = time.Second
	if _, err := Run(ctx, wrongProbe); err == nil {
		t.Fatal("the udp probe accepted a hold window it cannot measure")
	}
	badTunnel := base
	badTunnel.TunnelAddr = "not an address"
	if _, err := RunADNL(ctx, badTunnel); err == nil {
		t.Fatal("an unresolvable tunnel relay address was accepted")
	}
	udpTunnel := base
	udpTunnel.Probe = reachability.ProbeUDP
	udpTunnel.TunnelAddr = "127.0.0.1:9"
	if _, err := Run(ctx, udpTunnel); err == nil {
		t.Fatal("the udp probe accepted a tunnel it cannot measure")
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
