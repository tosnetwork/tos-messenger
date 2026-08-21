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
		// And the phase-status booleans agree: nothing was attempted, so
		// nothing may claim to have run, let alone completed.
		if result.HoldAttempted || result.HoldCompleted ||
			result.ReconnectAttempted || result.ReconnectSucceeded ||
			result.TunnelHoldAttempted || result.TunnelHoldCompleted {
			t.Fatalf("an establishment-only run claimed a measurement phase: %+v", result)
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
	results := runADNLPair(t, "127.0.0.1", func(role Role, config *Config) {
		config.HoldWindow = hold
		config.KeepaliveInterval = 300 * time.Millisecond
		// Only the initiator asks for the reconnect. The responder refuses the
		// request outright at validation, because it never dials and a request
		// it cannot act on must not pass as a run that measured it.
		config.MeasureReconnect = role == RoleA
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
		// The hold phase ran and the loopback session survived its full window,
		// and the booleans have to say so: they are how a died-mid-window hold
		// would be told apart from this one.
		if !result.HoldAttempted || !result.HoldCompleted {
			t.Fatalf("role %s did not report its hold phase: attempted=%t completed=%t",
				role, result.HoldAttempted, result.HoldCompleted)
		}
		if result.TunnelHoldAttempted || result.TunnelHoldCompleted {
			t.Fatalf("role %s claimed a tunnel hold on a direct session", role)
		}
	}
	if results[RoleA].ReconnectMillis == 0 {
		t.Fatal("the initiator measured no reconnect")
	}
	if !results[RoleA].ReconnectAttempted || !results[RoleA].ReconnectSucceeded {
		t.Fatalf("the initiator's reconnect status does not match its measurement: %+v", results[RoleA])
	}
	if results[RoleB].ReconnectMillis != 0 {
		t.Fatalf("the responder invented a reconnect: %d", results[RoleB].ReconnectMillis)
	}
	if results[RoleB].ReconnectAttempted || results[RoleB].ReconnectSucceeded {
		t.Fatal("the responder claimed a reconnect phase it cannot run")
	}
}

// A reconnect the network refuses must stay visible: attempted and not
// succeeded, with the latency left at its unmeasured zero. The failure is
// forced deterministically by shrinking the reconnect window below any
// possible round trip, so the deadline expires before a ping can confirm --
// the same recording path a real refusal takes.
func TestEndToEndADNLFailedReconnectIsRecorded(t *testing.T) {
	reconnectWindowForTest = time.Nanosecond
	defer func() { reconnectWindowForTest = 0 }()

	results := runADNLPair(t, "127.0.0.1", func(role Role, config *Config) {
		config.HoldWindow = 2 * time.Second
		config.KeepaliveInterval = 300 * time.Millisecond
		config.MeasureReconnect = role == RoleA
	})
	initiator := results[RoleA]
	if !initiator.Established || !initiator.HoldCompleted {
		t.Fatalf("the session never reached the reconnect phase: %+v", initiator)
	}
	if !initiator.ReconnectAttempted {
		t.Fatal("a reconnect that ran and failed was recorded as never attempted")
	}
	if initiator.ReconnectSucceeded {
		t.Fatal("a reconnect that could not complete claimed success")
	}
	if initiator.ReconnectMillis != 0 {
		t.Fatalf("a failed reconnect carried a latency: %d", initiator.ReconnectMillis)
	}
}

// runADNLPair runs both endpoints of one ADNL attempt against a live
// coordinator on the given loopback host, applies the configuration
// adjustment to each role, and returns each role's result. The adjustment
// sees the role because the phases are not symmetric: only the initiator may
// request a reconnect.
func runADNLPair(t *testing.T, host string, adjust func(Role, *Config)) map[Role]Result {
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
			if adjust != nil {
				adjust(role, &local)
			}
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
	// The responder never dials, so it has no channel to deliberately drop and
	// re-dial: a responder run that accepted the request would validate and
	// then silently measure nothing.
	responder := base
	responder.Role = RoleB
	responder.EndpointKeyHex = testEndpointKey(RoleB)
	responder.HoldWindow = time.Second
	responder.MeasureReconnect = true
	if _, err := RunADNL(ctx, responder); err == nil {
		t.Fatal("the responder accepted a reconnect it cannot measure")
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

// The echo cross-check must work between two of this collector's own
// endpoints before it can prove anything about another implementation: each
// side answers the other's sized queries with the payload hash, and the
// querier verifies the exact hash came back over the session under test. Both
// the fragmentation-exercising size and the largest permitted size must round
// trip on loopback.
func TestEndToEndADNLEchoCrossCheck(t *testing.T) {
	sizes := []int{1024, MaxEchoBytes}
	results := runADNLPair(t, "127.0.0.1", func(role Role, config *Config) {
		config.EchoSizes = sizes
	})
	for role, result := range results {
		if !result.Established {
			t.Fatalf("no ADNL session was established for role %s: failure=%q", role, result.Failure)
		}
		if len(result.EchoResults) != len(sizes) {
			t.Fatalf("role %s ran %d echoes, configured %d: %+v",
				role, len(result.EchoResults), len(sizes), result.EchoResults)
		}
		for index, echoed := range result.EchoResults {
			if echoed.Bytes != sizes[index] {
				t.Fatalf("role %s echo %d carried %d bytes, configured %d",
					role, index, echoed.Bytes, sizes[index])
			}
			if !echoed.OK {
				t.Fatalf("role %s echo of %d bytes did not verify", role, echoed.Bytes)
			}
			if echoed.Millis == 0 {
				t.Fatalf("role %s echo of %d bytes verified without a latency", role, echoed.Bytes)
			}
		}
	}
}

// One application query must survive a real loss window after making
// measurable progress. The 4,000,001-byte response necessarily spans three
// pinned RLDP parts; each endpoint drops both inbound and outbound RLDP custom
// messages after its first decoded part, then requires the original DoQuery to
// return the exact deterministic payload after the window. No retry is issued.
func TestEndToEndRLDPSegmentationAndSameTransferRecovery(t *testing.T) {
	plan := RLDPTransferPlan{
		PayloadBytes:        4_000_001,
		InterruptAfterBytes: RLDPPartSizeBytes,
		Interruption:        150 * time.Millisecond,
	}
	results := runADNLPair(t, "127.0.0.1", func(_ Role, config *Config) {
		config.PunchTimeout = 8 * time.Second
		config.RLDPTransfers = []RLDPTransferPlan{plan}
	})
	for role, result := range results {
		if !result.Established || len(result.RLDPResults) != 1 {
			t.Fatalf("role %s did not run one RLDP transfer: %+v", role, result)
		}
		measured := result.RLDPResults[0]
		if measured.PayloadBytes != plan.PayloadBytes || measured.PartSizeBytes != RLDPPartSizeBytes || measured.ExpectedParts != 3 {
			t.Fatalf("role %s did not prove the pinned three-part shape: %+v", role, measured)
		}
		if !measured.Succeeded || measured.PayloadSHA256 == "" || measured.RoundTripMillis == 0 {
			t.Fatalf("role %s did not verify the exact large response: %+v", role, measured)
		}
		if !measured.InterruptionAttempted || measured.InterruptAfterBytes != RLDPPartSizeBytes ||
			measured.InterruptionMillis < 100 || measured.SuppressedMessages == 0 || !measured.SameTransferResumed {
			t.Fatalf("role %s did not recover the same transfer after observable interruption: %+v", role, measured)
		}
	}
}

// The gateway library cannot parse the native peer's raw hash answer, so the
// answer watch and Query completion can become ready together at the timeout
// boundary. Go deliberately randomizes a select between ready cases; every
// iteration must still prefer the cryptographically matched answer.
func TestEchoAnswerWinsTheQueryCompletionRace(t *testing.T) {
	for attempt := 0; attempt < 1000; attempt++ {
		arrived := make(chan struct{}, 1)
		queryDone := make(chan struct{}, 1)
		arrived <- struct{}{}
		queryDone <- struct{}{}
		if !echoAnswerArrived(arrived, queryDone) {
			t.Fatalf("verified answer lost to simultaneous query completion on attempt %d", attempt)
		}
	}

	queryDone := make(chan struct{}, 1)
	queryDone <- struct{}{}
	if echoAnswerArrived(make(chan struct{}), queryDone) {
		t.Fatal("query completion without an answer was accepted")
	}
}

// An establishment-only run must keep its empty echo slice: nothing was
// configured, so nothing may claim to have run.
func TestADNLEchoNotRunUnlessConfigured(t *testing.T) {
	results := runADNLPair(t, "127.0.0.1", nil)
	for role, result := range results {
		if len(result.EchoResults) != 0 {
			t.Fatalf("role %s ran echoes nobody configured: %+v", role, result.EchoResults)
		}
	}
}

// What a runner cannot measure it must refuse, not silently skip: echo sizes
// past the native cap or under a byte, echoes on the sessionless udp probe,
// the tunnel fallback on the sidecar runner, and each runner given the other
// runner's configuration.
func TestConfigRefusesWhatTheRunnersCannotMeasure(t *testing.T) {
	base := Config{
		EndpointKeyHex: testEndpointKey(RoleA), Probe: reachability.ProbeADNL,
		Coordinators: []string{"127.0.0.1:9"},
		SessionID:    "ses_00000000000000000000000000000000",
		Role:         RoleA,
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	oversized := base
	oversized.EchoSizes = []int{MaxEchoBytes + 1}
	if _, err := RunADNL(ctx, oversized); err == nil {
		t.Fatal("an echo past the native query cap was accepted")
	}
	empty := base
	empty.EchoSizes = []int{0}
	if _, err := RunADNL(ctx, empty); err == nil {
		t.Fatal("a zero-byte echo was accepted")
	}
	duplicate := base
	duplicate.EchoSizes = []int{1024, 1024}
	if _, err := RunADNL(ctx, duplicate); err == nil {
		t.Fatal("duplicate echo sizes were accepted")
	}
	tooMany := base
	for size := 1; size <= reachability.MaxSizedEchoMeasurements+1; size++ {
		tooMany.EchoSizes = append(tooMany.EchoSizes, size)
	}
	if _, err := RunADNL(ctx, tooMany); err == nil {
		t.Fatal("too many echo sizes were accepted")
	}
	udpEcho := base
	udpEcho.Probe = reachability.ProbeUDP
	udpEcho.EchoSizes = []int{1024}
	if _, err := Run(ctx, udpEcho); err == nil {
		t.Fatal("the udp probe accepted an echo it cannot measure")
	}
	segmented := RLDPTransferPlan{PayloadBytes: 4_000_001,
		InterruptAfterBytes: RLDPPartSizeBytes, Interruption: 150 * time.Millisecond}
	udpRLDP := base
	udpRLDP.Probe = reachability.ProbeUDP
	udpRLDP.RLDPTransfers = []RLDPTransferPlan{segmented}
	if _, err := Run(ctx, udpRLDP); err == nil {
		t.Fatal("the udp probe accepted an RLDP transfer it cannot measure")
	}
	sidecarRLDP := base
	sidecarRLDP.SidecarPath = "/no/such/sidecar"
	sidecarRLDP.RLDPTransfers = []RLDPTransferPlan{segmented}
	if _, err := RunADNLSidecar(ctx, sidecarRLDP); err == nil {
		t.Fatal("the native sidecar claimed an RLDP command its protocol does not expose")
	}
	beforePart := base
	beforePart.RLDPTransfers = []RLDPTransferPlan{{PayloadBytes: 4_000_001,
		InterruptAfterBytes: RLDPPartSizeBytes - 1, Interruption: 150 * time.Millisecond}}
	if _, err := RunADNL(ctx, beforePart); err == nil {
		t.Fatal("an RLDP interruption before one complete part was accepted")
	}
	tunneled := base
	tunneled.SidecarPath = "/no/such/sidecar"
	tunneled.TunnelAddr = "127.0.0.1:9"
	if _, err := RunADNLSidecar(ctx, tunneled); err == nil {
		t.Fatal("the sidecar runner accepted a tunnel it cannot measure")
	}
	misrouted := base
	misrouted.SidecarPath = "/no/such/sidecar"
	if _, err := RunADNL(ctx, misrouted); err == nil {
		t.Fatal("the gateway runner accepted a sidecar configuration")
	}
	pathless := base
	if _, err := RunADNLSidecar(ctx, pathless); err == nil {
		t.Fatal("the sidecar runner accepted a run without a sidecar binary")
	}
	// The sidecar protocol freezes its window bounds; a run outside them must
	// be refused here as tooling, before the sidecar could answer the same
	// refusal mid-measurement.
	overlong := base
	overlong.SidecarPath = "/no/such/sidecar"
	overlong.PunchTimeout = 121 * time.Second
	if _, err := RunADNLSidecar(ctx, overlong); err == nil {
		t.Fatal("the sidecar runner accepted a timeout past the protocol bound")
	}
	overheld := base
	overheld.SidecarPath = "/no/such/sidecar"
	overheld.HoldWindow = 601 * time.Second
	if _, err := RunADNLSidecar(ctx, overheld); err == nil {
		t.Fatal("the sidecar runner accepted a hold window past the protocol bound")
	}
	overpaced := base
	overpaced.SidecarPath = "/no/such/sidecar"
	overpaced.HoldWindow = 300 * time.Second
	overpaced.KeepaliveInterval = 121 * time.Second
	if _, err := RunADNLSidecar(ctx, overpaced); err == nil {
		t.Fatal("the sidecar runner accepted a keepalive past the protocol bound")
	}
	udpSidecar := base
	udpSidecar.Probe = reachability.ProbeUDP
	udpSidecar.SidecarPath = "/no/such/sidecar"
	if _, err := Run(ctx, udpSidecar); err == nil {
		t.Fatal("the udp probe accepted a sidecar it cannot use")
	}
}

// skipUnderRace names the reason once. The Makefile's verify target runs these
// tests in a dedicated non-race pass, so the skip is a relocation, not a loss.
func skipUnderRace(t *testing.T) {
	t.Helper()
	if RaceEnabled {
		t.Skip("tosutils-go's TL serializer trips checkptr; the ADNL gateway cannot run under -race")
	}
}
