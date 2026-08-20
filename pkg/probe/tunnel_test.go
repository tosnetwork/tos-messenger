package probe

import (
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/tosnetwork/tos-messenger/pkg/reachability"
)

// testTunnelRelay builds a relay with test-friendly limits and a controllable
// clock.
func testTunnelRelay(t *testing.T, options TunnelRelayOptions) *TunnelRelay {
	t.Helper()
	relay, err := NewTunnelRelay(options)
	if err != nil {
		t.Fatalf("relay: %v", err)
	}
	return relay
}

// registerTunnelEndpoint walks one endpoint through register and echo directly
// against Handle, asserting the anti-amplification rule at every step, and
// returns the token the relay issued.
func registerTunnelEndpoint(t *testing.T, relay *TunnelRelay, session string, role Role,
	from netip.AddrPort) [tunnelTokenBytes]byte {
	t.Helper()
	register, err := encodeTunnelFrame(tunnelFrame{
		kind: tunnelKindRegister, sessionID: session, role: role,
	}, TunnelRequestFloor)
	if err != nil {
		t.Fatalf("encode register: %v", err)
	}
	challenge, to := relay.Handle(register, from)
	if challenge == nil || to != from {
		t.Fatal("registration got no challenge")
	}
	if len(challenge) > len(register) {
		t.Fatalf("the challenge amplified its request: %d > %d", len(challenge), len(register))
	}
	frame, err := decodeTunnelFrame(challenge)
	if err != nil || frame.kind != tunnelKindChallenge {
		t.Fatalf("unexpected challenge: %v", err)
	}
	echo, err := encodeTunnelFrame(tunnelFrame{
		kind: tunnelKindEcho, sessionID: session, role: role, token: frame.token,
	}, TunnelRequestFloor)
	if err != nil {
		t.Fatalf("encode echo: %v", err)
	}
	status, to := relay.Handle(echo, from)
	if status == nil || to != from {
		t.Fatal("the echo got no status answer")
	}
	if len(status) > len(echo) {
		t.Fatalf("the status amplified its request: %d > %d", len(status), len(echo))
	}
	parsed, err := decodeTunnelFrame(status)
	if err != nil || parsed.kind != tunnelKindStatus {
		t.Fatalf("unexpected status: %v", err)
	}
	return frame.token
}

// A datagram from a tuple that never completed a registration is dropped
// without a word, whatever it contains: answering it would acknowledge a
// stranger, and forwarding it would relay for one.
func TestTunnelRelayDropsUnregisteredTraffic(t *testing.T) {
	relay := testTunnelRelay(t, TunnelRelayOptions{})
	stranger := source(t, "203.0.113.9:4001")
	payload := make([]byte, 200)
	for index := range payload {
		payload[index] = byte(index)
	}
	if answer, _ := relay.Handle(payload, stranger); answer != nil {
		t.Fatal("payload from an unregistered tuple was answered or forwarded")
	}
	// A well-formed control frame below the padding floor is equally refused:
	// answering it would amplify it.
	bare, err := encodeTunnelFrame(tunnelFrame{
		kind: tunnelKindRegister, sessionID: testSession, role: RoleA,
	}, 0)
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	if answer, _ := relay.Handle(bare, stranger); answer != nil {
		t.Fatal("an unpadded register was answered")
	}
}

// The token proves the registrant can receive at the address it claims. An
// echo carrying the right token from the wrong address is exactly what a
// spoofing bystander would produce, and it must not complete the registration
// for either address.
func TestTunnelRelayRefusesAnEchoFromTheWrongAddress(t *testing.T) {
	relay := testTunnelRelay(t, TunnelRelayOptions{})
	honest := source(t, "203.0.113.9:4001")
	thief := source(t, "198.51.100.7:5002")

	register, err := encodeTunnelFrame(tunnelFrame{
		kind: tunnelKindRegister, sessionID: testSession, role: RoleA,
	}, TunnelRequestFloor)
	if err != nil {
		t.Fatalf("encode register: %v", err)
	}
	challenge, _ := relay.Handle(register, honest)
	if challenge == nil {
		t.Fatal("registration got no challenge")
	}
	frame, err := decodeTunnelFrame(challenge)
	if err != nil {
		t.Fatalf("decode challenge: %v", err)
	}
	echo, err := encodeTunnelFrame(tunnelFrame{
		kind: tunnelKindEcho, sessionID: testSession, role: RoleA, token: frame.token,
	}, TunnelRequestFloor)
	if err != nil {
		t.Fatalf("encode echo: %v", err)
	}
	if answer, _ := relay.Handle(echo, thief); answer != nil {
		t.Fatal("an echo from the wrong address was answered")
	}
	// The honest tuple can still complete with the same token.
	if answer, _ := relay.Handle(echo, honest); answer == nil {
		t.Fatal("the honest echo was refused after the spoofed one")
	}
	// And a wrong token from the right address is refused too.
	var wrong [tunnelTokenBytes]byte
	wrong[0] = ^frame.token[0]
	badEcho, err := encodeTunnelFrame(tunnelFrame{
		kind: tunnelKindEcho, sessionID: testSession, role: RoleB, token: wrong,
	}, TunnelRequestFloor)
	if err != nil {
		t.Fatalf("encode bad echo: %v", err)
	}
	if answer, _ := relay.Handle(badEcho, honest); answer != nil {
		t.Fatal("an echo with the wrong token was answered")
	}
}

// Forwarding happens only between the two registered endpoints of one session,
// verbatim and in both directions, and a completed registration cannot be
// evicted by a later register for the same slot.
func TestTunnelRelayForwardsBetweenRegisteredEndpoints(t *testing.T) {
	relay := testTunnelRelay(t, TunnelRelayOptions{})
	endpointA := source(t, "203.0.113.9:4001")
	endpointB := source(t, "198.51.100.7:5002")
	registerTunnelEndpoint(t, relay, testSession, RoleA, endpointA)

	payload := []byte("not yet: the peer has not registered")
	if answer, _ := relay.Handle(payload, endpointA); answer != nil {
		t.Fatal("payload was forwarded into a half-registered session")
	}
	registerTunnelEndpoint(t, relay, testSession, RoleB, endpointB)

	forwarded, to := relay.Handle(payload, endpointA)
	if string(forwarded) != string(payload) || to != endpointB {
		t.Fatalf("payload was not forwarded verbatim to the peer: %q -> %v", forwarded, to)
	}
	reply := []byte("and back again")
	forwarded, to = relay.Handle(reply, endpointB)
	if string(forwarded) != string(reply) || to != endpointA {
		t.Fatalf("the reverse direction was not forwarded: %q -> %v", forwarded, to)
	}

	// A late register for an already-proven slot is dropped: answering it
	// would let anyone who learned the session identifier evict a registered
	// endpoint.
	intruder := source(t, "192.0.2.44:6003")
	register, err := encodeTunnelFrame(tunnelFrame{
		kind: tunnelKindRegister, sessionID: testSession, role: RoleA,
	}, TunnelRequestFloor)
	if err != nil {
		t.Fatalf("encode register: %v", err)
	}
	if answer, _ := relay.Handle(register, intruder); answer != nil {
		t.Fatal("a completed registration was re-challenged")
	}
	if forwarded, to := relay.Handle([]byte("still the same pair"), endpointA); forwarded == nil || to != endpointB {
		t.Fatal("the registered pair stopped forwarding after the intrusion attempt")
	}
}

// The per-session byte budget bounds what a registered pair can push through
// the relay, both directions counted together, and an oversized datagram is
// dropped rather than truncated.
func TestTunnelRelayEnforcesTheSessionByteBudget(t *testing.T) {
	relay := testTunnelRelay(t, TunnelRelayOptions{SessionByteBudget: 300})
	endpointA := source(t, "203.0.113.9:4001")
	endpointB := source(t, "198.51.100.7:5002")
	registerTunnelEndpoint(t, relay, testSession, RoleA, endpointA)
	registerTunnelEndpoint(t, relay, testSession, RoleB, endpointB)

	payload := make([]byte, 200)
	if forwarded, _ := relay.Handle(payload, endpointA); forwarded == nil {
		t.Fatal("the first datagram inside the budget was dropped")
	}
	if forwarded, _ := relay.Handle(payload, endpointB); forwarded != nil {
		t.Fatal("the budget was exceeded and the datagram still forwarded")
	}
	oversized := make([]byte, MaxTunnelDatagramBytes+1)
	if forwarded, _ := relay.Handle(oversized, endpointA); forwarded != nil {
		t.Fatal("an oversized datagram was forwarded")
	}
}

// A session past its lifetime stops forwarding, and its tuple bindings go with
// it, so the relay cannot be parked on indefinitely.
func TestTunnelRelayExpiresSessions(t *testing.T) {
	current := time.Unix(1_700_000_000, 0)
	relay := testTunnelRelay(t, TunnelRelayOptions{
		SessionTTL: time.Minute,
		Now:        func() time.Time { return current },
	})
	endpointA := source(t, "203.0.113.9:4001")
	endpointB := source(t, "198.51.100.7:5002")
	registerTunnelEndpoint(t, relay, testSession, RoleA, endpointA)
	registerTunnelEndpoint(t, relay, testSession, RoleB, endpointB)
	if relay.Sessions() != 1 {
		t.Fatalf("expected one live session, got %d", relay.Sessions())
	}
	current = current.Add(2 * time.Minute)
	if forwarded, _ := relay.Handle([]byte("too late"), endpointA); forwarded != nil {
		t.Fatal("an expired session still forwarded")
	}
	if relay.Sessions() != 0 {
		t.Fatalf("the expired session was kept: %d", relay.Sessions())
	}
}

// The relay holds a bounded number of sessions; a register beyond capacity is
// dropped rather than growing without limit.
func TestTunnelRelayHonoursItsCapacity(t *testing.T) {
	relay := testTunnelRelay(t, TunnelRelayOptions{MaxSessions: 1})
	first := source(t, "203.0.113.9:4001")
	registerTunnelEndpoint(t, relay, testSession, RoleA, first)

	second, err := NewSessionID()
	if err != nil {
		t.Fatalf("session: %v", err)
	}
	register, err := encodeTunnelFrame(tunnelFrame{
		kind: tunnelKindRegister, sessionID: second, role: RoleA,
	}, TunnelRequestFloor)
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	if answer, _ := relay.Handle(register, source(t, "198.51.100.7:5002")); answer != nil {
		t.Fatal("a session beyond capacity was admitted")
	}
}

// Every structural rule of the control framing fails closed.
func TestTunnelFrameValidation(t *testing.T) {
	valid, err := encodeTunnelFrame(tunnelFrame{
		kind: tunnelKindRegister, sessionID: testSession, role: RoleA,
	}, TunnelRequestFloor)
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	if _, err := decodeTunnelFrame(valid); err != nil {
		t.Fatalf("a valid frame was refused: %v", err)
	}

	mutate := func(index int, value byte) []byte {
		copied := append([]byte(nil), valid...)
		copied[index] = value
		return copied
	}
	cases := map[string][]byte{
		"bad magic":       mutate(0, 'X'),
		"bad kind":        mutate(8, 99),
		"bad session":     mutate(9, 'X'),
		"bad role":        mutate(45, 'c'),
		"bad flag":        mutate(62, 7),
		"nonzero padding": mutate(TunnelRequestFloor-1, 1),
		"short frame":     valid[:tunnelHeaderBytes-1],
		"oversized frame": append(append([]byte(nil), valid...), 0),
		"empty frame":     {},
	}
	for name, raw := range cases {
		if _, err := decodeTunnelFrame(raw); err == nil {
			t.Fatalf("expected %q to be refused", name)
		}
	}
	if _, err := encodeTunnelFrame(tunnelFrame{
		kind: tunnelKindRegister, sessionID: "ses_short", role: RoleA,
	}, TunnelRequestFloor); err == nil {
		t.Fatal("an invalid session identifier was encoded")
	}
}

// The tunnel phase is what gives the study's tunnel-first route a collection
// path. The direct phase is forced to fail deterministically by replacing the
// initiator's candidates with an address nothing answers at; both halves must
// then establish through the relay, mark the establishment as tunneled, and
// keep the direct phase's failure class -- the exact pairing the trial schema
// requires of a proxy-fallback outcome. With a hold window configured, the
// hold phase also runs over the tunneled session: its status booleans are the
// tunnel-survival evidence, while the survival SPAN stays a direct-session
// measurement and must keep its unmeasured zero here.
func TestEndToEndADNLTunnelFallback(t *testing.T) {
	skipUnderRace(t)
	relay := testTunnelRelay(t, TunnelRelayOptions{})
	listener, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer listener.Close()
	go func() { _ = relay.Serve(listener) }()

	directPeersForTest = func([]netip.AddrPort) []netip.AddrPort {
		return []netip.AddrPort{netip.MustParseAddrPort("127.0.0.1:1")}
	}
	defer func() { directPeersForTest = nil }()

	results := runADNLPair(t, "127.0.0.1", func(_ Role, config *Config) {
		config.PunchTimeout = 3 * time.Second
		config.TunnelAddr = listener.LocalAddr().String()
		config.HoldWindow = 2 * time.Second
		config.KeepaliveInterval = 300 * time.Millisecond
	})
	for role, result := range results {
		if !result.Established {
			t.Fatalf("role %s never established through the relay: failure=%q", role, result.Failure)
		}
		if !result.TunneledEstablish {
			t.Fatalf("role %s established but not through the tunnel", role)
		}
		if result.Failure != reachability.FailureHandshake {
			t.Fatalf("role %s lost the direct phase's failure class: %q", role, result.Failure)
		}
		if result.EstablishMillis == 0 {
			t.Fatalf("role %s recorded no tunnel establishment latency", role)
		}
		// Survival and reconnect numbers are direct-session measurements; the
		// schema forbids them off a direct outcome and the tunnel phase never
		// takes them.
		if result.SurvivalSeconds != 0 || result.ReconnectMillis != 0 {
			t.Fatalf("role %s measured survival or reconnect over the tunnel", role)
		}
		// The direct hold never ran -- there was no direct session to hold --
		// so its booleans stay false, and the tunnel hold ran to the end of its
		// window on loopback.
		if result.HoldAttempted || result.HoldCompleted {
			t.Fatalf("role %s claimed a direct hold over the tunnel", role)
		}
		if !result.TunnelHoldAttempted || !result.TunnelHoldCompleted {
			t.Fatalf("role %s did not report its tunnel hold: attempted=%t completed=%t",
				role, result.TunnelHoldAttempted, result.TunnelHoldCompleted)
		}
	}
}
