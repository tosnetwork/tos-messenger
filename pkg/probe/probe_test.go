package probe

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"net"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/tosnetwork/tos-messenger/pkg/reachability"
)

const testSession = "ses_" + "0123456789abcdef0123456789abcdef"
const testNonce = "fedcba9876543210fedcba9876543210"

func testKey(seed byte) ed25519.PrivateKey {
	return ed25519.NewKeyFromSeed(bytes.Repeat([]byte{seed}, ed25519.SeedSize))
}

func testServerID(t *testing.T) string {
	t.Helper()
	public, ok := testKey(0x33).Public().(ed25519.PublicKey)
	if !ok {
		t.Fatal("unexpected public key type")
	}
	identifier, err := reachability.CoordinatorID(public)
	if err != nil {
		t.Fatalf("coordinator id: %v", err)
	}
	return identifier
}

func TestRequestsReachThePaddingFloor(t *testing.T) {
	encoded, err := EncodeRequest(Message{
		Kind: KindBind, SessionID: testSession, Role: RoleA, Nonce: testNonce,
	})
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	if len(encoded) < MinRequestBytes {
		t.Fatalf("request is below the padding floor: %d bytes", len(encoded))
	}
	decoded, err := Decode(encoded)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if decoded.Kind != KindBind || decoded.SessionID != testSession {
		t.Fatal("padding changed the message")
	}
}

func TestAmplificationIsRefused(t *testing.T) {
	request := make([]byte, MinRequestBytes)
	if err := CheckNoAmplification(request, make([]byte, MinRequestBytes)); err != nil {
		t.Fatalf("an equal-sized response must be allowed: %v", err)
	}
	if err := CheckNoAmplification(request, make([]byte, MinRequestBytes+1)); err == nil {
		t.Fatal("expected a larger response to be refused")
	}
	if err := CheckNoAmplification(make([]byte, MinRequestBytes-1), make([]byte, 1)); err == nil {
		t.Fatal("expected an unpadded request to be refused")
	}
}

func TestValidateRejectsMalformedMessages(t *testing.T) {
	base := Message{Kind: KindBind, SessionID: testSession, Role: RoleA, Nonce: testNonce}
	cases := map[string]func(*Message){
		"bad kind":        func(m *Message) { m.Kind = "relay" },
		"bad session":     func(m *Message) { m.SessionID = "ses_bad" },
		"bad role":        func(m *Message) { m.Role = "c" },
		"bad nonce":       func(m *Message) { m.Nonce = "zz" },
		"bad observed":    func(m *Message) { m.Observed = "not-an-address" },
		"bad candidate":   func(m *Message) { m.Candidates = []string{"1.2.3.4"} },
		"zero port":       func(m *Message) { m.Candidates = []string{"1.2.3.4:0"} },
		"duplicate":       func(m *Message) { m.Candidates = []string{"1.2.3.4:1", "1.2.3.4:1"} },
		"too many":        func(m *Message) { m.Candidates = manyCandidates(MaxCandidates + 1) },
		"bad server":      func(m *Message) { m.ServerID = "srv_bad" },
		"long reason":     func(m *Message) { m.Reason = strings.Repeat("r", 65) },
		"non-pad padding": func(m *Message) { m.Padding = "abc" },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			message := base
			mutate(&message)
			if err := Validate(message); err == nil {
				t.Fatalf("expected %q to be refused", name)
			}
			if _, err := Encode(message); err == nil {
				t.Fatalf("expected %q to be unencodable", name)
			}
		})
	}
}

func TestDecodeRejectsMalformedDatagrams(t *testing.T) {
	valid, err := Encode(Message{Kind: KindBind, SessionID: testSession, Role: RoleA, Nonce: testNonce})
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	cases := map[string][]byte{
		"empty":         nil,
		"oversized":     make([]byte, MaxMessageBytes+1),
		"unknown field": []byte(string(valid[:len(valid)-1]) + `,"extra":1}`),
		"trailing":      append(append([]byte{}, valid...), []byte("{}")...),
		"wrong schema":  []byte(strings.Replace(string(valid), Schema, "other", 1)),
		"garbage":       []byte("not json at all"),
	}
	for name, raw := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := Decode(raw); err == nil {
				t.Fatalf("expected %q to be refused", name)
			}
		})
	}
}

func testCoordinator(t *testing.T) *Coordinator {
	t.Helper()
	coordinator, err := NewCoordinator(CoordinatorOptions{PrivateKey: testKey(0x33)})
	if err != nil {
		t.Fatalf("coordinator: %v", err)
	}
	return coordinator
}

func source(t *testing.T, text string) netip.AddrPort {
	t.Helper()
	address, err := netip.ParseAddrPort(text)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	return address
}

func TestCoordinatorReportsObservedAddress(t *testing.T) {
	coordinator := testCoordinator(t)
	request, err := EncodeRequest(Message{Kind: KindBind, SessionID: testSession, Role: RoleA, Nonce: testNonce})
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	response := coordinator.Handle(request, source(t, "203.0.113.7:41234"))
	if response == nil {
		t.Fatal("expected a bind answer")
	}
	if err := CheckNoAmplification(request, response); err != nil {
		t.Fatalf("coordinator amplified its request: %v", err)
	}
	message, err := Decode(response)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if message.Kind != KindBindOK || message.Observed != "203.0.113.7:41234" || message.ServerID != testServerID(t) {
		t.Fatalf("unexpected bind answer: %+v", message)
	}
}

// A bind request that names the endpoint key and probe is answered with a
// coordinator-signed reflection of the source address, which is what lets the
// NAT mapping class be derived from evidence instead of the endpoint's own
// declaration.
func TestCoordinatorAttestsBindReflection(t *testing.T) {
	coordinator := testCoordinator(t)
	endpointKey := strings.Repeat("a", 64)
	request, err := EncodeRequest(Message{
		Kind: KindBind, SessionID: testSession, Role: RoleA, Nonce: testNonce,
		EndpointKey: endpointKey, Probe: string(reachability.ProbeUDP),
	})
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	response := coordinator.Handle(request, source(t, "203.0.113.7:41234"))
	if response == nil {
		t.Fatal("expected a bind answer")
	}
	if err := CheckNoAmplification(request, response); err != nil {
		t.Fatalf("coordinator amplified its request: %v", err)
	}
	message, err := Decode(response)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if message.Signature == "" || message.SignerKey == "" {
		t.Fatalf("bind answer carried no attestation: %+v", message)
	}
	// Reconstruct the reflection the way the runner does and check it verifies
	// and attests exactly what was presented.
	identifier, err := reachability.CoordinatorID(mustKey(message.SignerKey))
	if err != nil {
		t.Fatalf("coordinator id: %v", err)
	}
	observation := reachability.BindObservation{
		CoordinatorID:        identifier,
		SessionID:            testSession,
		Role:                 string(RoleA),
		EndpointPublicKeyHex: endpointKey,
		Probe:                string(reachability.ProbeUDP),
		Observed:             message.Observed,
		AtUnix:               message.ObservedAt,
		PublicKeyHex:         message.SignerKey,
		SignatureHex:         message.Signature,
	}
	if err := reachability.VerifyBindObservation(observation); err != nil {
		t.Fatalf("the coordinator's bind reflection did not verify: %v", err)
	}
	if observation.Observed != "203.0.113.7:41234" || identifier != testServerID(t) {
		t.Fatalf("the reflection attested the wrong thing: %+v", observation)
	}
	// A bind request that omits the endpoint key gets its address but no
	// attestation, so an older client is still answered.
	bare, err := EncodeRequest(Message{Kind: KindBind, SessionID: testSession, Role: RoleA, Nonce: testNonce})
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	plain, err := Decode(coordinator.Handle(bare, source(t, "203.0.113.7:41234")))
	if err != nil {
		t.Fatalf("decode bare bind: %v", err)
	}
	if plain.Signature != "" || plain.SignerKey != "" {
		t.Fatal("a bind request without an endpoint key was attested anyway")
	}
}

// testEndpointKey is the key an endpoint tells the coordinator it will sign
// with. The attestation names it, so a test that omitted it would be
// exercising a pairing the coordinator now refuses.
func testEndpointKey(role Role) string {
	if role == RoleB {
		return strings.Repeat("b", 64)
	}
	return strings.Repeat("a", 64)
}

func TestCoordinatorExchangesCandidates(t *testing.T) {
	coordinator := testCoordinator(t)
	pair := func(role Role, from string, candidates []string) Message {
		t.Helper()
		request, err := EncodeRequest(Message{
			Kind: KindPair, SessionID: testSession, Role: role, Nonce: testNonce, Candidates: candidates,
			EndpointKey: testEndpointKey(role), Probe: string(reachability.ProbeUDP),
		})
		if err != nil {
			t.Fatalf("encode: %v", err)
		}
		response := coordinator.Handle(request, source(t, from))
		if response == nil {
			t.Fatal("expected a pair answer")
		}
		if err := CheckNoAmplification(request, response); err != nil {
			t.Fatalf("coordinator amplified its request: %v", err)
		}
		message, err := Decode(response)
		if err != nil {
			t.Fatalf("decode: %v", err)
		}
		return message
	}

	first := pair(RoleA, "203.0.113.7:41234", []string{"192.168.1.5:41234"})
	if first.Kind != KindPairOK || len(first.Candidates) != 0 {
		t.Fatalf("expected an empty answer before the peer arrives: %+v", first)
	}
	second := pair(RoleB, "198.51.100.9:52000", []string{"10.0.0.3:52000"})
	if second.Kind != KindPairOK {
		t.Fatalf("unexpected answer: %+v", second)
	}
	if len(second.Candidates) != 2 || second.Candidates[0] != "203.0.113.7:41234" ||
		second.Candidates[1] != "192.168.1.5:41234" {
		t.Fatalf("unexpected peer candidates: %v", second.Candidates)
	}
	third := pair(RoleA, "203.0.113.7:41234", []string{"192.168.1.5:41234"})
	if len(third.Candidates) != 2 || third.Candidates[0] != "198.51.100.9:52000" {
		t.Fatalf("unexpected peer candidates: %v", third.Candidates)
	}
	if coordinator.Sessions() != 1 {
		t.Fatalf("expected one live pairing, got %d", coordinator.Sessions())
	}
}

func TestCoordinatorDropsWhatItCannotAnswerSafely(t *testing.T) {
	coordinator := testCoordinator(t)
	unpadded, err := Encode(Message{Kind: KindBind, SessionID: testSession, Role: RoleA, Nonce: testNonce})
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	if coordinator.Handle(unpadded, source(t, "203.0.113.7:1")) != nil {
		t.Fatal("expected an unpadded request to be dropped")
	}
	punch, err := EncodeRequest(Message{Kind: KindPunch, SessionID: testSession, Role: RoleA, Nonce: testNonce})
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	if coordinator.Handle(punch, source(t, "203.0.113.7:1")) != nil {
		t.Fatal("a coordinator that answered punch traffic would be acting as a relay")
	}
	if coordinator.Handle([]byte(strings.Repeat("x", MinRequestBytes)), source(t, "203.0.113.7:1")) != nil {
		t.Fatal("expected garbage to be dropped")
	}
	if coordinator.Handle(punch, netip.AddrPort{}) != nil {
		t.Fatal("expected an invalid source to be dropped")
	}
}

func TestCoordinatorRateLimitsAndExpires(t *testing.T) {
	clock := time.Unix(1_800_000_000, 0)
	coordinator, err := NewCoordinator(CoordinatorOptions{
		PrivateKey:        testKey(0x33),
		RequestsPerWindow: 2,
		RateWindow:        time.Minute,
		SessionTTL:        time.Minute,
		Now:               func() time.Time { return clock },
	})
	if err != nil {
		t.Fatalf("coordinator: %v", err)
	}
	request, err := EncodeRequest(Message{Kind: KindPair, SessionID: testSession, Role: RoleA,
		Nonce: testNonce, EndpointKey: testEndpointKey(RoleA), Probe: string(reachability.ProbeUDP)})
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	from := source(t, "203.0.113.7:41234")
	if coordinator.Handle(request, from) == nil || coordinator.Handle(request, from) == nil {
		t.Fatal("expected the first two requests to be answered")
	}
	if coordinator.Handle(request, from) != nil {
		t.Fatal("expected the rate limit to drop the third request")
	}
	if coordinator.Handle(request, source(t, "198.51.100.9:1")) == nil {
		t.Fatal("expected another source to be unaffected")
	}
	clock = clock.Add(2 * time.Minute)
	if coordinator.Sessions() != 0 {
		t.Fatal("expected the pairing to expire")
	}
	if coordinator.Handle(request, from) == nil {
		t.Fatal("expected a new window to admit the source again")
	}
}

func TestCoordinatorRejectsInvalidOptions(t *testing.T) {
	for name, options := range map[string]CoordinatorOptions{
		"no key":        {},
		"short key":     {PrivateKey: make(ed25519.PrivateKey, 8)},
		"negative ttl":  {PrivateKey: testKey(0x33), SessionTTL: -time.Second},
		"zero capacity": {PrivateKey: testKey(0x33), MaxSessions: -1},
		"bad window":    {PrivateKey: testKey(0x33), RateWindow: -time.Second},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := NewCoordinator(options); err == nil {
				t.Fatalf("expected %q to be refused", name)
			}
		})
	}
}

func TestMappingClassificationIsHonestAboutOneObservation(t *testing.T) {
	// The host's own public address, used for the unmapped case.
	own := source(t, "203.0.113.7:41234").Addr()
	local := []netip.Addr{own}

	single := []netip.AddrPort{source(t, "203.0.113.7:41234")}
	if behavior := classifyMapping(single, 55555, local); behavior != reachability.NATUndetermined {
		t.Fatalf("one coordinator cannot separate mapping classes, got %q", behavior)
	}
	same := []netip.AddrPort{source(t, "203.0.113.7:41234"), source(t, "203.0.113.7:41234")}
	if behavior := classifyMapping(same, 55555, local); behavior != reachability.NATEndpointIndependent {
		t.Fatalf("expected an endpoint-independent mapping, got %q", behavior)
	}
	differing := []netip.AddrPort{source(t, "203.0.113.7:41234"), source(t, "203.0.113.7:41999")}
	if behavior := classifyMapping(differing, 55555, local); behavior != reachability.NATAddressPortDependent {
		t.Fatalf("expected an address-and-port-dependent mapping, got %q", behavior)
	}
	// Unmapped: the observed address is the host's own, at the same port.
	direct := []netip.AddrPort{source(t, "203.0.113.7:41234")}
	if behavior := classifyMapping(direct, 41234, local); behavior != reachability.NATNone {
		t.Fatalf("expected an unmapped endpoint, got %q", behavior)
	}
	// A NAT that preserves the source port but translates the IP is not
	// unmapped: the observed IP is not one the host holds, so matching the port
	// must not call it public. One observation, so it stays undetermined.
	behindPortPreservingNAT := []netip.AddrPort{source(t, "203.0.113.7:41234")}
	if behavior := classifyMapping(behindPortPreservingNAT, 41234, []netip.Addr{source(t, "192.168.1.10:41234").Addr()}); behavior != reachability.NATUndetermined {
		t.Fatalf("a port-preserving NAT was classified %q, not undetermined", behavior)
	}
	if behavior := classifyMapping(nil, 1, local); behavior != reachability.NATUndetermined {
		t.Fatalf("expected no observation to be undetermined, got %q", behavior)
	}
}

func TestEndToEndDirectEstablishment(t *testing.T) {
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
	config := Config{
		EndpointKeyHex: testEndpointKey(RoleA), Probe: reachability.ProbeUDP,
		Coordinators: []string{address},
		SessionID:    session,
		ListenAddr:   "127.0.0.1:0",
		BindTimeout:  3 * time.Second,
		PairTimeout:  8 * time.Second,
		PunchTimeout: 8 * time.Second,
		PollInterval: 50 * time.Millisecond,
		LingerWindow: 300 * time.Millisecond,
	}
	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Second)
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
			result, err := Run(ctx, local)
			results <- outcome{result: result, err: err}
		}(role)
	}
	for index := 0; index < 2; index++ {
		select {
		case received := <-results:
			if received.err != nil {
				t.Fatalf("probe returned an error: %v", received.err)
			}
			if !received.result.Established {
				t.Fatalf("probe did not establish a direct path: failure=%q", received.result.Failure)
			}
			if received.result.Failure != reachability.FailureNone {
				t.Fatalf("an established session reported a failure: %q", received.result.Failure)
			}
			if received.result.EstablishMillis == 0 {
				t.Fatal("an established session reported no latency")
			}
			if received.result.TxBytes == 0 || received.result.RxBytes == 0 {
				t.Fatal("expected byte counters to be measured")
			}
			// The coordinator attested its reflection at bind, and the runner
			// carried the verified reflection into the result.
			if len(received.result.BindObservations) == 0 {
				t.Fatal("no bind reflection was collected")
			}
			for _, observation := range received.result.BindObservations {
				if err := reachability.VerifyBindObservation(observation); err != nil {
					t.Fatalf("a collected bind reflection did not verify: %v", err)
				}
			}
		case <-ctx.Done():
			t.Fatal("probes did not finish")
		}
	}
}

func TestProbeRejectsInvalidConfiguration(t *testing.T) {
	ctx := context.Background()
	for name, config := range map[string]Config{
		"no coordinator":  {SessionID: testSession, Role: RoleA},
		"bad coordinator": {Coordinators: []string{"not an address"}, SessionID: testSession, Role: RoleA},
		"bad session":     {Coordinators: []string{"127.0.0.1:1"}, SessionID: "ses_bad", Role: RoleA},
		"bad role":        {Coordinators: []string{"127.0.0.1:1"}, SessionID: testSession, Role: "c"},
		"bad interval":    {Coordinators: []string{"127.0.0.1:1"}, SessionID: testSession, Role: RoleA, PollInterval: -1},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := Run(ctx, config); err == nil {
				t.Fatalf("expected %q to be refused", name)
			}
		})
	}
}

func TestProbeClassifiesAnUnreachableCoordinator(t *testing.T) {
	ctx := context.Background()
	// A closed port on loopback answers nothing, which is what a blocked UDP
	// path looks like to the probe.
	result, err := Run(ctx, Config{
		EndpointKeyHex: testEndpointKey(RoleA), Probe: reachability.ProbeUDP,
		Coordinators: []string{"127.0.0.1:9"},
		SessionID:    testSession,
		Role:         RoleA,
		ListenAddr:   "127.0.0.1:0",
		BindTimeout:  300 * time.Millisecond,
		PollInterval: 50 * time.Millisecond,
	})
	if err != nil {
		t.Fatalf("probe returned an error: %v", err)
	}
	if result.Established {
		t.Fatal("expected no direct session")
	}
	if result.Failure != reachability.FailureUDPBlocked {
		t.Fatalf("expected a blocked-path classification, got %q", result.Failure)
	}
}

func manyCandidates(count int) []string {
	candidates := make([]string, count)
	for index := range candidates {
		candidates[index] = netip.AddrPortFrom(netip.MustParseAddr("192.0.2.1"), uint16(1000+index)).String()
	}
	return candidates
}

func TestCoordinatorReportsWhetherThePeerIsPublic(t *testing.T) {
	coordinator := testCoordinator(t)
	ask := func(role Role, from string, candidates []string) Message {
		t.Helper()
		request, err := EncodeRequest(Message{
			Kind: KindPair, SessionID: testSession, Role: role, Nonce: testNonce, Candidates: candidates,
			EndpointKey: testEndpointKey(role), Probe: string(reachability.ProbeUDP),
		})
		if err != nil {
			t.Fatalf("encode: %v", err)
		}
		response := coordinator.Handle(request, source(t, from))
		if response == nil {
			t.Fatal("expected a pair answer")
		}
		message, err := Decode(response)
		if err != nil {
			t.Fatalf("decode: %v", err)
		}
		return message
	}
	// Role A advertises exactly the address the coordinator observes, so
	// nothing mapped it.
	ask(RoleA, "203.0.113.7:41234", []string{"203.0.113.7:41234"})
	fromB := ask(RoleB, "198.51.100.9:52000", []string{"10.0.0.3:52000"})
	if fromB.Signature == "" || fromB.SignerKey == "" {
		t.Fatal("the coordinator did not attest to what it saw")
	}
	if fromB.PeerPublic != PeerPublicYes {
		t.Fatalf("expected the unmapped peer to be reported as public, got %q", fromB.PeerPublic)
	}
	fromA := ask(RoleA, "203.0.113.7:41234", []string{"203.0.113.7:41234"})
	if fromA.PeerPublic != PeerPublicNo {
		t.Fatalf("expected the mapped peer to be reported as mapped, got %q", fromA.PeerPublic)
	}
}

func TestEndpointClassifiesOnlyItself(t *testing.T) {
	cases := []struct {
		name         string
		selfPublic   bool
		selfMapping  reachability.NATBehavior
		reachability reachability.Reachability
		mapping      reachability.NATBehavior
	}{
		{"public", true, reachability.NATNone, reachability.PublicAddress, reachability.NATNone},
		{"mapped, class known", false, reachability.NATEndpointIndependent,
			reachability.BehindNAT, reachability.NATEndpointIndependent},
		{"mapped, class unknown", false, "", reachability.BehindNAT, reachability.NATUndetermined},
		{"public despite a stale mapping guess", true, reachability.NATSymmetric,
			reachability.PublicAddress, reachability.NATNone},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			instance := &runner{selfPublic: testCase.selfPublic}
			instance.result.Mapping = testCase.selfMapping
			instance.classifySelf()
			if instance.result.Reachability != testCase.reachability {
				t.Fatalf("expected %q, got %q", testCase.reachability, instance.result.Reachability)
			}
			if instance.result.Mapping != testCase.mapping {
				t.Fatalf("expected mapping %q, got %q", testCase.mapping, instance.result.Mapping)
			}
			endpoint := reachability.EndpointStratum{
				Family: reachability.FamilyIPv4, Reachability: instance.result.Reachability,
				NATBehavior: instance.result.Mapping, Carrier: reachability.CarrierConsumerISP,
				UDPPolicy: reachability.UDPAllowed, Mobility: reachability.MobilityStationary,
				EndpointClass: reachability.ClassDesktop, Assistance: reachability.AssistanceNone,
			}
			if err := endpoint.Validate(); err != nil {
				t.Fatalf("classification produced an invalid endpoint stratum: %v", err)
			}
		})
	}
}
func TestAddressFamilyIsMeasured(t *testing.T) {
	four := []netip.AddrPort{source(t, "203.0.113.7:1")}
	six := []netip.AddrPort{source(t, "[2001:db8::1]:1")}
	if classifyFamily(four) != reachability.FamilyIPv4 {
		t.Fatal("expected IPv4")
	}
	if classifyFamily(six) != reachability.FamilyIPv6 {
		t.Fatal("expected IPv6")
	}
	if classifyFamily(append(four, six...)) != reachability.FamilyDual {
		t.Fatal("expected dual stack")
	}
}

func TestSlowPeerIsNotStranded(t *testing.T) {
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
	base := Config{
		EndpointKeyHex: testEndpointKey(RoleA), Probe: reachability.ProbeUDP,
		Coordinators: []string{listener.LocalAddr().String()},
		SessionID:    session,
		ListenAddr:   "127.0.0.1:0",
		BindTimeout:  3 * time.Second,
		PairTimeout:  8 * time.Second,
		PunchTimeout: 8 * time.Second,
		PollInterval: 50 * time.Millisecond,
		LingerWindow: 2 * time.Second,
	}
	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Second)
	defer cancel()

	results := make(chan Result, 2)
	go func() {
		local := base
		local.Role = RoleA
		result, _ := Run(ctx, local)
		results <- result
	}()
	go func() {
		// The second endpoint starts well after the first, which is what
		// happens whenever two operators do not press start at the same
		// moment. The endpoint that succeeds first must still be answering.
		time.Sleep(700 * time.Millisecond)
		local := base
		local.Role = RoleB
		result, _ := Run(ctx, local)
		results <- result
	}()

	for index := 0; index < 2; index++ {
		select {
		case result := <-results:
			if !result.Established {
				t.Fatalf("a late start stranded an endpoint: failure=%q", result.Failure)
			}
		case <-ctx.Done():
			t.Fatal("probes did not finish")
		}
	}
}

func TestPollingIsPacedNotFlooded(t *testing.T) {
	coordinator := testCoordinator(t)
	listener, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer listener.Close()

	var mutex sync.Mutex
	requests := 0
	go func() {
		buffer := make([]byte, MaxMessageBytes)
		for {
			count, from, err := listener.ReadFrom(buffer)
			if err != nil {
				return
			}
			mutex.Lock()
			requests++
			mutex.Unlock()
			source, ok := addrPort(from)
			if !ok {
				continue
			}
			if response := coordinator.Handle(buffer[:count], source); response != nil {
				_, _ = listener.WriteTo(response, from)
			}
		}
	}()

	session, err := NewSessionID()
	if err != nil {
		t.Fatalf("session: %v", err)
	}
	// The peer never arrives, so every pair answer is an immediate empty one.
	// That is the case an unpaced loop turns into a flood.
	const interval = 20 * time.Millisecond
	const window = 600 * time.Millisecond
	_, err = Run(context.Background(), Config{
		EndpointKeyHex: testEndpointKey(RoleA), Probe: reachability.ProbeUDP,
		Coordinators: []string{listener.LocalAddr().String()},
		SessionID:    session,
		Role:         RoleA,
		ListenAddr:   "127.0.0.1:0",
		BindTimeout:  time.Second,
		PairTimeout:  window,
		PunchTimeout: time.Millisecond,
		PollInterval: interval,
		LingerWindow: time.Millisecond,
	})
	if err != nil {
		t.Fatalf("probe: %v", err)
	}
	mutex.Lock()
	observed := requests
	mutex.Unlock()

	ceiling := int(window/interval) + 8
	if observed > ceiling {
		t.Fatalf("polling sent %d requests where at most %d are paced", observed, ceiling)
	}
	if observed < 2 {
		t.Fatalf("polling sent %d requests, so nothing was measured", observed)
	}
}
