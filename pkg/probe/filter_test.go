package probe

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/tosnetwork/tos-messenger/pkg/reachability"
)

// captureConn is a write-only cold source: it records what the coordinator
// sends and where, and refuses to be read, exactly as a real cold socket is
// never read.
type captureConn struct {
	mutex   sync.Mutex
	writes  [][]byte
	targets []net.Addr
}

func (c *captureConn) WriteTo(payload []byte, target net.Addr) (int, error) {
	c.mutex.Lock()
	defer c.mutex.Unlock()
	copied := make([]byte, len(payload))
	copy(copied, payload)
	c.writes = append(c.writes, copied)
	c.targets = append(c.targets, target)
	return len(payload), nil
}

func (c *captureConn) ReadFrom([]byte) (int, net.Addr, error) {
	return 0, nil, errors.New("a cold source is never read")
}

func (c *captureConn) Close() error                     { return nil }
func (c *captureConn) LocalAddr() net.Addr              { return &net.UDPAddr{} }
func (c *captureConn) SetDeadline(time.Time) error      { return nil }
func (c *captureConn) SetReadDeadline(time.Time) error  { return nil }
func (c *captureConn) SetWriteDeadline(time.Time) error { return nil }

func (c *captureConn) sent() [][]byte {
	c.mutex.Lock()
	defer c.mutex.Unlock()
	out := make([][]byte, len(c.writes))
	copy(out, c.writes)
	return out
}

func filterRequest(t *testing.T, endpointKey string) []byte {
	t.Helper()
	request, err := EncodeRequest(Message{
		Kind: KindFilter, SessionID: testSession, Role: RoleA, Nonce: testNonce,
		EndpointKey: endpointKey, Probe: string(reachability.ProbeUDP),
	})
	if err != nil {
		t.Fatalf("encode filter request: %v", err)
	}
	return request
}

// The filter exchange in one Handle-level pass: a request draws cold-source
// probes to the observed flow address and nowhere else, the probes stay within
// the request's amplification budget, and echoing a token over the same flow
// earns a signed observation that verifies and attests the right cold source.
func TestCoordinatorFilterExchange(t *testing.T) {
	coordinator := testCoordinator(t)
	port := &captureConn{}
	address := &captureConn{}
	if err := coordinator.AttachFilterSource(reachability.FilterSourceOtherPort, port); err != nil {
		t.Fatalf("attach: %v", err)
	}
	if err := coordinator.AttachFilterSource(reachability.FilterSourceOtherAddress, address); err != nil {
		t.Fatalf("attach: %v", err)
	}
	if err := coordinator.AttachFilterSource(reachability.FilterSourceOtherPort, port); err == nil {
		t.Fatal("one source kind was attached twice")
	}
	if err := coordinator.AttachFilterSource("somewhere-else", port); err == nil {
		t.Fatal("an unknown source kind was attached")
	}

	endpointKey := testEndpointKey(RoleA)
	from := source(t, "203.0.113.7:41234")
	request := filterRequest(t, endpointKey)
	if response := coordinator.Handle(request, from); response != nil {
		t.Fatal("a filter request must be answered by the probes, not on the primary flow")
	}

	probes := append(port.sent(), address.sent()...)
	if len(port.sent()) != 1 || len(address.sent()) != 1 {
		t.Fatalf("expected one probe per cold source, got %d and %d", len(port.sent()), len(address.sent()))
	}
	total := 0
	tokens := make([]string, 0, 2)
	for _, raw := range probes {
		total += len(raw)
		message, err := Decode(raw)
		if err != nil {
			t.Fatalf("decode probe: %v", err)
		}
		if message.Kind != KindFilterProbe || message.SessionID != testSession || message.Token == "" {
			t.Fatalf("unexpected probe: %+v", message)
		}
		tokens = append(tokens, message.Token)
	}
	if total > len(request) {
		t.Fatalf("the cold probes amplified the request: %d > %d", total, len(request))
	}
	if tokens[0] == tokens[1] {
		t.Fatal("two cold sources shared one token")
	}
	for _, targets := range [][]net.Addr{port.targets, address.targets} {
		udp, ok := targets[0].(*net.UDPAddr)
		if !ok || udp.AddrPort() != from {
			t.Fatalf("a cold probe left for somewhere other than the observed flow: %v", targets[0])
		}
	}

	echo := func(token, key string) []byte {
		encoded, err := EncodeRequest(Message{
			Kind: KindFilterEcho, SessionID: testSession, Role: RoleA, Nonce: testNonce,
			Token: token, EndpointKey: key, Probe: string(reachability.ProbeUDP),
		})
		if err != nil {
			t.Fatalf("encode echo: %v", err)
		}
		return encoded
	}

	// A token echoed over another flow, under another key, or never issued is
	// silence: the receipt belongs to the flow the probe was sent to.
	if coordinator.Handle(echo(tokens[0], endpointKey), source(t, "198.51.100.9:5000")) != nil {
		t.Fatal("a token was redeemed over a different flow")
	}
	if coordinator.Handle(echo(tokens[0], testEndpointKey(RoleB)), from) != nil {
		t.Fatal("a token was redeemed under a different endpoint key")
	}
	if coordinator.Handle(echo(strings.Repeat("0", 32), endpointKey), from) != nil {
		t.Fatal("an unissued token was redeemed")
	}

	seen := map[reachability.FilterSourceKind]bool{}
	for _, token := range tokens {
		request := echo(token, endpointKey)
		response := coordinator.Handle(request, from)
		if response == nil {
			t.Fatal("an honest echo earned no observation")
		}
		if err := CheckNoAmplification(request, response); err != nil {
			t.Fatalf("the filter answer amplified its echo: %v", err)
		}
		message, err := Decode(response)
		if err != nil {
			t.Fatalf("decode answer: %v", err)
		}
		if message.Kind != KindFilterOK || message.Token != token {
			t.Fatalf("unexpected answer: %+v", message)
		}
		observation := reachability.FilteringObservation{
			CoordinatorID:        testServerID(t),
			SessionID:            testSession,
			Role:                 string(RoleA),
			EndpointPublicKeyHex: endpointKey,
			Probe:                string(reachability.ProbeUDP),
			Observed:             message.Observed,
			Source:               reachability.FilterSourceKind(message.FilterSource),
			AtUnix:               message.ObservedAt,
			PublicKeyHex:         message.SignerKey,
			SignatureHex:         message.Signature,
		}
		if err := reachability.VerifyFilteringObservation(observation); err != nil {
			t.Fatalf("the signed observation did not verify: %v", err)
		}
		if observation.Observed != from.String() {
			t.Fatalf("the observation attested the wrong flow: %+v", observation)
		}
		seen[observation.Source] = true
	}
	if !seen[reachability.FilterSourceOtherPort] || !seen[reachability.FilterSourceOtherAddress] {
		t.Fatalf("the two receipts did not cover both cold sources: %+v", seen)
	}
}

// A coordinator with no cold sockets attached, or a request that does not name
// the endpoint key it is asking for, produces nothing at all.
func TestFilterRequestsThatCannotBeHonouredAreSilence(t *testing.T) {
	bare := testCoordinator(t)
	if bare.Handle(filterRequest(t, testEndpointKey(RoleA)), source(t, "203.0.113.7:41234")) != nil {
		t.Fatal("a coordinator without cold sources answered a filter request")
	}
	// A filter request without the endpoint key does not validate at all: the
	// attestation names a party, so there is nothing to grant.
	if _, err := EncodeRequest(Message{
		Kind: KindFilter, SessionID: testSession, Role: RoleA, Nonce: testNonce,
		Probe: string(reachability.ProbeUDP),
	}); err == nil {
		t.Fatal("a filter request without an endpoint key was encodable")
	}
	if _, err := EncodeRequest(Message{
		Kind: KindFilterEcho, SessionID: testSession, Role: RoleA, Nonce: testNonce,
		EndpointKey: testEndpointKey(RoleA), Probe: string(reachability.ProbeUDP),
	}); err == nil {
		t.Fatal("an echo without a token was encodable")
	}
}

// The full exchange over real sockets: an endpoint binds, asks for filter
// probes, receives them on its established socket, and comes away with
// verified observations for both cold sources -- which derive, honestly, as
// endpoint-independent filtering, since the loopback path filters nothing.
func TestMeasureFilteringEndToEnd(t *testing.T) {
	coordinator := testCoordinator(t)
	listener, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer listener.Close()
	for _, kind := range []reachability.FilterSourceKind{
		reachability.FilterSourceOtherPort, reachability.FilterSourceOtherAddress,
	} {
		cold, err := net.ListenPacket("udp", "127.0.0.1:0")
		if err != nil {
			t.Fatalf("listen cold: %v", err)
		}
		defer cold.Close()
		if err := coordinator.AttachFilterSource(kind, cold); err != nil {
			t.Fatalf("attach: %v", err)
		}
	}
	go func() { _ = coordinator.Serve(listener) }()

	endpoint, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen endpoint: %v", err)
	}
	defer endpoint.Close()

	config := Config{
		Coordinators:   []string{listener.LocalAddr().String()},
		SessionID:      testSession,
		Role:           RoleA,
		EndpointKeyHex: testEndpointKey(RoleA),
		Probe:          reachability.ProbeUDP,
		BindTimeout:    5 * time.Second,
		PollInterval:   50 * time.Millisecond,
	}
	strays := 0
	result := MeasureFiltering(context.Background(), endpoint, listener.LocalAddr().String(),
		config, func(Message, netip.AddrPort) { strays++ })
	if len(result.Observations) != 2 {
		t.Fatalf("expected receipts from both cold sources, got %d", len(result.Observations))
	}
	for _, observation := range result.Observations {
		if err := reachability.VerifyFilteringObservation(observation); err != nil {
			t.Fatalf("an unverifiable observation was returned: %v", err)
		}
		if observation.EndpointPublicKeyHex != config.EndpointKeyHex ||
			observation.SessionID != config.SessionID {
			t.Fatalf("the observation names the wrong party: %+v", observation)
		}
	}
	if derived := reachability.DeriveFiltering(result.Observations); derived != reachability.FilteringEndpointIndependent {
		t.Fatalf("an unfiltered path derived %q", derived)
	}
	if result.TxBytes == 0 || result.RxBytes == 0 {
		t.Fatal("the exchange's traffic was not accounted")
	}
	if strays != 0 {
		t.Fatalf("the exchange misfiled %d of its own messages as strays", strays)
	}
}

// An exchange that cannot be run -- an invalid configuration, a dead
// coordinator -- yields the empty result, never a fabricated one.
func TestMeasureFilteringFailsClosed(t *testing.T) {
	endpoint, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer endpoint.Close()
	valid := Config{
		SessionID: testSession, Role: RoleA,
		EndpointKeyHex: testEndpointKey(RoleA), Probe: reachability.ProbeUDP,
		BindTimeout: 200 * time.Millisecond, PollInterval: 50 * time.Millisecond,
	}

	broken := valid
	broken.EndpointKeyHex = ""
	if got := MeasureFiltering(context.Background(), endpoint, "127.0.0.1:1", broken, nil); len(got.Observations) != 0 {
		t.Fatal("a run without an endpoint key returned observations")
	}
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	if got := MeasureFiltering(cancelled, endpoint, "127.0.0.1:1", valid, nil); len(got.Observations) != 0 {
		t.Fatal("a cancelled run returned observations")
	}
	// A coordinator that never answers is an empty result after the window.
	if got := MeasureFiltering(context.Background(), endpoint, "127.0.0.1:1", valid, nil); len(got.Observations) != 0 {
		t.Fatal("silence produced observations")
	}
}
