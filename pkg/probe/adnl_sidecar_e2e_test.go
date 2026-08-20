package probe

import (
	"context"
	"net"
	"os"
	"testing"
	"time"

	"github.com/tosnetwork/tos-messenger/pkg/reachability"
)

// sidecarBinaryEnv names the real tos-adnl-probe binary. These tests are the
// live interop evidence between this collector and the native ADNL stack;
// without the binary they skip cleanly, so the hermetic verify target is
// unaffected.
const sidecarBinaryEnv = "TOS_ADNL_PROBE_BIN"

func sidecarBinary(t *testing.T) string {
	t.Helper()
	binary := os.Getenv(sidecarBinaryEnv)
	if binary == "" {
		t.Skipf("set %s to a tos-adnl-probe binary to run the live interop tests", sidecarBinaryEnv)
	}
	if _, err := os.Stat(binary); err != nil {
		t.Fatalf("%s names an unusable binary: %v", sidecarBinaryEnv, err)
	}
	return binary
}

// runADNLMatrixPair runs one measured pair on loopback with each role's
// runner chosen independently, which is what the cross matrix needs: both
// native, or one native against the tosutils gateway in either initiating
// direction.
func runADNLMatrixPair(t *testing.T, sidecarRole map[Role]bool, adjust func(Role, *Config)) map[Role]Result {
	t.Helper()
	skipUnderRace(t)
	binary := sidecarBinary(t)

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
		Probe:        reachability.ProbeADNL,
		Coordinators: []string{listener.LocalAddr().String()},
		SessionID:    session,
		ListenAddr:   "127.0.0.1:0",
		BindTimeout:  3 * time.Second,
		PairTimeout:  10 * time.Second,
		PunchTimeout: 10 * time.Second,
		PollInterval: 50 * time.Millisecond,
		LingerWindow: 500 * time.Millisecond,
	}
	ctx, cancel := context.WithTimeout(context.Background(), 150*time.Second)
	defer cancel()

	type outcome struct {
		role   Role
		result Result
		err    error
	}
	outcomes := make(chan outcome, 2)
	for _, role := range []Role{RoleA, RoleB} {
		go func(role Role) {
			local := base
			local.Role = role
			local.EndpointKeyHex = testEndpointKey(role)
			if adjust != nil {
				adjust(role, &local)
			}
			var result Result
			var err error
			if sidecarRole[role] {
				local.SidecarPath = binary
				result, err = RunADNLSidecar(ctx, local)
			} else {
				result, err = RunADNL(ctx, local)
			}
			outcomes <- outcome{role: role, result: result, err: err}
		}(role)
	}
	results := make(map[Role]Result, 2)
	for index := 0; index < 2; index++ {
		received := <-outcomes
		if received.err != nil {
			t.Fatalf("role %s runner returned an error: %v", received.role, received.err)
		}
		results[received.role] = received.result
	}
	return results
}

// assertMatrixPair holds every combination to the same bar: both halves
// establish, both survive the full hold window, and each side's echo verdicts
// are logged as the interop record. The fragmentation-exercising size must
// verify everywhere; the maximum size's verdict is logged rather than
// asserted, because the native stack's own message bound sits inside its
// query-payload cap and what actually happens there is exactly what these
// tests exist to observe.
func assertMatrixPair(t *testing.T, results map[Role]Result, hold time.Duration) {
	t.Helper()
	for role, result := range results {
		if !result.Established {
			t.Fatalf("role %s did not establish: failure=%q", role, result.Failure)
		}
		if result.EstablishMillis == 0 {
			t.Fatalf("role %s established without a latency", role)
		}
		t.Logf("role %s: established in %d ms via %s", role, result.EstablishMillis, result.PeerAddress)
		if hold > 0 {
			if !result.HoldAttempted || !result.HoldCompleted {
				t.Fatalf("role %s hold: attempted=%t completed=%t survival=%d",
					role, result.HoldAttempted, result.HoldCompleted, result.SurvivalSeconds)
			}
			t.Logf("role %s: hold completed, survival %d s", role, result.SurvivalSeconds)
		}
		for _, echoed := range result.EchoResults {
			t.Logf("role %s: echo %d bytes -> ok=%t millis=%d", role, echoed.Bytes, echoed.OK, echoed.Millis)
		}
		for _, echoed := range result.EchoResults {
			if echoed.Bytes == 1024 && !echoed.OK {
				t.Errorf("role %s: the fragmentation-exercising 1024-byte echo did not verify", role)
			}
		}
	}
}

// Native against native: the full collector pair with both halves speaking
// through the sidecar -- establishment, a held session, the initiator's
// deliberate reconnect, and the sized echoes.
func TestEndToEndADNLSidecarNativePair(t *testing.T) {
	hold := 3 * time.Second
	results := runADNLMatrixPair(t, map[Role]bool{RoleA: true, RoleB: true}, func(role Role, config *Config) {
		config.HoldWindow = hold
		config.KeepaliveInterval = 500 * time.Millisecond
		config.MeasureReconnect = role == RoleA
		config.EchoSizes = []int{1024, MaxEchoBytes}
	})
	assertMatrixPair(t, results, hold)
	initiator := results[RoleA]
	if !initiator.ReconnectAttempted || !initiator.ReconnectSucceeded || initiator.ReconnectMillis == 0 {
		t.Fatalf("the initiator's reconnect was not measured: %+v", initiator)
	}
	t.Logf("role a: reconnect in %d ms", initiator.ReconnectMillis)
	if results[RoleB].ReconnectAttempted || results[RoleB].ReconnectMillis != 0 {
		t.Fatalf("the responder claimed a reconnect: %+v", results[RoleB])
	}
}

// The gateway initiates toward a native responder: the first wire-compat
// proof in the go-to-native direction.
func TestEndToEndADNLGatewayDialsNative(t *testing.T) {
	hold := 3 * time.Second
	results := runADNLMatrixPair(t, map[Role]bool{RoleB: true}, func(role Role, config *Config) {
		config.HoldWindow = hold
		config.KeepaliveInterval = 500 * time.Millisecond
		config.EchoSizes = []int{1024, MaxEchoBytes}
	})
	assertMatrixPair(t, results, hold)
}

// The native stack initiates toward the gateway: the same proof in the
// opposite initiating direction, which is a different measurement -- who
// dials decides whose NAT mapping must already exist.
func TestEndToEndADNLNativeDialsGateway(t *testing.T) {
	hold := 3 * time.Second
	results := runADNLMatrixPair(t, map[Role]bool{RoleA: true}, func(role Role, config *Config) {
		config.HoldWindow = hold
		config.KeepaliveInterval = 500 * time.Millisecond
		config.EchoSizes = []int{1024, MaxEchoBytes}
	})
	assertMatrixPair(t, results, hold)
}

// The sidecar runner refuses what the native transport cannot serve: an
// explicitly IPv6 rendezvous socket. The refusal is an error before anything
// pairs, not a failed trial, because those cells belong to the gateway
// runner.
func TestADNLSidecarRefusesIPv6Socket(t *testing.T) {
	binary := sidecarBinary(t)
	if !hasIPv6Loopback() {
		t.Skip("no usable IPv6 loopback on this host")
	}
	config := Config{
		Probe:          reachability.ProbeADNL,
		SidecarPath:    binary,
		Coordinators:   []string{"127.0.0.1:9"},
		SessionID:      "ses_00000000000000000000000000000000",
		Role:           RoleA,
		EndpointKeyHex: testEndpointKey(RoleA),
		ListenAddr:     "[::1]:0",
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if _, err := RunADNLSidecar(ctx, config); err == nil {
		t.Fatal("an IPv6 rendezvous socket was accepted for the IPv4-only sidecar")
	}
}
