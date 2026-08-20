package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/tosnetwork/tos-messenger/pkg/probe"
	"github.com/tosnetwork/tos-messenger/pkg/reachability"
)

func TestSplitAddresses(t *testing.T) {
	got := splitAddresses(" host-1:7691 , host-2:7691 ,, ")
	if len(got) != 2 || got[0] != "host-1:7691" || got[1] != "host-2:7691" {
		t.Fatalf("unexpected addresses: %v", got)
	}
	if len(splitAddresses("   ")) != 0 {
		t.Fatal("expected no addresses from blank input")
	}
}

func TestMeasureRefusesUnusableInput(t *testing.T) {
	ctx := context.Background()
	labels := declared{operator: "lab", site: "uplink", carrier: "consumer-isp", udpPolicy: "allowed",
		mobility: "stationary", class: "desktop", assistance: "none"}
	commit := strings.Repeat("a", 40)
	session := "ses_0123456789abcdef0123456789abcdef"

	if _, _, err := measure(ctx, "", session, "a", ":0", commit, identityFile(t), reachability.ProbeUDP, time.Second, time.Second, sessionPhases{}, labels); err == nil {
		t.Fatal("expected a missing coordinator to be refused")
	}
	blank := labels
	blank.operator = ""
	if _, _, err := measure(ctx, "127.0.0.1:1", session, "a", ":0", commit, identityFile(t), reachability.ProbeUDP, time.Second, time.Second, sessionPhases{}, blank); err == nil {
		t.Fatal("expected a missing operator to be refused")
	}
	noSite := labels
	noSite.site = ""
	if _, _, err := measure(ctx, "127.0.0.1:1", session, "a", ":0", commit, identityFile(t), reachability.ProbeUDP, time.Second, time.Second, sessionPhases{}, noSite); err == nil {
		t.Fatal("expected a missing site to be refused")
	}
	if _, _, err := measure(ctx, "127.0.0.1:1", "ses_short", "a", ":0", commit, identityFile(t), reachability.ProbeUDP, time.Second, time.Second, sessionPhases{}, labels); err == nil {
		t.Fatal("expected an invalid session to be refused")
	}
	if _, _, err := measure(ctx, "127.0.0.1:1", session, "c", ":0", commit, identityFile(t), reachability.ProbeUDP, time.Second, time.Second, sessionPhases{}, labels); err == nil {
		t.Fatal("expected an invalid role to be refused")
	}
}

// A probe that never reached a coordinator has no stratum to file its result
// under, so it must refuse to write a record rather than invent labels.
func TestMeasureRefusesToRecordAnUnclassifiedTrial(t *testing.T) {
	labels := declared{operator: "lab", site: "uplink", carrier: "consumer-isp", udpPolicy: "allowed",
		mobility: "stationary", class: "desktop", assistance: "none"}
	_, _, err := measure(context.Background(), "127.0.0.1:9",
		"ses_0123456789abcdef0123456789abcdef", "a", "127.0.0.1:0",
		strings.Repeat("a", 40), identityFile(t), reachability.ProbeUDP,
		200*time.Millisecond, 200*time.Millisecond, sessionPhases{}, labels)
	if err == nil {
		t.Fatal("expected an unclassified trial to be refused")
	}
	if !strings.Contains(err.Error(), "commit") && !strings.Contains(err.Error(), "reachability") {
		t.Fatalf("unexpected refusal reason: %v", err)
	}
}

func identityFile(t *testing.T) string {
	t.Helper()
	return filepath.Join(t.TempDir(), "identity")
}

// A missing identity file is created, and the key it holds is stable across
// runs, because a key that changed each run would make one host look like many.
func TestIdentityIsStable(t *testing.T) {
	path := identityFile(t)
	first, err := loadOrCreateKey(path)
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	second, err := loadOrCreateKey(path)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if !first.Equal(second) {
		t.Fatal("the endpoint identity changed between runs")
	}
	if _, err := loadOrCreateKey(""); err == nil {
		t.Fatal("a missing identity path was accepted")
	}
	if err := os.WriteFile(path, []byte("not a key"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	if _, err := loadOrCreateKey(path); err == nil {
		t.Fatal("a malformed identity file was accepted")
	}
}

// The CLI produces a verifiable ADNL trial the same way it produces a UDP one:
// same rendezvous, same attestation, different measured protocol.
func TestADNLTrialEndToEnd(t *testing.T) {
	if probe.RaceEnabled {
		t.Skip("tonutils-go's TL serializer trips checkptr; the ADNL gateway cannot run under -race")
	}
	coordinatorAddress, coordinatorID := startCoordinator(t)
	session := "ses_0123456789abcdef0123456789abcdef"
	labels := declared{operator: "op-one", site: "site-one", carrier: "consumer-isp",
		udpPolicy: "allowed", mobility: "stationary", class: "desktop", assistance: "none"}
	peerLabels := declared{operator: "op-two", site: "site-two", carrier: "datacenter",
		udpPolicy: "allowed", mobility: "stationary", class: "server", assistance: "none"}

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	type outcome struct {
		trial reachability.Trial
		err   error
	}
	results := make(chan outcome, 2)
	go func() {
		trial, _, err := measure(ctx, coordinatorAddress, session, "a", "127.0.0.1:0",
			strings.Repeat("a", 40), identityFile(t), reachability.ProbeADNL,
			8*time.Second, 10*time.Second, sessionPhases{}, labels)
		results <- outcome{trial: trial, err: err}
	}()
	go func() {
		trial, _, err := measure(ctx, coordinatorAddress, session, "b", "127.0.0.1:0",
			strings.Repeat("b", 40), identityFile(t), reachability.ProbeADNL,
			8*time.Second, 10*time.Second, sessionPhases{}, peerLabels)
		results <- outcome{trial: trial, err: err}
	}()
	policy := testPolicyWith(coordinatorID)
	for index := 0; index < 2; index++ {
		received := <-results
		if received.err != nil {
			t.Fatalf("measure: %v", received.err)
		}
		if received.trial.Probe != reachability.ProbeADNL {
			t.Fatalf("the trial filed under %q", received.trial.Probe)
		}
		if received.trial.Outcome != reachability.OutcomeDirect {
			t.Fatalf("no direct ADNL session: %q/%q", received.trial.Outcome, received.trial.Failure)
		}
		// The full evidence chain holds: endpoint signature, coordinator
		// attestation naming this endpoint and this probe.
		if err := reachability.VerifyTrial(policy, received.trial); err != nil {
			t.Fatalf("the trial does not verify: %v", err)
		}
		// No hold window was requested, so the trial must carry the unmeasured
		// zeros rather than an invented survival or reconnect.
		if received.trial.SurvivalSeconds != 0 || received.trial.ReconnectMillis != 0 {
			t.Fatalf("an establishment-only trial carried measurements: survival=%d reconnect=%d",
				received.trial.SurvivalSeconds, received.trial.ReconnectMillis)
		}
	}
}

// classify is the single translation from what the probe measured to the
// trial vocabulary the schema validates, so its cases are pinned directly.
func TestClassifyOutcomes(t *testing.T) {
	direct := reachability.Trial{EstablishMillis: 42}
	if err := classify(&direct, probe.Result{
		Established: true, SurvivalSeconds: 7, ReconnectMillis: 90,
	}); err != nil {
		t.Fatalf("classify direct: %v", err)
	}
	if direct.Outcome != reachability.OutcomeDirect || direct.Failure != reachability.FailureNone {
		t.Fatalf("direct misclassified: %q/%q", direct.Outcome, direct.Failure)
	}
	if direct.SurvivalSeconds != 7 || direct.ReconnectMillis != 90 {
		t.Fatal("a direct trial dropped its survival or reconnect measurement")
	}

	failed := reachability.Trial{EstablishMillis: 42}
	if err := classify(&failed, probe.Result{Failure: reachability.FailureHandshake}); err != nil {
		t.Fatalf("classify failed: %v", err)
	}
	if failed.Outcome != reachability.OutcomeFailed || failed.Failure != reachability.FailureHandshake {
		t.Fatalf("failure misclassified: %q/%q", failed.Outcome, failed.Failure)
	}
	if failed.EstablishMillis != 0 {
		t.Fatal("a failed trial kept an establishment latency")
	}

	tunneled := reachability.Trial{EstablishMillis: 42}
	if err := classify(&tunneled, probe.Result{
		Established: true, TunneledEstablish: true, Failure: reachability.FailureHandshake,
	}); err != nil {
		t.Fatalf("classify tunneled: %v", err)
	}
	if tunneled.Outcome != reachability.OutcomeProxyFallback || tunneled.Failure != reachability.FailureHandshake {
		t.Fatalf("tunneled misclassified: %q/%q", tunneled.Outcome, tunneled.Failure)
	}
	if tunneled.EstablishMillis != 42 {
		t.Fatal("a proxy-fallback trial lost its tunnel establishment latency")
	}
	if tunneled.SurvivalSeconds != 0 || tunneled.ReconnectMillis != 0 {
		t.Fatal("a proxy-fallback trial carried direct-session measurements")
	}

	// A tunneled result without the direct phase's failure class cannot become
	// a valid proxy-fallback trial, so it is refused rather than signed.
	inconsistent := reachability.Trial{}
	if err := classify(&inconsistent, probe.Result{
		Established: true, TunneledEstablish: true, Failure: reachability.FailureNone,
	}); err == nil {
		t.Fatal("a tunneled result without a direct failure class was accepted")
	}
}

// startCoordinator serves a probe coordinator on loopback and returns its
// address and derived identifier.
func startCoordinator(t *testing.T) (string, string) {
	t.Helper()
	key := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x21}, ed25519.SeedSize))
	coordinator, err := probe.NewCoordinator(probe.CoordinatorOptions{PrivateKey: key})
	if err != nil {
		t.Fatalf("coordinator: %v", err)
	}
	listener, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	go func() { _ = coordinator.Serve(listener) }()

	public, ok := key.Public().(ed25519.PublicKey)
	if !ok {
		t.Fatal("unexpected key type")
	}
	identifier, err := reachability.CoordinatorID(public)
	if err != nil {
		t.Fatalf("coordinator id: %v", err)
	}
	return listener.LocalAddr().String(), identifier
}

// testPolicyWith is the minimal policy VerifyTrial needs: whose attestations
// count.
func testPolicyWith(coordinatorID string) reachability.Policy {
	return reachability.Policy{Coordinators: []string{coordinatorID}}
}
