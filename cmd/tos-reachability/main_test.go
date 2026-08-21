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
		t.Skip("tosutils-go's TL serializer trips checkptr; the ADNL gateway cannot run under -race")
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
			8*time.Second, 10*time.Second, sessionPhases{echoSizes: []int{1024}}, labels)
		results <- outcome{trial: trial, err: err}
	}()
	go func() {
		trial, _, err := measure(ctx, coordinatorAddress, session, "b", "127.0.0.1:0",
			strings.Repeat("b", 40), identityFile(t), reachability.ProbeADNL,
			8*time.Second, 10*time.Second, sessionPhases{echoSizes: []int{1024}}, peerLabels)
		results <- outcome{trial: trial, err: err}
	}()
	policy := testPolicyWith(coordinatorID)
	trials := make(map[reachability.Role]reachability.Trial, 2)
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
		// zeros rather than an invented survival or reconnect, and the
		// phase-status booleans must say nothing ran.
		if received.trial.SurvivalSeconds != 0 || received.trial.ReconnectMillis != 0 {
			t.Fatalf("an establishment-only trial carried measurements: survival=%d reconnect=%d",
				received.trial.SurvivalSeconds, received.trial.ReconnectMillis)
		}
		if received.trial.HoldAttempted || received.trial.HoldCompleted ||
			received.trial.ReconnectAttempted || received.trial.ReconnectSucceeded ||
			received.trial.TunnelHoldAttempted || received.trial.TunnelHoldCompleted {
			t.Fatalf("an establishment-only trial claimed a measurement phase: %+v", received.trial)
		}
		if received.trial.LocalManifestDigest == "" || received.trial.PeerManifestDigest == "" {
			t.Fatalf("the trial did not carry both collector manifests: local=%q peer=%q",
				received.trial.LocalManifestDigest, received.trial.PeerManifestDigest)
		}
		if len(received.trial.SizedEchoes) != 1 || received.trial.SizedEchoes[0].PayloadBytes != 1024 ||
			!received.trial.SizedEchoes[0].Succeeded || received.trial.SizedEchoes[0].RoundTripMillis == 0 {
			t.Fatalf("the signed trial lost its sized echo: %+v", received.trial.SizedEchoes)
		}
		trials[received.trial.Role] = received.trial
	}
	// The manifest digests cross exactly as the commits do: what one half
	// names as its own build is what the other half learned as its peer's.
	// The two halves ran with different commits here, so the manifests differ
	// and the crossing is a real check rather than an equality of copies.
	a, b := trials[reachability.RoleA], trials[reachability.RoleB]
	if a.LocalManifestDigest != b.PeerManifestDigest || a.PeerManifestDigest != b.LocalManifestDigest {
		t.Fatalf("the halves disagree about each other's manifests: a=%q/%q b=%q/%q",
			a.LocalManifestDigest, a.PeerManifestDigest, b.LocalManifestDigest, b.PeerManifestDigest)
	}
	if a.LocalManifestDigest == b.LocalManifestDigest {
		t.Fatal("two builds at different commits produced one manifest digest")
	}
}

// With a sidecar configured, the CLI produces a trial whose collector
// manifest tells the truth about the build that spoke on the wire: the
// implementation and its commit from the sidecar's own hello, the binary hash
// of the sidecar binary itself. One half runs the sidecar, the other the
// gateway, so the trial also proves the two manifests cross correctly.
func TestADNLSidecarTrialEndToEnd(t *testing.T) {
	if probe.RaceEnabled {
		t.Skip("tosutils-go's TL serializer trips checkptr; the ADNL gateway cannot run under -race")
	}
	binary := os.Getenv("TOS_ADNL_PROBE_BIN")
	if binary == "" {
		t.Skip("set TOS_ADNL_PROBE_BIN to a tos-adnl-probe binary to run the live interop tests")
	}
	coordinatorAddress, coordinatorID := startCoordinator(t)
	session := "ses_fedcba9876543210fedcba9876543210"
	labels := declared{operator: "op-one", site: "site-one", carrier: "consumer-isp",
		udpPolicy: "allowed", mobility: "stationary", class: "desktop", assistance: "none"}
	peerLabels := declared{operator: "op-two", site: "site-two", carrier: "datacenter",
		udpPolicy: "allowed", mobility: "stationary", class: "server", assistance: "none"}

	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()
	type outcome struct {
		trial     reachability.Trial
		artifacts measured
		err       error
	}
	results := make(chan outcome, 2)
	go func() {
		trial, artifacts, err := measure(ctx, coordinatorAddress, session, "a", "127.0.0.1:0",
			strings.Repeat("a", 40), identityFile(t), reachability.ProbeADNL,
			10*time.Second, 10*time.Second,
			sessionPhases{adnlProbe: binary, echoSizes: []int{1024}}, labels)
		results <- outcome{trial: trial, artifacts: artifacts, err: err}
	}()
	go func() {
		trial, artifacts, err := measure(ctx, coordinatorAddress, session, "b", "127.0.0.1:0",
			strings.Repeat("b", 40), identityFile(t), reachability.ProbeADNL,
			10*time.Second, 10*time.Second, sessionPhases{}, peerLabels)
		results <- outcome{trial: trial, artifacts: artifacts, err: err}
	}()
	policy := testPolicyWith(coordinatorID)
	trials := make(map[reachability.Role]reachability.Trial, 2)
	manifests := make(map[reachability.Role]reachability.CollectorManifest, 2)
	for index := 0; index < 2; index++ {
		received := <-results
		if received.err != nil {
			t.Fatalf("measure: %v", received.err)
		}
		if received.trial.Outcome != reachability.OutcomeDirect {
			t.Fatalf("no direct ADNL session: %q/%q", received.trial.Outcome, received.trial.Failure)
		}
		if err := reachability.VerifyTrial(policy, received.trial); err != nil {
			t.Fatalf("the trial does not verify: %v", err)
		}
		trials[received.trial.Role] = received.trial
		manifests[received.trial.Role] = received.artifacts.manifest
	}
	if len(trials[reachability.RoleA].SizedEchoes) != 1 ||
		trials[reachability.RoleA].SizedEchoes[0].PayloadBytes != 1024 ||
		!trials[reachability.RoleA].SizedEchoes[0].Succeeded {
		t.Fatalf("the native sidecar echo was not signed into role A's trial: %+v",
			trials[reachability.RoleA].SizedEchoes)
	}
	if len(trials[reachability.RoleB].SizedEchoes) != 0 {
		t.Fatalf("role B claimed an echo it did not configure: %+v", trials[reachability.RoleB].SizedEchoes)
	}
	sidecarManifest := manifests[reachability.RoleA]
	if sidecarManifest.ADNLImplementation != "tos-native-adnl" {
		t.Fatalf("the sidecar half's manifest names %q as its implementation", sidecarManifest.ADNLImplementation)
	}
	if len(sidecarManifest.ADNLImplementationCommit) != 40 ||
		sidecarManifest.DependencyVersion != sidecarManifest.ADNLImplementationCommit {
		t.Fatalf("the sidecar manifest does not pin the implementation commit: %+v", sidecarManifest)
	}
	wantHash, err := fileSHA256(binary)
	if err != nil {
		t.Fatalf("hash sidecar binary: %v", err)
	}
	if sidecarManifest.BinarySHA256 != wantHash {
		t.Fatalf("the manifest's binary hash %q is not the sidecar binary's %q",
			sidecarManifest.BinarySHA256, wantHash)
	}
	if manifests[reachability.RoleB].ADNLImplementation != "tosutils-go" {
		t.Fatalf("the gateway half's manifest names %q", manifests[reachability.RoleB].ADNLImplementation)
	}
	// The digests cross: what the gateway half learned as its peer's build is
	// the sidecar manifest, and vice versa.
	a, b := trials[reachability.RoleA], trials[reachability.RoleB]
	if a.LocalManifestDigest != b.PeerManifestDigest || a.PeerManifestDigest != b.LocalManifestDigest {
		t.Fatalf("the halves disagree about each other's manifests: a=%q/%q b=%q/%q",
			a.LocalManifestDigest, a.PeerManifestDigest, b.LocalManifestDigest, b.PeerManifestDigest)
	}
}

// classify is the single translation from what the probe measured to the
// trial vocabulary the schema validates, so its cases are pinned directly.
func TestClassifyOutcomes(t *testing.T) {
	direct := reachability.Trial{EstablishMillis: 42}
	if err := classify(&direct, probe.Result{
		Established: true, SurvivalSeconds: 7, ReconnectMillis: 90,
		HoldAttempted: true, HoldCompleted: false,
		ReconnectAttempted: true, ReconnectSucceeded: true,
	}); err != nil {
		t.Fatalf("classify direct: %v", err)
	}
	if direct.Outcome != reachability.OutcomeDirect || direct.Failure != reachability.FailureNone {
		t.Fatalf("direct misclassified: %q/%q", direct.Outcome, direct.Failure)
	}
	if direct.SurvivalSeconds != 7 || direct.ReconnectMillis != 90 {
		t.Fatal("a direct trial dropped its survival or reconnect measurement")
	}
	// The phase statuses travel with the measurements: an attempted-but-died
	// hold and a successful reconnect stay exactly what the runner reported.
	if !direct.HoldAttempted || direct.HoldCompleted ||
		!direct.ReconnectAttempted || !direct.ReconnectSucceeded {
		t.Fatalf("a direct trial dropped its phase statuses: %+v", direct)
	}

	// A reconnect that ran and failed is copied as attempted-and-not-succeeded
	// with its latency at zero: the recording this schema exists to make
	// possible.
	failedReconnect := reachability.Trial{EstablishMillis: 42}
	if err := classify(&failedReconnect, probe.Result{
		Established: true, SurvivalSeconds: 7,
		HoldAttempted: true, HoldCompleted: true,
		ReconnectAttempted: true,
	}); err != nil {
		t.Fatalf("classify failed reconnect: %v", err)
	}
	if !failedReconnect.ReconnectAttempted || failedReconnect.ReconnectSucceeded ||
		failedReconnect.ReconnectMillis != 0 {
		t.Fatalf("a failed reconnect was not recorded honestly: %+v", failedReconnect)
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
		TunnelHoldAttempted: true, TunnelHoldCompleted: true,
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
	// The tunnel hold's booleans are the tunnel-survival evidence and must
	// survive classification, with the direct phases staying unclaimed.
	if !tunneled.TunnelHoldAttempted || !tunneled.TunnelHoldCompleted {
		t.Fatalf("a proxy-fallback trial dropped its tunnel hold status: %+v", tunneled)
	}
	if tunneled.HoldAttempted || tunneled.ReconnectAttempted {
		t.Fatalf("a proxy-fallback trial claimed direct phases: %+v", tunneled)
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

func TestSignedEchoMeasurementsCanonicalizeAndRefuseSubstitution(t *testing.T) {
	echoes, err := signedEchoMeasurements([]probe.EchoResult{
		{Bytes: probe.MaxEchoBytes, OK: true, Millis: 9},
		{Bytes: 1024, OK: true, Millis: 4},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(echoes) != 2 || echoes[0].PayloadBytes != 1024 || echoes[1].PayloadBytes != uint32(probe.MaxEchoBytes) {
		t.Fatalf("echo measurements were not canonicalized: %+v", echoes)
	}
	for name, results := range map[string][]probe.EchoResult{
		"duplicate":               {{Bytes: 1024}, {Bytes: 1024}},
		"success without latency": {{Bytes: 1024, OK: true}},
		"failure with latency":    {{Bytes: 1024, Millis: 1}},
		"oversized":               {{Bytes: probe.MaxEchoBytes + 1}},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := signedEchoMeasurements(results); err == nil {
				t.Fatalf("invalid echo result %q was accepted", name)
			}
		})
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
