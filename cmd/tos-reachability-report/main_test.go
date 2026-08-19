package main

import (
	"bytes"
	"crypto/ed25519"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/tosnetwork/tos-messenger/pkg/reachability"
)

// The example policy is published as guidance, so a change that makes it
// invalid has to fail here rather than in someone else's study.
func TestExamplePolicyIsValid(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", "..", "docs", "reachability-policy.example.json"))
	if err != nil {
		t.Fatalf("read example policy: %v", err)
	}
	policy, err := reachability.DecodePolicyJSON(raw)
	if err != nil {
		t.Fatalf("example policy is invalid: %v", err)
	}
	if len(policy.RequiredScenarios) < 4 {
		t.Fatalf("example policy requires too little coverage: %d scenarios", len(policy.RequiredScenarios))
	}
}

func pairFor(t *testing.T, session string) string {
	t.Helper()
	pair, err := reachability.PairID(session)
	if err != nil {
		t.Fatalf("pair: %v", err)
	}
	return pair
}

func writeFile(t *testing.T, name, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("write %s: %v", name, err)
	}
	return path
}

func TestBuildRefusesIncompleteInput(t *testing.T) {
	policyPath := filepath.Join("..", "..", "docs", "reachability-policy.example.json")
	logPath := writeFile(t, "study.jsonl", "")

	if _, err := build("", logPath, "udp"); err == nil {
		t.Fatal("expected a missing policy to be refused")
	}
	if _, err := build(policyPath, "", "udp"); err == nil {
		t.Fatal("expected a missing log to be refused")
	}
	if _, err := build(policyPath, filepath.Join(t.TempDir(), "absent"), "udp"); err == nil {
		t.Fatal("expected an unreadable log to be refused")
	}
	if _, err := build(policyPath, logPath, "udp"); err == nil {
		t.Fatal("expected an empty study log to be refused")
	}
	if _, err := build(writeFile(t, "policy.json", "{}"), logPath, "udp"); err == nil {
		t.Fatal("expected an empty policy to be refused")
	}
}

// A study that covers nothing must still parse and must still refuse to
// conclude anything.
func TestBuildReportsInsufficientEvidence(t *testing.T) {
	coordinatorKey := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x11}, ed25519.SeedSize))
	endpointKey := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x22}, ed25519.SeedSize))

	endpointPublic, ok := endpointKey.Public().(ed25519.PublicKey)
	if !ok {
		t.Fatal("unexpected endpoint key type")
	}
	observation, err := reachability.SignObservation(reachability.Observation{
		SessionID:            "ses_0123456789abcdef0123456789abcdef",
		Role:                 "a",
		EndpointPublicKeyHex: hex.EncodeToString(endpointPublic),
		Probe:                string(reachability.ProbeUDP),
		Observed:             "203.0.113.7:41234",
		PeerPublic:           "no",
		AtUnix:               1_800_000_000,
	}, coordinatorKey)
	if err != nil {
		t.Fatalf("attest: %v", err)
	}
	trial := reachability.Trial{
		Local: reachability.EndpointStratum{
			Family: reachability.FamilyIPv4, Reachability: reachability.BehindNAT,
			NATBehavior: reachability.NATEndpointIndependent, Carrier: reachability.CarrierConsumerISP,
			UDPPolicy: reachability.UDPAllowed, Mobility: reachability.MobilityStationary,
			EndpointClass: reachability.ClassDesktop, Assistance: reachability.AssistanceNone,
		},
		PairID: pairFor(t, observation.SessionID), SiteID: "site_1111111111111111",
		OperatorID: "op_1111111111111111",
		SessionID:  observation.SessionID, Role: reachability.RoleA, Observation: observation,
		Probe:   reachability.ProbeUDP,
		Outcome: reachability.OutcomeDirect, Failure: reachability.FailureNone,
		EstablishMillis: 12, StartedAtUnix: 1_800_000_000,
		LocalCommit: strings.Repeat("a", 40), PeerCommit: strings.Repeat("b", 40),
	}
	signed, err := reachability.SignTrial(trial, endpointKey)
	if err != nil {
		t.Fatalf("sign trial: %v", err)
	}
	encoded, err := reachability.EncodeTrialJSON(signed)
	if err != nil {
		t.Fatalf("encode trial: %v", err)
	}
	report, err := build(filepath.Join("..", "..", "docs", "reachability-policy.example.json"),
		writeFile(t, "study.jsonl", string(encoded)+"\n"), "udp")
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	if report.Finding != reachability.FindingInsufficient {
		t.Fatalf("a single trial must not conclude anything, got %q", report.Finding)
	}
	if report.SupportsRouteDecision() {
		t.Fatal("a single UDP trial was accepted as a route decision")
	}
	if report.UnverifiedTrials != 0 {
		t.Fatalf("a correctly signed trial was rejected: %+v", report)
	}
	// It verified, and it still is not a measurement: the peer never reported.
	if report.IncompletePairs != 1 {
		t.Fatalf("an unpaired half was not reported as incomplete: %+v", report)
	}

	// The same trial attested by a coordinator the policy never predeclared is
	// not weaker evidence; it is not evidence.
	stranger, err := reachability.SignObservation(observation,
		ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x33}, ed25519.SeedSize)))
	if err != nil {
		t.Fatalf("attest: %v", err)
	}
	unattested := trial
	unattested.Observation = stranger
	resigned, err := reachability.SignTrial(unattested, endpointKey)
	if err != nil {
		t.Fatalf("sign trial: %v", err)
	}
	encoded, err = reachability.EncodeTrialJSON(resigned)
	if err != nil {
		t.Fatalf("encode trial: %v", err)
	}
	if _, err := build(filepath.Join("..", "..", "docs", "reachability-policy.example.json"),
		writeFile(t, "stranger.jsonl", string(encoded)+"\n"), "udp"); err == nil {
		t.Fatal("a study of unpredeclared attestations produced a report")
	}
}
