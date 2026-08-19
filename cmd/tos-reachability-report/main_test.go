package main

import (
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
	if len(policy.RequiredStrata) < 4 {
		t.Fatalf("example policy requires too little coverage: %d strata", len(policy.RequiredStrata))
	}
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

// A study that covers nothing must still parse and must still refuse to decide.
func TestBuildReportsInsufficientEvidence(t *testing.T) {
	trial := reachability.Trial{
		Stratum: reachability.Stratum{
			Family: reachability.FamilyIPv4, Reachability: reachability.NeitherPublic,
			NATBehavior: reachability.NATEndpointIndependent, Carrier: reachability.CarrierConsumerISP,
			UDPPolicy: reachability.UDPAllowed, Mobility: reachability.MobilityStationary,
			EndpointClass: reachability.ClassDesktop, Assistance: reachability.AssistanceNone,
		},
		PairID: "pair_" + strings.Repeat("1", 32), SiteID: "site_1111111111111111",
		OperatorID: "op_1111111111111111", Probe: reachability.ProbeUDP,
		Outcome: reachability.OutcomeDirect, Failure: reachability.FailureNone,
		EstablishMillis: 12, StartedAtUnix: 1_800_000_000,
		LocalCommit: strings.Repeat("a", 40), PeerCommit: strings.Repeat("b", 40),
	}
	encoded, err := reachability.EncodeTrialJSON(trial)
	if err != nil {
		t.Fatalf("encode trial: %v", err)
	}
	report, err := build(filepath.Join("..", "..", "docs", "reachability-policy.example.json"),
		writeFile(t, "study.jsonl", string(encoded)+"\n"), "udp")
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	if report.Finding != reachability.FindingInsufficient {
		t.Fatalf("a single trial must not decide anything, got %q", report.Finding)
	}
	if report.SupportsRouteDecision() {
		t.Fatal("a single UDP trial was accepted as a route decision")
	}
	if report.PolicyDigest == "" {
		t.Fatal("the report must name the policy it was judged against")
	}
}
