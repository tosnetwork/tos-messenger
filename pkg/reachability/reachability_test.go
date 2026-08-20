package reachability

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"
	"testing"
)

const (
	commitA = "1111111111111111111111111111111111111111"
	commitB = "2222222222222222222222222222222222222222"
	opA     = "op_1111111111111111"
	opB     = "op_2222222222222222"
	opC     = "op_3333333333333333"
)

// Each operator measures from its own site, which is what the site minimum is
// there to require.
func siteFor(operator string) string {
	return "site_" + operator[len("op_"):]
}

var sessionCounter int

func nextSession() string {
	sessionCounter++
	return fmt.Sprintf("ses_%012d", sessionCounter)
}

// testManifest is a complete collector manifest whose identity varies with the
// seed, so the two halves of a constructed pair can name two different builds
// the way two real endpoints do.
func testManifest(seed string) CollectorManifest {
	return CollectorManifest{
		OrchestratorRepository:   "github.com/tosnetwork/tos-messenger",
		OrchestratorCommit:       commitA,
		ADNLImplementation:       "tonutils-go",
		ADNLImplementationCommit: "v1.0.0-" + seed,
		DependencyVersion:        "v1.0.0-" + seed,
		BinarySHA256:             strings.Repeat("ab", 32),
		Target:                   "linux/amd64",
		Toolchain:                "go1.26.5",
		WireProfile:              "ton-adnl",
	}
}

func testManifestDigest(seed string) string {
	digest, err := testManifest(seed).Digest()
	if err != nil {
		panic(err)
	}
	return digest
}

// manifestA and manifestB are the digests every constructed pair uses, mirrored
// between the halves the way the commits are.
var (
	manifestA = testManifestDigest("collector-a")
	manifestB = testManifestDigest("collector-b")
)

func mapped(carrier Carrier, class EndpointClass) EndpointStratum {
	return EndpointStratum{
		Family:        FamilyIPv4,
		Reachability:  BehindNAT,
		NATBehavior:   NATAddressPortDependent,
		Carrier:       carrier,
		UDPPolicy:     UDPAllowed,
		Mobility:      MobilityStationary,
		EndpointClass: class,
		Assistance:    AssistanceNone,
	}
}

func publicEndpoint() EndpointStratum {
	return EndpointStratum{
		Family:        FamilyIPv4,
		Reachability:  PublicAddress,
		NATBehavior:   NATNone,
		Carrier:       CarrierDatacenter,
		UDPPolicy:     UDPAllowed,
		Mobility:      MobilityStationary,
		EndpointClass: ClassServer,
		Assistance:    AssistanceNone,
	}
}

// A real scenario is asymmetric: the two ends are in different situations, and
// the model has to be able to say so.
func scenario(carrier Carrier, class EndpointClass) Scenario {
	return Scenario{Initiator: mapped(carrier, class), Responder: publicEndpoint()}
}

func publicScenario() Scenario {
	responder := publicEndpoint()
	responder.Carrier = CarrierConsumerISP
	return Scenario{Initiator: publicEndpoint(), Responder: responder}
}

// mobileScenario is the study's only source of IPv6 and of a rate-limited UDP
// path, so each coverage rule the policy enforces has exactly one place it can
// be removed from.
func mobileScenario() Scenario { return mobileScenarioOn(FamilyIPv6) }

func mobileScenarioOn(family AddressFamily) Scenario {
	phone := EndpointStratum{
		Family:        family,
		Reachability:  BehindNAT,
		NATBehavior:   NATSymmetric,
		Carrier:       CarrierMobile,
		UDPPolicy:     UDPRateLimited,
		Mobility:      MobilityWiFiToMobile,
		EndpointClass: ClassMobile,
		Assistance:    AssistanceNone,
	}
	responder := mapped(CarrierConsumerISP, ClassDesktop)
	responder.Family = family
	return Scenario{Initiator: phone, Responder: responder}
}

// Every constructed trial is attested and signed the way a real one would be,
// so the tests exercise the verification path rather than bypassing it.
func testCoordinatorKey() ed25519.PrivateKey {
	return ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x11}, ed25519.SeedSize))
}

func testCoordinatorID() string {
	public, ok := testCoordinatorKey().Public().(ed25519.PublicKey)
	if !ok {
		panic("unexpected key type")
	}
	identifier, err := CoordinatorID(public)
	if err != nil {
		panic(err)
	}
	return identifier
}

// One key per endpoint. Both ends of a measurement are separate endpoints even
// when one operator runs both of them, so the key varies by role as well as by
// operator. A shared key is the impersonation the report is meant to catch,
// not the normal case.
func endpointKeyFor(operator string, role Role) ed25519.PrivateKey {
	seed := sha256.Sum256([]byte("endpoint/" + operator + "/" + string(role)))
	return ed25519.NewKeyFromSeed(seed[:])
}

// observedFor is an address in the family the coordinator would have reached
// the endpoint over, so the signed observation matches the declared family. A
// dual-stack endpoint is reached over one family at a time, so v4 stands in.
func observedFor(family AddressFamily) string {
	if family == FamilyIPv6 {
		return "[2001:db8::7]:41234"
	}
	return "203.0.113.7:41234"
}

// attest names the endpoint it is about, so a copied attestation cannot be
// worn by another key. The observed address is in the endpoint's declared
// family, and peerPublic is the coordinator's view of the endpoint's peer.
func attest(session string, role Role, operator, peerPublic string, family AddressFamily) Observation {
	public, ok := endpointKeyFor(operator, role).Public().(ed25519.PublicKey)
	if !ok {
		panic("unexpected key type")
	}
	observation, err := SignObservation(Observation{
		SessionID:            session,
		Role:                 string(role),
		EndpointPublicKeyHex: hex.EncodeToString(public),
		Probe:                string(ProbeUDP),
		Observed:             observedFor(family),
		PeerPublic:           peerPublic,
		AtUnix:               1_800_000_000,
	}, testCoordinatorKey())
	if err != nil {
		panic(err)
	}
	return observation
}

// switchProbe moves a trial to another probe. The attestation names the probe,
// so it has to be reissued: changing the probe alone would leave an
// attestation about a different measurement, which is what the binding is for.
func switchProbe(trial Trial, probe ProbeKind) Trial {
	trial.Probe = probe
	trial.Observation = attest(trial.SessionID, trial.Role, trial.OperatorID, trial.Observation.PeerPublic, trial.Local.Family)
	trial.Observation.Probe = string(probe)
	signed, err := SignObservation(trial.Observation, testCoordinatorKey())
	if err != nil {
		panic(err)
	}
	trial.Observation = signed
	return resign(trial)
}

// resign re-signs a trial a test mutated. Mutating a signed trial invalidates
// it, which is the signature doing its job.
func resign(trial Trial) Trial {
	signed, err := SignTrial(trial, endpointKeyFor(trial.OperatorID, trial.Role))
	if err != nil {
		panic(err)
	}
	return signed
}

// localOf is the side of a scenario one role reports. Each endpoint describes
// only itself, which is the whole point of the pair model.
func localOf(s Scenario, role Role) EndpointStratum {
	if role == RoleB {
		return s.Responder
	}
	return s.Initiator
}

func rawTrial(s Scenario, session string, role Role, operator string,
	outcome Outcome, failure FailureClass, millis uint64) Trial {
	pair, err := PairID(session)
	if err != nil {
		panic(err)
	}
	local, peer := commitA, commitB
	localManifest, peerManifest := manifestA, manifestB
	if role == RoleB {
		local, peer = commitB, commitA
		localManifest, peerManifest = manifestB, manifestA
	}
	return Trial{
		Local:               localOf(s, role),
		PairID:              pair,
		SiteID:              siteFor(operator),
		OperatorID:          operator,
		SessionID:           session,
		Role:                role,
		Probe:               ProbeUDP,
		Outcome:             outcome,
		Failure:             failure,
		EstablishMillis:     millis,
		StartedAtUnix:       1_800_000_000,
		LocalCommit:         local,
		PeerCommit:          peer,
		LocalManifestDigest: localManifest,
		PeerManifestDigest:  peerManifest,
	}
}

// complete attests and signs a half. The coordinator's peer observation is
// about the endpoint's peer, so it is derived from the peer stratum rather than
// from the endpoint's own reachability.
func complete(trial Trial, peer EndpointStratum) Trial {
	peerPublic := "no"
	if peer.Reachability == PublicAddress {
		peerPublic = "yes"
	}
	trial.Observation = attest(trial.SessionID, trial.Role, trial.OperatorID, peerPublic, trial.Local.Family)
	signed, err := SignTrial(trial, endpointKeyFor(trial.OperatorID, trial.Role))
	if err != nil {
		panic(err)
	}
	return signed
}

// measurement builds both halves of one attempt. Aggregation counts pairs, so
// a helper that produced a single record would be manufacturing exactly the
// evidence the report is right to discard. Each half's peer observation is the
// other end's stratum, which is what the pairing cross-check verifies.
func measurement(s Scenario, operator string, outcome Outcome, failure FailureClass, millis uint64) []Trial {
	session := nextSession()
	return []Trial{
		complete(rawTrial(s, session, RoleA, operator, outcome, failure, millis), s.Responder),
		complete(rawTrial(s, session, RoleB, operator, outcome, failure, millis), s.Initiator),
	}
}

func directPair(s Scenario, operator string, millis uint64) []Trial {
	return measurement(s, operator, OutcomeDirect, FailureNone, millis)
}

func fallbackPair(s Scenario, operator string, outcome Outcome, failure FailureClass) []Trial {
	return measurement(s, operator, outcome, failure, 0)
}

// directTrial and fallbackTrial return one half, for the tests that are about
// a single record rather than about an aggregate.
func directTrial(s Scenario, operator string, millis uint64) Trial {
	return directPair(s, operator, millis)[0]
}

func fallbackTrial(s Scenario, operator string, outcome Outcome, failure FailureClass) Trial {
	return fallbackPair(s, operator, outcome, failure)[0]
}

func testPolicy() Policy {
	return Policy{
		MinSamplesPerCell:                  4,
		MinOperatorsPerCell:                2,
		MinSitesPerCell:                    2,
		MaxTrialsPerOperatorPerCell:        8,
		DirectViableRate:                   0.75,
		TunnelViableRate:                   0.9,
		MinDirectSurvivalRate:              0.75,
		MinTunnelSurvivalRate:              0.75,
		MinReconnectSuccessRate:            0.75,
		MinSurvivalSamplesPerCell:          2,
		MinReconnectSamplesPerMobilityCell: 2,
		Coordinators:                       []string{testCoordinatorID()},
		RequiredScenarios: []Scenario{
			scenario(CarrierConsumerISP, ClassDesktop),
			scenario(CarrierCarrierGrade, ClassEdgeARM),
			mobileScenario(),
		},
	}
}

// withHealthyDirectPhases marks one ADNL direct half with the healthy
// post-establishment story: the hold ran and survived the full window, and on
// the initiating half the deliberate reconnect ran and succeeded. The
// responder never dials, so its half truthfully carries no reconnect flags --
// the pair join takes the initiator's.
func withHealthyDirectPhases(trial Trial) Trial {
	trial.HoldAttempted, trial.HoldCompleted = true, true
	trial.SurvivalSeconds = 60
	if trial.Role == RoleA {
		trial.ReconnectAttempted, trial.ReconnectSucceeded = true, true
		trial.ReconnectMillis = 40
	}
	return resign(trial)
}

// withHealthyTunnelPhases marks one ADNL proxy-fallback half as having held
// the tunneled session for the full window.
func withHealthyTunnelPhases(trial Trial) Trial {
	trial.TunnelHoldAttempted, trial.TunnelHoldCompleted = true, true
	return resign(trial)
}

// adnlStudy moves a constructed UDP study to the ADNL probe and gives every
// half the healthy phase story its outcome supports, so a fixture that used to
// exercise only establishment keeps deciding what it decided before the
// survival and reconnect gates existed.
func adnlStudy(trials []Trial) []Trial {
	moved := make([]Trial, len(trials))
	for index, trial := range trials {
		trial = switchProbe(trial, ProbeADNL)
		switch trial.Outcome {
		case OutcomeDirect:
			trial = withHealthyDirectPhases(trial)
		case OutcomeProxyFallback:
			trial = withHealthyTunnelPhases(trial)
		}
		moved[index] = trial
	}
	return moved
}

func fillCell(trials []Trial, s Scenario, direct int, outcome Outcome, failure FailureClass, other int) []Trial {
	operators := []string{opA, opB, opC}
	for index := 0; index < direct; index++ {
		trials = append(trials, directPair(s, operators[index%len(operators)], uint64(100+index))...)
	}
	for index := 0; index < other; index++ {
		trials = append(trials, fallbackPair(s, operators[(direct+index)%len(operators)], outcome, failure)...)
	}
	return trials
}

func TestPolicyRejectsSmokeTests(t *testing.T) {
	cases := map[string]func(*Policy){
		"single operator":   func(p *Policy) { p.MinOperatorsPerCell = 1 },
		"samples below ops": func(p *Policy) { p.MinSamplesPerCell = 1 },
		"zero direct rate":  func(p *Policy) { p.DirectViableRate = 0 },
		"rate above one":    func(p *Policy) { p.TunnelViableRate = 1.5 },
		"tunnel below direct": func(p *Policy) {
			p.DirectViableRate = 0.9
			p.TunnelViableRate = 0.5
		},
		"zero survival rate": func(p *Policy) { p.MinDirectSurvivalRate = 0 },
		"survival rate above one": func(p *Policy) {
			p.MinTunnelSurvivalRate = 1.5
		},
		"zero reconnect rate":         func(p *Policy) { p.MinReconnectSuccessRate = 0 },
		"no survival sample minimum":  func(p *Policy) { p.MinSurvivalSamplesPerCell = 0 },
		"no reconnect sample minimum": func(p *Policy) { p.MinReconnectSamplesPerMobilityCell = 0 },
		"no scenarios":                func(p *Policy) { p.RequiredScenarios = nil },
		"public pairs only": func(p *Policy) {
			p.RequiredScenarios = []Scenario{publicScenario()}
		},
		"matched pairs only": func(p *Policy) {
			matched := Scenario{
				Initiator: mapped(CarrierConsumerISP, ClassDesktop),
				Responder: mapped(CarrierConsumerISP, ClassDesktop),
			}
			p.RequiredScenarios = []Scenario{matched}
		},
		"duplicate scenario": func(p *Policy) {
			p.RequiredScenarios = append(p.RequiredScenarios, p.RequiredScenarios[0])
		},
		"no carrier grade nat": func(p *Policy) {
			p.RequiredScenarios = []Scenario{scenario(CarrierConsumerISP, ClassEdgeARM), mobileScenario()}
		},
		"no low cost endpoint": func(p *Policy) {
			p.RequiredScenarios[1] = scenario(CarrierCarrierGrade, ClassServer)
		},
		"single address family": func(p *Policy) {
			p.RequiredScenarios[2] = mobileScenarioOn(FamilyIPv4)
		},
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			policy := testPolicy()
			mutate(&policy)
			if err := policy.Validate(); err == nil {
				t.Fatalf("expected %q to be refused", name)
			}
			if _, err := policy.Digest(); err == nil {
				t.Fatalf("expected %q to have no digest", name)
			}
		})
	}
	if err := testPolicy().Validate(); err != nil {
		t.Fatalf("expected the reference policy to be accepted: %v", err)
	}
}

func TestPolicyDigestIsOrderIndependentAndThresholdSensitive(t *testing.T) {
	first := testPolicy()
	digest, err := first.Digest()
	if err != nil {
		t.Fatalf("digest: %v", err)
	}
	reordered := testPolicy()
	reordered.RequiredScenarios[0], reordered.RequiredScenarios[2] = reordered.RequiredScenarios[2], reordered.RequiredScenarios[0]
	reorderedDigest, err := reordered.Digest()
	if err != nil {
		t.Fatalf("digest: %v", err)
	}
	if digest != reorderedDigest {
		t.Fatal("scenario ordering changed the policy identity")
	}
	for name, mutate := range map[string]func(*Policy){
		"samples": func(p *Policy) { p.MinSamplesPerCell = 5 },
		"operators": func(p *Policy) {
			p.MinOperatorsPerCell = 3
			p.MinSamplesPerCell = 5
		},
		"sites":        func(p *Policy) { p.MinSitesPerCell = 3 },
		"operator cap": func(p *Policy) { p.MaxTrialsPerOperatorPerCell = 4 },
		"coordinators": func(p *Policy) {
			p.Coordinators = append(p.Coordinators, "srv_9999999999999999")
		},
		"direct rate":             func(p *Policy) { p.DirectViableRate = 0.74 },
		"tunnel rate":             func(p *Policy) { p.TunnelViableRate = 0.95 },
		"direct survival rate":    func(p *Policy) { p.MinDirectSurvivalRate = 0.8 },
		"tunnel survival rate":    func(p *Policy) { p.MinTunnelSurvivalRate = 0.8 },
		"reconnect success rate":  func(p *Policy) { p.MinReconnectSuccessRate = 0.8 },
		"survival sample minimum": func(p *Policy) { p.MinSurvivalSamplesPerCell = 3 },
		"reconnect sample minimum": func(p *Policy) {
			p.MinReconnectSamplesPerMobilityCell = 3
		},
		"scenarios": func(p *Policy) {
			p.RequiredScenarios = append(p.RequiredScenarios, scenario(CarrierMobile, ClassEdgeRISC))
		},
	} {
		t.Run(name, func(t *testing.T) {
			mutated := testPolicy()
			mutate(&mutated)
			mutatedDigest, err := mutated.Digest()
			if err != nil {
				t.Fatalf("digest: %v", err)
			}
			if mutatedDigest == digest {
				t.Fatalf("changing %q did not change the policy identity", name)
			}
		})
	}
}

func TestMissingRequiredScenarioYieldsNoDecision(t *testing.T) {
	policy := testPolicy()
	var trials []Trial
	trials = fillCell(trials, policy.RequiredScenarios[0], 4, OutcomeFailed, FailureHandshake, 0)
	report, err := Aggregate(policy, trials, ProbeUDP)
	if err != nil {
		t.Fatalf("aggregate: %v", err)
	}
	if report.Finding != FindingInsufficient {
		t.Fatalf("expected no decision from partial coverage, got %q", report.Finding)
	}
	if len(report.Missing) != 2 {
		t.Fatalf("expected two missing strata, got %d", len(report.Missing))
	}
}

func TestUnderSampledScenarioYieldsNoDecision(t *testing.T) {
	policy := testPolicy()
	single := policy.RequiredScenarios[1]
	var trials []Trial
	for index, required := range policy.RequiredScenarios {
		if index == 1 {
			// Enough samples, all of them from one operator on one site.
			for attempt := 0; attempt < 4; attempt++ {
				trials = append(trials, fallbackPair(required, opA, OutcomeFailed, FailureHandshake)...)
			}
			continue
		}
		trials = fillCell(trials, required, 4, OutcomeFailed, FailureHandshake, 0)
	}
	report, err := Aggregate(policy, trials, ProbeUDP)
	if err != nil {
		t.Fatalf("aggregate: %v", err)
	}
	if report.Finding != FindingInsufficient {
		t.Fatalf("expected no decision without operator diversity, got %q", report.Finding)
	}
	if len(report.Missing) != 1 || report.Missing[0] != single.Key() {
		t.Fatalf("expected the single-operator cell to be named, got %v", report.Missing)
	}
}

func TestDecisionFollowsMeasurement(t *testing.T) {
	policy := testPolicy()
	cases := []struct {
		name     string
		direct   []int
		proxy    []int
		expected Finding
	}{
		{"direct everywhere", []int{4, 4, 4}, []int{0, 0, 0}, FindingDirectFirst},
		{"direct nowhere, tunnel everywhere", []int{0, 0, 0}, []int{4, 4, 4}, FindingTunnelFirst},
		{"direct nowhere, tunnel nowhere", []int{0, 0, 0}, []int{0, 0, 0}, FindingRelayRequired},
		{"direct in one class only", []int{4, 0, 0}, []int{0, 4, 4}, FindingHybrid},
		{"direct just under the bar", []int{2, 2, 2}, []int{2, 2, 2}, FindingTunnelFirst},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			var trials []Trial
			for index, required := range policy.RequiredScenarios {
				direct := testCase.direct[index]
				proxy := testCase.proxy[index]
				trials = fillCell(trials, required, direct, OutcomeProxyFallback, FailureHandshake, proxy)
				remaining := 4 - direct - proxy
				if remaining > 0 {
					trials = fillCell(trials, required, 0, OutcomeRelayFallback, FailurePeerUnreachable, remaining)
				}
			}
			trials = adnlStudy(trials)
			report, err := Aggregate(policy, trials, ProbeADNL)
			if err != nil {
				t.Fatalf("aggregate: %v", err)
			}
			if report.Finding != testCase.expected {
				t.Fatalf("expected %q, got %q (reasons %v)", testCase.expected, report.Finding, report.Reasons)
			}
			if !report.SupportsRouteDecision() {
				t.Fatal("an ADNL study did not support a route decision")
			}
			if report.PolicyDigest == "" {
				t.Fatal("a report must name the policy it was judged against")
			}
		})
	}
}

func TestReportKeepsUnrequiredEvidence(t *testing.T) {
	policy := testPolicy()
	var trials []Trial
	for _, required := range policy.RequiredScenarios {
		trials = fillCell(trials, required, 4, OutcomeFailed, FailureHandshake, 0)
	}
	trials = fillCell(trials, publicScenario(), 4, OutcomeFailed, FailureHandshake, 0)
	report, err := Aggregate(policy, trials, ProbeUDP)
	if err != nil {
		t.Fatalf("aggregate: %v", err)
	}
	if len(report.Cells) != 4 {
		t.Fatalf("expected every measured cell to be published, got %d", len(report.Cells))
	}
	if report.Finding != FindingUDPDirectViable {
		t.Fatalf("unexpected finding %q", report.Finding)
	}
}

func TestProbeKindsAreNotMixed(t *testing.T) {
	policy := testPolicy()
	var trials []Trial
	for _, required := range policy.RequiredScenarios {
		trials = fillCell(trials, required, 4, OutcomeFailed, FailureHandshake, 0)
	}
	for _, half := range directPair(policy.RequiredScenarios[0], opA, 50) {
		trials = append(trials, switchProbe(half, ProbeADNL))
	}

	report, err := Aggregate(policy, trials, ProbeUDP)
	if err != nil {
		t.Fatalf("aggregate: %v", err)
	}
	for _, cell := range report.Cells {
		if cell.Samples != 4 {
			t.Fatalf("a different probe leaked into cell %s: %d samples", cell.ScenarioKey, cell.Samples)
		}
	}
	if _, err := Aggregate(policy, trials, ProbeADNL); err != nil {
		t.Fatalf("expected the ADNL probe to aggregate on its own: %v", err)
	}
}

func TestPercentilesUseMeasuredSessionsOnly(t *testing.T) {
	policy := testPolicy()
	target := policy.RequiredScenarios[0]
	var trials []Trial
	trials = append(trials, directPair(target, opA, 10)...)
	trials = append(trials, directPair(target, opB, 20)...)
	trials = append(trials, directPair(target, opA, 30)...)
	trials = append(trials, directPair(target, opB, 400)...)
	trials = append(trials, fallbackPair(target, opC, OutcomeRelayFallback, FailureHandshake)...)
	for _, required := range policy.RequiredScenarios[1:] {
		trials = fillCell(trials, required, 4, OutcomeFailed, FailureHandshake, 0)
	}
	report, err := Aggregate(policy, trials, ProbeUDP)
	if err != nil {
		t.Fatalf("aggregate: %v", err)
	}
	var cell CellReport
	for _, candidate := range report.Cells {
		if candidate.ScenarioKey == target.Key() {
			cell = candidate
		}
	}
	if cell.Samples != 5 || cell.Operators != 3 {
		t.Fatalf("unexpected cell shape: %+v", cell)
	}
	if cell.EstablishP50 != 20 || cell.EstablishP95 != 400 {
		t.Fatalf("unexpected latency percentiles: p50=%d p95=%d", cell.EstablishP50, cell.EstablishP95)
	}
	// The rate is the mean over operators, not over trials. Two operators
	// succeeded twice each and one failed once, so the cell reads two thirds
	// rather than the four fifths a pooled count would give. That difference
	// is the point: an operator does not gain influence by running more.
	if cell.DirectRate < 0.66 || cell.DirectRate > 0.67 {
		t.Fatalf("unexpected operator-weighted direct rate: %v", cell.DirectRate)
	}
	if cell.RelayShare != 0.2 {
		t.Fatalf("unexpected relay share: %v", cell.RelayShare)
	}
	if cell.Sites != 3 {
		t.Fatalf("unexpected site count: %d", cell.Sites)
	}
	if cell.FailureCounts[FailureHandshake] != 1 {
		t.Fatalf("unexpected failure counts: %v", cell.FailureCounts)
	}
}

func TestTrialValidationRejectsIncoherentRecords(t *testing.T) {
	base := directTrial(scenario(CarrierConsumerISP, ClassDesktop), opA, 100)
	cases := map[string]func(*Trial){
		"direct with failure":    func(t *Trial) { t.Failure = FailureHandshake },
		"direct without latency": func(t *Trial) { t.EstablishMillis = 0 },
		"failure without class":  func(t *Trial) { t.Outcome = OutcomeFailed; t.Failure = FailureNone },
		"failed with latency":    func(t *Trial) { t.Outcome = OutcomeFailed; t.Failure = FailureHandshake },
		"fallback without class": func(t *Trial) { t.Outcome = OutcomeRelayFallback; t.Failure = FailureNone },
		"reconnect without session": func(t *Trial) {
			t.Outcome = OutcomeRelayFallback
			t.Failure = FailureHandshake
			t.EstablishMillis = 0
			t.ReconnectMillis = 5
		},
		"survival without session": func(t *Trial) {
			t.Outcome = OutcomeRelayFallback
			t.Failure = FailureHandshake
			t.EstablishMillis = 0
			t.SurvivalSeconds = 5
		},
		"bad operator":                  func(t *Trial) { t.OperatorID = "operator-1" },
		"bad probe":                     func(t *Trial) { t.Probe = "quic" },
		"no start time":                 func(t *Trial) { t.StartedAtUnix = 0 },
		"short commit":                  func(t *Trial) { t.LocalCommit = "abc" },
		"missing peer commit":           func(t *Trial) { t.PeerCommit = "" },
		"missing local manifest digest": func(t *Trial) { t.LocalManifestDigest = "" },
		"short peer manifest digest":    func(t *Trial) { t.PeerManifestDigest = "sha256:abc" },
		"zero manifest digest": func(t *Trial) {
			t.LocalManifestDigest = "sha256:" + strings.Repeat("0", 64)
		},
		"nat on a public endpoint": func(t *Trial) {
			t.Local.Reachability = PublicAddress
		},
		"no nat behind nat": func(t *Trial) { t.Local.NATBehavior = NATNone },
		"unknown carrier":   func(t *Trial) { t.Local.Carrier = "satellite" },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			trial := base
			mutate(&trial)
			if err := trial.Validate(); err == nil {
				t.Fatalf("expected %q to be refused", name)
			}
			if _, err := EncodeTrialJSON(trial); err == nil {
				t.Fatalf("expected %q to be unencodable", name)
			}
		})
	}
}

// The phase-status booleans carry their own cross-rules, and every one fails
// closed: a record whose flags and measurements can disagree is a record whose
// meaning the reader chooses, which is the ambiguity the booleans exist to
// remove.
func TestPhaseStatusCrossRulesFailClosed(t *testing.T) {
	direct := switchProbe(directTrial(scenario(CarrierConsumerISP, ClassDesktop), opA, 100), ProbeADNL)

	// The honest shapes validate: a hold that completed its window with its
	// span, a reconnect that succeeded with its latency, and -- the case the
	// schema previously could not say -- a reconnect that ran and failed,
	// attempted with everything else at zero.
	honest := direct
	honest.HoldAttempted, honest.HoldCompleted = true, true
	honest.SurvivalSeconds = 30
	honest.ReconnectAttempted, honest.ReconnectSucceeded = true, true
	honest.ReconnectMillis = 40
	if err := honest.Validate(); err != nil {
		t.Fatalf("an honest measured trial was refused: %v", err)
	}
	failedReconnect := direct
	failedReconnect.HoldAttempted, failedReconnect.HoldCompleted = true, true
	failedReconnect.SurvivalSeconds = 30
	failedReconnect.ReconnectAttempted = true
	if err := failedReconnect.Validate(); err != nil {
		t.Fatalf("a truthfully recorded failed reconnect was refused: %v", err)
	}
	tunneled := fallbackTrial(scenario(CarrierConsumerISP, ClassDesktop), opA,
		OutcomeProxyFallback, FailureHandshake)
	tunneled = switchProbe(tunneled, ProbeADNL)
	tunneled.TunnelHoldAttempted, tunneled.TunnelHoldCompleted = true, true
	if err := tunneled.Validate(); err != nil {
		t.Fatalf("an honest tunnel hold was refused: %v", err)
	}

	cases := map[string]func(*Trial){
		"hold completed without being attempted": func(t *Trial) {
			t.HoldCompleted = true
			t.SurvivalSeconds = 30
		},
		"reconnect succeeded without being attempted": func(t *Trial) {
			t.ReconnectSucceeded = true
			t.ReconnectMillis = 40
		},
		"reconnect succeeded without a latency": func(t *Trial) {
			t.ReconnectAttempted, t.ReconnectSucceeded = true, true
		},
		"reconnect latency without a success": func(t *Trial) {
			t.ReconnectAttempted = true
			t.ReconnectMillis = 40
		},
		"hold completed without a survival span": func(t *Trial) {
			t.HoldAttempted, t.HoldCompleted = true, true
		},
		"tunnel hold on a direct outcome": func(t *Trial) {
			t.TunnelHoldAttempted = true
		},
		"tunnel hold completed without being attempted": func(t *Trial) {
			t.Outcome = OutcomeProxyFallback
			t.Failure = FailureHandshake
			t.TunnelHoldCompleted = true
		},
		"hold on a proxy fallback": func(t *Trial) {
			t.Outcome = OutcomeProxyFallback
			t.Failure = FailureHandshake
			t.HoldAttempted = true
		},
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			trial := direct
			mutate(&trial)
			if err := trial.Validate(); err == nil {
				t.Fatalf("expected %q to be refused", name)
			}
		})
	}

	// The udp probe has no session, so no phase may claim to have run on it,
	// whatever the outcome says.
	udp := directTrial(scenario(CarrierConsumerISP, ClassDesktop), opA, 100)
	udp.HoldAttempted = true
	udp.SurvivalSeconds = 30
	if err := udp.Validate(); err == nil {
		t.Fatal("a udp trial claimed a session phase")
	}
}

func TestTrialLogRefusesDuplicatesAndGarbage(t *testing.T) {
	trial := directTrial(scenario(CarrierConsumerISP, ClassDesktop), opA, 100)
	encoded, err := EncodeTrialJSON(trial)
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	line := string(encoded)

	parsed, err := DecodeTrialLog([]byte(line + "\n\n"))
	if err != nil {
		t.Fatalf("decode log: %v", err)
	}
	if len(parsed) != 1 {
		t.Fatalf("expected one trial, got %d", len(parsed))
	}
	if _, err := DecodeTrialLog([]byte(line + "\n" + line + "\n")); err == nil {
		t.Fatal("expected a replayed trial to be refused")
	}
	if _, err := DecodeTrialLog([]byte(line + "\nnot json\n")); err == nil {
		t.Fatal("expected a malformed line to be refused")
	}
	if _, err := DecodeTrialLog([]byte("\n \n")); err == nil {
		t.Fatal("expected an empty log to be refused")
	}
	if _, err := DecodeTrialJSON([]byte(strings.Replace(line, TrialSchema, "other", 1))); err == nil {
		t.Fatal("expected an unknown schema to be refused")
	}
	if _, err := DecodeTrialJSON([]byte(line[:len(line)-1] + `,"extra":1}`)); err == nil {
		t.Fatal("expected an unknown field to be refused")
	}
}

func TestPolicyRoundTrip(t *testing.T) {
	policy := testPolicy()
	encoded, err := EncodePolicyJSON(policy)
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	decoded, err := DecodePolicyJSON(encoded)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	first, err := policy.Digest()
	if err != nil {
		t.Fatalf("digest: %v", err)
	}
	second, err := decoded.Digest()
	if err != nil {
		t.Fatalf("digest: %v", err)
	}
	if first != second {
		t.Fatal("policy identity changed across transport")
	}
}

func TestOperatorIDIsStableAndOpaque(t *testing.T) {
	first, err := OperatorID("edge-lab-tokyo")
	if err != nil {
		t.Fatalf("operator: %v", err)
	}
	again, err := OperatorID("edge-lab-tokyo")
	if err != nil {
		t.Fatalf("operator: %v", err)
	}
	if first != again {
		t.Fatal("operator identity is not stable")
	}
	if !operatorPattern.MatchString(first) {
		t.Fatalf("unexpected operator shape: %s", first)
	}
	if strings.Contains(first, "tokyo") {
		t.Fatal("operator identity leaks the name it was derived from")
	}
	other, err := OperatorID("edge-lab-osaka")
	if err != nil {
		t.Fatalf("operator: %v", err)
	}
	if other == first {
		t.Fatal("different operators collided")
	}
	for _, invalid := range []string{"", " padded", "padded ", strings.Repeat("n", 129)} {
		if _, err := OperatorID(invalid); err == nil {
			t.Fatalf("expected %q to be refused", invalid)
		}
	}
}

// A UDP study reports whether a datagram path exists. It never reports a
// route, whatever its success rate, because an ADNL handshake, channel,
// keepalive, and recovery all still have to survive that path.
func TestUDPEvidenceNeverYieldsARouteDecision(t *testing.T) {
	policy := testPolicy()
	var trials []Trial
	for _, required := range policy.RequiredScenarios {
		trials = fillCell(trials, required, 4, OutcomeFailed, FailureHandshake, 0)
	}
	report, err := Aggregate(policy, trials, ProbeUDP)
	if err != nil {
		t.Fatalf("aggregate: %v", err)
	}
	if report.Kind != KindFeasibility {
		t.Fatalf("a UDP study reported kind %q", report.Kind)
	}
	if report.Finding != FindingUDPDirectViable {
		t.Fatalf("expected feasibility, got %q", report.Finding)
	}
	if report.SupportsRouteDecision() {
		t.Fatal("a UDP study was accepted as a route decision")
	}
	for _, forbidden := range []Finding{FindingDirectFirst, FindingTunnelFirst, FindingHybrid, FindingRelayRequired} {
		if report.Finding == forbidden {
			t.Fatalf("a UDP study produced the route vocabulary: %q", forbidden)
		}
	}
}

func TestUnreachableUDPPathIsReportedAsSuch(t *testing.T) {
	policy := testPolicy()
	var trials []Trial
	for _, required := range policy.RequiredScenarios {
		trials = fillCell(trials, required, 0, OutcomeFailed, FailureHandshake, 4)
	}
	report, err := Aggregate(policy, trials, ProbeUDP)
	if err != nil {
		t.Fatalf("aggregate: %v", err)
	}
	if report.Finding != FindingUDPDirectNotViable {
		t.Fatalf("expected an unviable direct path, got %q", report.Finding)
	}
}

// Relay-required says a Relay is necessary. Whether one performs adequately is
// a different milestone's acceptance, and the vocabulary must not blur them.
func TestRelayIsRequiredNotAccepted(t *testing.T) {
	if FindingRelayRequired != "relay-required" {
		t.Fatalf("unexpected finding name %q", FindingRelayRequired)
	}
	for _, name := range []Finding{FindingDirectFirst, FindingTunnelFirst, FindingHybrid,
		FindingRelayRequired, FindingUDPDirectViable, FindingUDPDirectNotViable, FindingInsufficient} {
		if strings.Contains(string(name), "relay-first") {
			t.Fatalf("the vocabulary still claims relay-first: %q", name)
		}
	}
}

// One operator running thousands of attempts must not decide a cell that
// everyone else measured a handful of times.
func TestOneOperatorCannotDominateACell(t *testing.T) {
	policy := testPolicy()
	target := policy.RequiredScenarios[0]

	var trials []Trial
	// A prolific operator succeeds every time.
	for index := 0; index < 200; index++ {
		trials = append(trials, directPair(target, opA, 10)...)
	}
	// Two others fail every time.
	for index := 0; index < 4; index++ {
		trials = append(trials, fallbackPair(target, opB, OutcomeFailed, FailureHandshake)...)
		trials = append(trials, fallbackPair(target, opC, OutcomeFailed, FailureHandshake)...)
	}
	for _, required := range policy.RequiredScenarios[1:] {
		trials = fillCell(trials, required, 4, OutcomeFailed, FailureHandshake, 0)
	}
	report, err := Aggregate(policy, trials, ProbeUDP)
	if err != nil {
		t.Fatalf("aggregate: %v", err)
	}
	var cell CellReport
	for _, candidate := range report.Cells {
		if candidate.ScenarioKey == target.Key() {
			cell = candidate
		}
	}
	if cell.DroppedOverCap != 200-policy.MaxTrialsPerOperatorPerCell {
		t.Fatalf("the cap was not applied or not reported: %+v", cell)
	}
	// One of three operators succeeded, so the cell reads a third, not the
	// ninety-six percent a pooled count would have produced.
	if cell.DirectRate > 0.34 {
		t.Fatalf("a single operator decided the cell: %v", cell.DirectRate)
	}
	if report.Finding != FindingUDPDirectNotViable {
		t.Fatalf("expected the cell to fail its rate, got %q", report.Finding)
	}
}

// Counting operators alone would not notice one operator running everything
// behind a single uplink.
func TestConcentratedEvidenceIsUnderSampled(t *testing.T) {
	policy := testPolicy()
	var trials []Trial
	for _, required := range policy.RequiredScenarios {
		trials = fillCell(trials, required, 4, OutcomeFailed, FailureHandshake, 0)
	}
	// Every operator now reports from the same network.
	for index := range trials {
		trials[index].SiteID = "site_0000000000000000"
		trials[index] = resign(trials[index])
	}
	report, err := Aggregate(policy, trials, ProbeUDP)
	if err != nil {
		t.Fatalf("aggregate: %v", err)
	}
	if report.Finding != FindingInsufficient {
		t.Fatalf("evidence from one network produced %q", report.Finding)
	}
	if len(report.Missing) != len(policy.RequiredScenarios) {
		t.Fatalf("expected every cell to be under-sampled, got %d", len(report.Missing))
	}
}

func TestPairAndSiteIdentityAreRequired(t *testing.T) {
	base := directTrial(scenario(CarrierConsumerISP, ClassDesktop), opA, 100)
	for name, mutate := range map[string]func(*Trial){
		"no pair":  func(t *Trial) { t.PairID = "" },
		"bad pair": func(t *Trial) { t.PairID = "pair_bad" },
		"no site":  func(t *Trial) { t.SiteID = "" },
		"bad site": func(t *Trial) { t.SiteID = "site_bad" },
	} {
		t.Run(name, func(t *testing.T) {
			trial := base
			mutate(&trial)
			if err := trial.Validate(); err == nil {
				t.Fatalf("expected %q to be refused", name)
			}
		})
	}
	pair, err := PairID("session-one")
	if err != nil {
		t.Fatalf("pair: %v", err)
	}
	if !pairPattern.MatchString(pair) {
		t.Fatalf("unexpected pair identifier: %s", pair)
	}
	site, err := SiteID("tokyo-uplink")
	if err != nil {
		t.Fatalf("site: %v", err)
	}
	if !sitePattern.MatchString(site) || strings.Contains(site, "tokyo") {
		t.Fatalf("unexpected site identifier: %s", site)
	}
	if _, err := SiteID(""); err == nil {
		t.Fatal("an empty site name was accepted")
	}
	if _, err := PairID(" padded "); err == nil {
		t.Fatal("an untrimmed pair session was accepted")
	}
}

// A trial altered after it was signed is not evidence, whatever it now says.
func TestAlteredTrialsAreNotCounted(t *testing.T) {
	policy := testPolicy()
	var trials []Trial
	for _, required := range policy.RequiredScenarios {
		trials = fillCell(trials, required, 4, OutcomeFailed, FailureHandshake, 0)
	}
	// Someone improves one result after the fact.
	trials[0].Outcome = OutcomeDirect
	trials[0].EstablishMillis = 5

	report, err := Aggregate(policy, trials, ProbeUDP)
	if err != nil {
		t.Fatalf("aggregate: %v", err)
	}
	if report.UnverifiedTrials != 1 {
		t.Fatalf("an altered trial was counted: %+v", report)
	}
}

// An attestation from a coordinator nobody predeclared proves only that
// somebody signed something.
func TestUnpredeclaredCoordinatorIsNotEvidence(t *testing.T) {
	policy := testPolicy()
	stranger := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x99}, ed25519.SeedSize))

	var trials []Trial
	for _, required := range policy.RequiredScenarios {
		trials = fillCell(trials, required, 4, OutcomeFailed, FailureHandshake, 0)
	}
	for index := range trials {
		observation, err := SignObservation(trials[index].Observation, stranger)
		if err != nil {
			t.Fatalf("attest: %v", err)
		}
		trials[index].Observation = observation
		trials[index] = resign(trials[index])
	}
	if _, err := Aggregate(policy, trials, ProbeUDP); err == nil {
		t.Fatal("a study attested by nobody the policy named produced a report")
	}
}

// One host answering to several operator names would satisfy the operator
// minimum by itself. The signing key is what gives that away.
func TestOneKeyUnderSeveralOperatorsIsExcluded(t *testing.T) {
	policy := testPolicy()
	target := policy.RequiredScenarios[0]

	var trials []Trial
	for _, operator := range []string{opA, opB, opC} {
		session := nextSession()
		for _, role := range []Role{RoleA, RoleB} {
			trial := rawTrial(target, session, role, operator, OutcomeDirect, FailureNone, 20)
			trial.Observation = attest(session, role, "one-host", "no", trial.Local.Family)
			// Every "operator" signs with the same key.
			signed, err := SignTrial(trial, endpointKeyFor("one-host", RoleA))
			if err != nil {
				t.Fatalf("sign: %v", err)
			}
			trials = append(trials, signed)
		}
	}
	for _, required := range policy.RequiredScenarios[1:] {
		trials = fillCell(trials, required, 4, OutcomeFailed, FailureHandshake, 0)
	}

	report, err := Aggregate(policy, trials, ProbeUDP)
	if err != nil {
		t.Fatalf("aggregate: %v", err)
	}
	if len(report.SharedEndpointKeys) != 1 {
		t.Fatalf("the shared key was not reported: %+v", report.SharedEndpointKeys)
	}
	for _, cell := range report.Cells {
		if cell.ScenarioKey == target.Key() {
			t.Fatalf("a cell built from one host under three names survived: %+v", cell)
		}
	}
	if report.Finding != FindingInsufficient {
		t.Fatalf("expected the study to fall short, got %q", report.Finding)
	}
}

// A measurement is what two endpoints agree happened. One endpoint's account
// of a session is an assertion, and an assertion nobody corroborated must not
// move a threshold.
func TestHalfAMeasurementIsNotEvidence(t *testing.T) {
	policy := testPolicy()
	target := policy.RequiredScenarios[0]

	var trials []Trial
	for index := 0; index < 4; index++ {
		pair := directPair(target, []string{opA, opB, opC}[index%3], uint64(100+index))
		if index == 0 {
			pair = pair[:1] // the peer never reported
		}
		trials = append(trials, pair...)
	}
	for _, required := range policy.RequiredScenarios[1:] {
		trials = fillCell(trials, required, 4, OutcomeFailed, FailureHandshake, 0)
	}

	report, err := Aggregate(policy, trials, ProbeUDP)
	if err != nil {
		t.Fatalf("aggregate: %v", err)
	}
	if report.IncompletePairs != 1 {
		t.Fatalf("an unpaired half was not reported: %+v", report)
	}
	for _, cell := range report.Cells {
		if cell.ScenarioKey == target.Key() && cell.Samples != 3 {
			t.Fatalf("an unpaired half was counted as a measurement: %+v", cell)
		}
	}
}

// Both halves have to say the same thing. Improving one half of a result now
// takes the other half's key as well, and the two keys are what the operator
// minimum is counting.
func TestContradictingHalvesAreDiscarded(t *testing.T) {
	policy := testPolicy()
	target := policy.RequiredScenarios[0]

	cases := map[string]func([]Trial) []Trial{
		"outcome": func(pair []Trial) []Trial {
			pair[1].Outcome = OutcomeRelayFallback
			pair[1].Failure = FailureHandshake
			pair[1].EstablishMillis = 0
			pair[1] = resign(pair[1])
			return pair
		},
		"commits": func(pair []Trial) []Trial {
			pair[1].PeerCommit = "3333333333333333333333333333333333333333"
			pair[1] = resign(pair[1])
			return pair
		},
		// Same discipline for the collector manifests: one half claiming its
		// peer ran a build the peer never named is a contradiction, not a
		// sample, because which implementation measured is part of what was
		// measured.
		"manifests": func(pair []Trial) []Trial {
			pair[1].PeerManifestDigest = testManifestDigest("collector-somebody-else")
			pair[1] = resign(pair[1])
			return pair
		},
		"one key twice": func(pair []Trial) []Trial {
			signed, err := SignTrial(pair[1], endpointKeyFor(pair[0].OperatorID, RoleA))
			if err != nil {
				panic(err)
			}
			return []Trial{pair[0], signed}
		},
		"both in one role": func(pair []Trial) []Trial {
			pair[1].Role = RoleA
			pair[1].Observation = attest(pair[1].SessionID, RoleA, pair[1].OperatorID, "no", pair[1].Local.Family)
			pair[1] = resign(pair[1])
			return pair
		},
	}
	for name, contradict := range cases {
		t.Run(name, func(t *testing.T) {
			var trials []Trial
			for index := 0; index < 4; index++ {
				pair := directPair(target, []string{opA, opB, opC}[index%3], uint64(100+index))
				if index == 0 {
					pair = contradict(pair)
				}
				trials = append(trials, pair...)
			}
			for _, required := range policy.RequiredScenarios[1:] {
				trials = fillCell(trials, required, 4, OutcomeFailed, FailureHandshake, 0)
			}
			report, err := Aggregate(policy, trials, ProbeUDP)
			if err != nil {
				t.Fatalf("aggregate: %v", err)
			}
			if report.IncompletePairs+report.UnverifiedTrials == 0 {
				t.Fatalf("contradicting halves were aggregated anyway: %+v", report)
			}
			for _, cell := range report.Cells {
				if cell.ScenarioKey == target.Key() && cell.Samples > 3 {
					t.Fatalf("a contradicted measurement was counted: %+v", cell)
				}
			}
		})
	}
}

// The pair identifier is derived from the session, so it cannot be chosen to
// glue together two halves that were never the same attempt.
func TestPairIdentifierMustBeDerivedFromItsSession(t *testing.T) {
	trial := directTrial(scenario(CarrierConsumerISP, ClassDesktop), opA, 100)
	other, err := PairID("some-other-session")
	if err != nil {
		t.Fatalf("pair: %v", err)
	}
	trial.PairID = other
	if err := trial.Validate(); err == nil {
		t.Fatal("a declared pair identifier was accepted")
	}
}

// Which trials survive the per-operator cap must not depend on submission
// order, or an operator chooses their own sample by choosing when to send.
func TestCapTruncatesTheSameSetWhateverTheOrder(t *testing.T) {
	policy := testPolicy()
	target := policy.RequiredScenarios[0]

	var trials []Trial
	for index := 0; index < 20; index++ {
		outcome, failure := OutcomeDirect, FailureNone
		if index%2 == 0 {
			outcome, failure = OutcomeFailed, FailureHandshake
		}
		trials = append(trials, measurement(target, opA, outcome, failure, map[bool]uint64{true: 0, false: 40}[index%2 == 0])...)
	}
	for _, required := range policy.RequiredScenarios {
		trials = fillCell(trials, required, 4, OutcomeFailed, FailureHandshake, 0)
	}

	forward, err := Aggregate(policy, trials, ProbeUDP)
	if err != nil {
		t.Fatalf("aggregate: %v", err)
	}
	reversed := make([]Trial, len(trials))
	for index, trial := range trials {
		reversed[len(trials)-1-index] = trial
	}
	backward, err := Aggregate(policy, reversed, ProbeUDP)
	if err != nil {
		t.Fatalf("aggregate reversed: %v", err)
	}
	for index, cell := range forward.Cells {
		mirror := backward.Cells[index]
		if cell.Samples != mirror.Samples || cell.DirectRate != mirror.DirectRate ||
			cell.DroppedOverCap != mirror.DroppedOverCap {
			t.Fatalf("the cap depended on arrival order: %+v vs %+v", cell, mirror)
		}
	}
	if forward.Finding != backward.Finding {
		t.Fatalf("the finding depended on arrival order: %q vs %q", forward.Finding, backward.Finding)
	}
}

// The two halves describe different situations by definition, and that is the
// measurement rather than a disagreement. A home node against a datacenter
// Agent is the case the study exists to answer; a model that required both
// ends to declare the same labels could not express it at all.
func TestAsymmetricPairsAreMeasurable(t *testing.T) {
	policy := testPolicy()
	target := Scenario{
		Initiator: mapped(CarrierCarrierGrade, ClassEdgeRISC),
		Responder: publicEndpoint(),
	}
	if !target.Asymmetric() {
		t.Fatal("the fixture is not actually asymmetric")
	}

	var trials []Trial
	for index := 0; index < 4; index++ {
		trials = append(trials, directPair(target, []string{opA, opB, opC}[index%3], uint64(100+index))...)
	}
	for _, required := range policy.RequiredScenarios {
		trials = fillCell(trials, required, 4, OutcomeFailed, FailureHandshake, 0)
	}

	report, err := Aggregate(policy, trials, ProbeUDP)
	if err != nil {
		t.Fatalf("aggregate: %v", err)
	}
	if report.IncompletePairs != 0 {
		t.Fatalf("an asymmetric pair was discarded: %+v", report)
	}
	var cell CellReport
	for _, candidate := range report.Cells {
		if candidate.ScenarioKey == target.Key() {
			cell = candidate
		}
	}
	if cell.Samples != 4 {
		t.Fatalf("the asymmetric cell was not measured: %+v", cell)
	}
	// The joint label is derived from the two ends rather than declared by
	// either, and neither end could have observed it.
	if cell.PairReachability != "one-public" {
		t.Fatalf("unexpected derived reachability: %q", cell.PairReachability)
	}
	if cell.Scenario.Initiator.EndpointClass != ClassEdgeRISC ||
		cell.Scenario.Responder.EndpointClass != ClassServer {
		t.Fatalf("the cell lost which side was which: %+v", cell.Scenario)
	}
}

// Which side opened the session is kept. A phone calling a server and a server
// calling a phone are two measurements: whether a mapping exists when the first
// packet arrives depends on who sent it.
func TestInitiatingDirectionIsPartOfTheCell(t *testing.T) {
	forward := Scenario{Initiator: mapped(CarrierMobile, ClassMobile), Responder: publicEndpoint()}
	backward := Scenario{Initiator: publicEndpoint(), Responder: mapped(CarrierMobile, ClassMobile)}
	if forward.Key() == backward.Key() {
		t.Fatal("the initiating direction was normalised away")
	}
	if forward.PairReachability() != backward.PairReachability() {
		t.Fatal("the derived joint label depended on direction")
	}
}

// The phase booleans join at the pair the way each phase works: a hold was
// attempted by the pair only when both halves ran it and completed only when
// both survived the window, while reconnect -- initiator-only by design -- is
// the OR across halves. Halves that disagree about completion are describing
// per-phase outcomes (one side's keepalives die first), not contradicting each
// other, so the pair is kept and joined rather than dropped.
func TestPhaseBooleansJoinAcrossHalves(t *testing.T) {
	policy := testPolicy()
	target := policy.RequiredScenarios[0]

	var trials []Trial
	makePair := func(operator string, shapeA, shapeB func(*Trial)) {
		pair := directPair(target, operator, 100)
		for index := range pair {
			pair[index] = switchProbe(pair[index], ProbeADNL)
		}
		shapeA(&pair[0])
		pair[0] = resign(pair[0])
		shapeB(&pair[1])
		pair[1] = resign(pair[1])
		trials = append(trials, pair...)
	}
	held := func(completed bool, span uint64) func(*Trial) {
		return func(trial *Trial) {
			trial.HoldAttempted, trial.HoldCompleted = true, completed
			trial.SurvivalSeconds = span
		}
	}
	nothing := func(*Trial) {}
	heldAndReconnected := func(trial *Trial) {
		held(true, 60)(trial)
		trial.ReconnectAttempted, trial.ReconnectSucceeded = true, true
		trial.ReconnectMillis = 40
	}

	// One pair whose halves disagree about completion, one whose responder
	// never held, two that held cleanly. Only the first initiator reconnected.
	makePair(opA, heldAndReconnected, held(false, 30))
	makePair(opB, held(true, 60), nothing)
	makePair(opC, held(true, 60), held(true, 45))
	makePair(opA, held(true, 60), held(true, 50))
	for _, required := range policy.RequiredScenarios[1:] {
		trials = append(trials, adnlStudy(fillCell(nil, required, 4, OutcomeFailed, FailureHandshake, 0))...)
	}

	report, err := Aggregate(policy, trials, ProbeADNL)
	if err != nil {
		t.Fatalf("aggregate: %v", err)
	}
	// Disagreeing about completion is a measurement, never a contradiction.
	if report.IncompletePairs != 0 {
		t.Fatalf("a completion disagreement was dropped as a contradiction: %+v", report)
	}
	var cell CellReport
	for _, candidate := range report.Cells {
		if candidate.ScenarioKey == target.Key() {
			cell = candidate
		}
	}
	// The one-sided hold does not count as attempted; the disagreeing pair
	// counts as attempted and not completed.
	if cell.HoldAttemptedSamples != 3 {
		t.Fatalf("expected three hold-attempted pairs, got %d", cell.HoldAttemptedSamples)
	}
	// Operator means: opA completed one of two attempted, opC one of one, opB
	// attempted nothing and contributes no invented rate.
	if cell.DirectSurvivalRate == nil || *cell.DirectSurvivalRate != 0.75 {
		t.Fatalf("unexpected direct survival rate: %+v", cell.DirectSurvivalRate)
	}
	// The initiator's reconnect speaks for the pair.
	if cell.ReconnectAttemptedSamples != 1 {
		t.Fatalf("expected one reconnect-attempted pair, got %d", cell.ReconnectAttemptedSamples)
	}
	if cell.ReconnectSuccessRate == nil || *cell.ReconnectSuccessRate != 1 {
		t.Fatalf("unexpected reconnect success rate: %+v", cell.ReconnectSuccessRate)
	}
}

func reasonNaming(reasons []string, fragment string) bool {
	for _, reason := range reasons {
		if strings.Contains(reason, fragment) {
			return true
		}
	}
	return false
}

// A study whose sessions all establish and then die passes every
// establishment threshold and must still not freeze direct-first: the
// survival gate is what the route decision now reads.
func TestDyingSessionsBlockDirectFirst(t *testing.T) {
	policy := testPolicy()
	var trials []Trial
	for _, required := range policy.RequiredScenarios {
		trials = fillCell(trials, required, 4, OutcomeFailed, FailureHandshake, 0)
	}
	for index := range trials {
		trial := switchProbe(trials[index], ProbeADNL)
		// Both halves ran the hold and neither survived the window. The span
		// each did survive stays recorded: attempted-and-not-completed, which
		// is exactly what the booleans exist to say.
		trial.HoldAttempted = true
		trial.SurvivalSeconds = 10
		if trial.Role == RoleA {
			trial.ReconnectAttempted, trial.ReconnectSucceeded = true, true
			trial.ReconnectMillis = 40
		}
		trials[index] = resign(trial)
	}
	report, err := Aggregate(policy, trials, ProbeADNL)
	if err != nil {
		t.Fatalf("aggregate: %v", err)
	}
	if report.Finding == FindingDirectFirst {
		t.Fatalf("dying sessions froze direct-first: %+v", report.Reasons)
	}
	// The tunnel was never exercised, so nothing supports tunnel-first either:
	// the honest answer is no finding, with the survival failure named.
	if report.Finding != FindingInsufficient {
		t.Fatalf("expected no finding, got %q (reasons %v)", report.Finding, report.Reasons)
	}
	if !reasonNaming(report.Reasons, "did not survive the hold window") {
		t.Fatalf("the survival failure was not named: %v", report.Reasons)
	}
	// The cell shows why: every pair attempted, none completed.
	for _, cell := range report.Cells {
		if cell.HoldAttemptedSamples != 4 || cell.DirectSurvivalRate == nil || *cell.DirectSurvivalRate != 0 {
			t.Fatalf("the cell does not show the failed gate: %+v", cell)
		}
	}
}

// Reconnect failures in a cell that exercises a mobility event disqualify
// direct-first there, whatever the establishment and survival rates say.
func TestFailedReconnectsBlockDirectFirst(t *testing.T) {
	policy := testPolicy()
	var trials []Trial
	for _, required := range policy.RequiredScenarios {
		trials = fillCell(trials, required, 4, OutcomeFailed, FailureHandshake, 0)
	}
	for index := range trials {
		trial := switchProbe(trials[index], ProbeADNL)
		trial.HoldAttempted, trial.HoldCompleted = true, true
		trial.SurvivalSeconds = 60
		if trial.Role == RoleA {
			trial.ReconnectAttempted = true
			// Every reconnect in the mobility cell ran and failed; elsewhere
			// they succeeded.
			if trial.Local.Mobility == MobilityStationary {
				trial.ReconnectSucceeded = true
				trial.ReconnectMillis = 40
			}
		}
		trials[index] = resign(trial)
	}
	report, err := Aggregate(policy, trials, ProbeADNL)
	if err != nil {
		t.Fatalf("aggregate: %v", err)
	}
	if report.Finding == FindingDirectFirst {
		t.Fatalf("failed reconnects froze direct-first: %+v", report.Reasons)
	}
	if report.Finding != FindingHybrid {
		t.Fatalf("expected the mobility cell alone to disqualify, got %q (reasons %v)", report.Finding, report.Reasons)
	}
	if !reasonNaming(report.Reasons, "reconnects did not succeed") {
		t.Fatalf("the reconnect failure was not named: %v", report.Reasons)
	}
}

// Tunnel-first is a claim that tunneled sessions hold up. A study where every
// tunneled hold dies establishes tunnels and still must not freeze
// tunnel-first.
func TestTunnelSurvivalBlocksTunnelFirst(t *testing.T) {
	policy := testPolicy()
	var trials []Trial
	for _, required := range policy.RequiredScenarios {
		trials = fillCell(trials, required, 0, OutcomeProxyFallback, FailureHandshake, 4)
	}
	for index := range trials {
		trial := switchProbe(trials[index], ProbeADNL)
		// The hold ran over every tunneled session and none survived.
		trial.TunnelHoldAttempted = true
		trials[index] = resign(trial)
	}
	report, err := Aggregate(policy, trials, ProbeADNL)
	if err != nil {
		t.Fatalf("aggregate: %v", err)
	}
	if report.Finding != FindingRelayRequired {
		t.Fatalf("dying tunnels yielded %q (reasons %v)", report.Finding, report.Reasons)
	}
	if !reasonNaming(report.Reasons, "tunneled sessions did not survive") {
		t.Fatalf("the tunnel survival failure was not named: %v", report.Reasons)
	}
	for _, cell := range report.Cells {
		if cell.TunnelHoldAttemptedSamples != 4 || cell.TunnelSurvivalRate == nil || *cell.TunnelSurvivalRate != 0 {
			t.Fatalf("the cell does not show the failed gate: %+v", cell)
		}
	}
}

// A cell that cannot show the predeclared minimum of hold-attempted samples
// has an unmeasured survival rate, and an unmeasured gate the finding depends
// on is missing evidence -- named, never silently passed or failed.
func TestUnderSampledSurvivalGateRefusesAFinding(t *testing.T) {
	policy := testPolicy()
	target := policy.RequiredScenarios[0]
	var trials []Trial
	for index, required := range policy.RequiredScenarios {
		cell := adnlStudy(fillCell(nil, required, 4, OutcomeFailed, FailureHandshake, 0))
		if index == 0 {
			// Establishment evidence stays complete, but only the first pair
			// (halves 0 and 1) ran the hold: one attempted sample, below the
			// predeclared minimum of two.
			for half := 2; half < len(cell); half++ {
				trial := cell[half]
				trial.HoldAttempted, trial.HoldCompleted = false, false
				trial.SurvivalSeconds = 0
				trial.ReconnectAttempted, trial.ReconnectSucceeded = false, false
				trial.ReconnectMillis = 0
				cell[half] = resign(trial)
			}
		}
		trials = append(trials, cell...)
	}
	report, err := Aggregate(policy, trials, ProbeADNL)
	if err != nil {
		t.Fatalf("aggregate: %v", err)
	}
	if report.Finding != FindingInsufficient {
		t.Fatalf("an under-sampled survival gate produced %q", report.Finding)
	}
	if !reasonNaming(report.Reasons, "direct survival gate is under-sampled: "+target.Key()) {
		t.Fatalf("the missing gate was not named: %v", report.Reasons)
	}
	if len(report.Missing) != 1 || report.Missing[0] != target.Key() {
		t.Fatalf("the under-sampled cell was not reported missing: %v", report.Missing)
	}
}

// The same refusal for the reconnect gate: a mobility cell where no reconnect
// was ever attempted has an unmeasured recovery story, not a passing one.
func TestUnderSampledReconnectGateRefusesAFinding(t *testing.T) {
	policy := testPolicy()
	mobile := mobileScenario()
	var trials []Trial
	for _, required := range policy.RequiredScenarios {
		trials = fillCell(trials, required, 4, OutcomeFailed, FailureHandshake, 0)
	}
	for index := range trials {
		trial := switchProbe(trials[index], ProbeADNL)
		trial.HoldAttempted, trial.HoldCompleted = true, true
		trial.SurvivalSeconds = 60
		// Reconnects ran only outside the mobility cell.
		if trial.Role == RoleA && trial.Local.Mobility == MobilityStationary {
			trial.ReconnectAttempted, trial.ReconnectSucceeded = true, true
			trial.ReconnectMillis = 40
		}
		trials[index] = resign(trial)
	}
	report, err := Aggregate(policy, trials, ProbeADNL)
	if err != nil {
		t.Fatalf("aggregate: %v", err)
	}
	if report.Finding != FindingInsufficient {
		t.Fatalf("an unmeasured mobility reconnect produced %q", report.Finding)
	}
	if !reasonNaming(report.Reasons, "reconnect gate is under-sampled in a mobility cell: "+mobile.Key()) {
		t.Fatalf("the missing gate was not named: %v", report.Reasons)
	}
}

// An attestation names the endpoint it is about. A bystander who copied a
// published one cannot wear it, so they cannot add a third half to somebody
// else's pair and have the pair discarded as malformed.
func TestCopiedAttestationCannotBeWorn(t *testing.T) {
	pair := directPair(scenario(CarrierConsumerISP, ClassDesktop), opA, 100)
	stranger := pair[0]
	// A different key, everything else copied verbatim.
	signed, err := SignTrial(stranger, endpointKeyFor("bystander", RoleA))
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	if err := VerifyTrial(testPolicy(), signed); err == nil {
		t.Fatal("a copied attestation was worn by another key")
	}
	// And the attestation cannot be moved to another probe either.
	moved := pair[0]
	moved.Probe = ProbeADNL
	if err := VerifyTrial(testPolicy(), resign(moved)); err == nil {
		t.Fatal("an attestation from one probe stood in for another")
	}
}

// Session survival needs both halves. A zero from one side means "not
// measured", and reporting the other side's number as the pair's would
// describe one endpoint's session as if it were the pair's.
func TestSurvivalNeedsBothHalves(t *testing.T) {
	policy := testPolicy()
	target := policy.RequiredScenarios[0]

	var trials []Trial
	for index := 0; index < 4; index++ {
		pair := directPair(target, []string{opA, opB, opC}[index%3], uint64(100+index))
		pair[0].SurvivalSeconds = 600
		pair[0] = resign(pair[0])
		if index == 0 {
			pair[1].SurvivalSeconds = 300
			pair[1] = resign(pair[1])
		}
		trials = append(trials, pair...)
	}
	for _, required := range policy.RequiredScenarios[1:] {
		trials = fillCell(trials, required, 4, OutcomeFailed, FailureHandshake, 0)
	}

	report, err := Aggregate(policy, trials, ProbeUDP)
	if err != nil {
		t.Fatalf("aggregate: %v", err)
	}
	for _, cell := range report.Cells {
		if cell.ScenarioKey != target.Key() {
			continue
		}
		if cell.SurvivalSamples != 1 {
			t.Fatalf("one-sided survival was counted: %+v", cell)
		}
		if cell.SurvivalP50 != 300 {
			t.Fatalf("survival did not take the shorter half: %+v", cell)
		}
	}
}

// resignObservation re-signs a coordinator observation a test mutated, so the
// tampered field is what the coordinator attests to rather than a broken
// signature the verifier would reject for a different reason.
func resignObservation(observation Observation) Observation {
	signed, err := SignObservation(observation, testCoordinatorKey())
	if err != nil {
		panic(err)
	}
	return signed
}

// The address family a trial counts toward is signed by the coordinator in its
// observed address, not by the endpoint. A trial that declares one family while
// the coordinator observed another is the endpoint attesting to a stratum the
// evidence never saw, and it must not be counted.
func TestDeclaredFamilyMustMatchSignedObservation(t *testing.T) {
	policy := testPolicy()
	pair := directPair(scenario(CarrierConsumerISP, ClassDesktop), opA, 100)

	// The honest IPv4 half verifies against its IPv4 observation.
	if err := VerifyTrial(policy, pair[0]); err != nil {
		t.Fatalf("an honest trial was rejected: %v", err)
	}

	// The endpoint keeps its IPv4 declaration but the coordinator signed an
	// IPv6 observation: the two disagree about which cell this is.
	tampered := pair[0]
	tampered.Observation.Observed = "[2001:db8::7]:41234"
	tampered.Observation = resignObservation(tampered.Observation)
	tampered = resign(tampered)
	if err := VerifyTrial(policy, tampered); err == nil {
		t.Fatal("a family that contradicts the signed observed address was accepted")
	}

	// And it is dropped in aggregation rather than counted.
	var trials []Trial
	for _, required := range policy.RequiredScenarios {
		trials = fillCell(trials, required, 4, OutcomeFailed, FailureHandshake, 0)
	}
	trials[0].Observation.Observed = "[2001:db8::7]:41234"
	trials[0].Observation = resignObservation(trials[0].Observation)
	trials[0] = resign(trials[0])
	report, err := Aggregate(policy, trials, ProbeUDP)
	if err != nil {
		t.Fatalf("aggregate: %v", err)
	}
	if report.UnverifiedTrials != 1 {
		t.Fatalf("a contradicting family was counted: %+v", report)
	}
}

// The coordinator's signed peer bit is cross-checked against the other half's
// self-declared reachability. A half that declares public while its peer's
// coordinator saw it treat that peer as non-public is a pair the signed
// evidence contradicts, and it is dropped as inconsistent rather than counted.
func TestPeerObservationMustMatchDeclaredReachability(t *testing.T) {
	policy := testPolicy()
	// Initiator behind NAT, Responder publicly addressable.
	target := policy.RequiredScenarios[0]

	var trials []Trial
	for index := 0; index < 4; index++ {
		pair := directPair(target, []string{opA, opB, opC}[index%3], uint64(100+index))
		if index == 0 {
			// RoleA's coordinator honestly saw a public peer (the Responder);
			// flip it to "no" so the signed observation contradicts the
			// Responder's own declaration of being public.
			pair[0].Observation.PeerPublic = "no"
			pair[0].Observation = resignObservation(pair[0].Observation)
			pair[0] = resign(pair[0])
		}
		trials = append(trials, pair...)
	}
	for _, required := range policy.RequiredScenarios[1:] {
		trials = fillCell(trials, required, 4, OutcomeFailed, FailureHandshake, 0)
	}

	report, err := Aggregate(policy, trials, ProbeUDP)
	if err != nil {
		t.Fatalf("aggregate: %v", err)
	}
	if report.UnverifiedTrials != 0 {
		t.Fatalf("both halves should verify individually: %+v", report)
	}
	if report.IncompletePairs != 1 {
		t.Fatalf("a contradicting peer observation was not dropped: %+v", report)
	}
	for _, cell := range report.Cells {
		if cell.ScenarioKey == target.Key() && cell.Samples != 3 {
			t.Fatalf("an inconsistent pair was counted: %+v", cell)
		}
	}
}

// A second predeclared coordinator, so a trial can carry reflections from two
// distinct coordinators -- the minimum the mapping class can be derived from.
func secondCoordinatorKey() ed25519.PrivateKey {
	return ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x22}, ed25519.SeedSize))
}

func secondCoordinatorID() string {
	public, ok := secondCoordinatorKey().Public().(ed25519.PublicKey)
	if !ok {
		panic("unexpected key type")
	}
	identifier, err := CoordinatorID(public)
	if err != nil {
		panic(err)
	}
	return identifier
}

// strangerCoordinatorKey signs a self-consistent reflection from a coordinator
// no policy predeclared.
func strangerCoordinatorKey() ed25519.PrivateKey {
	return ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x33}, ed25519.SeedSize))
}

// twoCoordinatorPolicy predeclares both test coordinators, which is all
// VerifyTrial reads from a policy.
func twoCoordinatorPolicy() Policy {
	return Policy{Coordinators: []string{testCoordinatorID(), secondCoordinatorID()}}
}

// endpointIndependentLocal is a mapped endpoint that declares an
// endpoint-independent mapping, the class an honest set of equal reflections
// derives.
func endpointIndependentLocal() EndpointStratum {
	local := mapped(CarrierConsumerISP, ClassDesktop)
	local.NATBehavior = NATEndpointIndependent
	return local
}

// signBind signs one coordinator's reflection of an endpoint's external
// address, for the same key the endpoint signs its trial with.
func signBind(session string, role Role, operator string, coordinatorKey ed25519.PrivateKey, observed string) BindObservation {
	public, ok := endpointKeyFor(operator, role).Public().(ed25519.PublicKey)
	if !ok {
		panic("unexpected key type")
	}
	observation, err := SignBindObservation(BindObservation{
		SessionID:            session,
		Role:                 string(role),
		EndpointPublicKeyHex: hex.EncodeToString(public),
		Probe:                string(ProbeUDP),
		Observed:             observed,
		AtUnix:               1_800_000_000,
	}, coordinatorKey)
	if err != nil {
		panic(err)
	}
	return observation
}

// sameAddressBinds is two coordinators reflecting one address: the signed
// evidence of an endpoint-independent mapping.
func sameAddressBinds(session string, role Role, operator string, family AddressFamily) []BindObservation {
	return []BindObservation{
		signBind(session, role, operator, testCoordinatorKey(), observedFor(family)),
		signBind(session, role, operator, secondCoordinatorKey(), observedFor(family)),
	}
}

// bindHalf is one signed measurement half whose bind observations are built by
// the given binder over the half's own session.
func bindHalf(local EndpointStratum, binder func(session string) []BindObservation) Trial {
	session := nextSession()
	scene := Scenario{Initiator: local, Responder: publicEndpoint()}
	trial := rawTrial(scene, session, RoleA, opA, OutcomeDirect, FailureNone, 100)
	// The responder is public, so the coordinator's peer observation is "yes".
	trial.Observation = attest(session, RoleA, opA, "yes", local.Family)
	trial.BindObservations = binder(session)
	return resign(trial)
}

// The NAT mapping class a trial declares is now checked against the
// coordinator-signed reflections it carries. A declaration the signed evidence
// refutes -- endpoint-independent against reflections that differ, or a
// destination-dependent class against reflections that agree -- is rejected;
// one the evidence supports is accepted.
func TestDeclaredMappingMustMatchBindObservations(t *testing.T) {
	policy := twoCoordinatorPolicy()

	consistent := func(session string) []BindObservation {
		return sameAddressBinds(session, RoleA, opA, FamilyIPv4)
	}
	if err := VerifyTrial(policy, bindHalf(endpointIndependentLocal(), consistent)); err != nil {
		t.Fatalf("an endpoint-independent declaration matching equal reflections was rejected: %v", err)
	}

	// Two coordinators reflected different addresses: the mapping depends on the
	// destination, which refutes the endpoint-independent declaration.
	differing := func(session string) []BindObservation {
		return []BindObservation{
			signBind(session, RoleA, opA, testCoordinatorKey(), "203.0.113.7:41234"),
			signBind(session, RoleA, opA, secondCoordinatorKey(), "198.51.100.9:5000"),
		}
	}
	if err := VerifyTrial(policy, bindHalf(endpointIndependentLocal(), differing)); err == nil {
		t.Fatal("endpoint-independent survived reflections that differ")
	}

	// The reverse contradiction: a destination-dependent declaration against
	// reflections that agree.
	dependent := mapped(CarrierConsumerISP, ClassDesktop) // NATAddressPortDependent
	agreeing := func(session string) []BindObservation {
		return sameAddressBinds(session, RoleA, opA, FamilyIPv4)
	}
	if err := VerifyTrial(policy, bindHalf(dependent, agreeing)); err == nil {
		t.Fatal("a destination-dependent declaration survived reflections that agree")
	}

	// Fewer than two distinct coordinators cannot separate the classes, so the
	// mapping is undetermined and the declaration stands unchecked. This is the
	// documented residual case, not a bug.
	single := func(session string) []BindObservation {
		return []BindObservation{signBind(session, RoleA, opA, testCoordinatorKey(), "203.0.113.7:41234")}
	}
	if err := VerifyTrial(policy, bindHalf(endpointIndependentLocal(), single)); err != nil {
		t.Fatalf("a single reflection should leave the mapping undetermined, not refute it: %v", err)
	}
}

// A reflection from a coordinator the policy did not predeclare proves only that
// somebody signed something, exactly as for the pair observation.
func TestBindObservationFromUndeclaredCoordinatorIsRejected(t *testing.T) {
	policy := twoCoordinatorPolicy()
	fromStranger := func(session string) []BindObservation {
		return []BindObservation{
			signBind(session, RoleA, opA, testCoordinatorKey(), observedFor(FamilyIPv4)),
			signBind(session, RoleA, opA, strangerCoordinatorKey(), observedFor(FamilyIPv4)),
		}
	}
	if err := VerifyTrial(policy, bindHalf(endpointIndependentLocal(), fromStranger)); err == nil {
		t.Fatal("a bind observation from an unpredeclared coordinator was accepted")
	}
}

// A reflection whose coordinator signature does not verify attests nothing, even
// though the endpoint signature over the trial that carries it is valid.
func TestForgedBindObservationSignatureIsRejected(t *testing.T) {
	policy := twoCoordinatorPolicy()
	forged := func(session string) []BindObservation {
		binds := sameAddressBinds(session, RoleA, opA, FamilyIPv4)
		signature, err := hex.DecodeString(binds[0].SignatureHex)
		if err != nil || len(signature) == 0 {
			t.Fatalf("decode bind signature: %v", err)
		}
		signature[0] ^= 0xff
		binds[0].SignatureHex = hex.EncodeToString(signature)
		return binds
	}
	trial := bindHalf(endpointIndependentLocal(), forged)
	// The endpoint signature still verifies: the forgery is in the reflection it
	// commits to, not in the trial signature.
	if err := VerifyBindObservation(trial.BindObservations[0]); err == nil {
		t.Fatal("the fixture's bind signature was not actually broken")
	}
	if err := VerifyTrial(policy, trial); err == nil {
		t.Fatal("a trial carrying a forged reflection was accepted")
	}
}

// An honest study whose declared mappings agree with the signed reflections
// still aggregates. The cross-check rejects contradictions, not consistent
// evidence, and a swapped set breaks the endpoint signature.
func TestConsistentBindEvidenceAggregates(t *testing.T) {
	policy := testPolicy()
	policy.Coordinators = append(policy.Coordinators, secondCoordinatorID())

	var trials []Trial
	for _, required := range policy.RequiredScenarios {
		trials = fillCell(trials, required, 4, OutcomeFailed, FailureHandshake, 0)
	}

	// An extra cell whose two halves both declare an endpoint-independent
	// mapping and carry the equal reflections that show it.
	initiator := endpointIndependentLocal()
	responder := endpointIndependentLocal()
	responder.Carrier = CarrierMobile
	responder.EndpointClass = ClassMobile
	extra := Scenario{Initiator: initiator, Responder: responder}
	for index := 0; index < 4; index++ {
		operator := []string{opA, opB, opC}[index%3]
		session := nextSession()
		a := rawTrial(extra, session, RoleA, operator, OutcomeDirect, FailureNone, uint64(100+index))
		a.Observation = attest(session, RoleA, operator, "no", initiator.Family)
		a.BindObservations = sameAddressBinds(session, RoleA, operator, initiator.Family)
		b := rawTrial(extra, session, RoleB, operator, OutcomeDirect, FailureNone, uint64(100+index))
		b.Observation = attest(session, RoleB, operator, "no", responder.Family)
		b.BindObservations = sameAddressBinds(session, RoleB, operator, responder.Family)
		trials = append(trials, resign(a), resign(b))
	}

	report, err := Aggregate(policy, trials, ProbeUDP)
	if err != nil {
		t.Fatalf("aggregate: %v", err)
	}
	if report.UnverifiedTrials != 0 {
		t.Fatalf("consistent bind evidence was dropped as unverified: %+v", report)
	}
	if report.IncompletePairs != 0 {
		t.Fatalf("a consistent pair was discarded: %+v", report)
	}
	found := false
	for _, cell := range report.Cells {
		if cell.ScenarioKey == extra.Key() {
			found = true
			if cell.Samples != 4 {
				t.Fatalf("the bind-evidenced cell was miscounted: %+v", cell)
			}
		}
	}
	if !found {
		t.Fatal("the bind-evidenced cell was not aggregated")
	}

	// A reflection set swapped after signing breaks the endpoint signature.
	tampered := resign(func() Trial {
		session := nextSession()
		half := rawTrial(extra, session, RoleA, opA, OutcomeDirect, FailureNone, 100)
		half.Observation = attest(session, RoleA, opA, "no", initiator.Family)
		half.BindObservations = sameAddressBinds(session, RoleA, opA, initiator.Family)
		return half
	}())
	tampered.BindObservations = differingReflections(tampered)
	if err := VerifyTrial(policy, tampered); err == nil {
		t.Fatal("swapping the reflections after signing left the trial verifiable")
	}
}

// differingReflections rewrites a half's reflections to disagree, without
// re-signing the trial, so the swap is caught by the endpoint signature rather
// than by the mapping check.
func differingReflections(trial Trial) []BindObservation {
	return []BindObservation{
		signBind(trial.SessionID, RoleA, opA, testCoordinatorKey(), "203.0.113.7:41234"),
		signBind(trial.SessionID, RoleA, opA, secondCoordinatorKey(), "198.51.100.9:5000"),
	}
}

// An honest study whose declarations agree with the coordinator-signed evidence
// still aggregates to a decision. The cross-checks reject contradictions, not
// consistent measurements.
func TestConsistentEvidenceStillDecides(t *testing.T) {
	policy := testPolicy()
	var trials []Trial
	for _, required := range policy.RequiredScenarios {
		trials = fillCell(trials, required, 4, OutcomeDirect, FailureNone, 0)
	}
	trials = adnlStudy(trials)
	report, err := Aggregate(policy, trials, ProbeADNL)
	if err != nil {
		t.Fatalf("aggregate: %v", err)
	}
	if report.UnverifiedTrials != 0 || report.IncompletePairs != 0 {
		t.Fatalf("consistent evidence was dropped: %+v", report)
	}
	if report.Finding != FindingDirectFirst {
		t.Fatalf("an honest direct study did not decide direct-first: %q", report.Finding)
	}
	if !report.SupportsRouteDecision() {
		t.Fatal("a consistent ADNL study did not support a route decision")
	}
}

// signFilter signs one coordinator's receipt that an endpoint demonstrably
// received a cold-source probe, for the same key the endpoint signs its trial
// with.
func signFilter(session string, role Role, operator string, coordinatorKey ed25519.PrivateKey,
	source FilterSourceKind, observed string) FilteringObservation {
	public, ok := endpointKeyFor(operator, role).Public().(ed25519.PublicKey)
	if !ok {
		panic("unexpected key type")
	}
	observation, err := SignFilteringObservation(FilteringObservation{
		SessionID:            session,
		Role:                 string(role),
		EndpointPublicKeyHex: hex.EncodeToString(public),
		Probe:                string(ProbeUDP),
		Observed:             observed,
		Source:               source,
		AtUnix:               1_800_000_000,
	}, coordinatorKey)
	if err != nil {
		panic(err)
	}
	return observation
}

// filterHalf is one signed measurement half whose filtering observations are
// built by the given builder over the half's own session.
func filterHalf(builder func(session string) []FilteringObservation) Trial {
	session := nextSession()
	local := endpointIndependentLocal()
	scene := Scenario{Initiator: local, Responder: publicEndpoint()}
	trial := rawTrial(scene, session, RoleA, opA, OutcomeDirect, FailureNone, 100)
	trial.Observation = attest(session, RoleA, opA, "yes", local.Family)
	trial.FilteringObservations = builder(session)
	return resign(trial)
}

// A filtering observation is signed and verified exactly like the other
// coordinator attestations, and a tampered one attests nothing.
func TestFilteringObservationSignatureVerifies(t *testing.T) {
	observation := signFilter(nextSession(), RoleA, opA, testCoordinatorKey(),
		FilterSourceOtherPort, "203.0.113.7:41234")
	if err := VerifyFilteringObservation(observation); err != nil {
		t.Fatalf("a freshly signed observation did not verify: %v", err)
	}
	tampered := observation
	signature, err := hex.DecodeString(tampered.SignatureHex)
	if err != nil || len(signature) == 0 {
		t.Fatalf("decode signature: %v", err)
	}
	signature[0] ^= 0xff
	tampered.SignatureHex = hex.EncodeToString(signature)
	if err := VerifyFilteringObservation(tampered); err == nil {
		t.Fatal("a forged filtering signature verified")
	}
	wrongSource := observation
	wrongSource.Source = "somewhere-warm"
	if err := VerifyFilteringObservation(wrongSource); err == nil {
		t.Fatal("an unknown source kind verified")
	}
	// The three observation schemas share a domain and are separated by their
	// schema string, so a bind signature cannot be worn as a filtering one.
	bind := signBind(observation.SessionID, RoleA, opA, testCoordinatorKey(), observation.Observed)
	crossed := observation
	crossed.SignatureHex = bind.SignatureHex
	if err := VerifyFilteringObservation(crossed); err == nil {
		t.Fatal("a bind signature was worn as a filtering observation")
	}
}

// The derived filtering class comes from receipts and from nothing else. A
// receipt can only loosen the class -- it proves a source was admitted -- and
// silence proves nothing, so the strict class is never derived and an empty
// set is undetermined.
func TestDeriveFilteringIsEvidenceOnly(t *testing.T) {
	session := nextSession()
	port := signFilter(session, RoleA, opA, testCoordinatorKey(),
		FilterSourceOtherPort, "203.0.113.7:41234")
	address := signFilter(session, RoleA, opA, secondCoordinatorKey(),
		FilterSourceOtherAddress, "203.0.113.7:41234")
	if got := DeriveFiltering(nil); got != FilteringUndetermined {
		t.Fatalf("no receipts derived %q", got)
	}
	if got := DeriveFiltering([]FilteringObservation{port}); got != FilteringAddressDependent {
		t.Fatalf("a cold-port receipt derived %q", got)
	}
	if got := DeriveFiltering([]FilteringObservation{port, address}); got != FilteringEndpointIndependent {
		t.Fatalf("a cold-address receipt derived %q", got)
	}
	if got := DeriveFiltering([]FilteringObservation{address}); got != FilteringEndpointIndependent {
		t.Fatalf("a cold-address receipt alone derived %q", got)
	}
}

// A trial's filtering receipts are held to the trial's own evidentiary
// standard: each must verify, come from a predeclared coordinator, and attest
// to this endpoint, probe, session, and role.
func TestTrialFilteringReceiptsAreVerified(t *testing.T) {
	policy := twoCoordinatorPolicy()

	honest := func(session string) []FilteringObservation {
		return []FilteringObservation{
			signFilter(session, RoleA, opA, testCoordinatorKey(), FilterSourceOtherPort, "203.0.113.7:41234"),
			signFilter(session, RoleA, opA, secondCoordinatorKey(), FilterSourceOtherAddress, "203.0.113.7:41234"),
		}
	}
	if err := VerifyTrial(policy, filterHalf(honest)); err != nil {
		t.Fatalf("honest filtering receipts were rejected: %v", err)
	}

	forged := func(session string) []FilteringObservation {
		receipts := honest(session)
		signature, err := hex.DecodeString(receipts[0].SignatureHex)
		if err != nil || len(signature) == 0 {
			t.Fatalf("decode signature: %v", err)
		}
		signature[0] ^= 0xff
		receipts[0].SignatureHex = hex.EncodeToString(signature)
		return receipts
	}
	if err := VerifyTrial(policy, filterHalf(forged)); err == nil {
		t.Fatal("a forged filtering receipt was accepted")
	}

	stranger := func(session string) []FilteringObservation {
		return []FilteringObservation{
			signFilter(session, RoleA, opA, strangerCoordinatorKey(), FilterSourceOtherPort, "203.0.113.7:41234"),
		}
	}
	if err := VerifyTrial(policy, filterHalf(stranger)); err == nil {
		t.Fatal("a filtering receipt from an unpredeclared coordinator was accepted")
	}

	foreignSession := func(string) []FilteringObservation {
		return []FilteringObservation{
			signFilter(nextSession(), RoleA, opA, testCoordinatorKey(), FilterSourceOtherPort, "203.0.113.7:41234"),
		}
	}
	if err := VerifyTrial(policy, filterHalf(foreignSession)); err == nil {
		t.Fatal("a filtering receipt for another session was accepted")
	}

	foreignParty := func(session string) []FilteringObservation {
		return []FilteringObservation{
			signFilter(session, RoleA, opB, testCoordinatorKey(), FilterSourceOtherPort, "203.0.113.7:41234"),
		}
	}
	if err := VerifyTrial(policy, filterHalf(foreignParty)); err == nil {
		t.Fatal("a filtering receipt attesting another endpoint was accepted")
	}

	// One coordinator attesting the same cold source twice is malformed before
	// anything is derived from it.
	duplicated := filterHalf(honest)
	duplicated.FilteringObservations = append(duplicated.FilteringObservations,
		duplicated.FilteringObservations[0])
	if err := duplicated.Validate(); err == nil {
		t.Fatal("a duplicated coordinator and source kind validated")
	}
	// Signing refuses it too, so the malformed set cannot even be committed.
	if _, err := SignTrial(duplicated, endpointKeyFor(opA, RoleA)); err == nil {
		t.Fatal("a duplicated receipt set was signable")
	}

	// A receipt set swapped after signing breaks the endpoint signature, so the
	// receipts a trial shows are the receipts that were signed over.
	swapped := filterHalf(honest)
	swapped.FilteringObservations = swapped.FilteringObservations[:1]
	if err := VerifyTrial(policy, swapped); err == nil {
		t.Fatal("dropping a receipt after signing left the trial verifiable")
	}
}

// The report surfaces each half's derived filtering class as per-cell counts
// and reads nothing from them: halves with receipts count under the class the
// receipts derive, halves without count as undetermined, a forged receipt
// takes its whole trial out before pairing, and the finding is identical with
// and without the evidence, because no threshold consumes it.
func TestReportSurfacesDerivedFilteringWithoutDeciding(t *testing.T) {
	policy := testPolicy()
	policy.Coordinators = append(policy.Coordinators, secondCoordinatorID())

	var plain []Trial
	for _, required := range policy.RequiredScenarios {
		plain = fillCell(plain, required, 4, OutcomeFailed, FailureHandshake, 0)
	}
	baseline, err := Aggregate(policy, plain, ProbeUDP)
	if err != nil {
		t.Fatalf("aggregate baseline: %v", err)
	}
	// Halves without receipts are undetermined -- silence is not evidence, and
	// the report says so per side rather than omitting the pairs.
	for _, cell := range baseline.Cells {
		if cell.Filtering.Initiator[FilteringUndetermined] != cell.Samples ||
			cell.Filtering.Responder[FilteringUndetermined] != cell.Samples {
			t.Fatalf("receipt-free halves were not counted undetermined: %+v", cell.Filtering)
		}
	}

	// The same measurements, now carrying receipts: every initiating half was
	// demonstrably reached from a cold address, every responding half from a
	// cold port on a contacted address.
	evidenced := make([]Trial, 0, len(plain))
	for _, trial := range plain {
		source := FilterSourceOtherAddress
		coordinator := secondCoordinatorKey()
		if trial.Role == RoleB {
			source = FilterSourceOtherPort
			coordinator = testCoordinatorKey()
		}
		trial.FilteringObservations = []FilteringObservation{signFilter(
			trial.SessionID, trial.Role, trial.OperatorID, coordinator,
			source, observedFor(trial.Local.Family))}
		evidenced = append(evidenced, resign(trial))
	}
	report, err := Aggregate(policy, evidenced, ProbeUDP)
	if err != nil {
		t.Fatalf("aggregate evidenced: %v", err)
	}
	if report.UnverifiedTrials != 0 || report.IncompletePairs != 0 {
		t.Fatalf("honest filtering receipts were dropped: %+v", report)
	}
	for _, cell := range report.Cells {
		if cell.Filtering.Initiator[FilteringEndpointIndependent] != cell.Samples {
			t.Fatalf("cold-address receipts were miscounted: %+v", cell.Filtering)
		}
		if cell.Filtering.Responder[FilteringAddressDependent] != cell.Samples {
			t.Fatalf("cold-port receipts were miscounted: %+v", cell.Filtering)
		}
	}
	// Decision-neutral: the receipts changed the counts and nothing else.
	if report.Finding != baseline.Finding {
		t.Fatalf("filtering evidence moved the finding: %q became %q", baseline.Finding, report.Finding)
	}
	for index, cell := range report.Cells {
		before := baseline.Cells[index]
		if cell.ScenarioKey != before.ScenarioKey || cell.DirectRate != before.DirectRate ||
			cell.Qualifying != before.Qualifying || cell.Samples != before.Samples {
			t.Fatalf("filtering evidence moved a cell aggregate: %+v vs %+v", cell, before)
		}
	}

	// A forged receipt is not weaker filtering evidence; it takes its trial out
	// entirely, so the pair is incomplete and contributes nothing anywhere.
	forgedScenario := scenario(CarrierConsumerISP, ClassEdgeRISC)
	forged := measurement(forgedScenario, opA, OutcomeDirect, FailureNone, 100)
	receipt := signFilter(forged[0].SessionID, forged[0].Role, forged[0].OperatorID,
		testCoordinatorKey(), FilterSourceOtherAddress, observedFor(forged[0].Local.Family))
	signature, err := hex.DecodeString(receipt.SignatureHex)
	if err != nil || len(signature) == 0 {
		t.Fatalf("decode signature: %v", err)
	}
	signature[0] ^= 0xff
	receipt.SignatureHex = hex.EncodeToString(signature)
	forged[0].FilteringObservations = []FilteringObservation{receipt}
	forged[0] = resign(forged[0])
	report, err = Aggregate(policy, append(evidenced, forged...), ProbeUDP)
	if err != nil {
		t.Fatalf("aggregate with forged receipt: %v", err)
	}
	if report.UnverifiedTrials != 1 || report.IncompletePairs != 1 {
		t.Fatalf("a forged receipt was not dropped with its trial: unverified=%d incomplete=%d",
			report.UnverifiedTrials, report.IncompletePairs)
	}
	for _, cell := range report.Cells {
		if cell.ScenarioKey == forgedScenario.Key() {
			t.Fatalf("a forged receipt's pair produced a cell: %+v", cell)
		}
	}
	if report.Finding != baseline.Finding {
		t.Fatalf("a forged receipt moved the finding: %q became %q", baseline.Finding, report.Finding)
	}
}

// The no-NAT declaration is consistent with all-equal reflections -- a public
// host produces exactly what an endpoint-independent NAT produces, so it lands
// in the same evidentiary bucket -- and refuted by differing ones, exactly as
// endpoint-independent is. It is never derived: the evidence cannot support it
// specifically, only the bucket.
func TestNoNATDeclarationSharesTheEndpointIndependentBucket(t *testing.T) {
	policy := twoCoordinatorPolicy()

	public := publicEndpoint() // declares Reachability public, NATBehavior none
	agreeing := func(session string) []BindObservation {
		return sameAddressBinds(session, RoleA, opA, public.Family)
	}
	differing := func(session string) []BindObservation {
		return []BindObservation{
			signBind(session, RoleA, opA, testCoordinatorKey(), "203.0.113.7:41234"),
			signBind(session, RoleA, opA, secondCoordinatorKey(), "198.51.100.9:5000"),
		}
	}
	noneHalf := func(binder func(session string) []BindObservation) Trial {
		session := nextSession()
		scene := Scenario{Initiator: public, Responder: publicEndpoint()}
		trial := rawTrial(scene, session, RoleA, opA, OutcomeDirect, FailureNone, 100)
		trial.Observation = attest(session, RoleA, opA, "yes", public.Family)
		trial.BindObservations = binder(session)
		return resign(trial)
	}

	if err := VerifyTrial(policy, noneHalf(agreeing)); err != nil {
		t.Fatalf("a no-NAT declaration was refuted by reflections that agree: %v", err)
	}
	// Differing reflections show a mapping that depends on the destination,
	// which no unmapped host has: the declaration is refuted, exactly as an
	// endpoint-independent one would be.
	if err := VerifyTrial(policy, noneHalf(differing)); err == nil {
		t.Fatal("a no-NAT declaration survived reflections that differ")
	}

	// The derivation never credits the no-NAT case: all-equal reflections
	// derive endpoint-independent, the bucket both declarations share, and
	// nothing a remote verifier holds can split it.
	session := nextSession()
	if got := deriveMapping(sameAddressBinds(session, RoleA, opA, FamilyIPv4)); got != NATEndpointIndependent {
		t.Fatalf("all-equal reflections derived %q, not the shared bucket", got)
	}
}
