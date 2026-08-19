package reachability

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
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

func stratum(carrier Carrier, class EndpointClass) Stratum {
	return Stratum{
		Family:        FamilyIPv4,
		Reachability:  NeitherPublic,
		NATBehavior:   NATAddressPortDependent,
		Carrier:       carrier,
		UDPPolicy:     UDPAllowed,
		Mobility:      MobilityStationary,
		EndpointClass: class,
		Assistance:    AssistanceNone,
	}
}

func publicStratum() Stratum {
	return Stratum{
		Family:        FamilyDual,
		Reachability:  BothPublic,
		NATBehavior:   NATNone,
		Carrier:       CarrierDatacenter,
		UDPPolicy:     UDPAllowed,
		Mobility:      MobilityStationary,
		EndpointClass: ClassServer,
		Assistance:    AssistanceNone,
	}
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

func attest(session string, role Role, peerPublic string) Observation {
	observation, err := SignObservation(Observation{
		SessionID:  session,
		Role:       string(role),
		Observed:   "203.0.113.7:41234",
		PeerPublic: peerPublic,
		AtUnix:     1_800_000_000,
	}, testCoordinatorKey())
	if err != nil {
		panic(err)
	}
	return observation
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

func rawTrial(s Stratum, session string, role Role, operator string,
	outcome Outcome, failure FailureClass, millis uint64) Trial {
	pair, err := PairID(session)
	if err != nil {
		panic(err)
	}
	local, peer := commitA, commitB
	if role == RoleB {
		local, peer = commitB, commitA
	}
	return Trial{
		Stratum:         s,
		PairID:          pair,
		SiteID:          siteFor(operator),
		OperatorID:      operator,
		SessionID:       session,
		Role:            role,
		Probe:           ProbeUDP,
		Outcome:         outcome,
		Failure:         failure,
		EstablishMillis: millis,
		StartedAtUnix:   1_800_000_000,
		LocalCommit:     local,
		PeerCommit:      peer,
	}
}

func complete(trial Trial) Trial {
	peerPublic := "no"
	if trial.Stratum.Reachability == BothPublic || trial.Stratum.Reachability == OnePublic {
		peerPublic = "yes"
	}
	trial.Observation = attest(trial.SessionID, trial.Role, peerPublic)
	signed, err := SignTrial(trial, endpointKeyFor(trial.OperatorID, trial.Role))
	if err != nil {
		panic(err)
	}
	return signed
}

// measurement builds both halves of one attempt. Aggregation counts pairs, so
// a helper that produced a single record would be manufacturing exactly the
// evidence the report is right to discard.
func measurement(s Stratum, operator string, outcome Outcome, failure FailureClass, millis uint64) []Trial {
	session := nextSession()
	return []Trial{
		complete(rawTrial(s, session, RoleA, operator, outcome, failure, millis)),
		complete(rawTrial(s, session, RoleB, operator, outcome, failure, millis)),
	}
}

func directPair(s Stratum, operator string, millis uint64) []Trial {
	return measurement(s, operator, OutcomeDirect, FailureNone, millis)
}

func fallbackPair(s Stratum, operator string, outcome Outcome, failure FailureClass) []Trial {
	return measurement(s, operator, outcome, failure, 0)
}

// directTrial and fallbackTrial return one half, for the tests that are about
// a single record rather than about an aggregate.
func directTrial(s Stratum, operator string, millis uint64) Trial {
	return directPair(s, operator, millis)[0]
}

func fallbackTrial(s Stratum, operator string, outcome Outcome, failure FailureClass) Trial {
	return fallbackPair(s, operator, outcome, failure)[0]
}

func testPolicy() Policy {
	return Policy{
		MinSamplesPerCell:           4,
		MinOperatorsPerCell:         2,
		MinSitesPerCell:             2,
		MaxTrialsPerOperatorPerCell: 8,
		DirectViableRate:            0.75,
		TunnelViableRate:            0.9,
		Coordinators:                []string{testCoordinatorID()},
		RequiredStrata: []Stratum{
			stratum(CarrierConsumerISP, ClassDesktop),
			stratum(CarrierCarrierGrade, ClassEdgeARM),
			{
				Family:        FamilyIPv6,
				Reachability:  OnePublic,
				NATBehavior:   NATSymmetric,
				Carrier:       CarrierMobile,
				UDPPolicy:     UDPRateLimited,
				Mobility:      MobilityWiFiToMobile,
				EndpointClass: ClassMobile,
				Assistance:    AssistanceNone,
			},
		},
	}
}

func fillCell(trials []Trial, s Stratum, direct int, outcome Outcome, failure FailureClass, other int) []Trial {
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
		"no strata": func(p *Policy) { p.RequiredStrata = nil },
		"public pairs only": func(p *Policy) {
			p.RequiredStrata = []Stratum{publicStratum()}
		},
		"duplicate stratum": func(p *Policy) {
			p.RequiredStrata = append(p.RequiredStrata, p.RequiredStrata[0])
		},
		"no carrier grade nat": func(p *Policy) {
			p.RequiredStrata = []Stratum{stratum(CarrierConsumerISP, ClassEdgeARM), stratum(CarrierMobile, ClassMobile)}
		},
		"no low cost endpoint": func(p *Policy) {
			p.RequiredStrata[1] = stratum(CarrierCarrierGrade, ClassServer)
		},
		"single address family": func(p *Policy) {
			p.RequiredStrata[2] = stratum(CarrierMobile, ClassMobile)
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
	reordered.RequiredStrata[0], reordered.RequiredStrata[2] = reordered.RequiredStrata[2], reordered.RequiredStrata[0]
	reorderedDigest, err := reordered.Digest()
	if err != nil {
		t.Fatalf("digest: %v", err)
	}
	if digest != reorderedDigest {
		t.Fatal("stratum ordering changed the policy identity")
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
		"direct rate": func(p *Policy) { p.DirectViableRate = 0.74 },
		"tunnel rate": func(p *Policy) { p.TunnelViableRate = 0.95 },
		"strata":      func(p *Policy) { p.RequiredStrata = append(p.RequiredStrata, stratum(CarrierMobile, ClassEdgeRISC)) },
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

func TestMissingRequiredStratumYieldsNoDecision(t *testing.T) {
	policy := testPolicy()
	var trials []Trial
	trials = fillCell(trials, policy.RequiredStrata[0], 4, OutcomeFailed, FailureHandshake, 0)
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

func TestUnderSampledStratumYieldsNoDecision(t *testing.T) {
	policy := testPolicy()
	var trials []Trial
	for _, required := range policy.RequiredStrata {
		trials = fillCell(trials, required, 4, OutcomeFailed, FailureHandshake, 0)
	}
	// Enough samples, but all of them from one operator.
	single := policy.RequiredStrata[1]
	filtered := trials[:0]
	for _, trial := range trials {
		if trial.Stratum.Key() == single.Key() {
			trial.OperatorID = opA
			trial = resign(trial)
		}
		filtered = append(filtered, trial)
	}
	report, err := Aggregate(policy, filtered, ProbeUDP)
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
			for index, required := range policy.RequiredStrata {
				direct := testCase.direct[index]
				proxy := testCase.proxy[index]
				trials = fillCell(trials, required, direct, OutcomeProxyFallback, FailureHandshake, proxy)
				remaining := 4 - direct - proxy
				if remaining > 0 {
					trials = fillCell(trials, required, 0, OutcomeRelayFallback, FailurePeerUnreachable, remaining)
				}
			}
			for index := range trials {
				trials[index].Probe = ProbeADNL
				trials[index] = resign(trials[index])
			}
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
	for _, required := range policy.RequiredStrata {
		trials = fillCell(trials, required, 4, OutcomeFailed, FailureHandshake, 0)
	}
	trials = fillCell(trials, publicStratum(), 4, OutcomeFailed, FailureHandshake, 0)
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
	for _, required := range policy.RequiredStrata {
		trials = fillCell(trials, required, 4, OutcomeFailed, FailureHandshake, 0)
	}
	for _, half := range directPair(policy.RequiredStrata[0], opA, 50) {
		half.Probe = ProbeADNL
		trials = append(trials, resign(half))
	}

	report, err := Aggregate(policy, trials, ProbeUDP)
	if err != nil {
		t.Fatalf("aggregate: %v", err)
	}
	for _, cell := range report.Cells {
		if cell.Samples != 4 {
			t.Fatalf("a different probe leaked into cell %s: %d samples", cell.StratumKey, cell.Samples)
		}
	}
	if _, err := Aggregate(policy, trials, ProbeADNL); err != nil {
		t.Fatalf("expected the ADNL probe to aggregate on its own: %v", err)
	}
}

func TestPercentilesUseMeasuredSessionsOnly(t *testing.T) {
	policy := testPolicy()
	target := policy.RequiredStrata[0]
	var trials []Trial
	trials = append(trials, directPair(target, opA, 10)...)
	trials = append(trials, directPair(target, opB, 20)...)
	trials = append(trials, directPair(target, opA, 30)...)
	trials = append(trials, directPair(target, opB, 400)...)
	trials = append(trials, fallbackPair(target, opC, OutcomeRelayFallback, FailureHandshake)...)
	for _, required := range policy.RequiredStrata[1:] {
		trials = fillCell(trials, required, 4, OutcomeFailed, FailureHandshake, 0)
	}
	report, err := Aggregate(policy, trials, ProbeUDP)
	if err != nil {
		t.Fatalf("aggregate: %v", err)
	}
	var cell CellReport
	for _, candidate := range report.Cells {
		if candidate.StratumKey == target.Key() {
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
	base := directTrial(stratum(CarrierConsumerISP, ClassDesktop), opA, 100)
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
		"bad operator":        func(t *Trial) { t.OperatorID = "operator-1" },
		"bad probe":           func(t *Trial) { t.Probe = "quic" },
		"no start time":       func(t *Trial) { t.StartedAtUnix = 0 },
		"short commit":        func(t *Trial) { t.LocalCommit = "abc" },
		"missing peer commit": func(t *Trial) { t.PeerCommit = "" },
		"nat on public pair": func(t *Trial) {
			t.Stratum.Reachability = BothPublic
		},
		"no nat behind nat": func(t *Trial) { t.Stratum.NATBehavior = NATNone },
		"unknown carrier":   func(t *Trial) { t.Stratum.Carrier = "satellite" },
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

func TestTrialLogRefusesDuplicatesAndGarbage(t *testing.T) {
	trial := directTrial(stratum(CarrierConsumerISP, ClassDesktop), opA, 100)
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
	for _, required := range policy.RequiredStrata {
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
	for _, required := range policy.RequiredStrata {
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
	target := policy.RequiredStrata[0]

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
	for _, required := range policy.RequiredStrata[1:] {
		trials = fillCell(trials, required, 4, OutcomeFailed, FailureHandshake, 0)
	}
	report, err := Aggregate(policy, trials, ProbeUDP)
	if err != nil {
		t.Fatalf("aggregate: %v", err)
	}
	var cell CellReport
	for _, candidate := range report.Cells {
		if candidate.StratumKey == target.Key() {
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
	for _, required := range policy.RequiredStrata {
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
	if len(report.Missing) != len(policy.RequiredStrata) {
		t.Fatalf("expected every cell to be under-sampled, got %d", len(report.Missing))
	}
}

func TestPairAndSiteIdentityAreRequired(t *testing.T) {
	base := directTrial(stratum(CarrierConsumerISP, ClassDesktop), opA, 100)
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
	for _, required := range policy.RequiredStrata {
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
	for _, required := range policy.RequiredStrata {
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
	target := policy.RequiredStrata[0]

	var trials []Trial
	for _, operator := range []string{opA, opB, opC} {
		session := nextSession()
		for _, role := range []Role{RoleA, RoleB} {
			trial := rawTrial(target, session, role, operator, OutcomeDirect, FailureNone, 20)
			trial.Observation = attest(session, role, "no")
			// Every "operator" signs with the same key.
			signed, err := SignTrial(trial, endpointKeyFor("one-host", RoleA))
			if err != nil {
				t.Fatalf("sign: %v", err)
			}
			trials = append(trials, signed)
		}
	}
	for _, required := range policy.RequiredStrata[1:] {
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
		if cell.StratumKey == target.Key() {
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
	target := policy.RequiredStrata[0]

	var trials []Trial
	for index := 0; index < 4; index++ {
		pair := directPair(target, []string{opA, opB, opC}[index%3], uint64(100+index))
		if index == 0 {
			pair = pair[:1] // the peer never reported
		}
		trials = append(trials, pair...)
	}
	for _, required := range policy.RequiredStrata[1:] {
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
		if cell.StratumKey == target.Key() && cell.Samples != 3 {
			t.Fatalf("an unpaired half was counted as a measurement: %+v", cell)
		}
	}
}

// Both halves have to say the same thing. Improving one half of a result now
// takes the other half's key as well, and the two keys are what the operator
// minimum is counting.
func TestContradictingHalvesAreDiscarded(t *testing.T) {
	policy := testPolicy()
	target := policy.RequiredStrata[0]

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
		"cell": func(pair []Trial) []Trial {
			pair[1].Stratum.Carrier = CarrierMobile
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
			pair[1].Observation = attest(pair[1].SessionID, RoleA, "no")
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
			for _, required := range policy.RequiredStrata[1:] {
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
				if cell.StratumKey == target.Key() && cell.Samples > 3 {
					t.Fatalf("a contradicted measurement was counted: %+v", cell)
				}
			}
		})
	}
}

// The pair identifier is derived from the session, so it cannot be chosen to
// glue together two halves that were never the same attempt.
func TestPairIdentifierMustBeDerivedFromItsSession(t *testing.T) {
	trial := directTrial(stratum(CarrierConsumerISP, ClassDesktop), opA, 100)
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
	target := policy.RequiredStrata[0]

	var trials []Trial
	for index := 0; index < 20; index++ {
		outcome, failure := OutcomeDirect, FailureNone
		if index%2 == 0 {
			outcome, failure = OutcomeFailed, FailureHandshake
		}
		trials = append(trials, measurement(target, opA, outcome, failure, map[bool]uint64{true: 0, false: 40}[index%2 == 0])...)
	}
	for _, required := range policy.RequiredStrata {
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
