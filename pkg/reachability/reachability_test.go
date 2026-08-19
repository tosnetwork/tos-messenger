package reachability

import (
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

var pairCounter int

func nextPair() string {
	pairCounter++
	return "pair_" + strings.Repeat("0", 28) + string([]byte{
		"0123456789abcdef"[(pairCounter>>12)&0xf],
		"0123456789abcdef"[(pairCounter>>8)&0xf],
		"0123456789abcdef"[(pairCounter>>4)&0xf],
		"0123456789abcdef"[pairCounter&0xf],
	})
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

func directTrial(s Stratum, operator string, millis uint64) Trial {
	return Trial{
		Stratum:         s,
		PairID:          nextPair(),
		SiteID:          siteFor(operator),
		OperatorID:      operator,
		Probe:           ProbeUDP,
		Outcome:         OutcomeDirect,
		Failure:         FailureNone,
		EstablishMillis: millis,
		StartedAtUnix:   1_800_000_000,
		LocalCommit:     commitA,
		PeerCommit:      commitB,
	}
}

func fallbackTrial(s Stratum, operator string, outcome Outcome, failure FailureClass) Trial {
	return Trial{
		Stratum:       s,
		PairID:        nextPair(),
		SiteID:        siteFor(operator),
		OperatorID:    operator,
		Probe:         ProbeUDP,
		Outcome:       outcome,
		Failure:       failure,
		StartedAtUnix: 1_800_000_000,
		LocalCommit:   commitA,
		PeerCommit:    commitB,
	}
}

func testPolicy() Policy {
	return Policy{
		MinSamplesPerCell:           4,
		MinOperatorsPerCell:         2,
		MinSitesPerCell:             2,
		MaxTrialsPerOperatorPerCell: 8,
		DirectViableRate:            0.75,
		TunnelViableRate:            0.9,
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
		trials = append(trials, directTrial(s, operators[index%len(operators)], uint64(100+index)))
	}
	for index := 0; index < other; index++ {
		trials = append(trials, fallbackTrial(s, operators[(direct+index)%len(operators)], outcome, failure))
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
		"direct rate":  func(p *Policy) { p.DirectViableRate = 0.74 },
		"tunnel rate":  func(p *Policy) { p.TunnelViableRate = 0.95 },
		"strata":       func(p *Policy) { p.RequiredStrata = append(p.RequiredStrata, stratum(CarrierMobile, ClassEdgeRISC)) },
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
	adnl := directTrial(policy.RequiredStrata[0], opA, 50)
	adnl.Probe = ProbeADNL
	trials = append(trials, adnl)

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
	trials := []Trial{
		directTrial(target, opA, 10),
		directTrial(target, opB, 20),
		directTrial(target, opA, 30),
		directTrial(target, opB, 400),
		fallbackTrial(target, opC, OutcomeRelayFallback, FailureHandshake),
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
		trials = append(trials, directTrial(target, opA, 10))
	}
	// Two others fail every time.
	for index := 0; index < 4; index++ {
		trials = append(trials, fallbackTrial(target, opB, OutcomeFailed, FailureHandshake))
		trials = append(trials, fallbackTrial(target, opC, OutcomeFailed, FailureHandshake))
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
