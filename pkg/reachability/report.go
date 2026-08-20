package reachability

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"sort"

	"github.com/tosnetwork/tos-messenger/internal/canon"
)

// Finding is what a study concluded. The vocabulary depends on which probe
// produced the evidence, and the two vocabularies do not overlap.
//
// A UDP probe measures whether a datagram path can be established. That is the
// network factor, and it is protocol independent, but it is not a route
// decision: a datagram getting through says nothing about whether an ADNL
// handshake completes, whether a channel stays up, whether keepalives survive
// a NAT, or whether a session recovers after a network change. A study that
// answered "direct-first" from UDP evidence would be inviting exactly the
// mistake of freezing an ADNL design on a measurement of something else.
type Finding string

// Kind separates the two questions a study can answer.
type Kind string

const (
	// KindFeasibility is what a UDP study produces.
	KindFeasibility Kind = "network-feasibility"
	// KindRouteDecision is what an ADNL study produces.
	KindRouteDecision Kind = "route-decision"
)

const (
	// FindingInsufficient means the study did not meet its own predeclared
	// minimums. It is not a weak preference for any route; it is the absence
	// of a result, and it is the only finding both vocabularies share.
	FindingInsufficient Finding = "insufficient-evidence"

	// FindingUDPDirectViable reports that a direct datagram path is reachable
	// across the required strata. It is an input to a route decision, never a
	// route decision.
	FindingUDPDirectViable Finding = "udp-direct-viable"
	// FindingUDPDirectNotViable reports that it is not.
	FindingUDPDirectNotViable Finding = "udp-direct-not-viable"

	// FindingDirectFirst means direct sessions carry the normal path.
	FindingDirectFirst Finding = "direct-first"
	// FindingTunnelFirst means a proxy or tunnel service is primary delivery
	// infrastructure.
	FindingTunnelFirst Finding = "tunnel-first"
	// FindingHybrid means the route order differs by network class.
	FindingHybrid Finding = "hybrid-by-network-class"
	// FindingRelayRequired means neither a direct path nor a tunnel reaches the
	// predeclared rate, so a Mailbox Relay is necessary.
	//
	// Necessary is all it means. That a Relay is required says nothing about
	// whether one works: its latency, retention, redundancy, and failover are
	// the technical Relay milestone's own acceptance, not this study's.
	FindingRelayRequired Finding = "relay-required"
)

// Policy is the predeclared acceptance policy. It is content-addressed and
// every report names the digest it was judged against, so thresholds chosen
// after seeing the data cannot be passed off as the ones the study committed
// to.
type Policy struct {
	MinSamplesPerCell   int `json:"min_samples_per_cell"`
	MinOperatorsPerCell int `json:"min_operators_per_cell"`
	// MinSitesPerCell bounds how concentrated the evidence may be. One
	// operator running twenty hosts behind one uplink has measured one
	// network, and counting operators alone would not notice.
	MinSitesPerCell int `json:"min_sites_per_cell"`
	// MaxTrialsPerOperatorPerCell caps how much of a cell one operator may
	// contribute. Trials past the cap are dropped and reported, never counted
	// silently.
	MaxTrialsPerOperatorPerCell int     `json:"max_trials_per_operator_per_cell"`
	DirectViableRate            float64 `json:"direct_viable_rate"`
	TunnelViableRate            float64 `json:"tunnel_viable_rate"`
	// Coordinators predeclares whose attestations count. Without it a signed
	// observation proves only that somebody signed something, since anyone can
	// run a coordinator and attest to whatever an operator wants.
	Coordinators      []string   `json:"coordinators"`
	RequiredScenarios []Scenario `json:"required_scenarios"`
}

type wirePolicy struct {
	Schema string `json:"schema"`
	Policy
}

// FilteringCounts is one cell's aggregate of derived filtering classes, one
// count per class per side of the ordered pair. Filtering is a property of
// each end, so the initiating and responding halves are counted separately
// rather than folded into a joint label neither endpoint could evidence.
//
// This is surfaced evidence, not an input to the decision. The counts exist
// for the humans reading the report and for policies that may one day
// predeclare something about them; nothing in decide or summarize reads them,
// no threshold consumes them, and Qualifying does not depend on them. Wiring
// the filtering class into the route decision would change what the study
// commits to, so it would require a new predeclared, content-addressed policy
// field -- it must never happen by this aggregate quietly growing a meaning.
//
// Every kept pair contributes exactly one count per side. A half that carried
// no receipts counts as undetermined, because a dropped probe and a lost probe
// are the same silence; the receipts of an unverifiable trial contribute
// nothing, because the whole trial was already dropped before pairing.
type FilteringCounts struct {
	Initiator map[FilteringBehavior]int `json:"initiator"`
	Responder map[FilteringBehavior]int `json:"responder"`
}

// CellReport is the aggregate for one scenario.
//
// The rates are means over operators rather than over trials. Pooling trials
// would let one operator who ran thousands of attempts decide a cell that
// everyone else measured a handful of times, and the point of requiring
// several operators is that no single one of them decides anything.
type CellReport struct {
	Scenario    Scenario `json:"scenario"`
	ScenarioKey string   `json:"scenario_key"`
	// PairReachability is the joint label, derived from the two endpoints
	// rather than declared by either.
	PairReachability string `json:"pair_reachability"`
	Samples          int    `json:"samples"`
	// Operators counts distinct self-declared operator identifiers whose
	// endpoint keys did not overlap. Nothing in the study proves that two
	// identifiers are two independent parties; the count is the floor the
	// evidence supports, not a claim of independence.
	Operators         int     `json:"operators"`
	Sites             int     `json:"sites"`
	DroppedOverCap    int     `json:"dropped_over_cap"`
	DirectRate        float64 `json:"direct_rate"`
	DirectOrProxyRate float64 `json:"direct_or_proxy_rate"`
	ProxyShare        float64 `json:"proxy_share"`
	RelayShare        float64 `json:"relay_share"`
	HTTPSShare        float64 `json:"https_share"`
	FailureShare      float64 `json:"failure_share"`
	EstablishP50      uint64  `json:"establish_p50_millis"`
	EstablishP95      uint64  `json:"establish_p95_millis"`
	ReconnectP50      uint64  `json:"reconnect_p50_millis"`
	ReconnectP95      uint64  `json:"reconnect_p95_millis"`
	SurvivalP50       uint64  `json:"survival_p50_seconds"`
	// SurvivalSamples counts the pairs where both halves measured survival. A
	// percentile over one-sided data would describe one endpoint's session,
	// not the pair's.
	SurvivalSamples int                  `json:"survival_samples"`
	FailureCounts   map[FailureClass]int `json:"failure_counts"`
	// Filtering counts the filtering class derived from each half's
	// coordinator-signed cold-source receipts. Evidence only: no threshold
	// reads it (see FilteringCounts).
	Filtering  FilteringCounts `json:"filtering"`
	Qualifying bool            `json:"qualifying"`
}

// Report is the published study result.
type Report struct {
	PolicyDigest string       `json:"policy_digest"`
	Probe        ProbeKind    `json:"probe"`
	Kind         Kind         `json:"kind"`
	Cells        []CellReport `json:"cells"`
	// UnverifiedTrials counts records dropped because their signatures did not
	// hold or their attestation came from a coordinator the policy did not
	// predeclare.
	UnverifiedTrials int `json:"unverified_trials"`
	// SharedEndpointKeys names endpoint keys that reported under more than one
	// operator. Every trial from such a key is excluded: the operator diversity
	// requirement means nothing if one host can answer to several names.
	SharedEndpointKeys []string `json:"shared_endpoint_keys,omitempty"`
	// IncompletePairs counts measurements where only one endpoint reported, or
	// the two halves contradicted each other. They are dropped and counted:
	// half a measurement is not a measurement, and two halves that disagree
	// are evidence of nothing except the disagreement.
	IncompletePairs int      `json:"incomplete_pairs"`
	Missing         []string `json:"missing_required_strata"`
	Finding         Finding  `json:"finding"`
	Reasons         []string `json:"reasons"`
}

// SupportsRouteDecision reports whether this study may be used to freeze a
// transport design.
func (r Report) SupportsRouteDecision() bool {
	return r.Kind == KindRouteDecision && r.Finding != FindingInsufficient
}

// Validate enforces that a policy is strong enough to decide anything.
//
// The coverage rules are the milestone's own acceptance conditions expressed
// as code. A policy that omits carrier-grade NAT, mobile networks, or low-cost
// endpoints could be satisfied by a laboratory pair, which is exactly the
// result the milestone says does not count.
func (p Policy) Validate() error {
	if p.MinOperatorsPerCell < 2 {
		return errors.New("a decision needs at least two distinct operator identifiers per cell")
	}
	if p.MinSamplesPerCell < p.MinOperatorsPerCell {
		return errors.New("a cell cannot hold more operators than samples")
	}
	if p.MinSitesPerCell < 2 {
		return errors.New("a decision needs at least two independent sites per cell")
	}
	if p.MinSitesPerCell > p.MinOperatorsPerCell*8 {
		return errors.New("a site requirement no operator set could satisfy is not a policy")
	}
	if p.MaxTrialsPerOperatorPerCell < 1 {
		return errors.New("a policy must cap how much of a cell one operator contributes")
	}
	if len(p.Coordinators) == 0 || len(p.Coordinators) > MaxCoordinatorsPerPolicy {
		return errors.New("a policy must predeclare whose attestations count")
	}
	seenCoordinators := make(map[string]struct{}, len(p.Coordinators))
	for _, coordinator := range p.Coordinators {
		if !serverPattern.MatchString(coordinator) {
			return errors.New("invalid predeclared coordinator")
		}
		if _, duplicate := seenCoordinators[coordinator]; duplicate {
			return errors.New("a policy cannot predeclare the same coordinator twice")
		}
		seenCoordinators[coordinator] = struct{}{}
	}
	if p.DirectViableRate <= 0 || p.DirectViableRate > 1 ||
		p.TunnelViableRate <= 0 || p.TunnelViableRate > 1 {
		return errors.New("viability rates must fall in (0,1]")
	}
	if p.TunnelViableRate < p.DirectViableRate {
		return errors.New("the tunnel bar cannot be lower than the direct bar")
	}
	if len(p.RequiredScenarios) == 0 || len(p.RequiredScenarios) > MaxScenariosPerPolicy {
		return errors.New("a policy must predeclare its required scenarios")
	}
	keys := make(map[string]struct{}, len(p.RequiredScenarios))
	coverage := struct {
		neitherPublic bool
		asymmetric    bool
		carriers      map[Carrier]struct{}
		families      map[AddressFamily]struct{}
		udpPolicies   map[UDPPolicy]struct{}
		lowCost       bool
		mobile        bool
	}{
		carriers:    map[Carrier]struct{}{},
		families:    map[AddressFamily]struct{}{},
		udpPolicies: map[UDPPolicy]struct{}{},
	}
	for _, scenario := range p.RequiredScenarios {
		if err := scenario.Validate(); err != nil {
			return err
		}
		key := scenario.Key()
		if _, duplicate := keys[key]; duplicate {
			return errors.New("a policy cannot require the same scenario twice")
		}
		keys[key] = struct{}{}
		if scenario.PairReachability() == "neither-public" {
			coverage.neitherPublic = true
		}
		if scenario.Asymmetric() {
			coverage.asymmetric = true
		}
		for _, endpoint := range []EndpointStratum{scenario.Initiator, scenario.Responder} {
			coverage.carriers[endpoint.Carrier] = struct{}{}
			coverage.families[endpoint.Family] = struct{}{}
			coverage.udpPolicies[endpoint.UDPPolicy] = struct{}{}
			if endpoint.EndpointClass == ClassEdgeARM || endpoint.EndpointClass == ClassEdgeRISC {
				coverage.lowCost = true
			}
			if endpoint.EndpointClass == ClassMobile || endpoint.Carrier == CarrierMobile {
				coverage.mobile = true
			}
		}
	}
	if !coverage.neitherPublic {
		return errors.New("a policy that never puts two endpoints behind NAT is a smoke test")
	}
	// The deployments this architecture is about are asymmetric: a home node
	// against a datacenter Agent, a phone against a machine behind
	// carrier-grade NAT. A matrix of matched pairs would answer an easier
	// question than the one being asked.
	if !coverage.asymmetric {
		return errors.New("a policy of matched pairs only has not measured the deployments in question")
	}
	for _, required := range []Carrier{CarrierConsumerISP, CarrierCarrierGrade, CarrierMobile} {
		if _, found := coverage.carriers[required]; !found {
			return errors.New("a policy must require measurements on " + string(required))
		}
	}
	if len(coverage.families) < 2 {
		return errors.New("a policy must require more than one address family")
	}
	if len(coverage.udpPolicies) < 2 {
		return errors.New("a policy must require more than one UDP policy environment")
	}
	if !coverage.lowCost {
		return errors.New("a policy must require a low-cost endpoint class")
	}
	if !coverage.mobile {
		return errors.New("a policy must require a mobile endpoint or carrier")
	}
	return nil
}

// CanonicalBytes returns the digest preimage of a policy.
func (p Policy) CanonicalBytes() ([]byte, error) {
	if err := p.Validate(); err != nil {
		return nil, err
	}
	keys := make([]string, 0, len(p.RequiredScenarios))
	for _, scenario := range p.RequiredScenarios {
		keys = append(keys, scenario.Key())
	}
	sort.Strings(keys)
	buffer := bytes.NewBufferString(canon.DomainReachabilityPolicy)
	canon.Text(buffer, PolicySchema)
	canon.Uint64(buffer, uint64(p.MinSamplesPerCell))
	canon.Uint64(buffer, uint64(p.MinOperatorsPerCell))
	canon.Uint64(buffer, uint64(p.MinSitesPerCell))
	canon.Uint64(buffer, uint64(p.MaxTrialsPerOperatorPerCell))
	canon.Uint64(buffer, ratePoints(p.DirectViableRate))
	canon.Uint64(buffer, ratePoints(p.TunnelViableRate))
	coordinators := append([]string(nil), p.Coordinators...)
	sort.Strings(coordinators)
	canon.Uint32(buffer, uint32(len(coordinators)))
	for _, coordinator := range coordinators {
		canon.Text(buffer, coordinator)
	}
	canon.Uint32(buffer, uint32(len(keys)))
	for _, key := range keys {
		canon.Text(buffer, key)
	}
	return buffer.Bytes(), nil
}

// Digest identifies one predeclared policy.
func (p Policy) Digest() (string, error) {
	preimage, err := p.CanonicalBytes()
	if err != nil {
		return "", err
	}
	return canon.Digest(preimage), nil
}

// ratePoints converts a rate to basis points so the digest never depends on
// floating-point formatting.
func ratePoints(rate float64) uint64 {
	return uint64(rate*10_000 + 0.5)
}

// EncodePolicyJSON returns the publishable policy.
func EncodePolicyJSON(policy Policy) ([]byte, error) {
	if err := policy.Validate(); err != nil {
		return nil, err
	}
	return json.MarshalIndent(wirePolicy{Schema: PolicySchema, Policy: policy}, "", "  ")
}

// DecodePolicyJSON rejects unknown fields, trailing data, and weak policies.
func DecodePolicyJSON(raw []byte) (Policy, error) {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	var value wirePolicy
	if err := decoder.Decode(&value); err != nil {
		return Policy{}, err
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return Policy{}, errors.New("policy has trailing JSON")
	}
	if value.Schema != PolicySchema {
		return Policy{}, errors.New("unsupported policy schema")
	}
	if err := value.Policy.Validate(); err != nil {
		return Policy{}, err
	}
	return value.Policy, nil
}

// Aggregate builds the report and applies the predeclared policy.
//
// Trials from strata the policy did not require are still aggregated and
// published: they are evidence, and hiding them would make the matrix look
// tidier than the measurement was. They simply cannot rescue a required
// stratum that was never measured.
func Aggregate(policy Policy, trials []Trial, probe ProbeKind) (Report, error) {
	if err := policy.Validate(); err != nil {
		return Report{}, err
	}
	if !member(probes, probe) {
		return Report{}, errors.New("invalid probe kind")
	}
	if len(trials) == 0 {
		return Report{}, errors.New("no trials to aggregate")
	}
	digest, err := policy.Digest()
	if err != nil {
		return Report{}, err
	}

	// Nothing counts until it verifies. A trial whose signatures do not hold,
	// or whose attestation comes from a coordinator nobody predeclared, is not
	// weak evidence; it is somebody's unchecked assertion, and accepting it
	// would make every threshold in the policy advisory.
	verified := make([]Trial, 0, len(trials))
	operatorsByKey := make(map[string]map[string]struct{})
	unverified := 0
	for _, trial := range trials {
		if err := trial.Validate(); err != nil {
			return Report{}, err
		}
		if trial.Probe != probe {
			continue
		}
		if err := VerifyTrial(policy, trial); err != nil {
			unverified++
			continue
		}
		if operatorsByKey[trial.EndpointPublicKeyHex] == nil {
			operatorsByKey[trial.EndpointPublicKeyHex] = map[string]struct{}{}
		}
		operatorsByKey[trial.EndpointPublicKeyHex][trial.OperatorID] = struct{}{}
		verified = append(verified, trial)
	}

	// One host answering to several operator names would satisfy the operator
	// minimum by itself. The key it signs with is what gives that away.
	shared := map[string]struct{}{}
	for key, operators := range operatorsByKey {
		if len(operators) > 1 {
			shared[key] = struct{}{}
		}
	}

	// Nothing verifying at all is a different situation from nothing
	// qualifying: it means the submissions could not be checked, not that the
	// network answered badly, and it must not read as a completed study.
	if len(verified) == 0 {
		return Report{}, errors.New("no trial in the study could be verified")
	}

	// A measurement has two halves and counts once. Both endpoints report, and
	// a pair counts only when the two agree about what happened: forging a
	// result now takes both halves, from two different keys, saying the same
	// false thing.
	halves := make(map[string][]Trial)
	for _, trial := range verified {
		if _, impersonating := shared[trial.EndpointPublicKeyHex]; impersonating {
			continue
		}
		halves[trial.PairID] = append(halves[trial.PairID], trial)
	}

	grouped := make(map[string][]pairResult)
	scenarios := make(map[string]Scenario)
	incomplete := 0
	for _, both := range halves {
		result, err := combine(both)
		if err != nil {
			incomplete++
			continue
		}
		key := result.scenario.Key()
		grouped[key] = append(grouped[key], result)
		scenarios[key] = result.scenario
	}
	// A study with nothing complete in it is not an error. It is a study that
	// concluded nothing, and saying so is the useful answer: every required
	// scenario comes back missing rather than the caller getting a failure they
	// might mistake for a tooling problem.

	cells := make([]CellReport, 0, len(grouped))
	for key, group := range grouped {
		cells = append(cells, summarize(policy, scenarios[key], key, group))
	}
	sort.Slice(cells, func(i, j int) bool { return cells[i].ScenarioKey < cells[j].ScenarioKey })

	sharedKeys := make([]string, 0, len(shared))
	for key := range shared {
		sharedKeys = append(sharedKeys, key)
	}
	sort.Strings(sharedKeys)

	report := Report{
		PolicyDigest: digest, Probe: probe, Kind: kindFor(probe), Cells: cells,
		UnverifiedTrials: unverified, SharedEndpointKeys: sharedKeys,
		IncompletePairs: incomplete,
	}
	report.Finding, report.Missing, report.Reasons = decide(policy, cells, probe)
	return report, nil
}

func summarize(policy Policy, scenario Scenario, key string, group []pairResult) CellReport {
	cell := CellReport{
		Scenario:         scenario,
		ScenarioKey:      key,
		PairReachability: scenario.PairReachability(),
		FailureCounts:    map[FailureClass]int{},
		Filtering: FilteringCounts{
			Initiator: map[FilteringBehavior]int{},
			Responder: map[FilteringBehavior]int{},
		},
	}

	// The cap is applied in digest order, not arrival order, so the same set of
	// measurements always truncates to the same sample -- otherwise an operator
	// could choose which of their trials survive by choosing when to submit
	// them. A pair spans up to two operators and counts against both caps.
	ordered := make([]pairResult, len(group))
	copy(ordered, group)
	sort.Slice(ordered, func(i, j int) bool { return ordered[i].digest < ordered[j].digest })

	counts := map[string]int{}
	byOperator := map[string][]pairResult{}
	sites := map[string]struct{}{}
	kept := make([]pairResult, 0, len(ordered))
	for _, pair := range ordered {
		room := true
		for _, operator := range pair.operators {
			if counts[operator] >= policy.MaxTrialsPerOperatorPerCell {
				room = false
			}
		}
		if !room {
			cell.DroppedOverCap++
			continue
		}
		for _, operator := range pair.operators {
			counts[operator]++
			byOperator[operator] = append(byOperator[operator], pair)
		}
		for _, site := range pair.sites {
			sites[site] = struct{}{}
		}
		kept = append(kept, pair)
	}

	var establish, reconnect, survival []uint64
	var proxy, relay, https, failed int
	for _, pair := range kept {
		for _, failure := range pair.failures {
			cell.FailureCounts[failure]++
		}
		// Counted over the kept pairs, exactly as the failure classes are, so
		// the same cap that bounds an operator's samples bounds their receipts.
		cell.Filtering.Initiator[pair.initiatorFiltering]++
		cell.Filtering.Responder[pair.responderFiltering]++
		switch pair.outcome {
		case OutcomeDirect:
			establish = append(establish, pair.establish)
			if pair.reconnect != 0 {
				reconnect = append(reconnect, pair.reconnect)
			}
			if pair.survivalMeasured {
				survival = append(survival, pair.survival)
			}
		case OutcomeProxyFallback:
			proxy++
		case OutcomeRelayFallback:
			relay++
		case OutcomeHTTPSFallback:
			https++
		case OutcomeFailed:
			failed++
		}
	}

	// Rates are averaged over operators, not over measurements, so one operator
	// with a large fleet cannot outvote the rest of the study.
	var directRates, tunnelRates []float64
	for _, pairs := range byOperator {
		var direct, withProxy int
		for _, pair := range pairs {
			switch pair.outcome {
			case OutcomeDirect:
				direct++
				withProxy++
			case OutcomeProxyFallback:
				withProxy++
			}
		}
		total := float64(len(pairs))
		directRates = append(directRates, float64(direct)/total)
		tunnelRates = append(tunnelRates, float64(withProxy)/total)
	}

	cell.Samples = len(kept)
	cell.Operators = len(byOperator)
	cell.Sites = len(sites)
	cell.DirectRate = mean(directRates)
	cell.DirectOrProxyRate = mean(tunnelRates)
	if cell.Samples > 0 {
		total := float64(cell.Samples)
		cell.ProxyShare = float64(proxy) / total
		cell.RelayShare = float64(relay) / total
		cell.HTTPSShare = float64(https) / total
		cell.FailureShare = float64(failed) / total
	}
	cell.EstablishP50 = percentile(establish, 50)
	cell.EstablishP95 = percentile(establish, 95)
	cell.ReconnectP50 = percentile(reconnect, 50)
	cell.ReconnectP95 = percentile(reconnect, 95)
	cell.SurvivalP50 = percentile(survival, 50)
	cell.SurvivalSamples = len(survival)
	cell.Qualifying = cell.Samples >= policy.MinSamplesPerCell &&
		cell.Operators >= policy.MinOperatorsPerCell &&
		cell.Sites >= policy.MinSitesPerCell
	return cell
}

// mean gives every operator the same weight, whatever their sample count.
func mean(values []float64) float64 {
	if len(values) == 0 {
		return 0
	}
	var total float64
	for _, value := range values {
		total += value
	}
	return total / float64(len(values))
}

func kindFor(probe ProbeKind) Kind {
	if probe == ProbeADNL {
		return KindRouteDecision
	}
	return KindFeasibility
}

// decide applies the predeclared thresholds.
//
// Any required stratum that is missing or under-sampled ends the evaluation
// with no finding at all. Partial evidence does not become a weak preference,
// because a weak preference is what the implementation would then be built on.
//
// The vocabulary depends on the probe. A UDP study reports whether a direct
// datagram path is feasible; only an ADNL study reports a route.
func decide(policy Policy, cells []CellReport, probe ProbeKind) (Finding, []string, []string) {
	byKey := make(map[string]CellReport, len(cells))
	for _, cell := range cells {
		byKey[cell.ScenarioKey] = cell
	}
	var missing []string
	var reasons []string
	directViable, tunnelViable, evaluated := 0, 0, 0
	for _, scenario := range policy.RequiredScenarios {
		key := scenario.Key()
		cell, found := byKey[key]
		if !found {
			missing = append(missing, key)
			reasons = append(reasons, "required scenario was never measured: "+key)
			continue
		}
		if !cell.Qualifying {
			missing = append(missing, key)
			reasons = append(reasons, "required scenario is under-sampled: "+key)
			continue
		}
		evaluated++
		if cell.DirectRate >= policy.DirectViableRate {
			directViable++
		}
		if cell.DirectOrProxyRate >= policy.TunnelViableRate {
			tunnelViable++
		}
	}
	sort.Strings(missing)
	if len(missing) > 0 || evaluated == 0 {
		return FindingInsufficient, missing, reasons
	}

	if probe != ProbeADNL {
		if directViable == evaluated {
			reasons = append(reasons, "a direct datagram path reached the required rate in every required scenario; this is an input to a route decision, not one")
			return FindingUDPDirectViable, nil, reasons
		}
		reasons = append(reasons, "a direct datagram path did not reach the required rate in every required scenario")
		return FindingUDPDirectNotViable, nil, reasons
	}

	switch {
	case directViable == evaluated:
		reasons = append(reasons, "every required stratum reached the direct viability rate")
		return FindingDirectFirst, nil, reasons
	case directViable > 0:
		reasons = append(reasons, "direct establishment is viable in some required strata and not others")
		return FindingHybrid, nil, reasons
	case tunnelViable == evaluated:
		reasons = append(reasons, "no required stratum reached the direct rate, and a proxy or tunnel lifts every one of them")
		return FindingTunnelFirst, nil, reasons
	default:
		reasons = append(reasons, "neither direct establishment nor a proxy reaches the predeclared rate, so a Mailbox Relay is necessary; whether one performs adequately is the Relay milestone's own acceptance")
		return FindingRelayRequired, nil, reasons
	}
}

// EncodeReportJSON returns the publishable report.
func EncodeReportJSON(report Report) ([]byte, error) {
	return json.MarshalIndent(report, "", "  ")
}
