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
	MaxTrialsPerOperatorPerCell int       `json:"max_trials_per_operator_per_cell"`
	DirectViableRate            float64   `json:"direct_viable_rate"`
	TunnelViableRate            float64   `json:"tunnel_viable_rate"`
	RequiredStrata              []Stratum `json:"required_strata"`
}

type wirePolicy struct {
	Schema string `json:"schema"`
	Policy
}

// CellReport is the aggregate for one stratum.
//
// The rates are means over operators rather than over trials. Pooling trials
// would let one operator who ran thousands of attempts decide a cell that
// everyone else measured a handful of times, and the point of requiring
// several operators is that no single one of them decides anything.
type CellReport struct {
	Stratum           Stratum              `json:"stratum"`
	StratumKey        string               `json:"stratum_key"`
	Samples           int                  `json:"samples"`
	Operators         int                  `json:"operators"`
	Sites             int                  `json:"sites"`
	DroppedOverCap    int                  `json:"dropped_over_cap"`
	DirectRate        float64              `json:"direct_rate"`
	DirectOrProxyRate float64              `json:"direct_or_proxy_rate"`
	ProxyShare        float64              `json:"proxy_share"`
	RelayShare        float64              `json:"relay_share"`
	HTTPSShare        float64              `json:"https_share"`
	FailureShare      float64              `json:"failure_share"`
	EstablishP50      uint64               `json:"establish_p50_millis"`
	EstablishP95      uint64               `json:"establish_p95_millis"`
	ReconnectP50      uint64               `json:"reconnect_p50_millis"`
	ReconnectP95      uint64               `json:"reconnect_p95_millis"`
	SurvivalP50       uint64               `json:"survival_p50_seconds"`
	FailureCounts     map[FailureClass]int `json:"failure_counts"`
	Qualifying        bool                 `json:"qualifying"`
}

// Report is the published study result.
type Report struct {
	PolicyDigest string       `json:"policy_digest"`
	Probe        ProbeKind    `json:"probe"`
	Kind         Kind         `json:"kind"`
	Cells        []CellReport `json:"cells"`
	Missing      []string     `json:"missing_required_strata"`
	Finding      Finding      `json:"finding"`
	Reasons      []string     `json:"reasons"`
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
		return errors.New("a decision needs at least two independent operators per cell")
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
	if p.DirectViableRate <= 0 || p.DirectViableRate > 1 ||
		p.TunnelViableRate <= 0 || p.TunnelViableRate > 1 {
		return errors.New("viability rates must fall in (0,1]")
	}
	if p.TunnelViableRate < p.DirectViableRate {
		return errors.New("the tunnel bar cannot be lower than the direct bar")
	}
	if len(p.RequiredStrata) == 0 || len(p.RequiredStrata) > MaxStrataPerPolicy {
		return errors.New("a policy must predeclare its required strata")
	}
	keys := make(map[string]struct{}, len(p.RequiredStrata))
	coverage := struct {
		behindNAT   bool
		carriers    map[Carrier]struct{}
		families    map[AddressFamily]struct{}
		udpPolicies map[UDPPolicy]struct{}
		lowCost     bool
		mobile      bool
	}{
		carriers:    map[Carrier]struct{}{},
		families:    map[AddressFamily]struct{}{},
		udpPolicies: map[UDPPolicy]struct{}{},
	}
	for _, stratum := range p.RequiredStrata {
		if err := stratum.Validate(); err != nil {
			return err
		}
		key := stratum.Key()
		if _, duplicate := keys[key]; duplicate {
			return errors.New("a policy cannot require the same stratum twice")
		}
		keys[key] = struct{}{}
		if stratum.Reachability != BothPublic {
			coverage.behindNAT = true
		}
		coverage.carriers[stratum.Carrier] = struct{}{}
		coverage.families[stratum.Family] = struct{}{}
		coverage.udpPolicies[stratum.UDPPolicy] = struct{}{}
		if stratum.EndpointClass == ClassEdgeARM || stratum.EndpointClass == ClassEdgeRISC {
			coverage.lowCost = true
		}
		if stratum.EndpointClass == ClassMobile || stratum.Carrier == CarrierMobile {
			coverage.mobile = true
		}
	}
	if !coverage.behindNAT {
		return errors.New("a policy of publicly addressable pairs only is a smoke test")
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
	keys := make([]string, 0, len(p.RequiredStrata))
	for _, stratum := range p.RequiredStrata {
		keys = append(keys, stratum.Key())
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

	grouped := make(map[string][]Trial)
	strata := make(map[string]Stratum)
	for _, trial := range trials {
		if err := trial.Validate(); err != nil {
			return Report{}, err
		}
		if trial.Probe != probe {
			continue
		}
		key := trial.Stratum.Key()
		grouped[key] = append(grouped[key], trial)
		strata[key] = trial.Stratum
	}
	if len(grouped) == 0 {
		return Report{}, errors.New("no trials for the requested probe")
	}

	cells := make([]CellReport, 0, len(grouped))
	for key, group := range grouped {
		cells = append(cells, summarize(policy, strata[key], key, group))
	}
	sort.Slice(cells, func(i, j int) bool { return cells[i].StratumKey < cells[j].StratumKey })

	report := Report{PolicyDigest: digest, Probe: probe, Kind: kindFor(probe), Cells: cells}
	report.Finding, report.Missing, report.Reasons = decide(policy, cells, probe)
	return report, nil
}

func summarize(policy Policy, stratum Stratum, key string, group []Trial) CellReport {
	cell := CellReport{
		Stratum:       stratum,
		StratumKey:    key,
		FailureCounts: map[FailureClass]int{},
	}

	// One operator's trials are capped before anything is counted. Past the
	// cap they are dropped and reported: a truncation nobody can see reads as
	// coverage that was never measured.
	byOperator := map[string][]Trial{}
	for _, trial := range group {
		if len(byOperator[trial.OperatorID]) >= policy.MaxTrialsPerOperatorPerCell {
			cell.DroppedOverCap++
			continue
		}
		byOperator[trial.OperatorID] = append(byOperator[trial.OperatorID], trial)
	}

	sites := map[string]struct{}{}
	var establish, reconnect, survival []uint64
	var directRates, tunnelRates []float64
	var proxy, relay, https, failed, counted int

	for _, trials := range byOperator {
		var direct, withProxy int
		for _, trial := range trials {
			counted++
			sites[trial.SiteID] = struct{}{}
			if trial.Failure != FailureNone {
				cell.FailureCounts[trial.Failure]++
			}
			switch trial.Outcome {
			case OutcomeDirect:
				direct++
				withProxy++
				establish = append(establish, trial.EstablishMillis)
				if trial.ReconnectMillis != 0 {
					reconnect = append(reconnect, trial.ReconnectMillis)
				}
				if trial.SurvivalSeconds != 0 {
					survival = append(survival, trial.SurvivalSeconds)
				}
			case OutcomeProxyFallback:
				proxy++
				withProxy++
			case OutcomeRelayFallback:
				relay++
			case OutcomeHTTPSFallback:
				https++
			case OutcomeFailed:
				failed++
			}
		}
		total := float64(len(trials))
		directRates = append(directRates, float64(direct)/total)
		tunnelRates = append(tunnelRates, float64(withProxy)/total)
	}

	cell.Samples = counted
	cell.Operators = len(byOperator)
	cell.Sites = len(sites)
	cell.DirectRate = mean(directRates)
	cell.DirectOrProxyRate = mean(tunnelRates)
	if counted > 0 {
		total := float64(counted)
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
		byKey[cell.StratumKey] = cell
	}
	var missing []string
	var reasons []string
	directViable, tunnelViable, evaluated := 0, 0, 0
	for _, stratum := range policy.RequiredStrata {
		key := stratum.Key()
		cell, found := byKey[key]
		if !found {
			missing = append(missing, key)
			reasons = append(reasons, "required stratum was never measured: "+key)
			continue
		}
		if !cell.Qualifying {
			missing = append(missing, key)
			reasons = append(reasons, "required stratum is under-sampled: "+key)
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
			reasons = append(reasons, "a direct datagram path reached the required rate in every required stratum; this is an input to a route decision, not one")
			return FindingUDPDirectViable, nil, reasons
		}
		reasons = append(reasons, "a direct datagram path did not reach the required rate in every required stratum")
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
