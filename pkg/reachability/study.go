// Package reachability implements the M0-R reachability study record format.
//
// The architecture treats direct sessions as the normal path and Relays as a
// minority fallback. That assumption is unmeasured, and it decides the
// milestone order, so it has to be measured before an implementation is
// frozen around it.
//
// Two properties matter more than the arithmetic. First, the acceptance
// policy is content-addressed and every report names the exact policy digest
// it was judged against, so thresholds cannot be chosen after the data is in.
// Second, a study that does not meet its own predeclared sample and operator
// minimums yields no route decision at all rather than a weak one: a
// laboratory result between two public hosts is a smoke test, and this package
// refuses to let it read as anything else.
package reachability

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"regexp"
	"sort"
	"strings"

	"github.com/tosnetwork/tos-messenger/internal/canon"
)

const (
	// TrialSchema is the strict record schema identifier.
	TrialSchema = "tos.messaging.reachability-trial.v1"
	// PolicySchema is the strict acceptance-policy schema identifier.
	PolicySchema = "tos.messaging.reachability-policy.v1"

	// MaxStrataPerPolicy bounds a predeclared stratum set.
	MaxStrataPerPolicy = 128
)

// AddressFamily is the address family a trial ran over.
type AddressFamily string

// Reachability is how many endpoints held a publicly reachable address.
type Reachability string

// NATBehavior is the observed mapping and filtering behavior.
type NATBehavior string

// Carrier is the access-network class.
type Carrier string

// UDPPolicy is what the network did to UDP.
type UDPPolicy string

// Mobility is the network-mobility event exercised during the trial.
type Mobility string

// EndpointClass is the hardware class of the measured endpoint.
type EndpointClass string

// Assistance is the port-mapping assistance available to the trial.
type Assistance string

// Outcome is the path a trial actually used.
type Outcome string

// FailureClass records why a direct session was not used.
type FailureClass string

// ProbeKind identifies the transport the trial exercised.
type ProbeKind string

// Enumerated dimension values. Every value is closed: an unrecognised label
// is rejected rather than silently aggregated into its own bucket, because a
// typo would otherwise create a cell that always looks under-sampled.
const (
	FamilyIPv4 AddressFamily = "ipv4"
	FamilyIPv6 AddressFamily = "ipv6"
	FamilyDual AddressFamily = "dual"

	BothPublic    Reachability = "both-public"
	OnePublic     Reachability = "one-public"
	NeitherPublic Reachability = "neither-public"

	NATNone                 NATBehavior = "none"
	NATEndpointIndependent  NATBehavior = "endpoint-independent"
	NATAddressDependent     NATBehavior = "address-dependent"
	NATAddressPortDependent NATBehavior = "address-and-port-dependent"
	NATSymmetric            NATBehavior = "symmetric"
	NATUndetermined         NATBehavior = "undetermined"

	CarrierDatacenter   Carrier = "datacenter"
	CarrierConsumerISP  Carrier = "consumer-isp"
	CarrierCarrierGrade Carrier = "carrier-grade-nat"
	CarrierMobile       Carrier = "mobile-carrier"

	UDPAllowed     UDPPolicy = "allowed"
	UDPRateLimited UDPPolicy = "rate-limited"
	UDPBlocked     UDPPolicy = "blocked"

	MobilityStationary    Mobility = "stationary"
	MobilityWiFiToMobile  Mobility = "wifi-to-mobile"
	MobilityMobileToWiFi  Mobility = "mobile-to-wifi"
	MobilityAddressChange Mobility = "address-change"
	MobilitySleepWake     Mobility = "sleep-wake"

	ClassServer   EndpointClass = "server"
	ClassDesktop  EndpointClass = "desktop"
	ClassEdgeARM  EndpointClass = "edge-arm"
	ClassEdgeRISC EndpointClass = "edge-riscv"
	ClassMobile   EndpointClass = "mobile"

	AssistanceNone       Assistance = "none"
	AssistanceStaticPort Assistance = "static-port-mapping"
	AssistanceDiscovery  Assistance = "discovery-assisted"

	OutcomeDirect        Outcome = "direct-established"
	OutcomeProxyFallback Outcome = "proxy-fallback"
	OutcomeRelayFallback Outcome = "relay-fallback"
	OutcomeHTTPSFallback Outcome = "https-fallback"
	OutcomeFailed        Outcome = "failed"

	FailureNone            FailureClass = "none"
	FailureNoCandidate     FailureClass = "no-candidate"
	FailureHandshake       FailureClass = "handshake-timeout"
	FailureUDPBlocked      FailureClass = "udp-blocked"
	FailureRateLimited     FailureClass = "rate-limited"
	FailureAddressChange   FailureClass = "address-change-lost"
	FailurePeerUnreachable FailureClass = "peer-unreachable"
	FailureInternal        FailureClass = "internal-error"

	ProbeUDP  ProbeKind = "udp"
	ProbeADNL ProbeKind = "adnl"
)

var (
	families      = set(FamilyIPv4, FamilyIPv6, FamilyDual)
	reachabilties = set(BothPublic, OnePublic, NeitherPublic)
	behaviors     = set(NATNone, NATEndpointIndependent, NATAddressDependent, NATAddressPortDependent, NATSymmetric, NATUndetermined)
	carriers      = set(CarrierDatacenter, CarrierConsumerISP, CarrierCarrierGrade, CarrierMobile)
	udpPolicies   = set(UDPAllowed, UDPRateLimited, UDPBlocked)
	mobilities    = set(MobilityStationary, MobilityWiFiToMobile, MobilityMobileToWiFi, MobilityAddressChange, MobilitySleepWake)
	classes       = set(ClassServer, ClassDesktop, ClassEdgeARM, ClassEdgeRISC, ClassMobile)
	assistances   = set(AssistanceNone, AssistanceStaticPort, AssistanceDiscovery)
	outcomes      = set(OutcomeDirect, OutcomeProxyFallback, OutcomeRelayFallback, OutcomeHTTPSFallback, OutcomeFailed)
	failures      = set(FailureNone, FailureNoCandidate, FailureHandshake, FailureUDPBlocked, FailureRateLimited, FailureAddressChange, FailurePeerUnreachable, FailureInternal)
	probes        = set(ProbeUDP, ProbeADNL)

	commitPattern   = regexp.MustCompile(`^[0-9a-f]{40}$|^[0-9a-f]{64}$`)
	operatorPattern = regexp.MustCompile(`^op_[0-9a-f]{16}$`)
)

func set[T ~string](values ...T) map[T]struct{} {
	membership := make(map[T]struct{}, len(values))
	for _, value := range values {
		membership[value] = struct{}{}
	}
	return membership
}

// Stratum is one cell of the measurement matrix.
type Stratum struct {
	Family        AddressFamily `json:"address_family"`
	Reachability  Reachability  `json:"public_reachability"`
	NATBehavior   NATBehavior   `json:"nat_behavior"`
	Carrier       Carrier       `json:"carrier"`
	UDPPolicy     UDPPolicy     `json:"udp_policy"`
	Mobility      Mobility      `json:"mobility"`
	EndpointClass EndpointClass `json:"endpoint_class"`
	Assistance    Assistance    `json:"mapping_assistance"`
}

// Key is the stable identity of a cell.
func (s Stratum) Key() string {
	buffer := &bytes.Buffer{}
	canon.Text(buffer, string(s.Family))
	canon.Text(buffer, string(s.Reachability))
	canon.Text(buffer, string(s.NATBehavior))
	canon.Text(buffer, string(s.Carrier))
	canon.Text(buffer, string(s.UDPPolicy))
	canon.Text(buffer, string(s.Mobility))
	canon.Text(buffer, string(s.EndpointClass))
	canon.Text(buffer, string(s.Assistance))
	return canon.Digest(buffer.Bytes())
}

// Validate enforces the closed dimension vocabulary.
func (s Stratum) Validate() error {
	if !member(families, s.Family) || !member(reachabilties, s.Reachability) ||
		!member(behaviors, s.NATBehavior) || !member(carriers, s.Carrier) ||
		!member(udpPolicies, s.UDPPolicy) || !member(mobilities, s.Mobility) ||
		!member(classes, s.EndpointClass) || !member(assistances, s.Assistance) {
		return errors.New("invalid reachability stratum")
	}
	if s.Reachability == BothPublic && s.NATBehavior != NATNone {
		return errors.New("a stratum with two public endpoints cannot also describe NAT behavior")
	}
	if s.Reachability != BothPublic && s.NATBehavior == NATNone {
		return errors.New("a stratum behind NAT must describe its NAT behavior")
	}
	return nil
}

func member[T ~string](membership map[T]struct{}, value T) bool {
	_, found := membership[value]
	return found
}

// Trial is one measured attempt.
type Trial struct {
	Stratum         Stratum      `json:"stratum"`
	OperatorID      string       `json:"operator_id"`
	Probe           ProbeKind    `json:"probe"`
	Outcome         Outcome      `json:"outcome"`
	Failure         FailureClass `json:"failure_class"`
	EstablishMillis uint64       `json:"establish_millis"`
	ReconnectMillis uint64       `json:"reconnect_millis,omitempty"`
	SurvivalSeconds uint64       `json:"survival_seconds,omitempty"`
	StartedAtUnix   uint64       `json:"started_at_unix"`
	LocalCommit     string       `json:"local_commit"`
	PeerCommit      string       `json:"peer_commit"`
	TxBytes         uint64       `json:"tx_bytes,omitempty"`
	RxBytes         uint64       `json:"rx_bytes,omitempty"`
	PeakRSSBytes    uint64       `json:"peak_rss_bytes,omitempty"`
}

type wireTrial struct {
	Schema string `json:"schema"`
	Trial
}

// Validate enforces the internal consistency of one record.
//
// The outcome and the failure class are cross-checked in both directions. A
// trial that claims a direct session while naming a failure, or claims a
// fallback without naming what it fell back from, is not a weak data point --
// it is an unusable one, and averaging it would quietly move the decision.
func (t Trial) Validate() error {
	if err := t.Stratum.Validate(); err != nil {
		return err
	}
	if !operatorPattern.MatchString(t.OperatorID) {
		return errors.New("invalid trial operator identifier")
	}
	if !member(probes, t.Probe) || !member(outcomes, t.Outcome) || !member(failures, t.Failure) {
		return errors.New("invalid trial vocabulary")
	}
	if t.StartedAtUnix == 0 {
		return errors.New("trial has no start time")
	}
	if !commitPattern.MatchString(t.LocalCommit) || !commitPattern.MatchString(t.PeerCommit) {
		return errors.New("trial must name the exact commits it measured")
	}
	if t.Outcome == OutcomeDirect {
		if t.Failure != FailureNone {
			return errors.New("a direct session cannot also report a failure")
		}
		if t.EstablishMillis == 0 {
			return errors.New("a direct session must report its establishment latency")
		}
	} else {
		if t.Failure == FailureNone {
			return errors.New("a trial without a direct session must classify the failure")
		}
		if t.Outcome == OutcomeFailed && t.EstablishMillis != 0 {
			return errors.New("a failed trial cannot report an establishment latency")
		}
	}
	if t.ReconnectMillis != 0 && t.Outcome != OutcomeDirect {
		return errors.New("reconnect latency requires a direct session")
	}
	if t.SurvivalSeconds != 0 && t.Outcome != OutcomeDirect {
		return errors.New("session survival requires a direct session")
	}
	return nil
}

// CanonicalBytes returns the digest preimage of a trial.
func (t Trial) CanonicalBytes() ([]byte, error) {
	if err := t.Validate(); err != nil {
		return nil, err
	}
	buffer := bytes.NewBufferString(canon.DomainReachabilityTrial)
	canon.Text(buffer, TrialSchema)
	canon.Text(buffer, t.Stratum.Key())
	canon.Text(buffer, t.OperatorID)
	canon.Text(buffer, string(t.Probe))
	canon.Text(buffer, string(t.Outcome))
	canon.Text(buffer, string(t.Failure))
	canon.Uint64(buffer, t.EstablishMillis)
	canon.Uint64(buffer, t.ReconnectMillis)
	canon.Uint64(buffer, t.SurvivalSeconds)
	canon.Uint64(buffer, t.StartedAtUnix)
	canon.Text(buffer, t.LocalCommit)
	canon.Text(buffer, t.PeerCommit)
	canon.Uint64(buffer, t.TxBytes)
	canon.Uint64(buffer, t.RxBytes)
	canon.Uint64(buffer, t.PeakRSSBytes)
	return buffer.Bytes(), nil
}

// Digest identifies one trial record.
func (t Trial) Digest() (string, error) {
	preimage, err := t.CanonicalBytes()
	if err != nil {
		return "", err
	}
	return canon.Digest(preimage), nil
}

// EncodeTrialJSON returns one line of the study log.
func EncodeTrialJSON(trial Trial) ([]byte, error) {
	if err := trial.Validate(); err != nil {
		return nil, err
	}
	return json.Marshal(wireTrial{Schema: TrialSchema, Trial: trial})
}

// DecodeTrialJSON rejects unknown fields, trailing data, and inconsistent
// records.
func DecodeTrialJSON(raw []byte) (Trial, error) {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	var value wireTrial
	if err := decoder.Decode(&value); err != nil {
		return Trial{}, err
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return Trial{}, errors.New("trial has trailing JSON")
	}
	if value.Schema != TrialSchema {
		return Trial{}, errors.New("unsupported trial schema")
	}
	if err := value.Trial.Validate(); err != nil {
		return Trial{}, err
	}
	return value.Trial, nil
}

// DecodeTrialLog reads a study log and refuses duplicate records. A duplicate
// digest is a re-imported file or a replayed record, and either one inflates a
// sample count that the decision threshold depends on.
func DecodeTrialLog(raw []byte) ([]Trial, error) {
	var trials []Trial
	seen := make(map[string]struct{})
	for index, line := range bytes.Split(raw, []byte("\n")) {
		trimmed := bytes.TrimSpace(line)
		if len(trimmed) == 0 {
			continue
		}
		trial, err := DecodeTrialJSON(trimmed)
		if err != nil {
			return nil, errors.New("invalid trial on line " + itoa(index+1) + ": " + err.Error())
		}
		digest, err := trial.Digest()
		if err != nil {
			return nil, err
		}
		if _, duplicate := seen[digest]; duplicate {
			return nil, errors.New("duplicate trial on line " + itoa(index+1))
		}
		seen[digest] = struct{}{}
		trials = append(trials, trial)
	}
	if len(trials) == 0 {
		return nil, errors.New("study log contains no trials")
	}
	return trials, nil
}

func itoa(value int) string {
	if value == 0 {
		return "0"
	}
	var digits []byte
	for value > 0 {
		digits = append([]byte{byte('0' + value%10)}, digits...)
		value /= 10
	}
	return string(digits)
}

// percentile returns the nearest-rank percentile of a sample set.
func percentile(samples []uint64, rank int) uint64 {
	if len(samples) == 0 || rank <= 0 || rank > 100 {
		return 0
	}
	ordered := append([]uint64(nil), samples...)
	sort.Slice(ordered, func(i, j int) bool { return ordered[i] < ordered[j] })
	index := (rank*len(ordered) + 99) / 100
	if index < 1 {
		index = 1
	}
	if index > len(ordered) {
		index = len(ordered)
	}
	return ordered[index-1]
}

// OperatorID derives the opaque operator identifier used for diversity
// counting.
//
// The report needs to know how many independent operators contributed to a
// cell, never which ones. Deriving a stable opaque value from a local name
// gives the count without collecting the identity, and without operators
// having to coordinate identifiers with anyone.
func OperatorID(name string) (string, error) {
	trimmed := strings.TrimSpace(name)
	if trimmed == "" || len(trimmed) > 128 || trimmed != name {
		return "", errors.New("invalid operator name")
	}
	buffer := bytes.NewBufferString(canon.DomainReachabilityOperator)
	canon.Text(buffer, trimmed)
	digest := canon.Digest(buffer.Bytes())
	return "op_" + digest[len("sha256:"):len("sha256:")+16], nil
}
