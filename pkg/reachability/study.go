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

	// MaxScenariosPerPolicy bounds a predeclared scenario set.
	MaxScenariosPerPolicy = 128
)

// AddressFamily is the address family a trial ran over.
type AddressFamily string

// Reachability is whether one endpoint held a publicly reachable address.
//
// It is a property of an endpoint, not of a pair. The joint label a route
// decision reads -- both public, one public, neither -- is derived from the two
// endpoints rather than declared, because neither endpoint can observe it and
// asking both to agree on it is asking them to agree about the other's network.
type Reachability string

// NATBehavior is the observed mapping behavior: which external address a
// socket appears at toward different destinations. It deliberately says
// nothing about filtering -- which remote sources may reach that address
// inbound -- because the two are independent axes and the bind reflections
// that classify the mapping collect no filtering evidence. Filtering has its
// own evidence (FilteringObservation) and its own vocabulary
// (FilteringBehavior), derived rather than declared.
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

// Role is which half of a measured pair produced a trial.
type Role string

const (
	// RoleA is the endpoint that initiated the session.
	RoleA Role = "a"
	// RoleB is the endpoint that joined it.
	RoleB Role = "b"
)

// Enumerated dimension values. Every value is closed: an unrecognised label
// is rejected rather than silently aggregated into its own bucket, because a
// typo would otherwise create a cell that always looks under-sampled.
const (
	FamilyIPv4 AddressFamily = "ipv4"
	FamilyIPv6 AddressFamily = "ipv6"
	FamilyDual AddressFamily = "dual"

	// PublicAddress means this endpoint held an address a peer could reach
	// without traversal.
	PublicAddress Reachability = "public"
	// BehindNAT means it did not.
	BehindNAT Reachability = "behind-nat"

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
	reachabilties = set(PublicAddress, BehindNAT)
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
	pairPattern     = regexp.MustCompile(`^pair_[0-9a-f]{32}$`)
	sitePattern     = regexp.MustCompile(`^site_[0-9a-f]{16}$`)
)

func set[T ~string](values ...T) map[T]struct{} {
	membership := make(map[T]struct{}, len(values))
	for _, value := range values {
		membership[value] = struct{}{}
	}
	return membership
}

// EndpointStratum is what one endpoint declares about itself.
//
// Every field here is local knowledge: an endpoint knows its own carrier, its
// own hardware, what its own network does to UDP, and what mapping assistance
// it has. It knows none of that about its peer, which is why the measurement
// matrix is built from two of these rather than from one label both sides have
// to agree on. Requiring agreement would have made the interesting pairs -- a
// home node against a datacenter Agent, a phone against a machine behind
// carrier-grade NAT -- impossible to express, because those pairs differ on
// every field by definition.
//
// Local knowledge is not the same as trustworthy, and the strata a route
// decision reads are the ones an operator has a reason to get wrong. Two of
// them are now cross-checked against the coordinator-signed evidence rather
// than taken on faith:
//
//   - Family is checked in VerifyTrial against the family of the signed
//     Observed address: a trial whose declared family contradicts what the
//     coordinator was reached over is rejected and not counted.
//   - Reachability is checked at pairing (see combine): each half's signed
//     PeerPublic observation about its peer must agree with the other half's
//     declared reachability, so a side cannot self-declare "public" while the
//     coordinator saw its peer treat it as behind NAT.
//   - NATBehavior's mapping class is checked in VerifyTrial against the
//     per-coordinator BindObservations the trial carries: endpoint-independent
//     when two or more distinct coordinators reflected the same external
//     address, address-and-port-dependent when they differ. A declaration that
//     contradicts the signed reflections is rejected and not counted.
//
// The mapping check is a refutation, not a full derivation. With fewer than two
// distinct coordinator reflections the class is undetermined and the
// declaration stands unchecked. The no-NAT (none) case is never credited
// remotely at all: bind reflections cannot distinguish a truly public endpoint
// from one behind an endpoint-independent NAT, so a "none" declaration is
// accepted where "endpoint-independent" would be and refuted where it would be,
// and every consumer of the derived class must keep the two in that one
// evidentiary bucket rather than treating "none" as verified.
//
// FILTERING behaviour -- whether unsolicited inbound datagrams are admitted --
// is a separate axis with its own coordinator-signed evidence: the
// FilteringObservations a trial carries, each a proof that a datagram from a
// cold source was demonstrably received. It has no declared counterpart at all;
// DeriveFiltering computes the class from the receipts or reports it
// undetermined.
//
// Carrier, EndpointClass, Mobility, and Assistance are legitimately
// operator-self-reported: they are facts about the operator's own deployment
// that no coordinator can independently witness, so they stay attested.
type EndpointStratum struct {
	Family        AddressFamily `json:"address_family"`
	Reachability  Reachability  `json:"public_reachability"`
	NATBehavior   NATBehavior   `json:"nat_behavior"`
	Carrier       Carrier       `json:"carrier"`
	UDPPolicy     UDPPolicy     `json:"udp_policy"`
	Mobility      Mobility      `json:"mobility"`
	EndpointClass EndpointClass `json:"endpoint_class"`
	Assistance    Assistance    `json:"mapping_assistance"`
}

// Key is the stable identity of one endpoint's situation.
func (e EndpointStratum) Key() string {
	buffer := &bytes.Buffer{}
	e.canonical(buffer)
	return canon.Digest(buffer.Bytes())
}

func (e EndpointStratum) canonical(buffer *bytes.Buffer) {
	canon.Text(buffer, string(e.Family))
	canon.Text(buffer, string(e.Reachability))
	canon.Text(buffer, string(e.NATBehavior))
	canon.Text(buffer, string(e.Carrier))
	canon.Text(buffer, string(e.UDPPolicy))
	canon.Text(buffer, string(e.Mobility))
	canon.Text(buffer, string(e.EndpointClass))
	canon.Text(buffer, string(e.Assistance))
}

// Validate enforces the closed dimension vocabulary.
func (e EndpointStratum) Validate() error {
	if !member(families, e.Family) || !member(reachabilties, e.Reachability) ||
		!member(behaviors, e.NATBehavior) || !member(carriers, e.Carrier) ||
		!member(udpPolicies, e.UDPPolicy) || !member(mobilities, e.Mobility) ||
		!member(classes, e.EndpointClass) || !member(assistances, e.Assistance) {
		return errors.New("invalid endpoint stratum")
	}
	if e.Reachability == PublicAddress && e.NATBehavior != NATNone {
		return errors.New("a publicly addressable endpoint cannot also describe NAT behavior")
	}
	if e.Reachability == BehindNAT && e.NATBehavior == NATNone {
		return errors.New("an endpoint behind NAT must describe its NAT behavior")
	}
	return nil
}

// Scenario is one cell of the measurement matrix: an ordered pair of endpoint
// situations.
//
// The order is the initiating direction, and it is kept rather than
// normalised. Which side opens the session decides whether a mapping exists
// when the first packet arrives, so a phone calling a server and a server
// calling a phone are two measurements, not one measured twice.
type Scenario struct {
	Initiator EndpointStratum `json:"initiator"`
	Responder EndpointStratum `json:"responder"`
}

// Key is the stable identity of a cell.
func (s Scenario) Key() string {
	buffer := &bytes.Buffer{}
	s.Initiator.canonical(buffer)
	s.Responder.canonical(buffer)
	return canon.Digest(buffer.Bytes())
}

// Validate enforces the vocabulary on both sides.
func (s Scenario) Validate() error {
	if err := s.Initiator.Validate(); err != nil {
		return err
	}
	return s.Responder.Validate()
}

// PairReachability is the joint label, derived rather than declared.
func (s Scenario) PairReachability() string {
	public := 0
	if s.Initiator.Reachability == PublicAddress {
		public++
	}
	if s.Responder.Reachability == PublicAddress {
		public++
	}
	switch public {
	case 2:
		return "both-public"
	case 1:
		return "one-public"
	default:
		return "neither-public"
	}
}

// Asymmetric reports whether the two sides differ at all. A study made
// entirely of matched pairs has not measured the deployments the architecture
// is actually about.
func (s Scenario) Asymmetric() bool {
	return s.Initiator.Key() != s.Responder.Key()
}

func member[T ~string](membership map[T]struct{}, value T) bool {
	_, found := membership[value]
	return found
}

// Trial is one measured attempt, from one side.
type Trial struct {
	// Local is what this endpoint declares about itself, and nothing about its
	// peer. The cell a measurement lands in is built by pairing the two halves.
	Local EndpointStratum `json:"endpoint"`
	// PairID is shared by the two endpoints of one measurement, so the two
	// halves of an attempt can be recognised as one attempt rather than
	// counted as two independent successes.
	PairID string `json:"pair_id"`
	// SiteID identifies the network an operator ran from. One operator with
	// twenty hosts on one uplink has measured one network, not twenty.
	SiteID     string `json:"site_id"`
	OperatorID string `json:"operator_id"`
	// SessionID and Role tie this half of a measurement to the attestation the
	// coordinator made about it.
	SessionID   string      `json:"session_id"`
	Role        Role        `json:"role"`
	Observation Observation `json:"observation"`
	// BindObservations are the per-coordinator reflections the endpoint's own
	// external address was seen at, one signed by each coordinator it bound to.
	// They carry the evidence the NAT mapping class is derived from, and they
	// are folded into the trial's canonical preimage so the endpoint signature
	// covers them: a set swapped after signing breaks the signature.
	BindObservations []BindObservation `json:"bind_observations,omitempty"`
	// FilteringObservations are the per-coordinator receipts of cold-source
	// probes: each one is a coordinator's signed statement that a datagram it
	// sent from a source this endpoint never contacted was demonstrably
	// received. They carry the evidence the filtering class is derived from,
	// and they are folded into the trial's canonical preimage so the endpoint
	// signature covers them.
	FilteringObservations []FilteringObservation `json:"filtering_observations,omitempty"`
	EndpointPublicKeyHex  string                 `json:"endpoint_public_key_hex"`
	EndpointSignatureHex  string                 `json:"endpoint_signature_hex,omitempty"`

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
	if err := t.Local.Validate(); err != nil {
		return err
	}
	if !operatorPattern.MatchString(t.OperatorID) {
		return errors.New("invalid trial operator identifier")
	}
	if !pairPattern.MatchString(t.PairID) {
		return errors.New("invalid trial pair identifier")
	}
	// The pair identifier is derived, not declared. A field a reporter chooses
	// freely cannot tie two halves of one measurement together.
	derived, err := PairID(t.SessionID)
	if err != nil || derived != t.PairID {
		return errors.New("trial pair identifier is not derived from its session")
	}
	if !sitePattern.MatchString(t.SiteID) {
		return errors.New("invalid trial site identifier")
	}
	if t.SessionID == "" || len(t.SessionID) > 128 {
		return errors.New("invalid trial session identifier")
	}
	if t.Role != RoleA && t.Role != RoleB {
		return errors.New("invalid trial role")
	}
	if !keyPattern.MatchString(t.EndpointPublicKeyHex) {
		return errors.New("invalid trial endpoint public key")
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
	// Bind observations are bounded and well-shaped before anything is derived
	// from them. Each coordinator reflects once, so a set with the same
	// coordinator twice is malformed: it would let a reporter pad the distinct
	// count with duplicates, or slip two conflicting reflections under one name.
	if len(t.BindObservations) > MaxBindObservations {
		return errors.New("too many bind observations")
	}
	seenBindCoordinators := make(map[string]struct{}, len(t.BindObservations))
	for _, observation := range t.BindObservations {
		if err := validateBindObservationShape(observation, true); err != nil {
			return err
		}
		if _, duplicate := seenBindCoordinators[observation.CoordinatorID]; duplicate {
			return errors.New("a coordinator bound more than once")
		}
		seenBindCoordinators[observation.CoordinatorID] = struct{}{}
	}
	// Filtering observations are bounded and well-shaped the same way. One
	// coordinator attests at most once per cold source kind: a duplicate would
	// let a reporter pad the set, or slip two conflicting receipts under one
	// name.
	if len(t.FilteringObservations) > MaxFilteringObservations {
		return errors.New("too many filtering observations")
	}
	seenFilterSources := make(map[string]struct{}, len(t.FilteringObservations))
	for _, observation := range t.FilteringObservations {
		if err := validateFilteringObservationShape(observation, true); err != nil {
			return err
		}
		key := observation.CoordinatorID + "|" + string(observation.Source)
		if _, duplicate := seenFilterSources[key]; duplicate {
			return errors.New("a coordinator attested the same filter source more than once")
		}
		seenFilterSources[key] = struct{}{}
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
	canon.Text(buffer, t.Local.Key())
	canon.Text(buffer, t.PairID)
	canon.Text(buffer, t.SiteID)
	canon.Text(buffer, t.OperatorID)
	canon.Text(buffer, t.SessionID)
	canon.Text(buffer, string(t.Role))
	canon.Text(buffer, t.EndpointPublicKeyHex)
	canon.Text(buffer, t.Observation.CoordinatorID)
	canon.Text(buffer, t.Observation.Observed)
	canon.Text(buffer, t.Observation.PeerPublic)
	canon.Text(buffer, t.Observation.SignatureHex)
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
	// The bind observations are folded in so the endpoint signature covers the
	// mapping evidence in the exact order and content the trial carries. The
	// coordinator id, reflected address, and coordinator signature of each are
	// what the mapping is derived from, so committing to them is what stops the
	// set from being rewritten after signing.
	canon.Uint32(buffer, uint32(len(t.BindObservations)))
	for _, observation := range t.BindObservations {
		canon.Text(buffer, observation.CoordinatorID)
		canon.Text(buffer, observation.Observed)
		canon.Text(buffer, observation.SignatureHex)
	}
	// The filtering observations are folded in the same additive, count-prefixed
	// way: a trial that carries none commits an empty set, and one that carries
	// receipts commits exactly which coordinator attested which cold source, so
	// the set cannot be rewritten after signing.
	canon.Uint32(buffer, uint32(len(t.FilteringObservations)))
	for _, observation := range t.FilteringObservations {
		canon.Text(buffer, observation.CoordinatorID)
		canon.Text(buffer, string(observation.Source))
		canon.Text(buffer, observation.Observed)
		canon.Text(buffer, observation.SignatureHex)
	}
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

// SiteID derives the opaque site identifier used to tell one network from
// another within an operator.
func SiteID(name string) (string, error) {
	digest, err := opaque(canon.DomainReachabilitySite, name)
	if err != nil {
		return "", errors.New("invalid site name")
	}
	return "site_" + digest[:16], nil
}

// PairID derives the identifier the two endpoints of one measurement share.
func PairID(session string) (string, error) {
	digest, err := opaque(canon.DomainReachabilityPairID, session)
	if err != nil {
		return "", errors.New("invalid pair session")
	}
	return "pair_" + digest[:32], nil
}

func opaque(domain, name string) (string, error) {
	trimmed := strings.TrimSpace(name)
	if trimmed == "" || len(trimmed) > 128 || trimmed != name {
		return "", errors.New("invalid name")
	}
	buffer := bytes.NewBufferString(domain)
	canon.Text(buffer, trimmed)
	digest := canon.Digest(buffer.Bytes())
	return digest[len("sha256:"):], nil
}

// OperatorID derives the opaque operator identifier used for diversity
// counting.
//
// The report needs to know how many distinct operators contributed to a cell,
// never which ones. Deriving a stable opaque value from a local name gives the
// count without collecting the identity, and without operators having to
// coordinate identifiers with anyone.
//
// The identifier is self-declared. It makes two submissions from one name
// recognisable as one operator; it does not prove that two names are two
// parties. Shared endpoint keys are what catches the obvious case, and the
// report says how many it caught.
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
