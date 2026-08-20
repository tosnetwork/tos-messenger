package reachability

import (
	"bytes"
	"errors"
	"sort"

	"github.com/tosnetwork/tos-messenger/internal/canon"
)

// pairResult is one complete measurement: two halves that agree.
//
// The unit of evidence is the pair, not the trial. One endpoint's account of
// a session is an assertion; two endpoints, holding different keys and signing
// separately, asserting the same thing is a measurement. Anything that arrives
// as half a pair, or as two halves that contradict each other, is dropped and
// counted rather than averaged in.
type pairResult struct {
	scenario Scenario
	// digest orders pairs independently of arrival, so a per-operator cap
	// truncates the same set whatever order the trials were submitted in.
	digest    string
	operators []string
	sites     []string

	outcome Outcome
	// failures holds the classes the two halves reported. They may legitimately
	// differ -- each side sees its own end of the failure -- so both are kept.
	failures []FailureClass
	// establish and reconnect take the slower half: a session exists once both
	// ends have it. survival takes the shorter half, for the same reason in
	// reverse.
	establish uint64
	reconnect uint64
	// survival is only set when both halves measured it. A zero from one side
	// means "not measured", not "the other side's number speaks for both", and
	// treating it as the latter would report one endpoint's session lifetime
	// as a pair's.
	survival         uint64
	survivalMeasured bool
	// The phase statuses join the two halves' booleans, and each join follows
	// what the phase is. A hold was attempted by the pair only when BOTH
	// halves ran it -- session survival needs both halves, and one side
	// holding alone measured its own patience, not a session -- and completed
	// only when both survived the full window. The halves may honestly
	// disagree about completion (one side's keepalives die first), so a
	// completion mismatch joins by AND rather than dropping the pair as a
	// contradiction: these are per-phase outcomes, not descriptions of one
	// shared fact. Reconnect is initiator-only by design -- the responder
	// never dials, and the collector refuses the flag on it -- so the pair's
	// reconnect status is the OR across halves, mirroring how the reconnect
	// latency already takes the max. The tunnel hold joins exactly as the
	// direct hold does.
	holdAttempted       bool
	holdCompleted       bool
	reconnectAttempted  bool
	reconnectSucceeded  bool
	tunnelHoldAttempted bool
	tunnelHoldCompleted bool
	// initiatorFiltering and responderFiltering are the filtering classes
	// derived from each half's coordinator-signed cold-source receipts.
	// Filtering is a property of each end, not of the pair, so each side gets
	// its own class rather than the two being folded into one label. A half
	// that carried no receipts derives undetermined, which is that word's
	// documented meaning: silence is not evidence.
	initiatorFiltering FilteringBehavior
	responderFiltering FilteringBehavior
}

// combine folds the two halves of a measurement into one sample.
//
// The halves must agree on everything the decision depends on: the probe, the
// outcome, and which commits were running on each side. They must also come
// from two different keys in the two different roles, because a "pair" one
// host produced by itself is a single assertion wearing two hats.
//
// They are deliberately not required to agree on the cell. Each half describes
// only its own end, and the cell is the ordered pair of those descriptions.
func combine(halves []Trial) (pairResult, error) {
	if len(halves) != 2 {
		return pairResult{}, errors.New("a measurement needs exactly two halves")
	}
	a, b := halves[0], halves[1]
	if a.Role == RoleB {
		a, b = b, a
	}
	if a.Role != RoleA || b.Role != RoleB {
		return pairResult{}, errors.New("a measurement needs one half in each role")
	}
	if a.EndpointPublicKeyHex == b.EndpointPublicKeyHex {
		return pairResult{}, errors.New("both halves of a measurement were signed by one key")
	}
	if a.SessionID != b.SessionID || a.Probe != b.Probe {
		return pairResult{}, errors.New("the halves describe different sessions")
	}
	if a.Outcome != b.Outcome {
		return pairResult{}, errors.New("the halves disagree about the outcome")
	}
	// Crossed, not equal: what A ran is what B saw its peer run.
	if a.LocalCommit != b.PeerCommit || a.PeerCommit != b.LocalCommit {
		return pairResult{}, errors.New("the halves disagree about which commits were measured")
	}
	// The collector-manifest digests cross the same way, and for the same
	// reason: with per-implementation collectors, which build each side ran is
	// part of what was measured, and two halves that disagree about it are a
	// contradiction to drop and count, not a sample.
	if a.LocalManifestDigest != b.PeerManifestDigest || a.PeerManifestDigest != b.LocalManifestDigest {
		return pairResult{}, errors.New("the halves disagree about which collector manifests were measured")
	}
	// The coordinator signs, about each endpoint, whether that endpoint's peer
	// was publicly addressable -- the one reachability fact an endpoint cannot
	// observe about itself. Each half's signed peer observation is cross-checked
	// against the other half's self-declared reachability, so a side that
	// declares public while the coordinator saw its peer treat it as non-public
	// (or the reverse) is a pair the signed evidence contradicts. This makes the
	// reachability stratum evidence-checked rather than self-attested.
	if !peerReachabilityConsistent(a.Observation.PeerPublic, b.Local.Reachability) ||
		!peerReachabilityConsistent(b.Observation.PeerPublic, a.Local.Reachability) {
		return pairResult{}, errors.New("a coordinator's signed peer observation contradicts the other half's declared reachability")
	}
	digestA, err := a.Digest()
	if err != nil {
		return pairResult{}, err
	}
	digestB, err := b.Digest()
	if err != nil {
		return pairResult{}, err
	}

	result := pairResult{
		// The cell is built from the two halves rather than agreed between
		// them. Each endpoint describes only itself, which is the only thing
		// it can describe honestly.
		scenario:  Scenario{Initiator: a.Local, Responder: b.Local},
		digest:    canonPairDigest(digestA, digestB),
		operators: distinct(a.OperatorID, b.OperatorID),
		sites:     distinct(a.SiteID, b.SiteID),
		outcome:   a.Outcome,
		establish: maxOf(a.EstablishMillis, b.EstablishMillis),
		reconnect: maxOf(a.ReconnectMillis, b.ReconnectMillis),
		// The receipts were already verified: only trials that passed VerifyTrial
		// reach pairing, so a forged or misattributed receipt never gets here. The
		// derivation itself is evidence-only -- see DeriveFiltering.
		initiatorFiltering: DeriveFiltering(a.FilteringObservations),
		responderFiltering: DeriveFiltering(b.FilteringObservations),
	}
	if a.Failure != FailureNone {
		result.failures = append(result.failures, a.Failure)
	}
	if b.Failure != FailureNone && b.Failure != a.Failure {
		result.failures = append(result.failures, b.Failure)
	}
	if a.SurvivalSeconds != 0 && b.SurvivalSeconds != 0 {
		result.survival = minOf(a.SurvivalSeconds, b.SurvivalSeconds)
		result.survivalMeasured = true
	}
	// The phase joins: holds by AND on both booleans (the pair held only while
	// both ends did), reconnect by OR (only the initiator can attempt it), the
	// tunnel hold exactly as the direct one. See the field comment for why a
	// completion mismatch is a measurement rather than a contradiction.
	result.holdAttempted = a.HoldAttempted && b.HoldAttempted
	result.holdCompleted = a.HoldCompleted && b.HoldCompleted
	result.reconnectAttempted = a.ReconnectAttempted || b.ReconnectAttempted
	result.reconnectSucceeded = a.ReconnectSucceeded || b.ReconnectSucceeded
	result.tunnelHoldAttempted = a.TunnelHoldAttempted && b.TunnelHoldAttempted
	result.tunnelHoldCompleted = a.TunnelHoldCompleted && b.TunnelHoldCompleted
	return result, nil
}

// peerReachabilityConsistent reports whether a coordinator's signed peer bit
// agrees with the reachability the other half declared about itself. The
// coordinator observes "yes" for a publicly addressable peer and "no" for one
// behind NAT; anything else is treated as a contradiction.
func peerReachabilityConsistent(peerPublic string, declared Reachability) bool {
	switch declared {
	case PublicAddress:
		return peerPublic == "yes"
	case BehindNAT:
		return peerPublic == "no"
	default:
		return false
	}
}

func canonPairDigest(a, b string) string {
	if b < a {
		a, b = b, a
	}
	buffer := bytes.NewBufferString(canon.DomainReachabilityPairResult)
	canon.Text(buffer, a)
	canon.Text(buffer, b)
	return canon.Digest(buffer.Bytes())
}

func distinct(values ...string) []string {
	seen := map[string]struct{}{}
	unique := make([]string, 0, len(values))
	for _, value := range values {
		if _, repeated := seen[value]; repeated {
			continue
		}
		seen[value] = struct{}{}
		unique = append(unique, value)
	}
	sort.Strings(unique)
	return unique
}

func maxOf(a, b uint64) uint64 {
	if a > b {
		return a
	}
	return b
}

func minOf(a, b uint64) uint64 {
	if a < b {
		return a
	}
	return b
}
