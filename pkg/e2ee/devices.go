package e2ee

import (
	"bytes"
	"errors"
	"sort"
	"time"

	"github.com/tosnetwork/tos-messenger/internal/canon"
	"github.com/tosnetwork/tos-messenger/internal/ids"
)

var (
	// ErrSetRollback reports an observed publication older than the accepted
	// freshness watermark.
	ErrSetRollback = errors.New("prekey device set rolled back")
	// ErrSetEquivocation reports different non-retirement content at the same
	// freshness watermark. The two digests are intentionally not tie-broken:
	// arrival order is not endpoint authority.
	ErrSetEquivocation = errors.New("prekey device set equivocated")
)

// SetEquivocationError identifies the two conflicting commitments. The
// caller already holds the signed candidate set and can export this summary
// alongside it; errors.Is(err, ErrSetEquivocation) classifies the refusal.
type SetEquivocationError struct {
	CurrentDigest   string
	CandidateDigest string
	IssuedAtUnix    uint64
}

func (e *SetEquivocationError) Error() string { return ErrSetEquivocation.Error() }

// Unwrap supports errors.Is without discarding the conflicting digests.
func (e *SetEquivocationError) Unwrap() error { return ErrSetEquivocation }

// SetSummary is what a receiver remembers about a peer's device set.
//
// It is the anchor for two protections a single set cannot provide. Rollback:
// a peer's directory entry can be replayed by whoever can reach the DHT, so
// the receiver keeps the newest set it has accepted and refuses regressions.
// Revocation: a device removed from the set must stay removed, so the summary
// is judged against tombstones the receiver also keeps.
type SetSummary struct {
	// Digest is the set's identity, as committed in the descriptor.
	Digest string
	// EndpointID is whose devices these are.
	EndpointID string
	// DeviceIDs is the sorted device list.
	DeviceIDs []string
	// BundleDigests is the sorted per-bundle digest list. It is what lets a
	// pure retirement be recognised: a successor whose bundles are a subset of
	// the current ones removed devices and changed nothing else.
	BundleDigests []string
	// NewestIssuedAtUnix is the freshest issuance in the set. A successor that
	// is not a pure retirement must be strictly fresher, which is what stops
	// an old set being replayed as a new one.
	NewestIssuedAtUnix uint64
}

// Summarize reduces a valid set to what succession is judged on.
func Summarize(bundles []Bundle) (SetSummary, error) {
	if err := ValidateSet(bundles); err != nil {
		return SetSummary{}, err
	}
	digest, err := SetDigest(bundles)
	if err != nil {
		return SetSummary{}, err
	}
	summary := SetSummary{Digest: digest, EndpointID: bundles[0].EndpointID}
	for _, bundle := range bundles {
		summary.DeviceIDs = append(summary.DeviceIDs, bundle.DeviceID)
		bundleDigest, err := BundleDigest(bundle)
		if err != nil {
			return SetSummary{}, err
		}
		summary.BundleDigests = append(summary.BundleDigests, bundleDigest)
		if bundle.IssuedAtUnix > summary.NewestIssuedAtUnix {
			summary.NewestIssuedAtUnix = bundle.IssuedAtUnix
		}
	}
	sort.Strings(summary.DeviceIDs)
	sort.Strings(summary.BundleDigests)
	return summary, nil
}

// Succession is the outcome of judging a successor set.
type Succession struct {
	// Accepted is the summary to record.
	Accepted SetSummary
	// Removed are the devices this succession revoked. Their sessions are to
	// be closed, and their identifiers never return.
	Removed []string
}

// Succeed judges whether a set may replace the one on record.
//
// The rules are few and each has one reason:
//
//   - a device on the tombstone list never returns. Removal is revocation,
//     and revocation with an undo is a suggestion. A device that legitimately
//     comes back generates a fresh key, which is a fresh identifier;
//   - a pure retirement -- every bundle already in the current set, some
//     devices gone -- is accepted at the same freshness, because removing a
//     device should not require re-issuing everyone else's material;
//   - anything else must be strictly fresher than what is on record. Equal
//     freshness with different content is two sets claiming the same moment,
//     and the receiver has no way to order them except by whoever spoke last,
//     which is exactly the authority a replayed directory entry would have.
//
// current may be the zero SetSummary for a peer never seen before; tombstones
// still apply, because a first sight that includes an already-revoked device
// is a first sight of a forgery.
func Succeed(current SetSummary, tombstones map[string]struct{}, next []Bundle) (Succession, error) {
	summary, err := Summarize(next)
	if err != nil {
		return Succession{}, err
	}
	if current.EndpointID != "" && summary.EndpointID != current.EndpointID {
		return Succession{}, errors.New("a device set cannot change whose it is")
	}
	for _, device := range summary.DeviceIDs {
		if _, revoked := tombstones[device]; revoked {
			return Succession{}, errors.New("a revoked device cannot return to the set")
		}
	}
	if current.Digest == "" || summary.Digest == current.Digest {
		return Succession{Accepted: summary}, nil
	}

	removed := missingFrom(current.DeviceIDs, summary.DeviceIDs)
	// The freshness watermark never decreases. That single rule stops a
	// rollback even when the replayed old set is a strict subset of the
	// current one -- a subset that lowers the watermark is a replay of the
	// past wearing a retirement's shape. The cost is small and deliberate: to
	// retire the single newest-keyed device, the owner re-keys some other
	// device in the same publication, which publishing already re-signs.
	if summary.NewestIssuedAtUnix < current.NewestIssuedAtUnix {
		return Succession{}, ErrSetRollback
	}
	if isSubset(summary.BundleDigests, current.BundleDigests) {
		// A pure retirement: nothing new was issued, devices only left, and
		// the watermark held.
		if len(removed) == 0 {
			return Succession{}, errors.New("a successor set must change something")
		}
		return Succession{Accepted: summary, Removed: removed}, nil
	}
	if summary.NewestIssuedAtUnix == current.NewestIssuedAtUnix {
		// Same freshness, content that is not a pure retirement: two sets
		// claiming the same moment, orderable only by who spoke last.
		return Succession{}, &SetEquivocationError{
			CurrentDigest: current.Digest, CandidateDigest: summary.Digest,
			IssuedAtUnix: summary.NewestIssuedAtUnix,
		}
	}
	return Succession{Accepted: summary, Removed: removed}, nil
}

func missingFrom(current, next []string) []string {
	present := make(map[string]struct{}, len(next))
	for _, device := range next {
		present[device] = struct{}{}
	}
	var missing []string
	for _, device := range current {
		if _, found := present[device]; !found {
			missing = append(missing, device)
		}
	}
	return missing
}

func isSubset(smaller, larger []string) bool {
	held := make(map[string]struct{}, len(larger))
	for _, digest := range larger {
		held[digest] = struct{}{}
	}
	for _, digest := range smaller {
		if _, found := held[digest]; !found {
			return false
		}
	}
	return true
}

// DeviceSessionID derives the session identifier for one device pair.
//
// It is deterministic and symmetric: both ends compute the same identifier
// without negotiating, because a session-identity handshake would be one more
// exchange that can disagree. One pair, one session, across conversations --
// the ratchet inside it is what provides freshness, not session churn.
func DeviceSessionID(deviceA, deviceB string) (string, error) {
	if !ids.Device.MatchString(deviceA) || !ids.Device.MatchString(deviceB) {
		return "", errors.New("a device session needs two device identifiers")
	}
	if deviceA == deviceB {
		return "", errors.New("a device does not hold a session with itself")
	}
	first, second := deviceA, deviceB
	if second < first {
		first, second = second, first
	}
	buffer := bytes.NewBufferString(canon.DomainDeviceSession)
	canon.Text(buffer, first)
	canon.Text(buffer, second)
	digest := canon.Digest(buffer.Bytes())
	return "ses_" + digest[len("sha256:"):], nil
}

// Target is one sealed copy the fan-out owes.
type Target struct {
	DeviceID  string
	SessionID string
	// Bootstrap reports that no session exists yet and one has to be built
	// from the device's published bundle.
	Bootstrap bool
	// BundleDigest names the bundle to bootstrap from, when Bootstrap is set.
	BundleDigest string
}

// Plan computes the per-device fan-out for one logical event.
//
// One event, one identifier, many sealed copies: every live device of the
// recipient gets one, and every other device of the sender gets one, so the
// sender's own devices agree about what was said. The event's identity is its
// content, so the copies are the same event, not siblings.
//
// sessionExists answers whether a session is already established; expired
// bundles are skipped for bootstrap but do not close established sessions,
// because a bundle only ever bootstraps -- the ratchet is the ongoing key.
// A recipient device whose bundle has expired and with whom no session exists
// is simply unreachable until its owner rotates, and the plan says so rather
// than guessing.
type PlanInput struct {
	// SenderDeviceID is this device.
	SenderDeviceID string
	// SenderSet is the sender's own current set, for self-fan-out.
	SenderSet []Bundle
	// RecipientSet is the recipient's current set.
	RecipientSet []Bundle
	// Now bounds bundle expiry for bootstraps.
	Now time.Time
	// SessionExists reports whether a session identifier is established.
	SessionExists func(sessionID string) bool
}

// Plan output: recipient targets, then self targets, both sorted by device.
type PlanResult struct {
	Recipients []Target
	// SelfCopies are the sender's other devices.
	SelfCopies []Target
	// Unreachable are recipient devices with no session and no live bundle.
	Unreachable []string
}

// FanOut plans the sealed copies for one event.
func FanOut(input PlanInput) (PlanResult, error) {
	if !ids.Device.MatchString(input.SenderDeviceID) {
		return PlanResult{}, errors.New("a fan-out needs the sending device")
	}
	if input.SessionExists == nil {
		return PlanResult{}, errors.New("a fan-out needs to know which sessions exist")
	}
	if input.Now.IsZero() || input.Now.Unix() < 0 {
		return PlanResult{}, errors.New("invalid fan-out time")
	}
	if err := ValidateSet(input.RecipientSet); err != nil {
		return PlanResult{}, err
	}
	if err := ValidateSet(input.SenderSet); err != nil {
		return PlanResult{}, err
	}
	senderListed := false
	for _, bundle := range input.SenderSet {
		if bundle.DeviceID == input.SenderDeviceID {
			senderListed = true
		}
	}
	if !senderListed {
		// A sender not in its own published set is a sender the world cannot
		// verify; planning around that would hide a rotation gone wrong.
		return PlanResult{}, errors.New("the sending device is not in its own published set")
	}

	result := PlanResult{}
	appendTarget := func(list []Target, bundle Bundle) ([]Target, bool, error) {
		sessionID, err := DeviceSessionID(input.SenderDeviceID, bundle.DeviceID)
		if err != nil {
			return list, false, err
		}
		if input.SessionExists(sessionID) {
			return append(list, Target{DeviceID: bundle.DeviceID, SessionID: sessionID}), true, nil
		}
		if uint64(input.Now.Unix()) >= bundle.ExpiresAtUnix {
			return list, false, nil
		}
		digest, err := BundleDigest(bundle)
		if err != nil {
			return list, false, err
		}
		return append(list, Target{
			DeviceID: bundle.DeviceID, SessionID: sessionID,
			Bootstrap: true, BundleDigest: digest,
		}), true, nil
	}

	for _, bundle := range input.RecipientSet {
		extended, reachable, err := appendTarget(result.Recipients, bundle)
		if err != nil {
			return PlanResult{}, err
		}
		result.Recipients = extended
		if !reachable {
			result.Unreachable = append(result.Unreachable, bundle.DeviceID)
		}
	}
	for _, bundle := range input.SenderSet {
		if bundle.DeviceID == input.SenderDeviceID {
			continue
		}
		extended, reachable, err := appendTarget(result.SelfCopies, bundle)
		if err != nil {
			return PlanResult{}, err
		}
		result.SelfCopies = extended
		if !reachable {
			result.Unreachable = append(result.Unreachable, bundle.DeviceID)
		}
	}
	sort.Slice(result.Recipients, func(i, j int) bool { return result.Recipients[i].DeviceID < result.Recipients[j].DeviceID })
	sort.Slice(result.SelfCopies, func(i, j int) bool { return result.SelfCopies[i].DeviceID < result.SelfCopies[j].DeviceID })
	sort.Strings(result.Unreachable)
	return result, nil
}
