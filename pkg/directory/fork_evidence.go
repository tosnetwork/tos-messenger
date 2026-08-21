package directory

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"sort"
	"time"

	"github.com/tosnetwork/tos-messenger/pkg/e2ee"
	"github.com/tosnetwork/tos-messenger/pkg/identity"
)

const (
	// DeviceForkEvidenceSchema is the exchange format for two independently
	// observed, Endpoint-authorized complete device publications.
	DeviceForkEvidenceSchema = "tos.messaging.device-fork-evidence.v1"
	// MaxDeviceForkEvidenceWireBytes bounds two Descriptors and two complete
	// bundle sets with fixed JSON overhead.
	MaxDeviceForkEvidenceWireBytes = 384 << 10
)

// DeviceForkEvidence is intentionally self-contained public evidence. Each
// Descriptor proves that the Endpoint published the adjacent complete set;
// individual bundle signatures alone would not prove complete publication.
type DeviceForkEvidence struct {
	Schema           string          `json:"schema"`
	FirstDescriptor  json.RawMessage `json:"first_descriptor"`
	FirstBundleSet   json.RawMessage `json:"first_bundle_set"`
	SecondDescriptor json.RawMessage `json:"second_descriptor"`
	SecondBundleSet  json.RawMessage `json:"second_bundle_set"`
}

// NewDeviceForkEvidence validates both authority chains, proves an
// equal-watermark non-retirement fork, and emits deterministic exchange bytes.
// Pair order and bundle order do not change the result.
func NewDeviceForkEvidence(delegation identity.Delegation, policy DescriptorPolicy,
	firstDescriptor Descriptor, firstBundles []e2ee.Bundle,
	secondDescriptor Descriptor, secondBundles []e2ee.Bundle, now time.Time) ([]byte, error) {
	firstDescriptorJSON, err := EncodeDescriptorJSON(firstDescriptor)
	if err != nil {
		return nil, err
	}
	secondDescriptorJSON, err := EncodeDescriptorJSON(secondDescriptor)
	if err != nil {
		return nil, err
	}
	firstBundleJSON, err := canonicalBundleSetJSON(firstBundles)
	if err != nil {
		return nil, err
	}
	secondBundleJSON, err := canonicalBundleSetJSON(secondBundles)
	if err != nil {
		return nil, err
	}
	first := forkPublication{descriptor: firstDescriptor, descriptorJSON: firstDescriptorJSON,
		bundles: firstBundles, bundleJSON: firstBundleJSON}
	second := forkPublication{descriptor: secondDescriptor, descriptorJSON: secondDescriptorJSON,
		bundles: secondBundles, bundleJSON: secondBundleJSON}
	if _, err := verifyForkPair(delegation, policy, first, second, now); err != nil {
		return nil, err
	}
	if second.descriptor.PrekeyBundleDigest < first.descriptor.PrekeyBundleDigest {
		first, second = second, first
	}
	evidence := DeviceForkEvidence{
		Schema: DeviceForkEvidenceSchema, FirstDescriptor: first.descriptorJSON, FirstBundleSet: first.bundleJSON,
		SecondDescriptor: second.descriptorJSON, SecondBundleSet: second.bundleJSON,
	}
	raw, err := json.Marshal(evidence)
	if err != nil {
		return nil, err
	}
	if len(raw) > MaxDeviceForkEvidenceWireBytes {
		return nil, errors.New("device fork evidence exceeds its wire bound")
	}
	return raw, nil
}

// VerifyDeviceForkEvidence strictly decodes independently exchanged evidence,
// re-verifies both complete publication chains, and returns the two conflicting
// digests. The caller supplies current finalized authority and verification
// time; neither is accepted from the evidence itself.
func VerifyDeviceForkEvidence(raw []byte, delegation identity.Delegation, policy DescriptorPolicy,
	now time.Time) (e2ee.SetEquivocationError, error) {
	if len(raw) == 0 || len(raw) > MaxDeviceForkEvidenceWireBytes {
		return e2ee.SetEquivocationError{}, errors.New("invalid device fork evidence wire size")
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	var evidence DeviceForkEvidence
	if err := decoder.Decode(&evidence); err != nil {
		return e2ee.SetEquivocationError{}, err
	}
	if err := decoder.Decode(new(any)); !errors.Is(err, io.EOF) {
		return e2ee.SetEquivocationError{}, errors.New("device fork evidence has trailing JSON")
	}
	if evidence.Schema != DeviceForkEvidenceSchema {
		return e2ee.SetEquivocationError{}, errors.New("unsupported device fork evidence schema")
	}
	first, err := decodeForkPublication(evidence.FirstDescriptor, evidence.FirstBundleSet)
	if err != nil {
		return e2ee.SetEquivocationError{}, err
	}
	second, err := decodeForkPublication(evidence.SecondDescriptor, evidence.SecondBundleSet)
	if err != nil {
		return e2ee.SetEquivocationError{}, err
	}
	return verifyForkPair(delegation, policy, first, second, now)
}

type forkPublication struct {
	descriptor     Descriptor
	descriptorJSON []byte
	bundles        []e2ee.Bundle
	bundleJSON     []byte
}

func decodeForkPublication(descriptorJSON, bundleJSON []byte) (forkPublication, error) {
	if len(descriptorJSON) == 0 || len(descriptorJSON) > MaxDescriptorWireBytes ||
		len(bundleJSON) == 0 || len(bundleJSON) > e2ee.MaxBundleSetWireBytes {
		return forkPublication{}, errors.New("invalid fork publication size")
	}
	descriptor, err := DecodeDescriptorJSON(descriptorJSON)
	if err != nil {
		return forkPublication{}, err
	}
	bundles, err := e2ee.DecodeBundleSetJSON(bundleJSON)
	if err != nil {
		return forkPublication{}, err
	}
	return forkPublication{descriptor: descriptor, descriptorJSON: append([]byte(nil), descriptorJSON...),
		bundles: bundles, bundleJSON: append([]byte(nil), bundleJSON...)}, nil
}

func verifyForkPair(delegation identity.Delegation, policy DescriptorPolicy, first, second forkPublication,
	now time.Time) (e2ee.SetEquivocationError, error) {
	firstSummary, err := e2ee.Summarize(first.bundles)
	if err != nil {
		return e2ee.SetEquivocationError{}, err
	}
	secondSummary, err := e2ee.Summarize(second.bundles)
	if err != nil {
		return e2ee.SetEquivocationError{}, err
	}
	if firstSummary.EndpointID != secondSummary.EndpointID || firstSummary.EndpointID != delegation.EndpointID {
		return e2ee.SetEquivocationError{}, errors.New("device fork evidence mixes endpoints")
	}
	if firstSummary.Digest == secondSummary.Digest {
		return e2ee.SetEquivocationError{}, errors.New("device fork evidence contains one publication twice")
	}
	if firstSummary.NewestIssuedAtUnix != secondSummary.NewestIssuedAtUnix {
		return e2ee.SetEquivocationError{}, errors.New("device publications do not share a freshness watermark")
	}
	if now.IsZero() || now.Unix() < 0 {
		return e2ee.SetEquivocationError{}, errors.New("invalid device fork verification time")
	}
	// Verify at the earliest instant at which both signed publication chains
	// claim to be authoritative. Using the caller's current instant would let
	// an equivocating Endpoint erase durable proof merely by waiting for its
	// short-lived Descriptors to expire. The caller's clock still refuses
	// evidence whose signed issuance lies in the future.
	proofUnix := firstSummary.NewestIssuedAtUnix
	for _, issued := range []uint64{first.descriptor.IssuedAtUnix, second.descriptor.IssuedAtUnix} {
		if issued > proofUnix {
			proofUnix = issued
		}
	}
	if proofUnix > uint64(now.Unix()) {
		return e2ee.SetEquivocationError{}, errors.New("device fork evidence is issued in the future")
	}
	proofTime := time.Unix(int64(proofUnix), 0)
	for _, publication := range []forkPublication{first, second} {
		if err := Bind(delegation, publication.descriptor, policy, proofTime); err != nil {
			return e2ee.SetEquivocationError{}, err
		}
		if err := e2ee.BindBundleSet(delegation, publication.bundles,
			publication.descriptor.PrekeyBundleDigest, proofTime); err != nil {
			return e2ee.SetEquivocationError{}, err
		}
	}
	// A subset can be a legitimate pure retirement. Without trusted temporal
	// ordering, a pair containing a subset is not portable proof of a fork.
	if digestSubset(firstSummary.BundleDigests, secondSummary.BundleDigests) ||
		digestSubset(secondSummary.BundleDigests, firstSummary.BundleDigests) {
		return e2ee.SetEquivocationError{}, errors.New("device publications can be ordered as a pure retirement")
	}
	digests := []string{firstSummary.Digest, secondSummary.Digest}
	sort.Strings(digests)
	return e2ee.SetEquivocationError{CurrentDigest: digests[0], CandidateDigest: digests[1],
		IssuedAtUnix: firstSummary.NewestIssuedAtUnix}, nil
}

func canonicalBundleSetJSON(bundles []e2ee.Bundle) ([]byte, error) {
	ordered := append([]e2ee.Bundle(nil), bundles...)
	sort.Slice(ordered, func(i, j int) bool { return ordered[i].DeviceID < ordered[j].DeviceID })
	return e2ee.EncodeBundleSetJSON(ordered)
}

func digestSubset(smaller, larger []string) bool {
	present := make(map[string]struct{}, len(larger))
	for _, digest := range larger {
		present[digest] = struct{}{}
	}
	for _, digest := range smaller {
		if _, ok := present[digest]; !ok {
			return false
		}
	}
	return true
}
