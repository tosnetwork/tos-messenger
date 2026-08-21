package directory

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/tosnetwork/tos-messenger/pkg/e2ee"
	"github.com/tosnetwork/tos-messenger/pkg/identity"
)

func TestDeviceForkEvidenceRoundTripIsOrderIndependent(t *testing.T) {
	key := endpointKey(t, 0x71)
	delegation := testDelegation(t, key)
	firstDescriptor, first := forkPublicationFixture(t, delegation, key, []string{"1"})
	secondDescriptor, second := forkPublicationFixture(t, delegation, key, []string{"2"})
	now := time.Unix(int64(baseUnix+1), 0)

	forward, err := NewDeviceForkEvidence(delegation, testPolicy(), firstDescriptor, first, secondDescriptor, second, now)
	if err != nil {
		t.Fatal(err)
	}
	reverse, err := NewDeviceForkEvidence(delegation, testPolicy(), secondDescriptor, second, firstDescriptor, first, now)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(forward, reverse) {
		t.Fatal("observer arrival order changed the portable evidence")
	}
	proof, err := VerifyDeviceForkEvidence(forward, delegation, testPolicy(), now)
	if err != nil {
		t.Fatal(err)
	}
	firstDigest, _ := e2ee.SetDigest(first)
	secondDigest, _ := e2ee.SetDigest(second)
	if proof.CurrentDigest >= proof.CandidateDigest || proof.IssuedAtUnix != baseUnix ||
		(proof.CurrentDigest != firstDigest && proof.CurrentDigest != secondDigest) ||
		(proof.CandidateDigest != firstDigest && proof.CandidateDigest != secondDigest) {
		t.Fatalf("incomplete normalized fork proof: %+v", proof)
	}
	// Descriptor cache expiry must not let the Endpoint erase already signed
	// evidence while this exact delegation remains finalized and live.
	if _, err := VerifyDeviceForkEvidence(forward, delegation, testPolicy(), time.Unix(int64(baseUnix+7200), 0)); err != nil {
		t.Fatalf("durable evidence expired with its Descriptor cache: %v", err)
	}
	if _, err := VerifyDeviceForkEvidence(forward, delegation, testPolicy(), time.Unix(int64(baseUnix-1), 0)); err == nil ||
		!strings.Contains(err.Error(), "future") {
		t.Fatalf("future-issued evidence was accepted: %v", err)
	}
}

func TestDeviceForkEvidenceRefusesNonEvidence(t *testing.T) {
	key := endpointKey(t, 0x72)
	delegation := testDelegation(t, key)
	now := time.Unix(int64(baseUnix+1), 0)
	firstDescriptor, first := forkPublicationFixture(t, delegation, key, []string{"1", "2"})
	retiredDescriptor, retired := forkPublicationFixture(t, delegation, key, []string{"1"})
	if _, err := NewDeviceForkEvidence(delegation, testPolicy(), firstDescriptor, first,
		retiredDescriptor, retired, now); err == nil || !strings.Contains(err.Error(), "pure retirement") {
		t.Fatalf("a valid retirement became a fork accusation: %v", err)
	}

	newerDescriptor, newer := forkPublicationAt(t, delegation, key, []string{"3"}, baseUnix+1)
	if _, err := NewDeviceForkEvidence(delegation, testPolicy(), retiredDescriptor, retired,
		newerDescriptor, newer, now); err == nil || !strings.Contains(err.Error(), "freshness watermark") {
		t.Fatalf("ordered rotations became a fork accusation: %v", err)
	}
}

func TestDeviceForkEvidenceStrictlyReverifiesAuthority(t *testing.T) {
	key := endpointKey(t, 0x73)
	delegation := testDelegation(t, key)
	firstDescriptor, first := forkPublicationFixture(t, delegation, key, []string{"1"})
	secondDescriptor, second := forkPublicationFixture(t, delegation, key, []string{"2"})
	now := time.Unix(int64(baseUnix+1), 0)
	raw, err := NewDeviceForkEvidence(delegation, testPolicy(), firstDescriptor, first, secondDescriptor, second, now)
	if err != nil {
		t.Fatal(err)
	}

	var evidence map[string]json.RawMessage
	if err := json.Unmarshal(raw, &evidence); err != nil {
		t.Fatal(err)
	}
	var descriptor map[string]any
	if err := json.Unmarshal(evidence["first_descriptor"], &descriptor); err != nil {
		t.Fatal(err)
	}
	descriptor["endpoint_signature_hex"] = strings.Repeat("0", ed25519.SignatureSize*2)
	evidence["first_descriptor"], _ = json.Marshal(descriptor)
	tampered, _ := json.Marshal(evidence)
	if _, err := VerifyDeviceForkEvidence(tampered, delegation, testPolicy(), now); err == nil {
		t.Fatal("substituted Descriptor signature was accepted")
	}

	unknown := append(raw[:len(raw)-1], []byte(`,"observer_says_valid":true}`)...)
	if _, err := VerifyDeviceForkEvidence(unknown, delegation, testPolicy(), now); err == nil {
		t.Fatal("observer-controlled authority field was accepted")
	}
	if _, err := VerifyDeviceForkEvidence(append(raw, []byte(`{}`)...), delegation, testPolicy(), now); err == nil {
		t.Fatal("trailing evidence was accepted")
	}
}

func forkPublicationFixture(t *testing.T, delegation identity.Delegation, key ed25519.PrivateKey,
	devices []string) (Descriptor, []e2ee.Bundle) {
	t.Helper()
	return forkPublicationAt(t, delegation, key, devices, baseUnix)
}

func forkPublicationAt(t *testing.T, delegation identity.Delegation, key ed25519.PrivateKey,
	devices []string, issuedAt uint64) (Descriptor, []e2ee.Bundle) {
	t.Helper()
	bundles := make([]e2ee.Bundle, 0, len(devices))
	for _, suffix := range devices {
		bundle, err := e2ee.SignBundle(e2ee.Bundle{
			Network: delegation.Network, AgentID: delegation.AgentID, EndpointID: delegation.EndpointID,
			DeviceID: "dev_" + strings.Repeat(suffix, 64), AlgorithmID: e2ee.DefaultCandidateAlgorithmID,
			Material: []byte("material-" + suffix), IssuedAtUnix: issuedAt, ExpiresAtUnix: baseUnix + 3600,
		}, key)
		if err != nil {
			t.Fatal(err)
		}
		bundles = append(bundles, bundle)
	}
	digest, err := e2ee.SetDigest(bundles)
	if err != nil {
		t.Fatal(err)
	}
	descriptor := testDescriptor(t, delegation)
	descriptor.PrekeyBundleDigest = digest
	descriptor, err = SignDescriptor(descriptor, key)
	if err != nil {
		t.Fatal(err)
	}
	return descriptor, bundles
}
