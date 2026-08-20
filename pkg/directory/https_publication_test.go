package directory

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ed25519"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/tosnetwork/tos-messenger/pkg/e2ee"
)

func publicationPrekeys(t *testing.T, delegationKey ed25519.PrivateKey, descriptor Descriptor) (string, []byte) {
	t.Helper()
	bundle, err := e2ee.SignBundle(e2ee.Bundle{
		Network: descriptor.Network, AgentID: descriptor.AgentID, EndpointID: descriptor.EndpointID,
		DeviceID: "dev_" + strings.Repeat("9", 64), AlgorithmID: e2ee.DefaultCandidateAlgorithmID,
		Material: []byte("endpoint-signed device public material"), IssuedAtUnix: baseUnix, ExpiresAtUnix: baseUnix + 1800,
	}, delegationKey)
	if err != nil {
		t.Fatalf("sign bundle: %v", err)
	}
	digest, err := e2ee.SetDigest([]e2ee.Bundle{bundle})
	if err != nil {
		t.Fatalf("set digest: %v", err)
	}
	raw, err := e2ee.EncodeBundleSetJSON([]e2ee.Bundle{bundle})
	if err != nil {
		t.Fatalf("encode bundle set: %v", err)
	}
	return digest, raw
}

type activationSink struct {
	calls []string
	items map[string][]byte
	fail  string
}

func (s *activationSink) PutPrekeySet(_ context.Context, digest string, raw []byte) error {
	s.calls = append(s.calls, "prekeys")
	if s.fail == "prekeys" {
		return errors.New("prekey sink failed")
	}
	if s.items == nil {
		s.items = make(map[string][]byte)
	}
	s.items[digest] = append([]byte(nil), raw...)
	return nil
}

func (s *activationSink) PutDescriptor(_ context.Context, digest string, raw []byte) error {
	s.calls = append(s.calls, "descriptor")
	if s.fail == "descriptor" {
		return errors.New("descriptor sink failed")
	}
	if s.items == nil {
		s.items = make(map[string][]byte)
	}
	s.items[digest] = append([]byte(nil), raw...)
	return nil
}

func TestHTTPSActivationPublishesDependenciesBeforeReturningLocator(t *testing.T) {
	key := endpointKey(t, 0x31)
	delegation := testDelegation(t, key)
	descriptor := testDescriptor(t, delegation)
	prekeyDigest, prekeyJSON := publicationPrekeys(t, key, descriptor)
	sink := new(activationSink)
	now := time.Unix(int64(baseUnix+1), 0)
	activation, err := ActivateHTTPSPublication(context.Background(), sink, key, delegation, testPolicy(),
		HTTPSActivationPlan{
			Descriptor: descriptor, LocatorIssuedAt: uint64(now.Unix()), LocatorExpiresAt: uint64(now.Unix() + 900),
		}, prekeyDigest, prekeyJSON, now)
	if err != nil {
		t.Fatalf("activate: %v", err)
	}
	if len(sink.calls) != 2 || sink.calls[0] != "prekeys" || sink.calls[1] != "descriptor" {
		t.Fatalf("publication order = %v", sink.calls)
	}
	if activation.Descriptor.PrekeyBundleDigest != prekeyDigest ||
		!bytes.Equal(sink.items[prekeyDigest], prekeyJSON) ||
		!bytes.Equal(sink.items[activation.DescriptorDigest], activation.DescriptorJSON) {
		t.Fatal("activation objects do not match their commitments")
	}
	wantURL, err := DescriptorObjectURL(descriptor.HTTPSEndpoint, activation.DescriptorDigest)
	if err != nil || activation.Locator.DescriptorLocator != wantURL {
		t.Fatalf("locator reference=%q want=%q err=%v", activation.Locator.DescriptorLocator, wantURL, err)
	}
	if err := VerifyLocator(delegation, activation.Locator, now); err != nil {
		t.Fatalf("returned locator: %v", err)
	}
}

func TestHTTPSActivationFailureNeverPublishesASecondDependency(t *testing.T) {
	key := endpointKey(t, 0x32)
	delegation := testDelegation(t, key)
	descriptor := testDescriptor(t, delegation)
	digest, raw := publicationPrekeys(t, key, descriptor)
	now := time.Unix(int64(baseUnix+1), 0)
	plan := HTTPSActivationPlan{Descriptor: descriptor, LocatorIssuedAt: uint64(now.Unix()), LocatorExpiresAt: uint64(now.Unix() + 900)}

	prekeyFailure := &activationSink{fail: "prekeys"}
	if _, err := ActivateHTTPSPublication(context.Background(), prekeyFailure, key, delegation, testPolicy(), plan, digest, raw, now); err == nil {
		t.Fatal("prekey sink failure was hidden")
	}
	if len(prekeyFailure.calls) != 1 || prekeyFailure.calls[0] != "prekeys" {
		t.Fatalf("descriptor ran after prekey failure: %v", prekeyFailure.calls)
	}
	descriptorFailure := &activationSink{fail: "descriptor"}
	if _, err := ActivateHTTPSPublication(context.Background(), descriptorFailure, key, delegation, testPolicy(), plan, digest, raw, now); err == nil {
		t.Fatal("descriptor sink failure was hidden")
	}
	if len(descriptorFailure.calls) != 2 {
		t.Fatalf("unexpected failure sequence: %v", descriptorFailure.calls)
	}
}

type badDirectorySigner struct{ public ed25519.PublicKey }

func (s badDirectorySigner) Public() crypto.PublicKey { return s.public }
func (s badDirectorySigner) Sign(io.Reader, []byte, crypto.SignerOpts) ([]byte, error) {
	return make([]byte, ed25519.SignatureSize), nil
}

func TestHTTPSActivationValidatesSignerBeforePublishing(t *testing.T) {
	key := endpointKey(t, 0x33)
	delegation := testDelegation(t, key)
	descriptor := testDescriptor(t, delegation)
	digest, raw := publicationPrekeys(t, key, descriptor)
	now := time.Unix(int64(baseUnix+1), 0)
	sink := new(activationSink)
	_, err := ActivateHTTPSPublication(context.Background(), sink,
		badDirectorySigner{delegation.IdentityPublicKey}, delegation, testPolicy(), HTTPSActivationPlan{
			Descriptor: descriptor, LocatorIssuedAt: uint64(now.Unix()), LocatorExpiresAt: uint64(now.Unix() + 900),
		}, digest, raw, now)
	if err == nil || len(sink.calls) != 0 {
		t.Fatalf("bad signer mutated sink: calls=%v err=%v", sink.calls, err)
	}
}

func TestHTTPSPublisherWritesImmutableStaticObjects(t *testing.T) {
	key := endpointKey(t, 0x34)
	delegation := testDelegation(t, key)
	descriptor := testDescriptor(t, delegation)
	digest, raw := publicationPrekeys(t, key, descriptor)
	root := t.TempDir()
	if err := os.Chmod(root, 0o700); err != nil {
		t.Fatalf("protect root: %v", err)
	}
	publisher, err := OpenHTTPSPublisher(root)
	if err != nil {
		t.Fatalf("open publisher: %v", err)
	}
	now := time.Unix(int64(baseUnix+1), 0)
	activation, err := ActivateHTTPSPublication(context.Background(), publisher, key, delegation, testPolicy(),
		HTTPSActivationPlan{
			Descriptor: descriptor, LocatorIssuedAt: uint64(now.Unix()), LocatorExpiresAt: uint64(now.Unix() + 900),
		}, digest, raw, now)
	if err != nil {
		t.Fatalf("activate: %v", err)
	}
	prekeyPath := filepath.Join(root, ".well-known", "tos-messenger", "prekeys", strings.TrimPrefix(digest, "sha256:")+".json")
	descriptorPath := filepath.Join(root, ".well-known", "tos-messenger", descriptorObjectDir,
		strings.TrimPrefix(activation.DescriptorDigest, "sha256:")+".json")
	for path, want := range map[string][]byte{prekeyPath: raw, descriptorPath: activation.DescriptorJSON} {
		got, err := os.ReadFile(path)
		if err != nil || !bytes.Equal(got, want) {
			t.Fatalf("object %s differs: err=%v", path, err)
		}
		info, _ := os.Lstat(path)
		if info == nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0o644 {
			t.Fatalf("object mode for %s = %v", path, info)
		}
	}
	if _, err := ActivateHTTPSPublication(context.Background(), publisher, key, delegation, testPolicy(),
		HTTPSActivationPlan{
			Descriptor: descriptor, LocatorIssuedAt: uint64(now.Unix()), LocatorExpiresAt: uint64(now.Unix() + 900),
		}, digest, raw, now); err != nil {
		t.Fatalf("exact retry: %v", err)
	}
}

func TestHTTPSPublisherRefusesDirectorySubstitution(t *testing.T) {
	root := t.TempDir()
	if err := os.Chmod(root, 0o700); err != nil {
		t.Fatalf("protect root: %v", err)
	}
	publisher, err := OpenHTTPSPublisher(root)
	if err != nil {
		t.Fatalf("open publisher: %v", err)
	}
	prekeys := filepath.Join(root, ".well-known", "tos-messenger", "prekeys")
	if err := os.Remove(prekeys); err != nil {
		t.Fatalf("remove fixture directory: %v", err)
	}
	if err := os.Symlink(t.TempDir(), prekeys); err != nil {
		t.Fatalf("substitute directory: %v", err)
	}
	if err := publisher.PutPrekeySet(context.Background(), "sha256:"+strings.Repeat("1", 64), []byte("{}")); err == nil {
		t.Fatal("substituted publication directory was followed")
	}
}

func TestHTTPSPublisherRefusesAlternateBundleOrdering(t *testing.T) {
	key := endpointKey(t, 0x35)
	delegation := testDelegation(t, key)
	descriptor := testDescriptor(t, delegation)
	makeBundle := func(device string) e2ee.Bundle {
		bundle, err := e2ee.SignBundle(e2ee.Bundle{
			Network: descriptor.Network, AgentID: descriptor.AgentID, EndpointID: descriptor.EndpointID,
			DeviceID: device, AlgorithmID: e2ee.DefaultCandidateAlgorithmID, Material: []byte(device),
			IssuedAtUnix: baseUnix, ExpiresAtUnix: baseUnix + 1800,
		}, key)
		if err != nil {
			t.Fatalf("bundle: %v", err)
		}
		return bundle
	}
	bundles := []e2ee.Bundle{makeBundle("dev_" + strings.Repeat("2", 64)), makeBundle("dev_" + strings.Repeat("1", 64))}
	digest, _ := e2ee.SetDigest(bundles)
	raw, _ := e2ee.EncodeBundleSetJSON(bundles)
	root := t.TempDir()
	if err := os.Chmod(root, 0o700); err != nil {
		t.Fatalf("protect root: %v", err)
	}
	publisher, err := OpenHTTPSPublisher(root)
	if err != nil {
		t.Fatalf("open publisher: %v", err)
	}
	if err := publisher.PutPrekeySet(context.Background(), digest, raw); err == nil {
		t.Fatal("alternate wire ordering claimed the canonical content address")
	}
}
