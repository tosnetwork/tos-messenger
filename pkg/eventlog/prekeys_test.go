package eventlog

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ed25519"
	"errors"
	"io"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/tosnetwork/tos-messenger/pkg/e2ee"
	"github.com/tosnetwork/tos-messenger/pkg/identity"
	nativev1 "github.com/tosnetwork/tos-service-protocol/gen/tos/service/v1"
)

func prekeyFixture(t *testing.T) (identity.Delegation, ed25519.PrivateKey) {
	t.Helper()
	key := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x71}, ed25519.SeedSize))
	network := &nativev1.NetworkDomain{
		NetworkId: "tos-local", GenesisRootHash: strings.Repeat("a", 64), GenesisFileHash: strings.Repeat("b", 64),
	}
	agentID := "agent_" + strings.Repeat("c", 64)
	endpointID, err := identity.DeriveEndpointID(network, agentID, key.Public().(ed25519.PublicKey))
	if err != nil {
		t.Fatalf("derive endpoint: %v", err)
	}
	delegation := identity.Delegation{
		Network: network, AgentID: agentID, EndpointID: endpointID,
		IdentityPublicKey: key.Public().(ed25519.PublicKey), AllowedProtocolVersions: []uint32{1},
		AllowedOutboundEventClasses: []string{"message.text"}, NotBeforeUnix: 1_799_999_000,
		ExpiresAtUnix: 1_800_100_000, MaximumSessionLifetimeSeconds: 3600,
		ContactDescriptorPolicyDigest: "sha256:" + strings.Repeat("d", 64),
		InboxAdmissionPolicyDigest:    "sha256:" + strings.Repeat("e", 64),
	}
	if err := identity.Validate(delegation); err != nil {
		t.Fatalf("delegation: %v", err)
	}
	return delegation, key
}

func openPrekeyLedgers(t *testing.T, root string) (*Journal, *DevicePrekeyLedger, *PrekeyPublicationLedger) {
	t.Helper()
	journal, err := Open(root)
	if err != nil {
		t.Fatalf("open journal: %v", err)
	}
	devices, err := journal.OpenDevicePrekeys()
	if err != nil {
		journal.Close()
		t.Fatalf("open device prekeys: %v", err)
	}
	publications, err := journal.OpenPrekeyPublications()
	if err != nil {
		journal.Close()
		t.Fatalf("open publications: %v", err)
	}
	return journal, devices, publications
}

func coordinatedPlan(now time.Time) DevicePrekeyPlan {
	return DevicePrekeyPlan{IssuedAt: now, ExpiresAt: now.Add(100 * time.Second), ReplenishBefore: 20 * time.Second}
}

func TestDeviceSecretsStayOutsideEndpointPublication(t *testing.T) {
	delegation, key := prekeyFixture(t)
	journal, devices, publications := openPrekeyLedgers(t, t.TempDir()+"/state")
	defer journal.Close()
	now := time.Unix(1_800_000_000, 0)
	contributions := make([]e2ee.Bundle, 0, 2)
	for _, deviceID := range []string{deviceID(2), deviceID(1)} {
		prekey, created, err := devices.EnsureDevicePrekey(
			delegation, key, e2ee.NewDefaultSuite(), deviceID, coordinatedPlan(now), now,
		)
		if err != nil || !created {
			t.Fatalf("device %s: created=%v err=%v", deviceID, created, err)
		}
		contributions = append(contributions, prekey.Bundle)
		private, err := devices.DevicePrekeyPrivate(delegation.EndpointID, deviceID, prekey.BundleDigest, now)
		if err != nil || len(private) == 0 {
			t.Fatalf("device %s private: bytes=%d err=%v", deviceID, len(private), err)
		}
	}
	publication, created, err := publications.PreparePrekeyPublication(delegation, contributions, now)
	if err != nil || !created {
		t.Fatalf("aggregate: created=%v err=%v", created, err)
	}
	if len(publication.Bundles) != 2 || publication.Bundles[0].DeviceID != deviceID(1) {
		t.Fatalf("publication is not the sorted complete set: %+v", publication.Bundles)
	}
	raw, err := os.ReadFile(publications.path(delegation.EndpointID))
	if err != nil {
		t.Fatalf("read publication state: %v", err)
	}
	if bytes.Contains(raw, []byte("private_material")) {
		t.Fatal("Endpoint publication state contains device private material")
	}
}

func TestDevicePrekeyRetryAndRotationSurviveRestart(t *testing.T) {
	delegation, key := prekeyFixture(t)
	root := t.TempDir() + "/state"
	journal, devices, _ := openPrekeyLedgers(t, root)
	now := time.Unix(1_800_000_000, 0)
	first, created, err := devices.EnsureDevicePrekey(
		delegation, key, e2ee.NewDefaultSuite(), deviceID(1), coordinatedPlan(now), now,
	)
	if err != nil || !created {
		t.Fatalf("first: created=%v err=%v", created, err)
	}
	if err := journal.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	reopened, restored, _ := openPrekeyLedgers(t, root)
	defer reopened.Close()
	retry, created, err := restored.EnsureDevicePrekey(
		delegation, key, e2ee.NewDefaultSuite(), deviceID(1), coordinatedPlan(now), now.Add(10*time.Second),
	)
	if err != nil || created || retry.BundleDigest != first.BundleDigest {
		t.Fatalf("retry: created=%v digest=%s err=%v", created, retry.BundleDigest, err)
	}
	secondNow := now.Add(80 * time.Second)
	second, created, err := restored.EnsureDevicePrekey(
		delegation, key, e2ee.NewDefaultSuite(), deviceID(1), coordinatedPlan(secondNow), secondNow,
	)
	if err != nil || !created || second.BundleDigest == first.BundleDigest {
		t.Fatalf("rotate: created=%v same=%v err=%v", created, second.BundleDigest == first.BundleDigest, err)
	}
	if _, err := restored.DevicePrekeyPrivate(delegation.EndpointID, deviceID(1), first.BundleDigest, now.Add(99*time.Second)); err != nil {
		t.Fatalf("live previous generation disappeared: %v", err)
	}
	if err := restored.PruneDevicePrekeys(delegation.EndpointID, deviceID(1), now.Add(100*time.Second)); err != nil {
		t.Fatalf("prune: %v", err)
	}
	if _, err := restored.DevicePrekeyPrivate(delegation.EndpointID, deviceID(1), first.BundleDigest, now.Add(100*time.Second)); !errors.Is(err, ErrPrekeyUnavailable) {
		t.Fatalf("expired generation remained selectable: %v", err)
	}
}

func TestDeviceRevocationDropsOnlyThatDevicesSecrets(t *testing.T) {
	delegation, key := prekeyFixture(t)
	journal, devices, _ := openPrekeyLedgers(t, t.TempDir()+"/state")
	defer journal.Close()
	now := time.Unix(1_800_000_000, 0)
	first, _, err := devices.EnsureDevicePrekey(
		delegation, key, e2ee.NewDefaultSuite(), deviceID(1), coordinatedPlan(now), now,
	)
	if err != nil {
		t.Fatalf("prepare first: %v", err)
	}
	second, _, err := devices.EnsureDevicePrekey(
		delegation, key, e2ee.NewDefaultSuite(), deviceID(2), coordinatedPlan(now), now,
	)
	if err != nil {
		t.Fatalf("prepare second: %v", err)
	}
	if err := devices.RevokeDevicePrekeys(delegation.EndpointID, deviceID(2), now.Add(time.Second)); err != nil {
		t.Fatalf("revoke: %v", err)
	}
	if _, err := devices.DevicePrekeyPrivate(delegation.EndpointID, deviceID(2), second.BundleDigest, now.Add(time.Second)); !errors.Is(err, ErrPrekeyUnavailable) {
		t.Fatalf("revoked device retained bootstrap authority: %v", err)
	}
	if _, err := devices.DevicePrekeyPrivate(delegation.EndpointID, deviceID(1), first.BundleDigest, now.Add(time.Second)); err != nil {
		t.Fatalf("another device lost its secret: %v", err)
	}
	if _, _, err := devices.EnsureDevicePrekey(
		delegation, key, e2ee.NewDefaultSuite(), deviceID(2), coordinatedPlan(now.Add(2*time.Second)), now.Add(2*time.Second),
	); !errors.Is(err, ErrDevicePrekeyRevoked) {
		t.Fatalf("revoked local device was readmitted: %v", err)
	}
}

func TestPublicationClassifiesForkAndPermanentRetirement(t *testing.T) {
	delegation, key := prekeyFixture(t)
	journal, devices, publications := openPrekeyLedgers(t, t.TempDir()+"/state")
	defer journal.Close()
	now := time.Unix(1_800_000_000, 0)
	first, _, _ := devices.EnsureDevicePrekey(delegation, key, e2ee.NewDefaultSuite(), deviceID(1), coordinatedPlan(now), now)
	second, _, _ := devices.EnsureDevicePrekey(delegation, key, e2ee.NewDefaultSuite(), deviceID(2), coordinatedPlan(now), now)
	if _, _, err := publications.PreparePrekeyPublication(delegation, []e2ee.Bundle{first.Bundle, second.Bundle}, now); err != nil {
		t.Fatalf("initial publication: %v", err)
	}
	fork, err := e2ee.SignBundle(e2ee.Bundle{
		Network: delegation.Network, AgentID: delegation.AgentID, EndpointID: delegation.EndpointID,
		DeviceID: deviceID(1), AlgorithmID: first.Bundle.AlgorithmID, Material: []byte("different public material"),
		IssuedAtUnix: first.Bundle.IssuedAtUnix, ExpiresAtUnix: first.Bundle.ExpiresAtUnix,
	}, key)
	if err != nil {
		t.Fatalf("fork fixture: %v", err)
	}
	if _, _, err := publications.PreparePrekeyPublication(delegation, []e2ee.Bundle{fork, second.Bundle}, now); !errors.Is(err, e2ee.ErrSetEquivocation) {
		t.Fatalf("equal-time fork was not classified: %v", err)
	}
	if _, _, err := publications.PreparePrekeyPublication(delegation, []e2ee.Bundle{first.Bundle}, now); err != nil {
		t.Fatalf("pure retirement: %v", err)
	}
	newer := coordinatedPlan(now.Add(time.Second))
	third, _, err := devices.EnsureDevicePrekey(delegation, key, e2ee.NewDefaultSuite(), deviceID(2), newer, now.Add(time.Second))
	if err != nil {
		t.Fatalf("new device contribution: %v", err)
	}
	keep, _, err := devices.EnsureDevicePrekey(delegation, key, e2ee.NewDefaultSuite(), deviceID(1), newer, now.Add(time.Second))
	if err != nil {
		t.Fatalf("retained contribution: %v", err)
	}
	if _, _, err := publications.PreparePrekeyPublication(delegation, []e2ee.Bundle{keep.Bundle, third.Bundle}, now.Add(time.Second)); err == nil {
		t.Fatal("retired device returned to the public set")
	}
}

type invalidPrekeySigner struct{ public ed25519.PublicKey }

func (s invalidPrekeySigner) Public() crypto.PublicKey { return s.public }
func (s invalidPrekeySigner) Sign(io.Reader, []byte, crypto.SignerOpts) ([]byte, error) {
	return make([]byte, ed25519.SignatureSize), nil
}

func TestDevicePrekeysDoNotRecordInvalidSignerOutput(t *testing.T) {
	delegation, _ := prekeyFixture(t)
	journal, devices, _ := openPrekeyLedgers(t, t.TempDir()+"/state")
	defer journal.Close()
	now := time.Unix(1_800_000_000, 0)
	if _, _, err := devices.EnsureDevicePrekey(
		delegation, invalidPrekeySigner{delegation.IdentityPublicKey}, e2ee.NewDefaultSuite(), deviceID(1), coordinatedPlan(now), now,
	); err == nil {
		t.Fatal("invalid Endpoint signature was accepted")
	}
	if _, err := os.Stat(devices.path(deviceID(1))); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("failed signing left device state: %v", err)
	}
}

type prekeySink struct {
	digest string
	raw    []byte
}

func (s *prekeySink) PutPrekeySet(_ context.Context, digest string, raw []byte) error {
	s.digest = digest
	s.raw = append([]byte(nil), raw...)
	clear(raw)
	return nil
}

func TestPublicationReloadsBeforeSinkAndSurfacesCorruption(t *testing.T) {
	delegation, key := prekeyFixture(t)
	journal, devices, publications := openPrekeyLedgers(t, t.TempDir()+"/state")
	defer journal.Close()
	now := time.Unix(1_800_000_000, 0)
	device, _, _ := devices.EnsureDevicePrekey(delegation, key, e2ee.NewDefaultSuite(), deviceID(1), coordinatedPlan(now), now)
	publication, _, err := publications.PreparePrekeyPublication(delegation, []e2ee.Bundle{device.Bundle}, now)
	if err != nil {
		t.Fatalf("prepare: %v", err)
	}
	sink := new(prekeySink)
	published, err := publications.PublishCurrentPrekeys(context.Background(), sink, delegation, now)
	if err != nil || sink.digest != publication.SetDigest || !bytes.Equal(sink.raw, publication.BundleSetJSON) ||
		published.SetDigest != publication.SetDigest {
		t.Fatalf("publish: returned=%s sink=%s err=%v", published.SetDigest, sink.digest, err)
	}
	if err := os.WriteFile(publications.path(delegation.EndpointID), []byte("{}"), 0o600); err != nil {
		t.Fatalf("corrupt fixture: %v", err)
	}
	if _, err := publications.PublishCurrentPrekeys(context.Background(), sink, delegation, now); err == nil {
		t.Fatal("corrupt publication state reached the sink")
	}
}
