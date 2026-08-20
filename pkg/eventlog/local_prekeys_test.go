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

func localPrekeyFixture(t *testing.T) (identity.Delegation, ed25519.PrivateKey) {
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

func openLocalPrekeys(t *testing.T, root string) (*Journal, *LocalPrekeyLedger) {
	t.Helper()
	journal, err := Open(root)
	if err != nil {
		t.Fatalf("open journal: %v", err)
	}
	ledger, err := journal.OpenLocalPrekeys()
	if err != nil {
		journal.Close()
		t.Fatalf("open prekeys: %v", err)
	}
	return journal, ledger
}

func localPlan(devices ...string) PrekeyPlan {
	return PrekeyPlan{DeviceIDs: devices, Lifetime: 100 * time.Second, ReplenishBefore: 20 * time.Second}
}

func TestLocalPrekeysPersistExactGenerationBeforePublication(t *testing.T) {
	delegation, key := localPrekeyFixture(t)
	root := t.TempDir() + "/state"
	journal, ledger := openLocalPrekeys(t, root)
	now := time.Unix(1_800_000_000, 0)
	publication, created, err := ledger.EnsurePrekeys(
		delegation, key, e2ee.NewDefaultSuite(), localPlan(deviceID(2), deviceID(1)), now,
	)
	if err != nil || !created {
		t.Fatalf("prepare: created=%v err=%v", created, err)
	}
	if len(publication.Bundles) != 2 || publication.Bundles[0].DeviceID != deviceID(1) ||
		publication.IssuedAt != uint64(now.Unix()) || publication.ExpiresAt != uint64(now.Unix()+100) {
		t.Fatalf("unexpected publication: %+v", publication)
	}
	if err := e2ee.BindBundleSet(delegation, publication.Bundles, publication.SetDigest, now); err != nil {
		t.Fatalf("bind prepared publication: %v", err)
	}
	firstDigest, _ := e2ee.BundleDigest(publication.Bundles[0])
	private, err := ledger.PrekeyPrivate(delegation.EndpointID, firstDigest, now)
	if err != nil || len(private) == 0 {
		t.Fatalf("select private material: bytes=%d err=%v", len(private), err)
	}

	if err := journal.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	reopened, restored := openLocalPrekeys(t, root)
	defer reopened.Close()
	retry, created, err := restored.EnsurePrekeys(
		delegation, key, e2ee.NewDefaultSuite(), localPlan(deviceID(1), deviceID(2)), now.Add(79*time.Second),
	)
	if err != nil || created {
		t.Fatalf("retry: created=%v err=%v", created, err)
	}
	if retry.SetDigest != publication.SetDigest || !bytes.Equal(retry.BundleSetJSON, publication.BundleSetJSON) {
		t.Fatal("a restart changed the prepared publication")
	}
}

func TestLocalPrekeysReplenishAndRetainOnlyLiveAnsweringSecrets(t *testing.T) {
	delegation, key := localPrekeyFixture(t)
	journal, ledger := openLocalPrekeys(t, t.TempDir()+"/state")
	defer journal.Close()
	now := time.Unix(1_800_000_000, 0)
	first, _, err := ledger.EnsurePrekeys(delegation, key, e2ee.NewDefaultSuite(), localPlan(deviceID(1)), now)
	if err != nil {
		t.Fatalf("first: %v", err)
	}
	oldDigest, _ := e2ee.BundleDigest(first.Bundles[0])
	second, created, err := ledger.EnsurePrekeys(
		delegation, key, e2ee.NewDefaultSuite(), localPlan(deviceID(1)), now.Add(80*time.Second),
	)
	if err != nil || !created || second.SetDigest == first.SetDigest {
		t.Fatalf("replenish: created=%v same=%v err=%v", created, second.SetDigest == first.SetDigest, err)
	}
	if _, err := ledger.PrekeyPrivate(delegation.EndpointID, oldDigest, now.Add(99*time.Second)); err != nil {
		t.Fatalf("old live publication was made unanswerable: %v", err)
	}
	if err := ledger.PrunePrekeys(delegation.EndpointID, now.Add(100*time.Second)); err != nil {
		t.Fatalf("prune: %v", err)
	}
	if _, err := ledger.PrekeyPrivate(delegation.EndpointID, oldDigest, now.Add(100*time.Second)); !errors.Is(err, ErrPrekeyUnavailable) {
		t.Fatalf("expired private material remained selectable: %v", err)
	}
}

func TestLocalPrekeysRefuseEquivocationAndDeviceReadmission(t *testing.T) {
	delegation, key := localPrekeyFixture(t)
	journal, ledger := openLocalPrekeys(t, t.TempDir()+"/state")
	defer journal.Close()
	now := time.Unix(1_800_000_000, 0)
	initial, _, err := ledger.EnsurePrekeys(
		delegation, key, e2ee.NewDefaultSuite(), localPlan(deviceID(1), deviceID(2)), now,
	)
	if err != nil {
		t.Fatalf("initial: %v", err)
	}
	removedDigest, _ := e2ee.BundleDigest(initial.Bundles[1])
	if _, _, err := ledger.EnsurePrekeys(
		delegation, key, e2ee.NewDefaultSuite(), localPlan(deviceID(1)), now,
	); !errors.Is(err, ErrPrekeyEquivocation) {
		t.Fatalf("equal-time fork was not identified: %v", err)
	}
	if _, _, err := ledger.EnsurePrekeys(
		delegation, key, e2ee.NewDefaultSuite(), localPlan(deviceID(1)), now.Add(time.Second),
	); err != nil {
		t.Fatalf("retire: %v", err)
	}
	if _, err := ledger.PrekeyPrivate(delegation.EndpointID, removedDigest, now.Add(time.Second)); !errors.Is(err, ErrPrekeyUnavailable) {
		t.Fatalf("a revoked device retained bootstrap authority: %v", err)
	}
	if _, _, err := ledger.EnsurePrekeys(
		delegation, key, e2ee.NewDefaultSuite(), localPlan(deviceID(1), deviceID(2)), now.Add(2*time.Second),
	); err == nil {
		t.Fatal("a retired local device was readmitted")
	}
}

type invalidEd25519Signer struct{ public ed25519.PublicKey }

func (s invalidEd25519Signer) Public() crypto.PublicKey { return s.public }
func (s invalidEd25519Signer) Sign(io.Reader, []byte, crypto.SignerOpts) ([]byte, error) {
	return make([]byte, ed25519.SignatureSize), nil
}

func TestLocalPrekeysFailBeforeRecordingWrongSignerOutput(t *testing.T) {
	delegation, _ := localPrekeyFixture(t)
	journal, ledger := openLocalPrekeys(t, t.TempDir()+"/state")
	defer journal.Close()
	now := time.Unix(1_800_000_000, 0)
	if _, _, err := ledger.EnsurePrekeys(
		delegation, invalidEd25519Signer{delegation.IdentityPublicKey}, e2ee.NewDefaultSuite(), localPlan(deviceID(1)), now,
	); err == nil {
		t.Fatal("invalid signer output was accepted")
	}
	if _, found, err := ledger.CurrentPrekeys(delegation.EndpointID); err != nil || found {
		t.Fatalf("failed signing left publication state: found=%v err=%v", found, err)
	}
}

type recordingPrekeySink struct {
	digest string
	raw    []byte
}

func (s *recordingPrekeySink) PutPrekeySet(_ context.Context, digest string, raw []byte) error {
	s.digest = digest
	s.raw = append([]byte(nil), raw...)
	clear(raw)
	return nil
}

func TestPublishCurrentPrekeysReloadsAndCopiesDurableArtifact(t *testing.T) {
	delegation, key := localPrekeyFixture(t)
	journal, ledger := openLocalPrekeys(t, t.TempDir()+"/state")
	defer journal.Close()
	publication, _, err := ledger.EnsurePrekeys(
		delegation, key, e2ee.NewDefaultSuite(), localPlan(deviceID(1)), time.Unix(1_800_000_000, 0),
	)
	if err != nil {
		t.Fatalf("prepare: %v", err)
	}
	sink := new(recordingPrekeySink)
	published, err := ledger.PublishCurrentPrekeys(context.Background(), sink, delegation.EndpointID)
	if err != nil {
		t.Fatalf("publish: %v", err)
	}
	if sink.digest != publication.SetDigest || !bytes.Equal(sink.raw, publication.BundleSetJSON) {
		t.Fatal("sink did not receive the exact prepared artifact")
	}
	if published.SetDigest != publication.SetDigest || !bytes.Equal(published.BundleSetJSON, publication.BundleSetJSON) {
		t.Fatal("publisher did not return the artifact the sink received")
	}
}

func TestLocalPrekeyCorruptionIsNotReportedAsAbsence(t *testing.T) {
	delegation, key := localPrekeyFixture(t)
	journal, ledger := openLocalPrekeys(t, t.TempDir()+"/state")
	defer journal.Close()
	publication, _, err := ledger.EnsurePrekeys(
		delegation, key, e2ee.NewDefaultSuite(), localPlan(deviceID(1)), time.Unix(1_800_000_000, 0),
	)
	if err != nil {
		t.Fatalf("prepare: %v", err)
	}
	digest, _ := e2ee.BundleDigest(publication.Bundles[0])
	if err := os.WriteFile(ledger.path(delegation.EndpointID), []byte("{}"), 0o600); err != nil {
		t.Fatalf("corrupt fixture: %v", err)
	}
	if _, err := ledger.PrekeyPrivate(delegation.EndpointID, digest, time.Unix(1_800_000_001, 0)); err == nil || errors.Is(err, ErrPrekeyUnavailable) {
		t.Fatalf("corrupt state was hidden as ordinary absence: %v", err)
	}
}
