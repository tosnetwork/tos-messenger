package daemon

import (
	"bufio"
	"bytes"
	"context"
	"crypto"
	"crypto/ed25519"
	"encoding/json"
	"net"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/tosnetwork/tos-messenger/pkg/directory"
	"github.com/tosnetwork/tos-messenger/pkg/e2ee"
	"github.com/tosnetwork/tos-messenger/pkg/eventlog"
	"github.com/tosnetwork/tos-messenger/pkg/identity"
	"github.com/tosnetwork/tos-messenger/pkg/prekeyapi"
)

func publicationFixture(t *testing.T, config *Config, now time.Time) (identity.Delegation, ed25519.PrivateKey) {
	t.Helper()
	key := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x47}, ed25519.SeedSize))
	endpointID, err := identity.DeriveEndpointID(config.Network(), config.AgentID, key.Public().(ed25519.PublicKey))
	if err != nil {
		t.Fatalf("derive endpoint: %v", err)
	}
	config.EndpointID = endpointID
	config.Publication = PublicationConfig{
		Mode: PublicationPrekeys, DeviceSocketPath: config.SocketPath + ".prekeys",
		DeviceIDs: []string{config.DeviceID}, AlgorithmID: e2ee.DefaultCandidateAlgorithmID,
		GenerationLifetimeSeconds: 120, ReplenishBeforeSeconds: 30, CheckIntervalSeconds: 10,
	}
	policy := directory.DescriptorPolicy{MaxEnvelopeBytes: 64 << 10, MaxLifetimeSeconds: 3600, AllowHTTPSEndpoint: true}
	policyDigest, err := policy.Digest()
	if err != nil {
		t.Fatalf("policy digest: %v", err)
	}
	inboxPolicy, err := config.AdmissionPolicy()
	if err != nil {
		t.Fatalf("admission policy: %v", err)
	}
	delegation := identity.Delegation{
		Network: config.Network(), AgentID: config.AgentID, EndpointID: endpointID,
		IdentityPublicKey: key.Public().(ed25519.PublicKey), AllowedProtocolVersions: []uint32{1},
		AllowedOutboundEventClasses: []string{"text"}, NotBeforeUnix: uint64(now.Add(-time.Minute).Unix()),
		ExpiresAtUnix: uint64(now.Add(time.Hour).Unix()), MaximumSessionLifetimeSeconds: 3600,
		ContactDescriptorPolicyDigest: policyDigest,
		InboxAdmissionPolicyDigest:    inboxPolicy.Digest(),
	}
	if err := identity.Validate(delegation); err != nil {
		t.Fatalf("delegation: %v", err)
	}
	return delegation, key
}

type daemonPublicationSink struct {
	calls []string
}

func (s *daemonPublicationSink) PutPrekeySet(context.Context, string, []byte) error {
	s.calls = append(s.calls, "prekeys")
	return nil
}

func (s *daemonPublicationSink) PutDescriptor(context.Context, string, []byte) error {
	s.calls = append(s.calls, "descriptor")
	return nil
}

type daemonLocatorSink struct {
	calls    int
	locators []directory.Locator
}

func (s *daemonLocatorSink) PublishLocator(_ context.Context, _ identity.Delegation,
	locator directory.Locator, _ crypto.Signer) (int, error) {
	s.calls++
	s.locators = append(s.locators, locator)
	return 2, nil
}

func TestPrekeyPlannerFinalizesThenRotatesWithoutPrivateMaterial(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	config := testConfig(t)
	delegation, key := publicationFixture(t, &config, now)
	journal, err := eventlog.Open(config.StateDir)
	if err != nil {
		t.Fatalf("open journal: %v", err)
	}
	defer journal.Close()
	clock := now
	runtime, err := newPrekeyRuntime(config, delegation, journal, func() time.Time { return clock })
	if err != nil {
		t.Fatalf("new prekey runtime: %v", err)
	}
	collection, found, err := runtime.planner.contributions.CurrentPrekeyCollection(delegation, clock)
	if err != nil || !found {
		t.Fatalf("current generation: found=%v err=%v", found, err)
	}
	bundle, err := e2ee.SignBundle(e2ee.Bundle{
		Network: delegation.Network, AgentID: delegation.AgentID, EndpointID: delegation.EndpointID,
		DeviceID: config.DeviceID, AlgorithmID: collection.Plan.AlgorithmID, Material: []byte("public-prekey"),
		IssuedAtUnix: collection.Plan.IssuedAtUnix, ExpiresAtUnix: collection.Plan.ExpiresAtUnix,
	}, key)
	if err != nil {
		t.Fatalf("sign public contribution: %v", err)
	}
	if _, fresh, err := runtime.planner.contributions.AddPrekeyContribution(delegation, bundle, clock); err != nil || !fresh {
		t.Fatalf("add contribution: fresh=%v err=%v", fresh, err)
	}
	runtime, err = newPrekeyRuntime(config, delegation, journal, func() time.Time { return clock })
	if err != nil {
		t.Fatalf("restart repairs finalization: %v", err)
	}
	publication, found, err := runtime.planner.publications.CurrentPrekeyPublication(delegation.EndpointID)
	if err != nil || !found || publication.SetDigest == "" {
		t.Fatalf("finalized publication: found=%v publication=%+v err=%v", found, publication, err)
	}
	clock = time.Unix(int64(collection.Plan.ExpiresAtUnix)-30, 0)
	if err := runtime.planner.Ensure(); err != nil {
		t.Fatalf("rotate at horizon: %v", err)
	}
	rotated, _, err := runtime.planner.contributions.CurrentPrekeyCollection(delegation, clock)
	if err != nil || rotated.Plan.IssuedAtUnix <= collection.Plan.IssuedAtUnix || len(rotated.Contributions) != 0 {
		t.Fatalf("unexpected rotation: %+v err=%v", rotated, err)
	}
}

func TestPrekeyRuntimeOwnsConfiguredDeviceBootstrapMaterial(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	config := testConfig(t)
	delegation, key := publicationFixture(t, &config, now)
	journal, err := eventlog.Open(config.StateDir)
	if err != nil {
		t.Fatal(err)
	}
	defer journal.Close()
	clock := now
	runtime, err := newPrekeyRuntime(config, delegation, journal, func() time.Time { return clock })
	if err != nil {
		t.Fatal(err)
	}
	if err := runtime.configureLocalDevice(config.DeviceID, key); err != nil {
		t.Fatalf("configure local device: %v", err)
	}
	collection, found, err := runtime.planner.contributions.CurrentPrekeyCollection(delegation, clock)
	if err != nil || !found || !collection.Complete || collection.FinalizedSetDigest == "" ||
		len(collection.Contributions) != 1 {
		t.Fatalf("local contribution was not finalized: found=%v collection=%+v err=%v", found, collection, err)
	}
	digest, err := e2ee.BundleDigest(collection.Contributions[0])
	if err != nil {
		t.Fatal(err)
	}
	private, err := runtime.devices.DevicePrekeyPrivate(
		delegation.EndpointID, config.DeviceID, digest, clock,
	)
	if err != nil || len(private) == 0 {
		t.Fatalf("private answering material is unavailable: bytes=%d err=%v", len(private), err)
	}
	for index := range private {
		private[index] = 0
	}

	clock = time.Unix(int64(collection.Plan.ExpiresAtUnix)-30, 0)
	if err := runtime.maintainLocalDevice(); err != nil {
		t.Fatalf("rotate local device: %v", err)
	}
	rotated, found, err := runtime.planner.contributions.CurrentPrekeyCollection(delegation, clock)
	if err != nil || !found || !rotated.Complete || rotated.FinalizedSetDigest == "" ||
		rotated.Plan.IssuedAtUnix <= collection.Plan.IssuedAtUnix {
		t.Fatalf("rotated local contribution is incomplete: found=%v collection=%+v err=%v", found, rotated, err)
	}
}

func TestPrekeyPlannerPreservesLivePartialAndReplacesItOnlyAfterExpiry(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	config := testConfig(t)
	delegation, key := publicationFixture(t, &config, now)
	secondDevice := "dev_" + strings.Repeat("5", 64)
	config.Publication.DeviceIDs = []string{config.DeviceID, secondDevice}
	journal, err := eventlog.Open(config.StateDir)
	if err != nil {
		t.Fatalf("open journal: %v", err)
	}
	defer journal.Close()
	clock := now
	runtime, err := newPrekeyRuntime(config, delegation, journal, func() time.Time { return clock })
	if err != nil {
		t.Fatalf("new prekey runtime: %v", err)
	}
	initial, _, err := runtime.planner.contributions.CurrentPrekeyCollection(delegation, clock)
	if err != nil {
		t.Fatalf("current generation: %v", err)
	}
	bundle, err := e2ee.SignBundle(e2ee.Bundle{
		Network: delegation.Network, AgentID: delegation.AgentID, EndpointID: delegation.EndpointID,
		DeviceID: config.DeviceID, AlgorithmID: initial.Plan.AlgorithmID, Material: []byte("public-prekey"),
		IssuedAtUnix: initial.Plan.IssuedAtUnix, ExpiresAtUnix: initial.Plan.ExpiresAtUnix,
	}, key)
	if err != nil {
		t.Fatalf("sign contribution: %v", err)
	}
	if _, _, err := runtime.planner.contributions.AddPrekeyContribution(delegation, bundle, clock); err != nil {
		t.Fatalf("add contribution: %v", err)
	}
	clock = time.Unix(int64(initial.Plan.ExpiresAtUnix)-1, 0)
	if err := runtime.planner.Ensure(); err != nil {
		t.Fatalf("preserve live partial: %v", err)
	}
	live, _, err := runtime.planner.contributions.CurrentPrekeyCollection(delegation, clock)
	if err != nil || live.Plan.IssuedAtUnix != initial.Plan.IssuedAtUnix || len(live.Contributions) != 1 {
		t.Fatalf("live partial changed: %+v err=%v", live, err)
	}
	clock = time.Unix(int64(initial.Plan.ExpiresAtUnix)+1, 0)
	if err := runtime.planner.Ensure(); err != nil {
		t.Fatalf("replace expired partial: %v", err)
	}
	replaced, _, err := runtime.planner.contributions.CurrentPrekeyCollection(delegation, clock)
	if err != nil || replaced.Plan.IssuedAtUnix <= initial.Plan.IssuedAtUnix || len(replaced.Contributions) != 0 {
		t.Fatalf("expired partial was not replaced: %+v err=%v", replaced, err)
	}
}

func TestDaemonServesAndRemovesPrekeyDeviceSocket(t *testing.T) {
	now := time.Now().Truncate(time.Second)
	config := testConfig(t)
	delegation, _ := publicationFixture(t, &config, now)
	instance, err := open(config, nil, fixedVerifier{delegation: delegation})
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if instance.PrekeySocketPath() != config.Publication.DeviceSocketPath {
		t.Fatalf("unexpected prekey socket: %q", instance.PrekeySocketPath())
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- instance.Run(ctx) }()
	response := callPrekey(t, config.Publication.DeviceSocketPath, prekeyapi.Request{Op: prekeyapi.OpCurrentGeneration})
	if !response.OK || response.Generation == nil || response.Generation.EndpointID != delegation.EndpointID {
		t.Fatalf("current generation: %+v", response)
	}
	cancel()
	if err := <-done; err != nil {
		t.Fatalf("run: %v", err)
	}
	if _, err := os.Stat(config.Publication.DeviceSocketPath); !os.IsNotExist(err) {
		t.Fatalf("prekey socket was not removed: %v", err)
	}
}

func TestDaemonPublishesFinalizedGenerationInDependencyOrder(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	config := testConfig(t)
	delegation, key := publicationFixture(t, &config, now)
	journal, err := eventlog.Open(config.StateDir)
	if err != nil {
		t.Fatalf("open journal: %v", err)
	}
	defer journal.Close()
	runtime, err := newPrekeyRuntime(config, delegation, journal, func() time.Time { return now })
	if err != nil {
		t.Fatalf("runtime: %v", err)
	}
	collection, _, err := runtime.planner.contributions.CurrentPrekeyCollection(delegation, now)
	if err != nil {
		t.Fatalf("collection: %v", err)
	}
	bundle, err := e2ee.SignBundle(e2ee.Bundle{
		Network: delegation.Network, AgentID: delegation.AgentID, EndpointID: delegation.EndpointID,
		DeviceID: config.DeviceID, AlgorithmID: collection.Plan.AlgorithmID, Material: []byte("public-prekey"),
		IssuedAtUnix: collection.Plan.IssuedAtUnix, ExpiresAtUnix: collection.Plan.ExpiresAtUnix,
	}, key)
	if err != nil {
		t.Fatalf("bundle: %v", err)
	}
	if _, _, err := runtime.planner.contributions.AddPrekeyContribution(delegation, bundle, now); err != nil {
		t.Fatalf("contribution: %v", err)
	}
	if _, _, err := runtime.planner.contributions.FinalizePrekeyCollection(delegation, runtime.planner.publications, now); err != nil {
		t.Fatalf("finalize: %v", err)
	}
	delegationDigest, err := identity.Digest(delegation)
	if err != nil {
		t.Fatalf("delegation digest: %v", err)
	}
	objects := new(daemonPublicationSink)
	locators := new(daemonLocatorSink)
	runtime.publisher = &directory.GenerationPublisher{
		Objects: objects, Locators: locators, Signer: key, Delegation: delegation,
		Policy: directory.DescriptorPolicy{MaxEnvelopeBytes: 64 << 10, MaxLifetimeSeconds: 3600, AllowHTTPSEndpoint: true},
		Descriptor: directory.Descriptor{
			Network: delegation.Network, AgentID: delegation.AgentID, EndpointID: delegation.EndpointID,
			DelegationDigest: delegationDigest, SupportedMessagingVersions: []uint32{1},
			HTTPSEndpoint:              "https://endpoint.example/messaging",
			MailboxRelaySetDigest:      directory.EmptyRelaySetDigest(),
			InboxAdmissionPolicyDigest: delegation.InboxAdmissionPolicyDigest, MaximumEnvelopeBytes: 64 << 10,
		},
		PublishInterval: time.Minute,
	}
	if err := runtime.publishCurrent(context.Background()); err != nil {
		t.Fatalf("publish: %v", err)
	}
	if len(objects.calls) != 2 || objects.calls[0] != "prekeys" || objects.calls[1] != "descriptor" || locators.calls != 1 {
		t.Fatalf("publication order: objects=%v locators=%d", objects.calls, locators.calls)
	}
	first := append([]byte(nil), locators.locators[0].EndpointSignature...)
	if err := runtime.publishCurrent(context.Background()); err != nil {
		t.Fatalf("retry: %v", err)
	}
	if locators.calls != 2 || !bytes.Equal(first, locators.locators[1].EndpointSignature) {
		t.Fatal("daemon retry changed the inner signed locator")
	}
}

func callPrekey(t *testing.T, path string, request prekeyapi.Request) prekeyapi.Response {
	t.Helper()
	connection, err := net.Dial("unix", path)
	if err != nil {
		t.Fatalf("dial prekey API: %v", err)
	}
	defer connection.Close()
	encoded, err := prekeyapi.EncodeRequest(request)
	if err != nil {
		t.Fatalf("encode prekey request: %v", err)
	}
	if _, err := connection.Write(encoded); err != nil {
		t.Fatalf("write prekey request: %v", err)
	}
	body, err := prekeyapi.ReadFrame(bufio.NewReader(connection))
	if err != nil {
		t.Fatalf("read prekey response: %v", err)
	}
	response, err := prekeyapi.DecodeResponse(body)
	if err != nil {
		t.Fatalf("decode prekey response: %v body=%s", err, json.RawMessage(body))
	}
	return response
}
