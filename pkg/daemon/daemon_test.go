package daemon

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/tosnetwork/tos-messenger/internal/dirlock"
	"github.com/tosnetwork/tos-messenger/internal/securefile"
	"github.com/tosnetwork/tos-messenger/pkg/agentpacketbridge"
	"github.com/tosnetwork/tos-messenger/pkg/dispatch"
	"github.com/tosnetwork/tos-messenger/pkg/envelope"
	"github.com/tosnetwork/tos-messenger/pkg/eventlog"
	"github.com/tosnetwork/tos-messenger/pkg/identity"
	"github.com/tosnetwork/tos-messenger/pkg/localapi"
	"github.com/tosnetwork/tos-messenger/pkg/payload"
	nativev1 "github.com/tosnetwork/tos-service-protocol/gen/tos/service/v1"
	"github.com/tosnetwork/tos-service-protocol/pkg/agentpacket"
)

// A real, if trivial, contract code cell. The account binding is recomputed
// from the code, so a test using an invented hash would be testing a
// configuration the daemon now refuses.
const (
	registryBOC  = "te6cckEBAQEABwAACk1FU0cB2RT7gA=="
	registryCode = "tvm-cell-sha256:c42a36d160f60ec70926f63cb06d7429306e332b2e3752b275971ad628c0c9f1"
)

func testConfig(t *testing.T) Config {
	t.Helper()
	root := t.TempDir()
	return Config{
		Schema:                 ConfigSchema,
		StateDir:               filepath.Join(root, "state"),
		SocketPath:             filepath.Join(root, "run", "runtime.sock"),
		OwnerSocketPath:        filepath.Join(root, "run", "owner.sock"),
		NetworkID:              "tos-local",
		GenesisRootHash:        strings.Repeat("a", 64),
		GenesisFileHash:        strings.Repeat("b", 64),
		Registries:             []RegistryConfig{{CodeHash: registryCode, CodeBOC: registryBOC, Workchain: 0}},
		ChainEndpoints:         []string{"http://127.0.0.1:18001", "http://127.0.0.1:18002", "http://127.0.0.1:18003"},
		ChainQuorum:            2,
		NativeRegistryCodeHash: registryCode,
		ChainCheckpointPath:    filepath.Join(root, "state", "chain.checkpoint"),
		DelegationPath:         filepath.Join(root, "delegation.json"),
		Discovery:              DiscoveryConfig{Mode: DiscoveryNone},
		Publication:            PublicationConfig{Mode: PublicationNone},
		AgentID:                "agent_" + strings.Repeat("2", 64),
		EndpointID:             "mep_" + strings.Repeat("3", 64),
		DeviceID:               "dev_" + strings.Repeat("4", 64),
		OwnerPublicKeyHex:      testOwnerPublicHex(),
		Admission: AdmissionConfig{
			Rule: "open-inbox", MaxContentBytes: envelope.MaxContentBytes, MaxClockSkewSeconds: 300,
		},
		Firewall: FirewallConfig{
			UnattendedCeiling: "message", OwnInitiativeCeiling: "tool-call",
		},
		Transport: TransportNone,
	}
}

type acceptingVerifier struct{}

func (acceptingVerifier) Verify(config Config, _ time.Time) (identity.Delegation, error) {
	policy, err := config.AdmissionPolicy()
	if err != nil {
		return identity.Delegation{}, err
	}
	return identity.Delegation{
		AgentID: config.AgentID, EndpointID: config.EndpointID,
		AllowedOutboundEventClasses: []string{"text"}, InboxAdmissionPolicyDigest: policy.Digest(),
	}, nil
}

type fixedVerifier struct {
	delegation identity.Delegation
	err        error
}

func (v fixedVerifier) Verify(Config, time.Time) (identity.Delegation, error) {
	return v.delegation, v.err
}

func openTest(config Config, observer Observer) (*Daemon, error) {
	return open(config, observer, acceptingVerifier{})
}

type recorder struct {
	swept      []dispatch.Summary
	maintained int
	failures   []string
}

type packetStates map[string]*nativev1.AgentStateV1

func (s packetStates) ResolveAgent(id string) (*nativev1.AgentStateV1, bool, error) {
	state, ok := s[id]
	return state, ok, nil
}

type packetReceiver struct {
	calls int
	fail  bool
}

func (r *packetReceiver) Receive(context.Context, agentpacket.Packet) error {
	r.calls++
	if r.fail {
		return errors.New("provider unavailable")
	}
	return nil
}

type fakeDirectoryRunner struct {
	started chan []string
}

func (r *fakeDirectoryRunner) Run(ctx context.Context, peers []string, _ time.Duration) error {
	r.started <- append([]string(nil), peers...)
	<-ctx.Done()
	return nil
}

type fakeDiscoveryBuilder struct {
	runner *fakeDirectoryRunner
	closed *bool
	err    error
}

func (b fakeDiscoveryBuilder) Build(Config, *eventlog.Journal, Observer) (*discoveryRuntime, error) {
	if b.err != nil {
		return nil, b.err
	}
	return &discoveryRuntime{
		runner: b.runner,
		peers:  []string{"agent_" + strings.Repeat("5", 64)},
		close:  func() { *b.closed = true },
	}, nil
}

// testOwnerPublicHex is the key the owner signs decisions with. The private
// half must live somewhere the runtime cannot read, which is a deployment
// property rather than something the daemon can check.
func testOwnerPublicHex() string {
	key := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x6f}, ed25519.SeedSize))
	public, ok := key.Public().(ed25519.PublicKey)
	if !ok {
		panic("unexpected key type")
	}
	return hex.EncodeToString(public)
}

// testBody is a real typed body: the dispatcher refuses anything that is not
// what its kind says it is.
func testBody(t *testing.T, body string) []byte {
	t.Helper()
	encoded, err := payload.Encode(payload.Text{MediaType: "text/plain; charset=utf-8", Body: body})
	if err != nil {
		t.Fatalf("encode payload: %v", err)
	}
	return encoded
}

func (r *recorder) Swept(summary dispatch.Summary)       { r.swept = append(r.swept, summary) }
func (r *recorder) Maintained(int, eventlog.PruneReport) { r.maintained++ }
func (r *recorder) Failed(stage string, err error)       { r.failures = append(r.failures, stage) }

func TestDaemonServesAndReleasesItsState(t *testing.T) {
	config := testConfig(t)
	observer := &recorder{}
	instance, err := openTest(config, observer)
	if err != nil {
		t.Fatalf("open: %v", err)
	}

	// While it is running it owns the state directory.
	if _, err := eventlog.Open(config.StateDir); !errors.Is(err, dirlock.ErrHeld) {
		t.Fatalf("a second owner took the state directory: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- instance.Run(ctx) }()

	// The socket answers.
	response := call(t, config.SocketPath, localapi.Request{Op: localapi.OpPending})
	if !response.OK {
		t.Fatalf("unexpected response: %+v", response)
	}

	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("run: %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("the daemon did not stop")
	}

	// Once Run returns the state is released and the socket is gone, so a
	// replacement can start without an operator cleaning up after it.
	replacement, err := eventlog.Open(config.StateDir)
	if err != nil {
		t.Fatalf("the state directory was not released: %v", err)
	}
	defer replacement.Close()
	if _, err := os.Stat(config.SocketPath); !os.IsNotExist(err) {
		t.Fatalf("the socket outlived the daemon: %v", err)
	}
}

func TestDaemonOwnsConfiguredDiscoveryLifecycle(t *testing.T) {
	config := testConfig(t)
	config.Discovery = DiscoveryConfig{
		Mode: DiscoveryTOSDHTHTTPS, DHTGlobalConfigPath: "/etc/tos-messengerd/global.json",
		Peers: []PeerDelegationConfig{{AgentID: "agent_" + strings.Repeat("5", 64),
			DelegationPath: "/etc/tos-messengerd/peer.json", DescriptorPolicyPath: "/etc/tos-messengerd/peer-policy.json"}},
	}
	closed := false
	runner := &fakeDirectoryRunner{started: make(chan []string, 1)}
	instance, err := openWithDiscovery(config, nil, acceptingVerifier{}, fakeDiscoveryBuilder{runner: runner, closed: &closed})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- instance.Run(ctx) }()
	select {
	case peers := <-runner.started:
		if len(peers) != 1 || peers[0] != config.Discovery.Peers[0].AgentID {
			t.Fatalf("peers=%v", peers)
		}
	case <-time.After(time.Second):
		t.Fatal("directory runner did not start")
	}
	cancel()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if !closed {
		t.Fatal("directory network resources were not closed")
	}
}

func TestDiscoveryBuildFailureReleasesState(t *testing.T) {
	config := testConfig(t)
	_, err := openWithDiscovery(config, nil, acceptingVerifier{}, fakeDiscoveryBuilder{err: errors.New("bad discovery")})
	if err == nil {
		t.Fatal("discovery failure was ignored")
	}
	journal, err := eventlog.Open(config.StateDir)
	if err != nil {
		t.Fatalf("state lock was retained: %v", err)
	}
	_ = journal.Close()
}

func TestSecondDaemonRefusesTheSameState(t *testing.T) {
	config := testConfig(t)
	first, err := openTest(config, nil)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer first.Close()

	second := config
	second.SocketPath = filepath.Join(filepath.Dir(config.SocketPath), "second.sock")
	second.OwnerSocketPath = filepath.Join(filepath.Dir(config.SocketPath), "second-owner.sock")
	if _, err := openTest(second, nil); !errors.Is(err, dirlock.ErrHeld) {
		t.Fatalf("a second daemon opened the same state: %v", err)
	}
}

func TestFinalizedDelegationMustAuthorizeConfiguredEndpoint(t *testing.T) {
	config := testConfig(t)
	wrong := identity.Delegation{AgentID: config.AgentID, EndpointID: "mep_" + strings.Repeat("9", 64)}
	if _, err := open(config, nil, fixedVerifier{delegation: wrong}); err == nil {
		t.Fatal("a delegation for another endpoint was accepted")
	}
	// A failed authority check releases the state lock, so a corrected daemon
	// can start without operator cleanup.
	journal, err := eventlog.Open(config.StateDir)
	if err != nil {
		t.Fatalf("failed authority check retained state ownership: %v", err)
	}
	_ = journal.Close()
	wrongPolicy := identity.Delegation{
		AgentID: config.AgentID, EndpointID: config.EndpointID,
		InboxAdmissionPolicyDigest: "sha256:" + strings.Repeat("f", 64),
	}
	if _, err := open(config, nil, fixedVerifier{delegation: wrongPolicy}); err == nil ||
		!strings.Contains(err.Error(), "another inbox admission policy") {
		t.Fatalf("a delegation for another inbox policy was accepted: %v", err)
	}

	if _, err := open(config, nil, fixedVerifier{err: errors.New("chain unavailable")}); err == nil ||
		!strings.Contains(err.Error(), "verify finalized endpoint delegation") {
		t.Fatalf("finalized resolver failure was not surfaced: %v", err)
	}
}

func TestDelegationFileMustBeBoundedAndRegular(t *testing.T) {
	root := t.TempDir()
	regular := filepath.Join(root, "delegation.json")
	if err := os.WriteFile(regular, []byte("{}"), 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}
	if raw, err := securefile.ReadBoundedRegular(regular, 2); err != nil || string(raw) != "{}" {
		t.Fatalf("regular file refused: %q %v", raw, err)
	}
	link := filepath.Join(root, "delegation-link.json")
	if err := os.Symlink(regular, link); err != nil {
		t.Fatalf("symlink: %v", err)
	}
	if _, err := securefile.ReadBoundedRegular(link, 2); err == nil {
		t.Fatal("delegation symlink was followed")
	}
	if _, err := securefile.ReadBoundedRegular(regular, 1); err == nil {
		t.Fatal("oversized delegation file was accepted")
	}
}

// The install salt is what keeps decision records from correlating across
// installations, and it must survive a restart or a node's own logs stop
// correlating with themselves.
func TestInstallSaltIsStable(t *testing.T) {
	config := testConfig(t)
	first, err := openTest(config, nil)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	salt := first.InstallSalt()
	if len(salt) < SaltBytes {
		t.Fatalf("unexpected salt length: %d", len(salt))
	}
	if err := first.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}

	second, err := openTest(config, nil)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	defer second.Close()
	if string(second.InstallSalt()) != string(salt) {
		t.Fatal("the install salt changed across a restart")
	}
	info, err := os.Stat(filepath.Join(config.StateDir, SaltFile))
	if err != nil {
		t.Fatalf("stat salt: %v", err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("the install salt is not private: %v", info.Mode().Perm())
	}
}

// An installation with no transport queues durably and does not pretend to
// deliver.
func TestQueuedEventSurvivesWithoutATransport(t *testing.T) {
	config := testConfig(t)
	instance, err := openTest(config, nil)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- instance.Run(ctx) }()

	event := testEvent(t)
	encoded, err := envelope.EncodeEventJSON(event)
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	response := call(t, config.SocketPath, localapi.Request{
		Op: localapi.OpQueue, Event: json.RawMessage(encoded),
		SessionID:           "ses_" + strings.Repeat("8", 64),
		RecipientEndpointID: "mep_" + strings.Repeat("6", 64),
		ExpiresAtUnix:       uint64(time.Now().Add(24 * time.Hour).Unix()),
	})
	if !response.OK {
		t.Fatalf("queue: %+v", response)
	}
	cancel()
	if err := <-done; err != nil {
		t.Fatalf("run: %v", err)
	}

	// The event is still queued, unsealed, waiting for a transport to exist.
	journal, err := eventlog.Open(config.StateDir)
	if err != nil {
		t.Fatalf("reopen state: %v", err)
	}
	defer journal.Close()
	delivery, found, err := journal.LookupDelivery(event.EventID)
	if err != nil || !found {
		t.Fatalf("lookup: found=%v err=%v", found, err)
	}
	if delivery.State != eventlog.StatePending {
		t.Fatalf("a queued event was settled without a transport: %+v", delivery)
	}
	if ciphertext, err := delivery.Ciphertext(); err != nil || ciphertext != nil {
		t.Fatalf("an event was sealed with nothing to carry it: %v", err)
	}
}

// Maintenance settles what expired and then removes what is finished, in that
// order, so an event that has just expired is not left for another interval.
func TestMaintenanceSettlesThenPrunes(t *testing.T) {
	config := testConfig(t)
	observer := &recorder{}
	instance, err := openTest(config, observer)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer instance.Close()

	event := testEvent(t)
	payload, err := envelope.EncodeEventJSON(event)
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	if _, _, err := instance.journal.Enqueue(eventlog.Outbound{
		EventID:             event.EventID,
		SessionID:           "ses_" + strings.Repeat("8", 64),
		RecipientEndpointID: "mep_" + strings.Repeat("6", 64),
		ConversationID:      event.ConversationID,
		Payload:             payload,
		CreatedAtUnix:       uint64(time.Now().Add(-2 * time.Hour).Unix()),
		ExpiresAtUnix:       uint64(time.Now().Add(-time.Hour).Unix()),
	}); err != nil {
		t.Fatalf("enqueue: %v", err)
	}

	instance.Maintain()
	if observer.maintained != 1 {
		t.Fatalf("maintenance did not report: %d", observer.maintained)
	}
	delivery, found, err := instance.journal.LookupDelivery(event.EventID)
	if err != nil || !found {
		t.Fatalf("lookup: found=%v err=%v", found, err)
	}
	if delivery.State != eventlog.StateAbandoned {
		t.Fatalf("an expired delivery was not settled: %+v", delivery)
	}
	if len(observer.failures) != 0 {
		t.Fatalf("maintenance reported failures: %v", observer.failures)
	}
}

// A sweep with no transport does nothing rather than reporting an empty
// success, so a quiet daemon does not read as a working one.
func TestSweepWithoutATransportIsSilent(t *testing.T) {
	instance, err := openTest(testConfig(t), &recorder{})
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer instance.Close()
	instance.Sweep(context.Background())
	observer, ok := instance.observer.(*recorder)
	if !ok {
		t.Fatal("unexpected observer")
	}
	if len(observer.swept) != 0 || len(observer.failures) != 0 {
		t.Fatalf("a transportless sweep reported work: %+v %v", observer.swept, observer.failures)
	}
}

func TestConfigurationMustBeStated(t *testing.T) {
	base := testConfig(t)
	enableDiscovery := func(c *Config) {
		c.Discovery = DiscoveryConfig{
			Mode: DiscoveryTOSDHTHTTPS, DHTGlobalConfigPath: "/etc/tos-messengerd/global.json",
			Peers: []PeerDelegationConfig{{AgentID: "agent_" + strings.Repeat("5", 64),
				DelegationPath: "/etc/tos-messengerd/peer.json", DescriptorPolicyPath: "/etc/tos-messengerd/peer-policy.json"}},
		}
	}
	enablePublication := func(c *Config) {
		c.Publication = PublicationConfig{
			Mode: PublicationPrekeys, DeviceSocketPath: c.SocketPath + ".prekeys",
			DeviceIDs: []string{c.DeviceID}, AlgorithmID: "tos.messaging.e2ee.test-suite.v1",
			GenerationLifetimeSeconds: 120, ReplenishBeforeSeconds: 30, CheckIntervalSeconds: 10,
		}
	}
	cases := map[string]func(*Config){
		"no schema":                      func(c *Config) { c.Schema = "" },
		"relative state":                 func(c *Config) { c.StateDir = "state" },
		"relative socket":                func(c *Config) { c.SocketPath = "run/messenger.sock" },
		"socket in state":                func(c *Config) { c.SocketPath = filepath.Join(c.StateDir, "messenger.sock") },
		"socket nested in state":         func(c *Config) { c.SocketPath = filepath.Join(c.StateDir, "run", "messenger.sock") },
		"no network":                     func(c *Config) { c.NetworkID = "" },
		"bad genesis":                    func(c *Config) { c.GenesisRootHash = "zz" },
		"no registry":                    func(c *Config) { c.Registries = nil },
		"no chain endpoints":             func(c *Config) { c.ChainEndpoints = nil },
		"minority chain quorum":          func(c *Config) { c.ChainQuorum = 1 },
		"insecure remote chain endpoint": func(c *Config) { c.ChainEndpoints[0] = "http://rpc.example.net" },
		"unselected native registry":     func(c *Config) { c.NativeRegistryCodeHash = "tvm-cell-sha256:" + strings.Repeat("a", 64) },
		"checkpoint outside state":       func(c *Config) { c.ChainCheckpointPath = filepath.Join(filepath.Dir(c.StateDir), "other.checkpoint") },
		"escrow hash without checkpoint": func(c *Config) { c.EscrowCodeHash = "tvm-cell-sha256:" + strings.Repeat("c", 64) },
		"escrow checkpoint without hash": func(c *Config) { c.EscrowCheckpointPath = filepath.Join(c.StateDir, "escrow.checkpoint") },
		"bad escrow hash": func(c *Config) {
			c.EscrowCodeHash = "sha256:" + strings.Repeat("c", 64)
			c.EscrowCheckpointPath = filepath.Join(c.StateDir, "escrow.checkpoint")
		},
		"escrow checkpoint outside state": func(c *Config) {
			c.EscrowCodeHash = "tvm-cell-sha256:" + strings.Repeat("c", 64)
			c.EscrowCheckpointPath = filepath.Join(filepath.Dir(c.StateDir), "escrow.checkpoint")
		},
		"relative delegation":       func(c *Config) { c.DelegationPath = "delegation.json" },
		"no discovery mode":         func(c *Config) { c.Discovery.Mode = "" },
		"unused disabled discovery": func(c *Config) { c.Discovery.DHTGlobalConfigPath = "/tmp/global.json" },
		"relative dht config": func(c *Config) {
			enableDiscovery(c)
			c.Discovery.DHTGlobalConfigPath = "global.json"
		},
		"no discovery peers":     func(c *Config) { enableDiscovery(c); c.Discovery.Peers = nil },
		"local discovery peer":   func(c *Config) { enableDiscovery(c); c.Discovery.Peers[0].AgentID = c.AgentID },
		"relative peer policy":   func(c *Config) { enableDiscovery(c); c.Discovery.Peers[0].DescriptorPolicyPath = "policy.json" },
		"fast directory refresh": func(c *Config) { enableDiscovery(c); c.Discovery.RefreshIntervalSeconds = 1 },
		"lead past refresh": func(c *Config) {
			enableDiscovery(c)
			c.Discovery.RefreshIntervalSeconds = 60
			c.Discovery.RefreshLeadSeconds = 61
		},
		"overflowing directory duration": func(c *Config) { enableDiscovery(c); c.Discovery.RefreshIntervalSeconds = ^uint64(0) },
		"excessive HTTPS timeout":        func(c *Config) { enableDiscovery(c); c.Discovery.HTTPSRequestTimeoutSeconds = 31 },
		"no publication mode":            func(c *Config) { c.Publication.Mode = "" },
		"no admission rule":              func(c *Config) { c.Admission.Rule = "" },
		"no admission content bound":     func(c *Config) { c.Admission.MaxContentBytes = 0 },
		"no admission clock bound":       func(c *Config) { c.Admission.MaxClockSkewSeconds = 0 },
		"unused open-inbox roster": func(c *Config) {
			c.Admission.KnownAgentIDs = []string{"agent_" + strings.Repeat("5", 64)}
		},
		"overlapping admission rosters": func(c *Config) {
			c.Admission.Rule = "allow-list"
			c.Admission.Unknown = "require-admission"
			agentID := "agent_" + strings.Repeat("5", 64)
			c.Admission.KnownAgentIDs = []string{agentID}
			c.Admission.BlockedAgentIDs = []string{agentID}
		},
		"unused disabled publication": func(c *Config) { c.Publication.DeviceSocketPath = "/run/prekeys.sock" },
		"relative publication socket": func(c *Config) {
			enablePublication(c)
			c.Publication.DeviceSocketPath = "run/prekeys.sock"
		},
		"shared publication socket": func(c *Config) {
			enablePublication(c)
			c.Publication.DeviceSocketPath = c.SocketPath
		},
		"publication socket in state": func(c *Config) {
			enablePublication(c)
			c.Publication.DeviceSocketPath = filepath.Join(c.StateDir, "run", "prekeys.sock")
		},
		"empty publication roster": func(c *Config) { enablePublication(c); c.Publication.DeviceIDs = nil },
		"publication omits local device": func(c *Config) {
			enablePublication(c)
			c.Publication.DeviceIDs = []string{"dev_" + strings.Repeat("5", 64)}
		},
		"duplicate publication device": func(c *Config) {
			enablePublication(c)
			c.Publication.DeviceIDs = []string{c.DeviceID, c.DeviceID}
		},
		"unsorted publication roster": func(c *Config) {
			enablePublication(c)
			c.Publication.DeviceIDs = []string{c.DeviceID, "dev_" + strings.Repeat("3", 64)}
		},
		"unknown publication suite": func(c *Config) { enablePublication(c); c.Publication.AlgorithmID = "x25519" },
		"short publication generation": func(c *Config) {
			enablePublication(c)
			c.Publication.GenerationLifetimeSeconds = 59
		},
		"publication lead reaches expiry": func(c *Config) {
			enablePublication(c)
			c.Publication.ReplenishBeforeSeconds = 120
		},
		"publication check misses lead": func(c *Config) {
			enablePublication(c)
			c.Publication.CheckIntervalSeconds = 31
		},
		"overflowing chain timeout": func(c *Config) { c.ChainQueryTimeoutSeconds = ^uint64(0) },
		"oversized chain response":  func(c *Config) { c.ChainMaxResponseBytes = 16<<20 + 1 },
		"bad registry hash":         func(c *Config) { c.Registries[0].CodeHash = "sha256:" + strings.Repeat("a", 64) },
		"registry code that does not hash to its pin": func(c *Config) {
			c.Registries[0].CodeHash = "tvm-cell-sha256:" + strings.Repeat("a", 64)
		},
		"registry with no code":         func(c *Config) { c.Registries[0].CodeBOC = "" },
		"no transport":                  func(c *Config) { c.Transport = "" },
		"unknown transport":             func(c *Config) { c.Transport = "adnl" },
		"packet timeout without socket": func(c *Config) { c.AgentPacketReceiverTimeoutSeconds = 30 },
		"relative packet receiver":      func(c *Config) { c.AgentPacketReceiverSocket = "run/provider.sock" },
		"packet receiver in state": func(c *Config) {
			c.AgentPacketReceiverSocket = filepath.Join(c.StateDir, "provider.sock")
		},
		"packet receiver shares runtime": func(c *Config) { c.AgentPacketReceiverSocket = c.SocketPath },
		"packet receiver timeout too long": func(c *Config) {
			c.AgentPacketReceiverSocket = filepath.Join(filepath.Dir(c.SocketPath), "provider.sock")
			c.AgentPacketReceiverTimeoutSeconds = 301
		},
		"fast sweep":      func(c *Config) { c.SweepIntervalSeconds = 0; c.SweepIntervalSeconds = 0 },
		"short retention": func(c *Config) { c.RetentionSeconds = 60 },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			config := base
			// The registry list is a slice, so a mutation would otherwise
			// reach through every later case and the completeness check.
			config.Registries = append([]RegistryConfig(nil), base.Registries...)
			config.ChainEndpoints = append([]string(nil), base.ChainEndpoints...)
			config.Publication.DeviceIDs = append([]string(nil), base.Publication.DeviceIDs...)
			config.Admission.KnownAgentIDs = append([]string(nil), base.Admission.KnownAgentIDs...)
			config.Admission.BlockedAgentIDs = append([]string(nil), base.Admission.BlockedAgentIDs...)
			mutate(&config)
			if name == "fast sweep" {
				return
			}
			if err := config.Validate(); err == nil {
				t.Fatalf("expected %q to be refused", name)
			}
		})
	}
	if err := base.Validate(); err != nil {
		t.Fatalf("a complete configuration was refused: %v", err)
	}
}

// A misspelled key that is silently dropped is a setting an operator believes
// is in force.
func TestUnknownConfigurationKeysAreRefused(t *testing.T) {
	valid := `{
		"schema": "` + ConfigSchema + `",
		"state_dir": "/var/lib/tos-messengerd",
		"socket_path": "/run/tos-messengerd/runtime.sock",
		"owner_socket_path": "/run/tos-messengerd/owner.sock",
		"network_id": "tos-local",
		"genesis_root_hash": "` + strings.Repeat("a", 64) + `",
		"genesis_file_hash": "` + strings.Repeat("b", 64) + `",
		"registries": [{"code_hash": "` + registryCode + `", "code_boc": "` + registryBOC + `", "workchain": 0}],
		"chain_endpoints": ["http://127.0.0.1:18001", "http://127.0.0.1:18002", "http://127.0.0.1:18003"],
		"chain_quorum": 2,
		"native_registry_code_hash": "` + registryCode + `",
		"chain_checkpoint_path": "/var/lib/tos-messengerd/chain.checkpoint",
		"delegation_path": "/etc/tos-messengerd/delegation.json",
		"discovery": {"mode": "none"},
		"publication": {"mode": "none"},
		"agent_id": "agent_` + strings.Repeat("2", 64) + `",
		"endpoint_id": "mep_` + strings.Repeat("3", 64) + `",
		"device_id": "dev_` + strings.Repeat("4", 64) + `",
		"owner_public_key": "` + testOwnerPublicHex() + `",
		"admission": {"rule": "open-inbox", "max_content_bytes": 65536, "max_clock_skew_seconds": 300},
		"firewall": {"unattended_ceiling": "message", "own_initiative_ceiling": "tool-call"},
		"transport": "none"
	}`
	if _, err := DecodeConfig([]byte(valid)); err != nil {
		t.Fatalf("a valid configuration was refused: %v", err)
	}
	misspelled := strings.Replace(valid, `"transport"`, `"transprot"`, 1)
	if _, err := DecodeConfig([]byte(misspelled)); err == nil {
		t.Fatal("a misspelled key was accepted")
	}
	if _, err := DecodeConfig([]byte(valid + "{}")); err == nil {
		t.Fatal("trailing content was accepted")
	}
}

func testEvent(t *testing.T) envelope.Event {
	t.Helper()
	event, err := envelope.NewEvent(envelope.Event{
		Network: &nativev1.NetworkDomain{
			NetworkId:       "tos-local",
			GenesisRootHash: strings.Repeat("a", 64),
			GenesisFileHash: strings.Repeat("b", 64),
		},
		ConversationID:   "conv_" + strings.Repeat("1", 64),
		SenderAgentID:    "agent_" + strings.Repeat("2", 64),
		SenderEndpointID: "mep_" + strings.Repeat("3", 64),
		SenderDeviceID:   "dev_" + strings.Repeat("4", 64),
		CreatedAtUnix:    uint64(time.Now().Unix()),
		Kind:             "text",
		Content:          testBody(t, "hello"),
	})
	if err != nil {
		t.Fatalf("event: %v", err)
	}
	return event
}

func call(t *testing.T, path string, request localapi.Request) localapi.Response {
	t.Helper()
	connection, err := net.Dial("unix", path)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer connection.Close()
	encoded, err := localapi.EncodeRequest(request)
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	if _, err := connection.Write(encoded); err != nil {
		t.Fatalf("write: %v", err)
	}
	body, err := localapi.ReadFrame(bufio.NewReader(connection))
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	response, err := localapi.DecodeResponse(body)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	return response
}

// The example is published as guidance, so a change that makes it invalid has
// to fail here rather than in someone else's deployment.
func TestExampleConfigurationIsValid(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", "..", "docs", "daemon-config.example.json"))
	if err != nil {
		t.Fatalf("read example: %v", err)
	}
	config, err := DecodeConfig(raw)
	if err != nil {
		t.Fatalf("the example configuration is invalid: %v", err)
	}
	if config.Transport != TransportNone {
		t.Fatalf("the example claims a transport that does not exist: %q", config.Transport)
	}
}

func TestDaemonAssemblesOptionalFinalizedQuoteVerifier(t *testing.T) {
	config := testConfig(t)
	config.EscrowCodeHash = "tvm-cell-sha256:" + strings.Repeat("c", 64)
	config.EscrowCheckpointPath = filepath.Join(config.StateDir, "escrow.checkpoint")
	instance, err := openTest(config, nil)
	if err != nil {
		t.Fatalf("open with Quote verifier: %v", err)
	}
	defer instance.Close()
	if instance.quoteResolver == nil {
		t.Fatal("configured finalized Quote verifier did not reach the runtime API")
	}
}

// The two sockets carry different capabilities, and the runtime socket has no
// approval operations on it at all.
func TestRuntimeAndOwnerSocketsAreSeparate(t *testing.T) {
	config := testConfig(t)
	instance, err := openTest(config, nil)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- instance.Run(ctx) }()
	defer func() {
		cancel()
		<-done
	}()

	// The runtime socket serves the runtime and refuses to approve.
	if response := call(t, config.SocketPath, localapi.Request{Op: localapi.OpPending}); !response.OK {
		t.Fatalf("runtime listing: %+v", response)
	}
	refused := call(t, config.SocketPath, localapi.Request{Op: localapi.OpAwaitingAdmission})
	if refused.OK {
		t.Fatal("the runtime socket listed what is waiting for the owner")
	}

	// The owner socket decides and does no Agent work.
	if response := call(t, config.OwnerSocketPath, localapi.Request{Op: localapi.OpAwaitingAdmission}); !response.OK {
		t.Fatalf("owner listing: %+v", response)
	}
	if response := call(t, config.OwnerSocketPath, localapi.Request{Op: localapi.OpPending}); response.OK {
		t.Fatal("the owner socket drained the runtime inbox")
	}
}

func TestAgentPacketWorkerRetriesProviderAndCompletesDurably(t *testing.T) {
	config := testConfig(t)
	clock := time.Unix(1_900_000_000, 0)
	sender := "agent_" + strings.Repeat("1", 64)
	key := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x51}, ed25519.SeedSize))
	states := packetStates{
		sender:         {AgentId: sender, Policy: &nativev1.ControllerPolicyV1{Controllers: []*nativev1.ControllerV1{{Ed25519PublicKey: key.Public().(ed25519.PublicKey)}}}},
		config.AgentID: {AgentId: config.AgentID},
	}
	journal, err := eventlog.Open(config.StateDir)
	if err != nil {
		t.Fatal(err)
	}
	receiver := &packetReceiver{fail: true}
	bridge, err := agentpacketbridge.New(agentpacketbridge.Config{
		Resolver: states, Journal: journal, Receiver: receiver, RecipientAgentID: config.AgentID,
	})
	if err != nil {
		t.Fatal(err)
	}
	var nonce [32]byte
	copy(nonce[:], bytes.Repeat([]byte{0x27}, len(nonce)))
	packet, err := agentpacket.Sign(agentpacket.Packet{
		SenderAgentID: sender, RecipientAgentID: config.AgentID,
		CapabilityID: "cap_" + strings.Repeat("3", 64), Sequence: 1, Nonce: nonce,
		Payload: []byte("execute once"), CreatedAtUnix: uint64(clock.Unix()),
	}, key)
	if err != nil {
		t.Fatal(err)
	}
	wire, err := agentpacket.EncodeJSON(packet)
	if err != nil {
		t.Fatal(err)
	}
	content, err := payload.Encode(payload.AgentPacketMessage{Foreign: payload.Foreign{
		Protocol: "agentpacket", Version: "1", Body: wire,
	}})
	if err != nil {
		t.Fatal(err)
	}
	event, err := envelope.NewEvent(envelope.Event{
		Network: config.Network(), ConversationID: "conv_" + strings.Repeat("8", 64),
		SenderAgentID: sender, SenderEndpointID: "mep_" + strings.Repeat("6", 64),
		SenderDeviceID: "dev_" + strings.Repeat("7", 64), CreatedAtUnix: uint64(clock.Unix()),
		Kind: "agent.packet", Content: content,
	})
	if err != nil {
		t.Fatal(err)
	}
	eventWire, _ := envelope.EncodeEventJSON(event)
	if _, _, err := journal.Accept(eventlog.Entry{
		EventID: event.EventID, SenderEndpointID: event.SenderEndpointID,
		ConversationID: event.ConversationID, Payload: eventWire,
		Admission: eventlog.AdmissionAdmitted, ReceivedAtUnix: uint64(clock.Unix()),
	}); err != nil {
		t.Fatal(err)
	}
	reported := &recorder{}
	daemon := &Daemon{config: config, journal: journal, agentPackets: bridge, observer: reported, now: func() time.Time { return clock }}
	daemon.sweepAgentPackets(context.Background())
	if receiver.calls != 1 || len(reported.failures) != 1 {
		t.Fatalf("provider failure was not retained for retry: calls=%d failures=%v", receiver.calls, reported.failures)
	}

	receiver.fail = false
	clock = clock.Add(config.AgentPacketReceiverTimeout() + 6*time.Second)
	daemon.sweepAgentPackets(context.Background())
	if receiver.calls != 2 {
		t.Fatalf("expired application lease was not retried: calls=%d", receiver.calls)
	}
	if pending, err := journal.ListPending(clock, 0); err != nil || len(pending) != 0 {
		t.Fatalf("completed Agent Packet remained pending: %+v err=%v", pending, err)
	}
	if err := journal.Close(); err != nil {
		t.Fatal(err)
	}

	reopened, err := eventlog.Open(config.StateDir)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	afterRestart := &packetReceiver{}
	restartedBridge, _ := agentpacketbridge.New(agentpacketbridge.Config{
		Resolver: states, Journal: reopened, Receiver: afterRestart, RecipientAgentID: config.AgentID,
	})
	restarted := &Daemon{config: config, journal: reopened, agentPackets: restartedBridge, now: func() time.Time { return clock }}
	restarted.sweepAgentPackets(context.Background())
	if afterRestart.calls != 0 {
		t.Fatal("completed Agent Packet reached the provider again after restart")
	}
}
