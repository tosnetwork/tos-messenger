package daemon

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/tosnetwork/tos-messenger/pkg/directory"
	"github.com/tosnetwork/tos-messenger/pkg/dispatch"
	"github.com/tosnetwork/tos-messenger/pkg/e2ee"
	"github.com/tosnetwork/tos-messenger/pkg/eventlog"
	"github.com/tosnetwork/tos-messenger/pkg/identity"
)

type daemonContactDirectory struct {
	calls  []string
	result *directory.RefreshResult
}

func (d *daemonContactDirectory) Ensure(_ context.Context, agentID string) (directory.RefreshResult, error) {
	d.calls = append(d.calls, agentID)
	if d.result != nil {
		return *d.result, nil
	}
	return directory.RefreshResult{
		Delegation:          identity.Delegation{AgentID: agentID},
		Descriptor:          directory.Descriptor{AgentID: agentID, EndpointID: "mep_" + strings.Repeat("8", 64)},
		FinalizedCheckpoint: 73,
	}, nil
}

func TestDaemonEnsuresVerifiedDeviceSessionsWithoutCallerRouteAuthority(t *testing.T) {
	now := time.Unix(1_900_000_000, 0)
	config := testConfig(t)
	localDelegation, localKey := publicationFixture(t, &config, now)
	journal, err := eventlog.Open(config.StateDir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = journal.Close() })
	prekeys, err := newPrekeyRuntime(config, localDelegation, journal, func() time.Time { return now })
	if err != nil {
		t.Fatalf("open prekeys: %v", err)
	}
	if err := prekeys.configureLocalDevice(config.DeviceID, localKey); err != nil {
		t.Fatalf("configure local device: %v", err)
	}

	remoteAgent := "agent_" + strings.Repeat("7", 64)
	remoteDevice := "dev_" + strings.Repeat("9", 64)
	remoteKey := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x65}, ed25519.SeedSize))
	remoteEndpoint, err := identity.DeriveEndpointID(config.Network(), remoteAgent, remoteKey.Public().(ed25519.PublicKey))
	if err != nil {
		t.Fatalf("derive remote endpoint: %v", err)
	}
	public, _, err := e2ee.NewDefaultSuite().NewPrekeyMaterial()
	if err != nil {
		t.Fatalf("remote prekey: %v", err)
	}
	remoteBundle, err := e2ee.SignBundle(e2ee.Bundle{Network: config.Network(), AgentID: remoteAgent,
		EndpointID: remoteEndpoint, DeviceID: remoteDevice, AlgorithmID: e2ee.DefaultCandidateAlgorithmID,
		Material: public, IssuedAtUnix: uint64(now.Unix()), ExpiresAtUnix: uint64(now.Add(time.Hour).Unix())}, remoteKey)
	if err != nil {
		t.Fatalf("sign remote bundle: %v", err)
	}
	contacts := &daemonContactDirectory{result: &directory.RefreshResult{
		Delegation: identity.Delegation{AgentID: remoteAgent},
		Descriptor: directory.Descriptor{AgentID: remoteAgent, EndpointID: remoteEndpoint},
		Bundles:    []e2ee.Bundle{remoteBundle}, FinalizedCheckpoint: 73, RefreshedAt: now,
	}}
	d := &Daemon{config: config, journal: journal, prekeys: prekeys,
		discovery: &discoveryRuntime{contacts: contacts}, now: func() time.Time { return now }}
	d.dispatch, err = dispatch.New(dispatch.Config{Journal: journal, Identity: config.Identity(),
		Network: config.Network(), Now: func() time.Time { return now }})
	if err != nil {
		t.Fatalf("dispatcher: %v", err)
	}
	result, err := d.EnsureDirectConversation(context.Background(), remoteAgent, nil)
	if err != nil {
		t.Fatalf("ensure direct: %v", err)
	}
	sessionID, _ := e2ee.DeviceSessionID(config.DeviceID, remoteDevice)
	record, found, err := journal.SessionState(sessionID)
	if err != nil || !found {
		t.Fatalf("session: found=%v err=%v", found, err)
	}
	bootstrap, present, err := record.Bootstrap()
	if err != nil || !present {
		t.Fatalf("bootstrap: present=%v err=%v", present, err)
	}
	if bootstrap.Binding.ConversationID != result.ConversationID ||
		bootstrap.Binding.RecipientAgentID != remoteAgent ||
		bootstrap.Binding.RecipientEndpointID != remoteEndpoint ||
		bootstrap.Binding.RecipientDeviceID != remoteDevice {
		t.Fatalf("daemon selected wrong verified authority: %+v", bootstrap.Binding)
	}
	if _, err := d.EnsureDirectConversation(context.Background(), remoteAgent, nil); err != nil {
		t.Fatalf("idempotent ensure: %v", err)
	}
	reloaded, _, _ := journal.SessionState(sessionID)
	if reloaded.Generation != record.Generation || reloaded.BootstrapDigest != record.BootstrapDigest {
		t.Fatal("idempotent ensure replaced an established device session")
	}
	idempotency := "idem_" + strings.Repeat("e", 64)
	sent, err := d.SendDirectMessage(context.Background(), remoteAgent, "text/plain; charset=utf-8",
		"hello from OpenFox", idempotency, uint64(now.Add(time.Hour).Unix()))
	if err != nil {
		t.Fatalf("send direct: %v", err)
	}
	retry, err := d.SendDirectMessage(context.Background(), remoteAgent, "text/plain; charset=utf-8",
		"hello from OpenFox", idempotency, uint64(now.Add(time.Hour).Unix()))
	if err != nil || retry.EventID != sent.EventID {
		t.Fatalf("idempotent send: first=%+v retry=%+v err=%v", sent, retry, err)
	}
	due, err := journal.Due(now)
	if err != nil || len(due) != 1 {
		t.Fatalf("fan-out queue: deliveries=%+v err=%v", due, err)
	}
	if due[0].EventID != sent.EventID || due[0].RecipientEndpointID != remoteEndpoint ||
		due[0].RecipientDeviceID != remoteDevice || due[0].DeliveryID == "" {
		t.Fatalf("queued copy did not use daemon-verified target: %+v", due[0])
	}
}

func TestDaemonResolveContactExposesIDBoundDirectoryPath(t *testing.T) {
	agentID := "agent_" + strings.Repeat("7", 64)
	contacts := &daemonContactDirectory{}
	d := &Daemon{discovery: &discoveryRuntime{contacts: contacts}}

	result, err := d.ResolveContact(context.Background(), agentID, nil)
	if err != nil {
		t.Fatalf("resolve daemon contact: %v", err)
	}
	if result.AgentID != agentID || result.CanonicalName != "" || len(contacts.calls) != 1 || contacts.calls[0] != agentID {
		t.Fatalf("unexpected ID-bound contact result: result=%+v calls=%v", result, contacts.calls)
	}
}

func TestDaemonResolveContactRequiresDiscovery(t *testing.T) {
	if _, err := (&Daemon{}).ResolveContact(context.Background(), "alice.tos", nil); err == nil {
		t.Fatal("DNS contact was accepted without the directory verification chain")
	}
}

func TestDaemonEnsuresDurableAgentBoundConversationFromVerifiedDirectory(t *testing.T) {
	localAgentID := "agent_" + strings.Repeat("6", 64)
	remoteAgentID := "agent_" + strings.Repeat("7", 64)
	contacts := &daemonContactDirectory{}
	journal, err := eventlog.Open(filepath.Join(t.TempDir(), "state"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = journal.Close() })
	verifiedAt := time.Unix(1_900_000_000, 0)
	d := &Daemon{
		config: Config{AgentID: localAgentID}, journal: journal,
		discovery: &discoveryRuntime{contacts: contacts}, now: func() time.Time { return verifiedAt },
	}

	first, err := d.EnsureDirectConversation(context.Background(), remoteAgentID, nil)
	if err != nil {
		t.Fatalf("ensure direct conversation: %v", err)
	}
	second, err := d.EnsureDirectConversation(context.Background(), remoteAgentID, nil)
	if err != nil {
		t.Fatalf("retry direct conversation: %v", err)
	}
	if first.AgentID != remoteAgentID || first.CanonicalName != "" ||
		first.ConversationID == "" || first.ConversationID != second.ConversationID ||
		first.Readiness != "transport-pending" {
		t.Fatalf("unexpected direct conversation result: first=%+v second=%+v", first, second)
	}
	record, found, err := journal.DirectConversation(localAgentID, remoteAgentID)
	if err != nil || !found {
		t.Fatalf("load direct conversation: found=%v err=%v", found, err)
	}
	if record.ConversationID != first.ConversationID || record.FinalizedCheckpoint != 73 ||
		record.VerifiedRemoteEndpointID != "mep_"+strings.Repeat("8", 64) ||
		record.DirectoryVerifiedAtUnix != uint64(verifiedAt.Unix()) {
		t.Fatalf("directory evidence was not pinned: %+v", record)
	}
}
