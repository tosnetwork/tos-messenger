package daemon

import (
	"context"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/tosnetwork/tos-messenger/pkg/directory"
	"github.com/tosnetwork/tos-messenger/pkg/eventlog"
	"github.com/tosnetwork/tos-messenger/pkg/identity"
)

type daemonContactDirectory struct{ calls []string }

func (d *daemonContactDirectory) Ensure(_ context.Context, agentID string) (directory.RefreshResult, error) {
	d.calls = append(d.calls, agentID)
	return directory.RefreshResult{
		Delegation:          identity.Delegation{AgentID: agentID},
		Descriptor:          directory.Descriptor{AgentID: agentID, EndpointID: "mep_" + strings.Repeat("8", 64)},
		FinalizedCheckpoint: 73,
	}, nil
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
