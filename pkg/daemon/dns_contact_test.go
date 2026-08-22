package daemon

import (
	"context"
	"strings"
	"testing"

	"github.com/tosnetwork/tos-messenger/pkg/directory"
	"github.com/tosnetwork/tos-messenger/pkg/identity"
)

type daemonContactDirectory struct{ calls []string }

func (d *daemonContactDirectory) Ensure(_ context.Context, agentID string) (directory.RefreshResult, error) {
	d.calls = append(d.calls, agentID)
	return directory.RefreshResult{Delegation: identity.Delegation{AgentID: agentID}}, nil
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
