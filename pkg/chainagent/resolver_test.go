package chainagent

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/tosnetwork/tos-messenger/pkg/identity"
	nativev1 "github.com/tosnetwork/tos-service-protocol/gen/tos/service/v1"
)

// The resolver satisfies the Messenger's own interface.
var _ identity.AgentResolver = (*Resolver)(nil)

var testAgent = "agent_" + strings.Repeat("2", 64)

type fakeReader struct {
	state         *nativev1.NativeStateV1
	found         bool
	err           error
	gotObjectID   string
	gotExpectHash string
}

func (f *fakeReader) ResolveState(_ context.Context, objectID, expectedStateHash string) (*nativev1.NativeStateV1, bool, error) {
	f.gotObjectID = objectID
	f.gotExpectHash = expectedStateHash
	return f.state, f.found, f.err
}

// A well-formed agent id is passed through as the object id, with no pinned
// state hash, and the read's result is returned unchanged.
func TestResolveAgentPassesThrough(t *testing.T) {
	state := &nativev1.NativeStateV1{Network: &nativev1.NetworkDomain{NetworkId: "tos-local"}}
	reader := &fakeReader{state: state, found: true}
	resolver, err := New(reader)
	if err != nil {
		t.Fatalf("new: %v", err)
	}

	got, found, err := resolver.ResolveAgent(testAgent)
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if !found || got != state {
		t.Fatalf("the read result was not returned: found=%v state=%v", found, got)
	}
	if reader.gotObjectID != testAgent {
		t.Fatalf("the agent id was not used as the object id: %q", reader.gotObjectID)
	}
	if reader.gotExpectHash != "" {
		t.Fatalf("a state hash was pinned when none should be: %q", reader.gotExpectHash)
	}
}

// A malformed identifier is refused before any read is issued.
func TestResolveAgentRejectsMalformedID(t *testing.T) {
	reader := &fakeReader{}
	resolver, err := New(reader)
	if err != nil {
		t.Fatalf("new: %v", err)
	}
	if _, _, err := resolver.ResolveAgent("not-an-agent"); err == nil {
		t.Fatal("a malformed identifier was accepted")
	}
	if reader.gotObjectID != "" {
		t.Fatal("a read was issued for a malformed identifier")
	}
}

// A not-found Agent is reported as such, not as an error.
func TestResolveAgentNotFound(t *testing.T) {
	resolver, err := New(&fakeReader{found: false})
	if err != nil {
		t.Fatalf("new: %v", err)
	}
	_, found, err := resolver.ResolveAgent(testAgent)
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if found {
		t.Fatal("an absent Agent was reported found")
	}
}

// A reader error is propagated.
func TestResolveAgentPropagatesError(t *testing.T) {
	resolver, err := New(&fakeReader{err: errors.New("chain is unreachable")})
	if err != nil {
		t.Fatalf("new: %v", err)
	}
	if _, _, err := resolver.ResolveAgent(testAgent); err == nil {
		t.Fatal("a reader error was swallowed")
	}
}

func TestNewRejectsNilReader(t *testing.T) {
	if _, err := New(nil); err == nil {
		t.Fatal("a nil reader was accepted")
	}
}
