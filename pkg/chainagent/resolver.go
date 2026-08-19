// Package chainagent reads finalized Agent state from TOS chain state and
// satisfies the Messenger's identity.AgentResolver.
//
// Like pkg/chainquote, it reimplements no chain logic: the quorum-finalized,
// rollback-protected typed read belongs to tos-service-protocol's toschain, and
// this package only adapts that read to the single-argument shape the
// Messenger's delegation verifier calls. The finalized chain state is the
// authority; this is how the Messenger consumes it for the Agent whose
// delegation it is checking.
package chainagent

import (
	"context"
	"errors"

	"github.com/tosnetwork/tos-messenger/internal/ids"
	nativev1 "github.com/tosnetwork/tos-service-protocol/gen/tos/service/v1"
	"github.com/tosnetwork/tos-service-protocol/pkg/nativecore"
	"github.com/tosnetwork/tos-service-protocol/pkg/toschain"
)

// StateReader reads finalized typed object state by identifier. It is the narrow
// slice of toschain.NativeStateResolver this bridge depends on, declared here so
// the resolver can be exercised without a live chain.
//
// The second argument is an optional expected TVM state hash; the Messenger's
// verifier does not pin one, so the bridge passes it empty and lets the
// delegation-binding checks downstream establish the state is the right Agent's.
type StateReader interface {
	ResolveState(ctx context.Context, objectID, expectedStateHash string) (*nativev1.NativeStateV1, bool, error)
}

// Resolver adapts a StateReader to identity.AgentResolver.
type Resolver struct {
	reader StateReader
}

// New builds a resolver over a state reader.
func New(reader StateReader) (*Resolver, error) {
	if reader == nil {
		return nil, errors.New("an agent resolver needs a finalized state reader")
	}
	return &Resolver{reader: reader}, nil
}

// NewFromChain builds a resolver whose reader is a toschain simplified native
// resolver over a configured chain adapter. The adapter, locator and checkpoint
// path are the service protocol's, unchanged.
func NewFromChain(adapter *toschain.Adapter, locator *nativecore.Locator, checkpointPath string) (*Resolver, error) {
	if adapter == nil {
		return nil, errors.New("a chain-backed resolver needs a chain adapter")
	}
	reader, err := toschain.NewSimplifiedNativeResolver(adapter, locator, checkpointPath)
	if err != nil {
		return nil, err
	}
	return New(reader)
}

// ResolveAgent implements identity.AgentResolver.
//
// The identifier is checked to be a well-formed Agent identifier before a read
// is issued: a malformed identifier is this installation's own error, not a
// question worth putting to the chain. The read is bounded by the reader's own
// per-query timeout, so it is issued against the background context.
func (r *Resolver) ResolveAgent(agentID string) (*nativev1.NativeStateV1, bool, error) {
	if r == nil {
		return nil, false, errors.New("no agent resolver")
	}
	if !ids.Agent.MatchString(agentID) {
		return nil, false, errors.New("invalid agent identifier")
	}
	return r.reader.ResolveState(context.Background(), agentID, "")
}
