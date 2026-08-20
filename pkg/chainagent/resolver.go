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
	"google.golang.org/protobuf/proto"
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
	reader        StateReader
	network       *nativev1.NetworkDomain
	sourceNetwork *nativev1.NetworkDomain
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
func NewFromChain(adapter *toschain.Adapter, locator *nativecore.Locator, checkpointPath string,
	network *nativev1.NetworkDomain) (*Resolver, error) {
	if adapter == nil {
		return nil, errors.New("a chain-backed resolver needs a chain adapter")
	}
	reader, err := toschain.NewSimplifiedNativeResolver(adapter, locator, checkpointPath)
	if err != nil {
		return nil, err
	}
	if network == nil {
		return nil, errors.New("a chain-backed resolver needs the Messenger network representation")
	}
	return &Resolver{
		reader: reader,
		network: &nativev1.NetworkDomain{NetworkId: network.NetworkId,
			GenesisRootHash: network.GenesisRootHash, GenesisFileHash: network.GenesisFileHash},
		sourceNetwork: &nativev1.NetworkDomain{NetworkId: locator.Network.NetworkId,
			GenesisRootHash: locator.Network.GenesisRootHash, GenesisFileHash: locator.Network.GenesisFileHash},
	}, nil
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
	state, found, err := r.reader.ResolveState(context.Background(), agentID, "")
	if err != nil || !found || state == nil || r.network == nil {
		return state, found, err
	}
	if r.sourceNetwork != nil && (state.Network == nil || state.Network.NetworkId != r.sourceNetwork.NetworkId ||
		state.Network.GenesisRootHash != r.sourceNetwork.GenesisRootHash ||
		state.Network.GenesisFileHash != r.sourceNetwork.GenesisFileHash) {
		return nil, false, errors.New("finalized Agent resolver returned another Native network")
	}
	copy, ok := proto.Clone(state).(*nativev1.NativeStateV1)
	if !ok || copy == nil {
		return nil, false, errors.New("could not copy finalized Agent state")
	}
	copy.Network = &nativev1.NetworkDomain{NetworkId: r.network.NetworkId,
		GenesisRootHash: r.network.GenesisRootHash, GenesisFileHash: r.network.GenesisFileHash}
	return copy, true, nil
}
