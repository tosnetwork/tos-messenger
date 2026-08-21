package daemon

import (
	"errors"
	"time"

	"github.com/tosnetwork/tos-messenger/internal/securefile"
	"github.com/tosnetwork/tos-messenger/pkg/chainagent"
	"github.com/tosnetwork/tos-messenger/pkg/identity"
	nativev1 "github.com/tosnetwork/tos-service-protocol/gen/tos/service/v1"
	"github.com/tosnetwork/tos-service-protocol/pkg/agentpacket"
	"github.com/tosnetwork/tos-service-protocol/pkg/nativecore"
)

const maxDelegationFileBytes = 64 << 10

type delegationVerifier interface {
	Verify(Config, time.Time) (identity.Delegation, error)
}

type finalizedVerifier struct{}

type finalizedPacketResolver struct {
	resolver identity.AgentResolver
	policy   identity.ChainPolicy
	network  *nativev1.NetworkDomain
}

func (r finalizedPacketResolver) ResolveAgent(agentID string) (*nativev1.AgentStateV1, bool, error) {
	if r.resolver == nil {
		return nil, false, errors.New("no finalized Agent Packet resolver")
	}
	state, found, err := r.resolver.ResolveAgent(agentID)
	if err != nil || !found {
		return nil, found, err
	}
	agent, err := identity.CheckState(r.policy, r.network, agentID, state)
	if err != nil {
		return nil, false, err
	}
	return agent, true, nil
}

func newFinalizedPacketResolver(config Config) (agentpacket.AgentResolver, error) {
	resolver, policy, err := finalizedResolver(config)
	if err != nil {
		return nil, err
	}
	return finalizedPacketResolver{resolver: resolver, policy: policy, network: config.Network()}, nil
}

func (finalizedVerifier) Verify(config Config, now time.Time) (identity.Delegation, error) {
	resolver, policy, err := finalizedResolver(config)
	if err != nil {
		return identity.Delegation{}, err
	}
	raw, err := securefile.ReadBoundedRegular(config.DelegationPath, maxDelegationFileBytes)
	if err != nil {
		return identity.Delegation{}, err
	}
	return identity.Verify(resolver, config.Network(), policy, raw, now)
}

// VerifyFinalizedDelegation returns the same live, strict-majority verified
// Endpoint delegation used by daemon startup. Stock-command resource assembly
// uses it to pin an external signer client before opening the daemon; callers
// cannot replace this authority with an unverified configuration value.
func VerifyFinalizedDelegation(config Config, now time.Time) (identity.Delegation, error) {
	if err := config.Validate(); err != nil {
		return identity.Delegation{}, err
	}
	return finalizedVerifier{}.Verify(config, now)
}

func finalizedResolver(config Config) (*chainagent.Resolver, identity.ChainPolicy, error) {
	adapter, err := config.ChainAdapter()
	if err != nil {
		return nil, identity.ChainPolicy{}, err
	}
	registry, err := config.NativeRegistry()
	if err != nil {
		return nil, identity.ChainPolicy{}, err
	}
	messengerNetwork := config.Network()
	nativeNetwork := config.Network()
	nativeNetwork.GenesisRootHash = "sha256:" + nativeNetwork.GenesisRootHash
	nativeNetwork.GenesisFileHash = "sha256:" + nativeNetwork.GenesisFileHash
	locator, err := nativecore.NewLocator(nativeNetwork, registry.Workchain, registry.CodeBOC, registry.CodeHash)
	if err != nil {
		return nil, identity.ChainPolicy{}, err
	}
	resolver, err := chainagent.NewFromChain(adapter, locator, config.ChainCheckpointPath, messengerNetwork)
	if err != nil {
		return nil, identity.ChainPolicy{}, err
	}
	policy, err := config.Chain()
	if err != nil {
		return nil, identity.ChainPolicy{}, err
	}
	return resolver, policy, nil
}

// FinalizedAgentResolver exposes the same strict-majority finalized Agent
// authority used by daemon startup to separately deployed services such as a
// Mailbox Relay. The returned resolver and policy still require callers to
// verify each exact delegation document with identity.Verify.
func FinalizedAgentResolver(config Config) (identity.AgentResolver, identity.ChainPolicy, error) {
	return finalizedResolver(config)
}
