package daemon

import (
	"time"

	"github.com/tosnetwork/tos-messenger/internal/securefile"
	"github.com/tosnetwork/tos-messenger/pkg/chainagent"
	"github.com/tosnetwork/tos-messenger/pkg/identity"
	"github.com/tosnetwork/tos-service-protocol/pkg/nativecore"
)

const maxDelegationFileBytes = 64 << 10

type delegationVerifier interface {
	Verify(Config, time.Time) (identity.Delegation, error)
}

type finalizedVerifier struct{}

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
