package mailbox

import (
	"context"
	"crypto/ed25519"
	"errors"
	"time"

	"github.com/tosnetwork/tos-messenger/pkg/identity"
	nativev1 "github.com/tosnetwork/tos-service-protocol/gen/tos/service/v1"
)

// DelegationSource returns the exact delegation document provisioned for an
// Agent. The bytes are rendezvous input only: FinalizedAuthority verifies
// their digest against finalized Agent state on every Mailbox operation.
type DelegationSource interface {
	Delegation(context.Context, string) ([]byte, error)
}

// FinalizedAuthority adapts the shared finalized Agent verifier to Mailbox
// capability authentication. It deliberately holds no cache: endpoint
// rotation or revocation must take effect on the next operation.
type FinalizedAuthority struct {
	resolver identity.AgentResolver
	network  *nativev1.NetworkDomain
	policy   identity.ChainPolicy
	source   DelegationSource
}

func NewFinalizedAuthority(resolver identity.AgentResolver, network *nativev1.NetworkDomain, policy identity.ChainPolicy, source DelegationSource) (*FinalizedAuthority, error) {
	if resolver == nil || network == nil || source == nil {
		return nil, errors.New("invalid finalized Mailbox authority")
	}
	if err := policy.Validate(); err != nil {
		return nil, err
	}
	return &FinalizedAuthority{resolver: resolver, network: network, policy: policy, source: source}, nil
}

func (a *FinalizedAuthority) ResolveMailboxEndpoint(ctx context.Context, grant CapabilityGrant, now time.Time) (ed25519.PublicKey, error) {
	if a == nil || ctx == nil {
		return nil, errors.New("invalid finalized Mailbox authority lookup")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if grant.NetworkID != a.network.NetworkId || grant.GenesisRootHash != a.network.GenesisRootHash ||
		grant.GenesisFileHash != a.network.GenesisFileHash {
		return nil, errors.New("Mailbox grant belongs to another network")
	}
	raw, err := a.source.Delegation(ctx, grant.AgentID)
	if err != nil {
		return nil, err
	}
	delegation, err := identity.Verify(a.resolver, a.network, a.policy, raw, now)
	if err != nil {
		return nil, err
	}
	if delegation.AgentID != grant.AgentID || delegation.EndpointID != grant.EndpointID {
		return nil, errors.New("Mailbox grant names another finalized Endpoint")
	}
	if grant.ExpiresAtUnix > delegation.ExpiresAtUnix {
		return nil, errors.New("Mailbox grant outlives its Endpoint delegation")
	}
	return append(ed25519.PublicKey(nil), delegation.IdentityPublicKey...), nil
}

var _ FinalizedEndpointAuthority = (*FinalizedAuthority)(nil)
