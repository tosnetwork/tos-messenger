package attachments

import (
	"context"
	"crypto/ed25519"
	"errors"
	"time"

	"github.com/tosnetwork/tos-messenger/pkg/identity"
	nativev1 "github.com/tosnetwork/tos-service-protocol/gen/tos/service/v1"
)

type DelegationSource interface {
	Delegation(context.Context, string) ([]byte, error)
}

// FinalizedAuthority rereads and verifies the exact committed Endpoint
// delegation for every storage operation. A cached locator or grant claim
// cannot survive finalized revocation.
type FinalizedAuthority struct {
	resolver identity.AgentResolver
	network  *nativev1.NetworkDomain
	policy   identity.ChainPolicy
	source   DelegationSource
}

func NewFinalizedAuthority(resolver identity.AgentResolver, network *nativev1.NetworkDomain, policy identity.ChainPolicy, source DelegationSource) (*FinalizedAuthority, error) {
	if resolver == nil || network == nil || source == nil {
		return nil, errors.New("invalid finalized attachment authority")
	}
	if err := policy.Validate(); err != nil {
		return nil, err
	}
	return &FinalizedAuthority{resolver: resolver, network: network, policy: policy, source: source}, nil
}

func (a *FinalizedAuthority) ResolveAttachmentEndpoint(ctx context.Context, grant CapabilityGrant, now time.Time) (ed25519.PublicKey, error) {
	if a == nil || ctx == nil {
		return nil, errors.New("invalid finalized attachment authority lookup")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if grant.NetworkID != a.network.NetworkId || grant.GenesisRootHash != a.network.GenesisRootHash ||
		grant.GenesisFileHash != a.network.GenesisFileHash {
		return nil, errors.New("attachment grant belongs to another network")
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
		return nil, errors.New("attachment grant names another finalized Endpoint")
	}
	if grant.ExpiresAtUnix > delegation.ExpiresAtUnix {
		return nil, errors.New("attachment grant outlives its Endpoint delegation")
	}
	return append(ed25519.PublicKey(nil), delegation.IdentityPublicKey...), nil
}

var _ FinalizedEndpointAuthority = (*FinalizedAuthority)(nil)
