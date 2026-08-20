package mailbox

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/tosnetwork/tos-messenger/pkg/identity"
	nativev1 "github.com/tosnetwork/tos-service-protocol/gen/tos/service/v1"
)

const finalizedRegistry = "tvm-cell-sha256:" + "abababababababababababababababababababababababababababababababab"
const finalizedAccount = "0:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"

type mailboxResolver struct{ state *nativev1.NativeStateV1 }

func (r *mailboxResolver) ResolveAgent(string) (*nativev1.NativeStateV1, bool, error) {
	return r.state, r.state != nil, nil
}

type mailboxLocator struct{}

func (mailboxLocator) Locate(string, string) (string, error) { return finalizedAccount, nil }

type mailboxDelegationSource struct {
	raw []byte
	err error
}

func (s mailboxDelegationSource) Delegation(context.Context, string) ([]byte, error) {
	return s.raw, s.err
}

func finalizedFixture(t *testing.T) (*FinalizedAuthority, CapabilityGrant, *mailboxResolver, identity.Delegation) {
	t.Helper()
	now := time.Unix(1_800_000_000, 0)
	_ = now
	network := &nativev1.NetworkDomain{NetworkId: "tos-local", GenesisRootHash: strings.Repeat("a", 64), GenesisFileHash: strings.Repeat("b", 64)}
	key := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x61}, ed25519.SeedSize))
	agentID := "agent_" + strings.Repeat("c", 64)
	endpointID, err := identity.DeriveEndpointID(network, agentID, key.Public().(ed25519.PublicKey))
	if err != nil {
		t.Fatal(err)
	}
	delegation := identity.Delegation{Network: network, AgentID: agentID, EndpointID: endpointID, IdentityPublicKey: key.Public().(ed25519.PublicKey), ADNLID: "adnl:" + strings.Repeat("2", 64), AllowedProtocolVersions: []uint32{1}, AllowedOutboundEventClasses: []string{"text"}, NotBeforeUnix: 1_799_999_000, ExpiresAtUnix: 1_800_010_000, MaximumSessionLifetimeSeconds: 3600, ContactDescriptorPolicyDigest: "sha256:" + strings.Repeat("3", 64), InboxAdmissionPolicyDigest: "sha256:" + strings.Repeat("4", 64)}
	raw, err := identity.EncodeJSON(delegation)
	if err != nil {
		t.Fatal(err)
	}
	digest, err := identity.Digest(delegation)
	if err != nil {
		t.Fatal(err)
	}
	resolver := &mailboxResolver{state: &nativev1.NativeStateV1{Network: network, TvmStateHash: "tvm-cell-sha256:" + strings.Repeat("5", 64), Reference: &nativev1.ChainReference{Account: finalizedAccount, TransactionHash: "sha256:" + strings.Repeat("6", 64), ContractCodeHash: finalizedRegistry, FinalizedCheckpoint: 100}, State: &nativev1.NativeStateV1_Agent{Agent: &nativev1.AgentStateV1{AgentId: agentID, Policy: &nativev1.ControllerPolicyV1{Threshold: 1}, DelegationDigests: []string{digest}}}}}
	policy := identity.ChainPolicy{RegistryCodeHashes: []string{finalizedRegistry}, Locator: mailboxLocator{}}
	authority, err := NewFinalizedAuthority(resolver, network, policy, mailboxDelegationSource{raw: raw})
	if err != nil {
		t.Fatal(err)
	}
	grant := CapabilityGrant{NetworkID: network.NetworkId, GenesisRootHash: network.GenesisRootHash, GenesisFileHash: network.GenesisFileHash, AgentID: agentID, EndpointID: endpointID, ExpiresAtUnix: 1_800_005_000}
	return authority, grant, resolver, delegation
}

func TestFinalizedAuthorityRechecksCommitmentAndGrantLifetime(t *testing.T) {
	authority, grant, resolver, delegation := finalizedFixture(t)
	now := time.Unix(1_800_000_000, 0)
	key, err := authority.ResolveMailboxEndpoint(context.Background(), grant, now)
	if err != nil || !bytes.Equal(key, delegation.IdentityPublicKey) {
		t.Fatalf("resolve: %x %v", key, err)
	}
	grant.ExpiresAtUnix = delegation.ExpiresAtUnix + 1
	if _, err := authority.ResolveMailboxEndpoint(context.Background(), grant, now); err == nil {
		t.Fatal("grant outliving delegation accepted")
	}
	grant.ExpiresAtUnix = delegation.ExpiresAtUnix - 1
	grant.GenesisRootHash = strings.Repeat("9", 64)
	if _, err := authority.ResolveMailboxEndpoint(context.Background(), grant, now); err == nil {
		t.Fatal("cross-network grant accepted")
	}
	grant.GenesisRootHash = delegation.Network.GenesisRootHash
	resolver.state.GetAgent().DelegationDigests = []string{"sha256:" + strings.Repeat("8", 64)}
	if _, err := authority.ResolveMailboxEndpoint(context.Background(), grant, now); err == nil {
		t.Fatal("revoked finalized delegation remained usable")
	}
}

func TestFinalizedAuthorityFailsClosedOnSourceAndContext(t *testing.T) {
	authority, grant, _, _ := finalizedFixture(t)
	now := time.Unix(1_800_000_000, 0)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := authority.ResolveMailboxEndpoint(ctx, grant, now); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancel: %v", err)
	}
	authority.source = mailboxDelegationSource{err: errors.New("offline")}
	if _, err := authority.ResolveMailboxEndpoint(context.Background(), grant, now); err == nil {
		t.Fatal("source failure was ignored")
	}
}
