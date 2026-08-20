package room

import (
	"bytes"
	"crypto/ed25519"
	"strings"
	"testing"
	"time"

	"github.com/tosnetwork/tos-messenger/pkg/identity"
	nativev1 "github.com/tosnetwork/tos-service-protocol/gen/tos/service/v1"
)

func authorityNetwork() *nativev1.NetworkDomain {
	return &nativev1.NetworkDomain{NetworkId: "tos-local", GenesisRootHash: strings.Repeat("a", 64), GenesisFileHash: strings.Repeat("b", 64)}
}

func authorityDelegation(t *testing.T, agentID string, seed byte) (identity.Delegation, ed25519.PrivateKey) {
	t.Helper()
	key := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{seed}, ed25519.SeedSize))
	endpointID, err := identity.DeriveEndpointID(authorityNetwork(), agentID, key.Public().(ed25519.PublicKey))
	if err != nil {
		t.Fatal(err)
	}
	return identity.Delegation{
		Network: authorityNetwork(), AgentID: agentID, EndpointID: endpointID,
		IdentityPublicKey: key.Public().(ed25519.PublicKey), NotBeforeUnix: 100, ExpiresAtUnix: 1000,
	}, key
}

func signedAuthorityTransfer(t *testing.T) (Membership, Membership, AuthorityTransfer, identity.Delegation, identity.Delegation) {
	t.Helper()
	fromAgent := agent(1)
	toAgent := agent(2)
	fromDelegation, fromKey := authorityDelegation(t, fromAgent, 0x41)
	toDelegation, _ := authorityDelegation(t, toAgent, 0x42)
	prior := mustFound(t, fromAgent, toAgent)
	next, err := prior.AdvanceForAuthorityTransfer()
	if err != nil {
		t.Fatal(err)
	}
	value, err := SignAuthorityTransfer(AuthorityTransfer{
		Network: authorityNetwork(), RoomID: prior.RoomID,
		PriorEpoch: prior.Epoch, NextEpoch: next.Epoch,
		PriorMembershipDigest: prior.Digest, NextMembershipDigest: next.Digest,
		From:         Authority{AgentID: fromAgent, EndpointID: fromDelegation.EndpointID},
		To:           Authority{AgentID: toAgent, EndpointID: toDelegation.EndpointID},
		IssuedAtUnix: 200, ExpiresAtUnix: 300,
	}, fromKey)
	if err != nil {
		t.Fatal(err)
	}
	return prior, next, value, fromDelegation, toDelegation
}

func TestAuthorityTransferBindsCurrentAndNextFinalizedAuthority(t *testing.T) {
	prior, next, value, fromDelegation, toDelegation := signedAuthorityTransfer(t)
	current := value.From
	if err := VerifyAuthorityTransfer(current, prior, next, value, fromDelegation, toDelegation, time.Unix(250, 0)); err != nil {
		t.Fatalf("verify: %v", err)
	}

	wrongNetwork := value
	other := nativev1.NetworkDomain{NetworkId: wrongNetwork.Network.NetworkId,
		GenesisRootHash: wrongNetwork.Network.GenesisRootHash, GenesisFileHash: strings.Repeat("c", 64)}
	wrongNetwork.Network = &other
	wrongRecipient := toDelegation
	wrongRecipient.AgentID = agent(3)
	tampered := value
	tampered.CurrentEndpointSignature = append([]byte(nil), value.CurrentEndpointSignature...)
	tampered.CurrentEndpointSignature[0] ^= 1
	for name, candidate := range map[string]func() error{
		"foreign network": func() error {
			return VerifyAuthorityTransfer(current, prior, next, wrongNetwork, fromDelegation, toDelegation, time.Unix(250, 0))
		},
		"unfinalized successor": func() error {
			return VerifyAuthorityTransfer(current, prior, next, value, fromDelegation, wrongRecipient, time.Unix(250, 0))
		},
		"wrong current authority": func() error {
			return VerifyAuthorityTransfer(value.To, prior, next, value, fromDelegation, toDelegation, time.Unix(250, 0))
		},
		"tampered signature": func() error {
			return VerifyAuthorityTransfer(current, prior, next, tampered, fromDelegation, toDelegation, time.Unix(250, 0))
		},
		"expired": func() error {
			return VerifyAuthorityTransfer(current, prior, next, value, fromDelegation, toDelegation, time.Unix(300, 0))
		},
	} {
		t.Run(name, func(t *testing.T) {
			if err := candidate(); err == nil {
				t.Fatal("invalid authority transfer verified")
			}
		})
	}
}

func TestAuthorityTransferSigningBytesUseStrictRawGenesisHashes(t *testing.T) {
	_, _, value, _, _ := signedAuthorityTransfer(t)
	original, err := AuthorityTransferSigningBytes(value)
	if err != nil {
		t.Fatal(err)
	}
	changed := value
	network := nativev1.NetworkDomain{NetworkId: value.Network.NetworkId,
		GenesisRootHash: strings.Repeat("c", 64), GenesisFileHash: value.Network.GenesisFileHash}
	changed.Network = &network
	different, err := AuthorityTransferSigningBytes(changed)
	if err != nil || bytes.Equal(original, different) {
		t.Fatal("genesis substitution retained authority-transfer preimage")
	}
	prefixed := value
	prefixedNetwork := nativev1.NetworkDomain{NetworkId: value.Network.NetworkId,
		GenesisRootHash: "sha256:" + value.Network.GenesisRootHash, GenesisFileHash: value.Network.GenesisFileHash}
	prefixed.Network = &prefixedNetwork
	if _, err := AuthorityTransferSigningBytes(prefixed); err == nil {
		t.Fatal("display-prefixed genesis hash entered authority-transfer preimage")
	}
}

func TestMembershipAuthorizationBindsExactMembershipAndEndpoint(t *testing.T) {
	delegation, key := authorityDelegation(t, agent(1), 0x41)
	membership := mustFound(t, agent(1), agent(2))
	value, err := SignMembershipAuthorization(MembershipAuthorization{
		Network: authorityNetwork(), RoomID: membership.RoomID, Epoch: membership.Epoch,
		MembershipDigest: membership.Digest,
		Authority:        Authority{AgentID: delegation.AgentID, EndpointID: delegation.EndpointID},
		IssuedAtUnix:     200, ExpiresAtUnix: 300,
	}, key)
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyMembershipAuthorization(membership, value, delegation, time.Unix(250, 0)); err != nil {
		t.Fatalf("verify: %v", err)
	}
	next, err := membership.Add([]string{agent(3)})
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyMembershipAuthorization(next, value, delegation, time.Unix(250, 0)); err == nil {
		t.Fatal("authorization for one membership admitted its successor")
	}
	tampered := value
	tampered.EndpointSignature = append([]byte(nil), value.EndpointSignature...)
	tampered.EndpointSignature[0] ^= 1
	if err := VerifyMembershipAuthorization(membership, tampered, delegation, time.Unix(250, 0)); err == nil {
		t.Fatal("tampered membership authorization verified")
	}
	attackerKey := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x77}, ed25519.SeedSize))
	forgedDelegation := delegation
	forgedDelegation.IdentityPublicKey = attackerKey.Public().(ed25519.PublicKey)
	forgedValue, err := SignMembershipAuthorization(MembershipAuthorization{
		Network: value.Network, RoomID: value.RoomID, Epoch: value.Epoch,
		MembershipDigest: value.MembershipDigest, Authority: value.Authority,
		IssuedAtUnix: value.IssuedAtUnix, ExpiresAtUnix: value.ExpiresAtUnix,
	}, attackerKey)
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyMembershipAuthorization(membership, forgedValue, forgedDelegation, time.Unix(250, 0)); err == nil {
		t.Fatal("a caller-supplied key that does not derive the Endpoint authorized membership")
	}
}
