package group

import (
	"bytes"
	"crypto/ed25519"
	"strings"
	"testing"
	"time"

	"github.com/tosnetwork/tos-messenger/internal/canon"
	"github.com/tosnetwork/tos-messenger/pkg/e2ee"
	"github.com/tosnetwork/tos-messenger/pkg/identity"
	"github.com/tosnetwork/tos-messenger/pkg/room"
	nativev1 "github.com/tosnetwork/tos-service-protocol/gen/tos/service/v1"
)

func mlsNetwork() *nativev1.NetworkDomain {
	return &nativev1.NetworkDomain{NetworkId: "tos-local", GenesisRootHash: strings.Repeat("a", 64), GenesisFileHash: strings.Repeat("b", 64)}
}
func mlsAgent() string          { return "agent_" + strings.Repeat("c", 64) }
func mlsDevice(n string) string { return "dev_" + strings.Repeat(n, 64) }

func mlsAuthority(t *testing.T) (identity.Delegation, ed25519.PrivateKey) {
	t.Helper()
	key := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x31}, ed25519.SeedSize))
	endpoint, err := identity.DeriveEndpointID(mlsNetwork(), mlsAgent(), key.Public().(ed25519.PublicKey))
	if err != nil {
		t.Fatal(err)
	}
	return identity.Delegation{Network: mlsNetwork(), AgentID: mlsAgent(), EndpointID: endpoint, IdentityPublicKey: key.Public().(ed25519.PublicKey), NotBeforeUnix: 100, ExpiresAtUnix: 10000}, key
}

func mlsCredential(t *testing.T, delegation identity.Delegation, key ed25519.PrivateKey, device, setDigest string) DeviceCredential {
	t.Helper()
	leaf := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{byte(device[len(device)-1]) + 0x20}, ed25519.SeedSize))
	c, err := SignDeviceCredential(DeviceCredential{Network: mlsNetwork(), AgentID: mlsAgent(), EndpointID: delegation.EndpointID, DeviceID: device, DeviceSetDigest: setDigest, LeafSignaturePublicKey: leaf.Public().(ed25519.PublicKey), KeyPackage: []byte("rfc9420-key-package-" + device), IssuedAtUnix: 100, ExpiresAtUnix: 1000}, key)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func TestDeviceCredentialBindsCurrentAuthority(t *testing.T) {
	delegation, key := mlsAuthority(t)
	digest := canon.Digest([]byte("set-1"))
	c := mlsCredential(t, delegation, key, mlsDevice("1"), digest)
	set := e2ee.SetSummary{EndpointID: delegation.EndpointID, Digest: digest, DeviceIDs: []string{c.DeviceID}}
	if err := BindDeviceCredential(delegation, c, set, time.Unix(500, 0)); err != nil {
		t.Fatalf("bind: %v", err)
	}
	raw, err := EncodeDeviceCredentialJSON(c)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := DecodeDeviceCredentialJSON(raw)
	if err != nil {
		t.Fatal(err)
	}
	if ref, _ := KeyPackageRef(decoded); ref == "" {
		t.Fatal("round-tripped credential lost its KeyPackage reference")
	}
	unknown := append(raw[:len(raw)-1], []byte(`,"authority":true}`)...)
	if _, err := DecodeDeviceCredentialJSON(unknown); err == nil {
		t.Fatal("unknown credential field accepted")
	}

	stale := c
	stale.DeviceSetDigest = canon.Digest([]byte("old-set"))
	stale, _ = SignDeviceCredential(stale, key)
	if err := BindDeviceCredential(delegation, stale, set, time.Unix(500, 0)); err == nil {
		t.Fatal("stale device-set credential accepted")
	}
	wrongNetwork := c
	wrongNetwork.Network = &nativev1.NetworkDomain{NetworkId: "other", GenesisRootHash: c.Network.GenesisRootHash, GenesisFileHash: c.Network.GenesisFileHash}
	wrongNetwork, _ = SignDeviceCredential(wrongNetwork, key)
	if err := BindDeviceCredential(delegation, wrongNetwork, set, time.Unix(500, 0)); err == nil {
		t.Fatal("foreign-network credential accepted")
	}
	reused := c
	reused.LeafSignaturePublicKey = delegation.IdentityPublicKey
	reused, _ = SignDeviceCredential(reused, key)
	if err := BindDeviceCredential(delegation, reused, set, time.Unix(500, 0)); err == nil {
		t.Fatal("endpoint key reused as MLS leaf key")
	}
}

func TestTwoClockTransitionRules(t *testing.T) {
	roomID := "room_" + strings.Repeat("d", 64)
	first, err := room.Found(roomID, []string{mlsAgent(), "agent_" + strings.Repeat("e", 64)})
	if err != nil {
		t.Fatal(err)
	}
	prior := State{RoomID: roomID, Clock: Clock{RoomEpoch: 1, MLSEpoch: 4}, MembershipDigest: first.Digest, AcceptedCommitRef: canon.Digest([]byte("commit-4"))}
	refresh := Transition{Prior: prior, Next: State{RoomID: roomID, Clock: Clock{RoomEpoch: 1, MLSEpoch: 5}, MembershipDigest: first.Digest, AcceptedCommitRef: canon.Digest([]byte("commit-5"))}, CommitRef: canon.Digest([]byte("commit-5"))}
	if err := ValidateTransition(refresh); err != nil {
		t.Fatalf("PCS/device update: %v", err)
	}
	nextMembership, err := first.Add([]string{"agent_" + strings.Repeat("f", 64)})
	if err != nil {
		t.Fatal(err)
	}
	change := Transition{Prior: refresh.Next, Next: State{RoomID: roomID, Clock: Clock{RoomEpoch: 2, MLSEpoch: 6}, MembershipDigest: nextMembership.Digest, AcceptedCommitRef: canon.Digest([]byte("commit-6"))}, Membership: nextMembership, CommitRef: canon.Digest([]byte("commit-6"))}
	if err := ValidateTransition(change); err != nil {
		t.Fatalf("membership change: %v", err)
	}
	gap := refresh
	gap.Next.Clock.MLSEpoch = 7
	if err := ValidateTransition(gap); err == nil {
		t.Fatal("MLS epoch gap accepted")
	}
	lie := refresh
	lie.Next.MembershipDigest = canon.Digest([]byte("invented"))
	if err := ValidateTransition(lie); err == nil {
		t.Fatal("MLS-only update changed membership")
	}
}

func TestDeviceSuccessionKeepsOtherAgentDevice(t *testing.T) {
	delegation, key := mlsAuthority(t)
	oldDigest, newDigest := canon.Digest([]byte("old")), canon.Digest([]byte("new"))
	d1, d2, d3 := mlsDevice("1"), mlsDevice("2"), mlsDevice("3")
	current := []Leaf{{AgentID: mlsAgent(), EndpointID: delegation.EndpointID, DeviceID: d1, DeviceSetDigest: oldDigest, KeyPackageRef: canon.Digest([]byte("kp1"))}, {AgentID: mlsAgent(), EndpointID: delegation.EndpointID, DeviceID: d2, DeviceSetDigest: oldDigest, KeyPackageRef: canon.Digest([]byte("kp2"))}}
	succession := e2ee.Succession{Accepted: e2ee.SetSummary{EndpointID: delegation.EndpointID, Digest: newDigest, DeviceIDs: []string{d1, d3}}, Removed: []string{d2}}
	credentials := map[string]DeviceCredential{d1: mlsCredential(t, delegation, key, d1, newDigest), d3: mlsCredential(t, delegation, key, d3, newDigest)}
	ops, err := PlanDeviceSuccession(mlsAgent(), delegation.EndpointID, current, succession, credentials)
	if err != nil {
		t.Fatal(err)
	}
	counts := map[LeafOperationKind]int{}
	for _, op := range ops {
		counts[op.Kind]++
	}
	if counts[LeafUpdate] != 1 || counts[LeafAdd] != 1 || counts[LeafRemove] != 1 {
		t.Fatalf("unexpected operations: %#v", ops)
	}
	for _, op := range ops {
		if op.Kind == LeafRemove && op.Prior.DeviceID != d2 {
			t.Fatalf("wrong device removed: %s", op.Prior.DeviceID)
		}
	}
}

func TestUnchangedDeviceSuccessionNeedsNoMLSCommit(t *testing.T) {
	delegation, _ := mlsAuthority(t)
	digest := canon.Digest([]byte("same"))
	d1 := mlsDevice("1")
	current := []Leaf{{AgentID: mlsAgent(), EndpointID: delegation.EndpointID, DeviceID: d1, DeviceSetDigest: digest, KeyPackageRef: canon.Digest([]byte("kp"))}}
	succession := e2ee.Succession{Accepted: e2ee.SetSummary{EndpointID: delegation.EndpointID, Digest: digest, DeviceIDs: []string{d1}}}
	ops, err := PlanDeviceSuccession(mlsAgent(), delegation.EndpointID, current, succession, nil)
	if err != nil || len(ops) != 0 {
		t.Fatalf("unchanged set planned an MLS commit: %#v %v", ops, err)
	}
}
