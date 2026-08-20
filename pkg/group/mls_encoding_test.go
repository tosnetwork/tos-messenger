package group

import (
	"bytes"
	"encoding/hex"
	"strings"
	"testing"

	nativev1 "github.com/tosnetwork/tos-service-protocol/gen/tos/service/v1"
)

func TestMLSCanonicalIdentityAndGroupIDBindNetwork(t *testing.T) {
	delegation, key := mlsAuthority(t)
	credential := mlsCredential(t, delegation, key, mlsDevice("1"), "sha256:"+strings.Repeat("d", 64))
	identity, err := BasicCredentialIdentity(credential)
	if err != nil || len(identity) == 0 {
		t.Fatalf("basic credential: %x %v", identity, err)
	}
	groupID, err := MLSGroupID(credential.Network, "room_"+strings.Repeat("e", 64))
	if err != nil || len(groupID) != MLSGroupIDBytes {
		t.Fatalf("group id: %x %v", groupID, err)
	}

	otherNetwork := nativev1.NetworkDomain{NetworkId: credential.Network.NetworkId,
		GenesisRootHash: credential.Network.GenesisRootHash, GenesisFileHash: strings.Repeat("c", 64)}
	other := credential
	other.Network = &otherNetwork
	otherIdentity, err := BasicCredentialIdentity(other)
	if err != nil || bytes.Equal(identity, otherIdentity) {
		t.Fatal("another network retained the BasicCredential identity")
	}
	otherGroup, err := MLSGroupID(&otherNetwork, "room_"+strings.Repeat("e", 64))
	if err != nil || bytes.Equal(groupID, otherGroup) {
		t.Fatal("another network retained the MLS group identifier")
	}

	prefixed := nativev1.NetworkDomain{NetworkId: credential.Network.NetworkId,
		GenesisRootHash: "sha256:" + credential.Network.GenesisRootHash, GenesisFileHash: credential.Network.GenesisFileHash}
	if _, err := MLSGroupID(&prefixed, "room_"+strings.Repeat("e", 64)); err == nil {
		t.Fatal("display-prefixed genesis hash entered MLS canonical bytes")
	}
	if _, err := BasicCredentialIdentity(DeviceCredential{Network: &prefixed}); err == nil {
		t.Fatal("invalid credential entered MLS canonical bytes")
	}
}

func TestMLSCanonicalProfileVector(t *testing.T) {
	delegation, key := mlsAuthority(t)
	credential := mlsCredential(t, delegation, key, mlsDevice("1"), "sha256:"+strings.Repeat("d", 64))
	identity, err := BasicCredentialIdentity(credential)
	if err != nil {
		t.Fatal(err)
	}
	groupID, err := MLSGroupID(credential.Network, "room_"+strings.Repeat("e", 64))
	if err != nil {
		t.Fatal(err)
	}
	// These candidate values are cross-library inputs, not evidence that this
	// Go implementation is independent. A profile change must update them
	// loudly rather than silently changing bytes under the same version.
	const expectedIdentityHex = "746f732e6d6573736167696e672e6d6c732d62617369632d63726564656e7469616c2e76310000000025746f732e6d6573736167696e672e6d6c732d62617369632d63726564656e7469616c2e763100000009746f732d6c6f63616c00000020aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa00000020bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb000000466167656e745f63636363636363636363636363636363636363636363636363636363636363636363636363636363636363636363636363636363636363636363636363636363000000446d65705f30646161363563643732336231656631666236396337633931383239343261326136316635343039383639326239623462656562306664386466613037306234000000446465765f31313131313131313131313131313131313131313131313131313131313131313131313131313131313131313131313131313131313131313131313131313131000000477368613235363a6464646464646464646464646464646464646464646464646464646464646464646464646464646464646464646464646464646464646464646464646464646400000020c050c5637a44fa8629fff3cccce2300cb362a63d99d95fc54145266f4332445a00000001"
	const expectedGroupIDHex = "5e020daea300c2231274ca1ecddea1119c262a329b6d888680884bd9fcf129ef"
	if hex.EncodeToString(identity) != expectedIdentityHex {
		t.Fatalf("BasicCredential vector changed: %s", hex.EncodeToString(identity))
	}
	if hex.EncodeToString(groupID) != expectedGroupIDHex {
		t.Fatalf("group-id vector changed: %s", hex.EncodeToString(groupID))
	}
}
