package identity

import (
	"strings"
	"testing"

	nativev1 "github.com/tosnetwork/tos-service-protocol/gen/tos/service/v1"
)

type nativeNetwork = nativev1.NetworkDomain

// Decoders are the only place untrusted bytes enter, so they are the only
// place a panic turns a malformed message into a crash.
func FuzzDecodeJSON(f *testing.F) {
	delegation := Delegation{
		Network:                       testNetworkFuzz(),
		AgentID:                       "agent_" + repeat("c", 64),
		IdentityPublicKey:             make([]byte, 32),
		AllowedProtocolVersions:       []uint32{1},
		AllowedEventClasses:           []string{"text"},
		NotBeforeUnix:                 1_800_000_000,
		ExpiresAtUnix:                 1_800_086_400,
		MaximumSessionLifetimeSeconds: 3600,
		ContactDescriptorPolicyDigest: "sha256:" + repeat("3d", 32),
		InboxAdmissionPolicyDigest:    "sha256:" + repeat("4c", 32),
	}
	delegation.IdentityPublicKey[0] = 0x1f
	if endpoint, err := DeriveEndpointID(delegation.Network, delegation.AgentID, delegation.IdentityPublicKey); err == nil {
		delegation.EndpointID = endpoint
		if encoded, err := EncodeJSON(delegation); err == nil {
			f.Add(encoded)
		}
	}
	f.Add([]byte("{}"))
	f.Add([]byte(""))
	f.Fuzz(func(t *testing.T, raw []byte) {
		decoded, err := DecodeJSON(raw)
		if err != nil {
			return
		}
		// Anything that decodes must re-encode to something that decodes, or
		// the two directions disagree about what is representable.
		encoded, err := EncodeJSON(decoded)
		if err != nil {
			t.Fatalf("a decoded delegation could not be re-encoded: %v", err)
		}
		if _, err := DecodeJSON(encoded); err != nil {
			t.Fatalf("a re-encoded delegation could not be decoded: %v", err)
		}
	})
}

func testNetworkFuzz() *nativeNetwork {
	return &nativeNetwork{
		NetworkId:       "tos-local",
		GenesisRootHash: repeat("a", 64),
		GenesisFileHash: repeat("b", 64),
	}
}

func repeat(value string, count int) string { return strings.Repeat(value, count) }
