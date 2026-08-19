package e2ee

import (
	"bytes"
	"crypto/ed25519"
	"strings"
	"testing"
	"time"

	"github.com/tosnetwork/tos-messenger/pkg/identity"
	nativev1 "github.com/tosnetwork/tos-service-protocol/gen/tos/service/v1"
)

const (
	baseUnix    = uint64(1_800_000_000)
	algorithm   = "tos.messaging.e2ee.example-suite.v1"
	senderAgent = "agent_" + "2222222222222222222222222222222222222222222222222222222222222222"
	deviceOne   = "dev_" + "4444444444444444444444444444444444444444444444444444444444444444"
	deviceTwo   = "dev_" + "7777777777777777777777777777777777777777777777777777777777777777"
)

func testNetwork() *nativev1.NetworkDomain {
	return &nativev1.NetworkDomain{
		NetworkId:       "tos-local",
		GenesisRootHash: strings.Repeat("a", 64),
		GenesisFileHash: strings.Repeat("b", 64),
	}
}

func endpointKey(t *testing.T, seed byte) ed25519.PrivateKey {
	t.Helper()
	return ed25519.NewKeyFromSeed(bytes.Repeat([]byte{seed}, ed25519.SeedSize))
}

func testDelegation(t *testing.T, key ed25519.PrivateKey) identity.Delegation {
	t.Helper()
	public, ok := key.Public().(ed25519.PublicKey)
	if !ok {
		t.Fatal("unexpected public key type")
	}
	network := testNetwork()
	endpointID, err := identity.DeriveEndpointID(network, senderAgent, public)
	if err != nil {
		t.Fatalf("derive endpoint: %v", err)
	}
	delegation := identity.Delegation{
		Network:                       network,
		AgentID:                       senderAgent,
		EndpointID:                    endpointID,
		IdentityPublicKey:             public,
		AllowedProtocolVersions:       []uint32{1},
		AllowedOutboundEventClasses:   []string{"text"},
		NotBeforeUnix:                 baseUnix,
		ExpiresAtUnix:                 baseUnix + 86_400,
		MaximumSessionLifetimeSeconds: 3600,
		ContactDescriptorPolicyDigest: "sha256:" + strings.Repeat("3d", 32),
		InboxAdmissionPolicyDigest:    "sha256:" + strings.Repeat("4c", 32),
	}
	if err := identity.Validate(delegation); err != nil {
		t.Fatalf("delegation: %v", err)
	}
	return delegation
}

// A set digest is computed from bundles that were already signed, because a
// publisher signs each device before committing the set.
func signedBundle(t *testing.T, delegation identity.Delegation, device string, key ed25519.PrivateKey) Bundle {
	t.Helper()
	signed, err := SignBundle(testBundle(t, delegation, device), key)
	if err != nil {
		t.Fatalf("sign bundle: %v", err)
	}
	return signed
}

func testBundle(t *testing.T, delegation identity.Delegation, device string) Bundle {
	t.Helper()
	return Bundle{
		Network:       delegation.Network,
		AgentID:       delegation.AgentID,
		EndpointID:    delegation.EndpointID,
		DeviceID:      device,
		AlgorithmID:   algorithm,
		Material:      bytes.Repeat([]byte{0x5a, 0x1c}, 32),
		IssuedAtUnix:  baseUnix,
		ExpiresAtUnix: baseUnix + 3600,
	}
}

func testBinding() Binding {
	return Binding{
		Network:             testNetwork(),
		AlgorithmID:         algorithm,
		ConversationID:      "conv_" + strings.Repeat("1", 64),
		SenderAgentID:       senderAgent,
		SenderEndpointID:    "mep_" + strings.Repeat("3", 64),
		SenderDeviceID:      deviceOne,
		RecipientAgentID:    "agent_" + strings.Repeat("5", 64),
		RecipientEndpointID: "mep_" + strings.Repeat("6", 64),
		RecipientDeviceID:   deviceTwo,
	}
}

func TestBindingCoversEveryField(t *testing.T) {
	base := testBinding()
	original, err := base.Bytes()
	if err != nil {
		t.Fatalf("bytes: %v", err)
	}
	mutations := map[string]func(*Binding){
		"network":            func(b *Binding) { b.Network.NetworkId = "tos-other" },
		"genesis root":       func(b *Binding) { b.Network.GenesisRootHash = strings.Repeat("c", 64) },
		"algorithm":          func(b *Binding) { b.AlgorithmID = "tos.messaging.e2ee.other.v1" },
		"conversation":       func(b *Binding) { b.ConversationID = "conv_" + strings.Repeat("9", 64) },
		"sender agent":       func(b *Binding) { b.SenderAgentID = "agent_" + strings.Repeat("9", 64) },
		"sender endpoint":    func(b *Binding) { b.SenderEndpointID = "mep_" + strings.Repeat("9", 64) },
		"sender device":      func(b *Binding) { b.SenderDeviceID = "dev_" + strings.Repeat("9", 64) },
		"recipient agent":    func(b *Binding) { b.RecipientAgentID = "agent_" + strings.Repeat("8", 64) },
		"recipient endpoint": func(b *Binding) { b.RecipientEndpointID = "mep_" + strings.Repeat("8", 64) },
		"recipient device":   func(b *Binding) { b.RecipientDeviceID = "dev_" + strings.Repeat("8", 64) },
	}
	for name, mutate := range mutations {
		t.Run(name, func(t *testing.T) {
			binding := testBinding()
			mutate(&binding)
			mutated, err := binding.Bytes()
			if err != nil {
				t.Fatalf("bytes: %v", err)
			}
			if bytes.Equal(mutated, original) {
				t.Fatalf("changing %q did not change the binding", name)
			}
		})
	}
}

func TestBindingDirectionIsNotInterchangeable(t *testing.T) {
	forward := testBinding()
	reply := forward.Reply()
	forwardBytes, err := forward.Bytes()
	if err != nil {
		t.Fatalf("bytes: %v", err)
	}
	replyBytes, err := reply.Bytes()
	if err != nil {
		t.Fatalf("bytes: %v", err)
	}
	if bytes.Equal(forwardBytes, replyBytes) {
		t.Fatal("a reply binding matches its forward binding")
	}
	roundTrip, err := reply.Reply().Bytes()
	if err != nil {
		t.Fatalf("bytes: %v", err)
	}
	if !bytes.Equal(roundTrip, forwardBytes) {
		t.Fatal("reversing a binding twice did not return the original")
	}
}

func TestBindingValidationRejectsMalformedShapes(t *testing.T) {
	cases := map[string]func(*Binding){
		"nil network":       func(b *Binding) { b.Network = nil },
		"bad genesis":       func(b *Binding) { b.Network.GenesisRootHash = "zz" },
		"unnamed algorithm": func(b *Binding) { b.AlgorithmID = "aes" },
		"bad conversation":  func(b *Binding) { b.ConversationID = "conv_bad" },
		"bad sender":        func(b *Binding) { b.SenderAgentID = "agent_bad" },
		"bad sender device": func(b *Binding) { b.SenderDeviceID = "dev_bad" },
		"bad recipient":     func(b *Binding) { b.RecipientEndpointID = "mep_bad" },
		"self session":      func(b *Binding) { b.RecipientDeviceID = b.SenderDeviceID },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			binding := testBinding()
			mutate(&binding)
			if err := binding.Validate(); err == nil {
				t.Fatalf("expected %q to be refused", name)
			}
			if _, err := binding.Bytes(); err == nil {
				t.Fatalf("expected %q to produce no binding", name)
			}
		})
	}
}

func TestBundleRoundTripAndBinding(t *testing.T) {
	key := endpointKey(t, 0x11)
	delegation := testDelegation(t, key)
	bundle, err := SignBundle(testBundle(t, delegation, deviceOne), key)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	encoded, err := EncodeBundleJSON(bundle)
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	decoded, err := DecodeBundleJSON(encoded)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	now := time.Unix(int64(baseUnix)+60, 0)
	if err := BindBundle(delegation, decoded, now); err != nil {
		t.Fatalf("bind: %v", err)
	}
	first, err := BundleDigest(bundle)
	if err != nil {
		t.Fatalf("digest: %v", err)
	}
	second, err := BundleDigest(decoded)
	if err != nil {
		t.Fatalf("digest: %v", err)
	}
	if first != second {
		t.Fatal("bundle identity changed across transport")
	}
}

func TestBindBundleRejectsUnauthorizedMaterial(t *testing.T) {
	key := endpointKey(t, 0x11)
	other := endpointKey(t, 0x22)
	delegation := testDelegation(t, key)
	now := time.Unix(int64(baseUnix)+60, 0)

	cases := map[string]func(Bundle) Bundle{
		"foreign signature": func(b Bundle) Bundle {
			signed, err := SignBundle(b, other)
			if err != nil {
				t.Fatalf("sign: %v", err)
			}
			return signed
		},
		"another agent": func(b Bundle) Bundle {
			b.AgentID = "agent_" + strings.Repeat("9", 64)
			signed, _ := SignBundle(b, key)
			return signed
		},
		"another endpoint": func(b Bundle) Bundle {
			b.EndpointID = "mep_" + strings.Repeat("9", 64)
			signed, _ := SignBundle(b, key)
			return signed
		},
		"another network": func(b Bundle) Bundle {
			b.Network = &nativev1.NetworkDomain{NetworkId: "tos-other",
				GenesisRootHash: strings.Repeat("a", 64), GenesisFileHash: strings.Repeat("b", 64)}
			signed, _ := SignBundle(b, key)
			return signed
		},
		"outlives delegation": func(b Bundle) Bundle {
			b.IssuedAtUnix = delegation.ExpiresAtUnix - 10
			b.ExpiresAtUnix = delegation.ExpiresAtUnix + 10
			signed, _ := SignBundle(b, key)
			return signed
		},
		"tampered material": func(b Bundle) Bundle {
			signed, _ := SignBundle(b, key)
			signed.Material = bytes.Repeat([]byte{0x01}, 64)
			return signed
		},
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			bundle := mutate(testBundle(t, delegation, deviceOne))
			if err := BindBundle(delegation, bundle, now); err == nil {
				t.Fatalf("expected %q to be refused", name)
			}
		})
	}

	valid, err := SignBundle(testBundle(t, delegation, deviceOne), key)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	if err := BindBundle(delegation, valid, time.Unix(int64(valid.ExpiresAtUnix), 0)); err == nil {
		t.Fatal("an expired bundle was accepted")
	}
	if err := BindBundle(delegation, valid, time.Unix(int64(valid.IssuedAtUnix)-1, 0)); err == nil {
		t.Fatal("a bundle was accepted before it was issued")
	}
	if err := BindBundle(delegation, valid, time.Time{}); err == nil {
		t.Fatal("a zero clock was accepted")
	}
}

func TestBundleValidationRejectsMalformedShapes(t *testing.T) {
	key := endpointKey(t, 0x11)
	delegation := testDelegation(t, key)
	cases := map[string]func(*Bundle){
		"bad device":        func(b *Bundle) { b.DeviceID = "dev_bad" },
		"unnamed algorithm": func(b *Bundle) { b.AlgorithmID = "curve25519" },
		"empty material":    func(b *Bundle) { b.Material = nil },
		"zero material":     func(b *Bundle) { b.Material = make([]byte, 64) },
		"huge material":     func(b *Bundle) { b.Material = bytes.Repeat([]byte{1}, MaxMaterialBytes+1) },
		"inverted window":   func(b *Bundle) { b.ExpiresAtUnix = b.IssuedAtUnix },
		"overlong window": func(b *Bundle) {
			b.ExpiresAtUnix = b.IssuedAtUnix + MaxBundleLifetimeSeconds + 1
		},
		"nil network": func(b *Bundle) { b.Network = nil },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			bundle := testBundle(t, delegation, deviceOne)
			mutate(&bundle)
			if err := ValidateBundle(bundle, false); err == nil {
				t.Fatalf("expected %q to be refused", name)
			}
			if _, err := SignBundle(bundle, key); err == nil {
				t.Fatalf("expected %q to be unsignable", name)
			}
		})
	}
}

func TestSetDigestCoversEveryDevice(t *testing.T) {
	key := endpointKey(t, 0x11)
	delegation := testDelegation(t, key)
	first := signedBundle(t, delegation, deviceOne, key)
	second := signedBundle(t, delegation, deviceTwo, key)

	digest, err := SetDigest([]Bundle{first, second})
	if err != nil {
		t.Fatalf("set digest: %v", err)
	}
	reordered, err := SetDigest([]Bundle{second, first})
	if err != nil {
		t.Fatalf("set digest: %v", err)
	}
	if digest != reordered {
		t.Fatal("device order changed the published set")
	}
	single, err := SetDigest([]Bundle{first})
	if err != nil {
		t.Fatalf("set digest: %v", err)
	}
	if single == digest {
		t.Fatal("removing a device did not change the published set")
	}
	rotated, err := SignBundle(func() Bundle {
		bundle := testBundle(t, delegation, deviceTwo)
		bundle.Material = bytes.Repeat([]byte{0x33}, 32)
		return bundle
	}(), key)
	if err != nil {
		t.Fatalf("sign rotated: %v", err)
	}
	changed, err := SetDigest([]Bundle{first, rotated})
	if err != nil {
		t.Fatalf("set digest: %v", err)
	}
	if changed == digest {
		t.Fatal("rotating one device's material did not change the published set")
	}
}

func TestSetDigestRejectsIncoherentSets(t *testing.T) {
	key := endpointKey(t, 0x11)
	delegation := testDelegation(t, key)
	first := signedBundle(t, delegation, deviceOne, key)

	if _, err := SetDigest(nil); err == nil {
		t.Fatal("an empty set was accepted")
	}
	if _, err := SetDigest([]Bundle{first, first}); err == nil {
		t.Fatal("a duplicated device was accepted")
	}
	foreign := signedBundle(t, delegation, deviceTwo, key)
	foreign.EndpointID = "mep_" + strings.Repeat("9", 64)
	if _, err := SetDigest([]Bundle{first, foreign}); err == nil {
		t.Fatal("a set spanning two endpoints was accepted")
	}
	oversized := make([]Bundle, 0, MaxDevicesPerSet+1)
	for index := 0; index <= MaxDevicesPerSet; index++ {
		oversized = append(oversized, first)
	}
	if _, err := SetDigest(oversized); err == nil {
		t.Fatal("an oversized set was accepted")
	}
}

func TestDecodeBundleRejectsMalformedTransport(t *testing.T) {
	key := endpointKey(t, 0x11)
	delegation := testDelegation(t, key)
	signed, err := SignBundle(testBundle(t, delegation, deviceOne), key)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	valid, err := EncodeBundleJSON(signed)
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	cases := map[string][]byte{
		"unknown field": []byte(string(valid[:len(valid)-1]) + `,"extra":1}`),
		"trailing json": append(append([]byte{}, valid...), []byte("{}")...),
		"wrong schema":  []byte(strings.Replace(string(valid), BundleSchema, "other", 1)),
		"bad base64":    []byte(strings.Replace(string(valid), `"material_base64":"`, `"material_base64":"!!`, 1)),
		"empty":         []byte(""),
	}
	for name, raw := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := DecodeBundleJSON(raw); err == nil {
				t.Fatalf("expected %q to be refused", name)
			}
		})
	}
}

func TestAlgorithmIdentifiers(t *testing.T) {
	for _, valid := range []string{
		"tos.messaging.e2ee.x3dh-double-ratchet.v1",
		"tos.messaging.e2ee.mls.v999",
	} {
		if err := ValidateAlgorithmID(valid); err != nil {
			t.Fatalf("expected %q to be accepted: %v", valid, err)
		}
	}
	for _, invalid := range []string{
		"", "mls", "tos.messaging.e2ee..v1", "tos.messaging.e2ee.MLS.v1",
		"tos.messaging.e2ee.mls.v", "tos.messaging.e2ee.mls.v1234",
		"tos.messaging.e2ee." + strings.Repeat("x", 33) + ".v1",
	} {
		if err := ValidateAlgorithmID(invalid); err == nil {
			t.Fatalf("expected %q to be refused", invalid)
		}
	}
}

func TestDescriptorCommitmentIsChecked(t *testing.T) {
	key := endpointKey(t, 0x11)
	delegation := testDelegation(t, key)
	published := []Bundle{signedBundle(t, delegation, deviceOne, key), signedBundle(t, delegation, deviceTwo, key)}

	committed, err := SetDigest(published)
	if err != nil {
		t.Fatalf("set digest: %v", err)
	}
	if err := MatchesDescriptorDigest(committed, published); err != nil {
		t.Fatalf("expected the published set to match its commitment: %v", err)
	}
	// A server that returns one device's material instead of both is serving
	// something the endpoint never published.
	if err := MatchesDescriptorDigest(committed, published[:1]); err == nil {
		t.Fatal("a truncated device set matched the commitment")
	}
	substituted := append([]Bundle(nil), published...)
	substituted[1].Material = bytes.Repeat([]byte{0x77}, 32)
	if err := MatchesDescriptorDigest(committed, substituted); err == nil {
		t.Fatal("substituted material matched the commitment")
	}
	if err := MatchesDescriptorDigest("sha256:"+strings.Repeat("0", 64), published); err == nil {
		t.Fatal("an all-zero commitment was accepted")
	}
	if err := MatchesDescriptorDigest("not-a-digest", published); err == nil {
		t.Fatal("a malformed commitment was accepted")
	}
}

// A protocol core cannot rely on every caller remembering to check each bundle
// afterwards, so a mixed set has no digest at all.
func TestSetDigestRefusesMixedSets(t *testing.T) {
	key := endpointKey(t, 0x11)
	delegation := testDelegation(t, key)
	first := signedBundle(t, delegation, deviceOne, key)

	cases := map[string]func(Bundle) Bundle{
		"another Agent": func(b Bundle) Bundle {
			b.AgentID = "agent_" + strings.Repeat("9", 64)
			return b
		},
		"another network": func(b Bundle) Bundle {
			b.Network = &nativev1.NetworkDomain{NetworkId: "tos-other",
				GenesisRootHash: strings.Repeat("a", 64), GenesisFileHash: strings.Repeat("b", 64)}
			return b
		},
		"another suite": func(b Bundle) Bundle {
			b.AlgorithmID = "tos.messaging.e2ee.other-suite.v1"
			return b
		},
		"another endpoint": func(b Bundle) Bundle {
			b.EndpointID = "mep_" + strings.Repeat("9", 64)
			return b
		},
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			other := mutate(signedBundle(t, delegation, deviceTwo, key))
			if _, err := SetDigest([]Bundle{first, other}); err == nil {
				t.Fatalf("a set mixing %q produced a digest", name)
			}
		})
	}
}

func TestBindBundleSetChecksEveryDevice(t *testing.T) {
	key := endpointKey(t, 0x11)
	other := endpointKey(t, 0x22)
	delegation := testDelegation(t, key)
	now := time.Unix(int64(baseUnix)+60, 0)

	signOne := func(t *testing.T, device string, signing ed25519.PrivateKey) Bundle {
		t.Helper()
		signed, err := SignBundle(testBundle(t, delegation, device), signing)
		if err != nil {
			t.Fatalf("sign: %v", err)
		}
		return signed
	}

	good := []Bundle{signOne(t, deviceOne, key), signOne(t, deviceTwo, key)}
	committed, err := SetDigest(good)
	if err != nil {
		t.Fatalf("set digest: %v", err)
	}
	if err := BindBundleSet(delegation, good, committed, now); err != nil {
		t.Fatalf("a delegated set was refused: %v", err)
	}

	// One device signed by a key the delegation does not authorize fails the
	// whole set, rather than being noticed only if somebody checks that device.
	mixed := []Bundle{signOne(t, deviceOne, key), signOne(t, deviceTwo, other)}
	digest, err := SetDigest(mixed)
	if err != nil {
		t.Fatalf("set digest: %v", err)
	}
	if err := BindBundleSet(delegation, mixed, digest, now); err == nil {
		t.Fatal("a set containing a foreign signature was accepted")
	}

	// The set must also be the one the descriptor committed.
	if err := BindBundleSet(delegation, good[:1], committed, now); err == nil {
		t.Fatal("a truncated set matched the descriptor commitment")
	}
}
