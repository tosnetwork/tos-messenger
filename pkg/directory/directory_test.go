package directory

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
	baseUnix     = uint64(1_800_000_000)
	agentID      = "agent_" + "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
	otherAgentID = "agent_" + "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"
)

type stubResolver struct {
	states map[string]*nativev1.AgentStateV1
}

func (s stubResolver) ResolveAgent(id string) (*nativev1.AgentStateV1, bool, error) {
	state, found := s.states[id]
	return state, found, nil
}

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
	network := testNetwork()
	public, ok := key.Public().(ed25519.PublicKey)
	if !ok {
		t.Fatal("unexpected public key type")
	}
	endpointID, err := identity.DeriveEndpointID(network, agentID, public)
	if err != nil {
		t.Fatalf("derive endpoint: %v", err)
	}
	delegation := identity.Delegation{
		Network:                       network,
		AgentID:                       agentID,
		EndpointID:                    endpointID,
		IdentityPublicKey:             public,
		ADNLID:                        "adnl:" + strings.Repeat("2e", 32),
		AllowedProtocolVersions:       []uint32{1, 2},
		AllowedEventClasses:           []string{"agent.task", "text"},
		NotBeforeUnix:                 baseUnix,
		ExpiresAtUnix:                 baseUnix + 86_400,
		MaximumSessionLifetimeSeconds: 3600,
		ContactDescriptorPolicyDigest: "sha256:" + strings.Repeat("3d", 32),
		MailboxPolicyDigest:           "sha256:" + strings.Repeat("4c", 32),
	}
	if err := identity.Validate(delegation); err != nil {
		t.Fatalf("delegation: %v", err)
	}
	return delegation
}

func testDescriptor(t *testing.T, delegation identity.Delegation) Descriptor {
	t.Helper()
	digest, err := identity.Digest(delegation)
	if err != nil {
		t.Fatalf("delegation digest: %v", err)
	}
	return Descriptor{
		Network:                    delegation.Network,
		AgentID:                    delegation.AgentID,
		EndpointID:                 delegation.EndpointID,
		DelegationDigest:           digest,
		SupportedMessagingVersions: []uint32{1},
		SupportedA2AVersions:       []string{"0.3"},
		SupportedMCPVersions:       []string{"2025-06-18"},
		ADNLID:                     delegation.ADNLID,
		HTTPSEndpoint:              "https://endpoint.example/messaging",
		PrekeyBundleDigest:         "sha256:" + strings.Repeat("7a", 32),
		MailboxRelaySetDigest:      "sha256:" + strings.Repeat("8b", 32),
		AttachmentServiceDigest:    "",
		MaximumEnvelopeBytes:       64 << 10,
		IssuedAtUnix:               baseUnix,
		ExpiresAtUnix:              baseUnix + 3600,
	}
}

func signedDescriptor(t *testing.T, delegation identity.Delegation, key ed25519.PrivateKey) Descriptor {
	t.Helper()
	descriptor, err := SignDescriptor(testDescriptor(t, delegation), key)
	if err != nil {
		t.Fatalf("sign descriptor: %v", err)
	}
	return descriptor
}

func liveResolver(t *testing.T, delegation identity.Delegation) stubResolver {
	t.Helper()
	digest, err := identity.Digest(delegation)
	if err != nil {
		t.Fatalf("digest: %v", err)
	}
	return stubResolver{states: map[string]*nativev1.AgentStateV1{
		delegation.AgentID: {
			AgentId:           delegation.AgentID,
			Policy:            &nativev1.ControllerPolicyV1{Threshold: 1},
			DelegationDigests: []string{digest},
		},
	}}
}

func TestResolveAdmitsDelegatedDescriptor(t *testing.T) {
	key := endpointKey(t, 0x11)
	delegation := testDelegation(t, key)
	descriptor := signedDescriptor(t, delegation, key)

	delegationJSON, err := identity.EncodeJSON(delegation)
	if err != nil {
		t.Fatalf("encode delegation: %v", err)
	}
	descriptorJSON, err := EncodeDescriptorJSON(descriptor)
	if err != nil {
		t.Fatalf("encode descriptor: %v", err)
	}
	now := time.Unix(int64(baseUnix)+60, 0)
	resolvedDelegation, resolvedDescriptor, err := Resolve(liveResolver(t, delegation), testNetwork(), delegationJSON, descriptorJSON, now)
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if resolvedDelegation.EndpointID != delegation.EndpointID || resolvedDescriptor.EndpointID != delegation.EndpointID {
		t.Fatal("resolution returned another endpoint")
	}
}

func TestDescriptorRoundTripPreservesSignature(t *testing.T) {
	key := endpointKey(t, 0x11)
	delegation := testDelegation(t, key)
	descriptor := signedDescriptor(t, delegation, key)

	encoded, err := EncodeDescriptorJSON(descriptor)
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	decoded, err := DecodeDescriptorJSON(encoded)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if err := Bind(delegation, decoded, time.Unix(int64(baseUnix)+60, 0)); err != nil {
		t.Fatalf("bind after round trip: %v", err)
	}
}

func TestBindRejectsUnauthorizedDescriptors(t *testing.T) {
	key := endpointKey(t, 0x11)
	otherKey := endpointKey(t, 0x22)
	delegation := testDelegation(t, key)
	now := time.Unix(int64(baseUnix)+60, 0)

	cases := map[string]func(*Descriptor){
		"foreign signature": func(d *Descriptor) {
			signed, err := SignDescriptor(*d, otherKey)
			if err != nil {
				t.Fatalf("sign: %v", err)
			}
			*d = signed
		},
		"another Agent":    func(d *Descriptor) { d.AgentID = otherAgentID },
		"another endpoint": func(d *Descriptor) { d.EndpointID = "mep_" + strings.Repeat("1", 64) },
		"another network": func(d *Descriptor) {
			d.Network = &nativev1.NetworkDomain{NetworkId: "tos-other", GenesisRootHash: strings.Repeat("a", 64), GenesisFileHash: strings.Repeat("b", 64)}
		},
		"wrong delegation":       func(d *Descriptor) { d.DelegationDigest = "sha256:" + strings.Repeat("9", 64) },
		"undelegated adnl":       func(d *Descriptor) { d.ADNLID = "adnl:" + strings.Repeat("3f", 32) },
		"undelegated version":    func(d *Descriptor) { d.SupportedMessagingVersions = []uint32{3} },
		"outlives delegation":    func(d *Descriptor) { d.ExpiresAtUnix = delegation.ExpiresAtUnix + 1 },
		"tampered prekey":        func(d *Descriptor) { d.PrekeyBundleDigest = "sha256:" + strings.Repeat("1a", 32) },
		"tampered relay set":     func(d *Descriptor) { d.MailboxRelaySetDigest = "sha256:" + strings.Repeat("1b", 32) },
		"tampered envelope size": func(d *Descriptor) { d.MaximumEnvelopeBytes = 32 << 10 },
		"tampered https":         func(d *Descriptor) { d.HTTPSEndpoint = "https://attacker.example/messaging" },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			descriptor := signedDescriptor(t, delegation, key)
			mutate(&descriptor)
			if err := Bind(delegation, descriptor, now); err == nil {
				t.Fatalf("expected %q to be rejected", name)
			}
		})
	}
}

func TestBindEnforcesTimeBounds(t *testing.T) {
	key := endpointKey(t, 0x11)
	delegation := testDelegation(t, key)
	descriptor := signedDescriptor(t, delegation, key)

	if err := Bind(delegation, descriptor, time.Unix(int64(descriptor.IssuedAtUnix), 0)); err != nil {
		t.Fatalf("issued_at must be inclusive: %v", err)
	}
	if err := Bind(delegation, descriptor, time.Unix(int64(descriptor.ExpiresAtUnix)-1, 0)); err != nil {
		t.Fatalf("last valid second rejected: %v", err)
	}
	if err := Bind(delegation, descriptor, time.Unix(int64(descriptor.ExpiresAtUnix), 0)); err == nil {
		t.Fatal("expired descriptor accepted")
	}
	if err := Bind(delegation, descriptor, time.Unix(int64(descriptor.IssuedAtUnix)-1, 0)); err == nil {
		t.Fatal("descriptor accepted before it was issued")
	}
	if err := Bind(delegation, descriptor, time.Unix(int64(delegation.ExpiresAtUnix), 0)); err == nil {
		t.Fatal("descriptor accepted under an expired delegation")
	}
	if err := Bind(delegation, descriptor, time.Time{}); err == nil {
		t.Fatal("descriptor accepted with a zero clock")
	}
}

func TestDescriptorValidationRejectsMalformedShapes(t *testing.T) {
	key := endpointKey(t, 0x11)
	delegation := testDelegation(t, key)
	cases := map[string]func(*Descriptor){
		"no route":            func(d *Descriptor) { d.ADNLID = ""; d.HTTPSEndpoint = "" },
		"plaintext http":      func(d *Descriptor) { d.HTTPSEndpoint = "http://endpoint.example/messaging" },
		"endpoint with query": func(d *Descriptor) { d.HTTPSEndpoint = "https://endpoint.example/m?token=secret" },
		"endpoint with user":  func(d *Descriptor) { d.HTTPSEndpoint = "https://user:pass@endpoint.example/m" },
		"tiny envelope":       func(d *Descriptor) { d.MaximumEnvelopeBytes = MinEnvelopeBytes - 1 },
		"huge envelope":       func(d *Descriptor) { d.MaximumEnvelopeBytes = MaxEnvelopeBytes + 1 },
		"no messaging version": func(d *Descriptor) {
			d.SupportedMessagingVersions = nil
		},
		"unsorted versions":    func(d *Descriptor) { d.SupportedMessagingVersions = []uint32{2, 1} },
		"bad adapter version":  func(d *Descriptor) { d.SupportedA2AVersions = []string{"Alpha!"} },
		"unsorted adapters":    func(d *Descriptor) { d.SupportedMCPVersions = []string{"2025-06-18", "2024-01-01"} },
		"zero prekey digest":   func(d *Descriptor) { d.PrekeyBundleDigest = "sha256:" + strings.Repeat("0", 64) },
		"missing relay digest": func(d *Descriptor) { d.MailboxRelaySetDigest = "" },
		"inverted window":      func(d *Descriptor) { d.ExpiresAtUnix = d.IssuedAtUnix },
		"overlong window": func(d *Descriptor) {
			d.ExpiresAtUnix = d.IssuedAtUnix + MaxDescriptorLifetimeSeconds + 1
		},
		"bad attachment digest": func(d *Descriptor) { d.AttachmentServiceDigest = "sha256:zz" },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			descriptor := testDescriptor(t, delegation)
			mutate(&descriptor)
			if err := ValidateDescriptor(descriptor, false); err == nil {
				t.Fatalf("expected %q to be rejected", name)
			}
			if _, err := SignDescriptor(descriptor, key); err == nil {
				t.Fatalf("expected %q to be unsignable", name)
			}
		})
	}
}

func TestDecodeDescriptorRejectsMalformedTransport(t *testing.T) {
	key := endpointKey(t, 0x11)
	delegation := testDelegation(t, key)
	valid, err := EncodeDescriptorJSON(signedDescriptor(t, delegation, key))
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	cases := map[string][]byte{
		"unknown field": []byte(string(valid[:len(valid)-1]) + `,"extra":1}`),
		"trailing json": append(append([]byte{}, valid...), []byte(`{}`)...),
		"wrong schema":  []byte(strings.Replace(string(valid), DescriptorSchema, "tos.messaging.contact-descriptor.v2", 1)),
		"empty":         []byte(""),
		"array":         []byte(`[]`),
	}
	for name, raw := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := DecodeDescriptorJSON(raw); err == nil {
				t.Fatalf("expected %q to be rejected", name)
			}
		})
	}
}

func TestLocatorCommitsExactlyOneDescriptor(t *testing.T) {
	key := endpointKey(t, 0x11)
	delegation := testDelegation(t, key)
	descriptor := signedDescriptor(t, delegation, key)

	locator, err := NewLocator(descriptor, "https://directory.example/descriptor", descriptor.ExpiresAtUnix)
	if err != nil {
		t.Fatalf("new locator: %v", err)
	}
	locator, err = SignLocator(locator, key)
	if err != nil {
		t.Fatalf("sign locator: %v", err)
	}
	encoded, err := EncodeLocatorJSON(locator)
	if err != nil {
		t.Fatalf("encode locator: %v", err)
	}
	if len(encoded) > MaxLocatorBytes {
		t.Fatalf("locator exceeds its bound: %d bytes", len(encoded))
	}
	decoded, err := DecodeLocatorJSON(encoded)
	if err != nil {
		t.Fatalf("decode locator: %v", err)
	}
	now := time.Unix(int64(baseUnix)+60, 0)
	if err := VerifyLocator(delegation, decoded, now); err != nil {
		t.Fatalf("verify locator: %v", err)
	}
	if err := MatchesDescriptor(decoded, descriptor); err != nil {
		t.Fatalf("descriptor should match its locator: %v", err)
	}

	substituted := signedDescriptor(t, delegation, key)
	substituted.HTTPSEndpoint = "https://attacker.example/messaging"
	substituted, err = SignDescriptor(substituted, key)
	if err != nil {
		t.Fatalf("sign substituted: %v", err)
	}
	if err := MatchesDescriptor(decoded, substituted); err == nil {
		t.Fatal("a substituted descriptor was accepted under the locator commitment")
	}
}

func TestVerifyLocatorRejectsUnauthorizedValues(t *testing.T) {
	key := endpointKey(t, 0x11)
	otherKey := endpointKey(t, 0x22)
	delegation := testDelegation(t, key)
	descriptor := signedDescriptor(t, delegation, key)
	now := time.Unix(int64(baseUnix)+60, 0)

	build := func(t *testing.T, signing ed25519.PrivateKey, mutate func(*Locator)) Locator {
		t.Helper()
		locator, err := NewLocator(descriptor, "https://directory.example/descriptor", descriptor.ExpiresAtUnix)
		if err != nil {
			t.Fatalf("new locator: %v", err)
		}
		if mutate != nil {
			mutate(&locator)
		}
		signed, err := SignLocator(locator, signing)
		if err != nil {
			t.Fatalf("sign locator: %v", err)
		}
		return signed
	}

	cases := map[string]Locator{
		"foreign signature": build(t, otherKey, nil),
		"another endpoint":  build(t, key, func(l *Locator) { l.EndpointID = "mep_" + strings.Repeat("1", 64) }),
		"another agent digest": build(t, key, func(l *Locator) {
			digest, err := AgentIDDigest(testNetwork(), otherAgentID)
			if err != nil {
				t.Fatalf("digest: %v", err)
			}
			l.AgentIDDigest = digest
		}),
		"outlives delegation": build(t, key, func(l *Locator) { l.ExpiresAtUnix = delegation.ExpiresAtUnix + 1 }),
	}
	for name, locator := range cases {
		t.Run(name, func(t *testing.T) {
			if err := VerifyLocator(delegation, locator, now); err == nil {
				t.Fatalf("expected %q to be rejected", name)
			}
		})
	}

	expired := build(t, key, nil)
	if err := VerifyLocator(delegation, expired, time.Unix(int64(expired.ExpiresAtUnix), 0)); err == nil {
		t.Fatal("expired locator accepted")
	}
	if err := VerifyLocator(delegation, expired, time.Unix(int64(delegation.ExpiresAtUnix)+1, 0)); err == nil {
		t.Fatal("locator accepted after its delegation expired")
	}
}

func TestLocatorReferenceIsBounded(t *testing.T) {
	key := endpointKey(t, 0x11)
	delegation := testDelegation(t, key)
	descriptor := signedDescriptor(t, delegation, key)

	for _, reference := range []string{
		"",
		"ftp://directory.example/descriptor",
		"http://directory.example/descriptor",
		"https://user:pass@directory.example/descriptor",
		"https://directory.example/descriptor#fragment",
		"https:///descriptor",
		" https://directory.example/descriptor",
		"https://directory.example/" + strings.Repeat("p", MaxDescriptorLocatorBytes),
	} {
		if _, err := NewLocator(descriptor, reference, descriptor.ExpiresAtUnix); err == nil {
			t.Fatalf("expected reference %q to be rejected", reference)
		}
	}
	for _, reference := range []string{
		"https://directory.example/descriptor",
		"adnl://" + strings.Repeat("2e", 32),
		"rldp://" + strings.Repeat("2e", 32) + "/descriptor",
		"http://127.0.0.1:8080/descriptor",
	} {
		if _, err := NewLocator(descriptor, reference, descriptor.ExpiresAtUnix); err != nil {
			t.Fatalf("expected reference %q to be accepted: %v", reference, err)
		}
	}
}

func TestLookupKeySeparatesIdentities(t *testing.T) {
	key := endpointKey(t, 0x11)
	delegation := testDelegation(t, key)
	network := testNetwork()
	other := testNetwork()
	other.NetworkId = "tos-other"

	first, err := LookupKey(network, agentID, delegation.EndpointID)
	if err != nil {
		t.Fatalf("lookup key: %v", err)
	}
	byAgent, err := LookupKey(network, otherAgentID, delegation.EndpointID)
	if err != nil {
		t.Fatalf("lookup key: %v", err)
	}
	byNetwork, err := LookupKey(other, agentID, delegation.EndpointID)
	if err != nil {
		t.Fatalf("lookup key: %v", err)
	}
	byEndpoint, err := LookupKey(network, agentID, "mep_"+strings.Repeat("1", 64))
	if err != nil {
		t.Fatalf("lookup key: %v", err)
	}
	if first == byAgent || first == byNetwork || first == byEndpoint {
		t.Fatal("lookup key does not separate Agent, network, and endpoint")
	}
	if _, err := LookupKey(network, "agent_bad", delegation.EndpointID); err == nil {
		t.Fatal("expected an invalid Agent identifier to be rejected")
	}
}

func TestLocatorSizeBoundIsEnforcedOnDecode(t *testing.T) {
	if _, err := DecodeLocatorJSON(bytes.Repeat([]byte("x"), MaxLocatorBytes+1)); err == nil {
		t.Fatal("expected an oversized locator to be rejected before parsing")
	}
}
