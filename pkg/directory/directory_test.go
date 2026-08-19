package directory

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/binary"
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
	states map[string]*nativev1.NativeStateV1
}

func (s stubResolver) ResolveAgent(id string) (*nativev1.NativeStateV1, bool, error) {
	state, found := s.states[id]
	return state, found, nil
}

const testRegistryCode = "tvm-cell-sha256:" + "abababababababababababababababababababababababababababababababab"

func testChain() identity.ChainPolicy {
	return identity.ChainPolicy{RegistryCodeHashes: []string{testRegistryCode}}
}

// A finalized native state shaped the way a correct resolver returns one.
func nativeState(agent *nativev1.AgentStateV1) *nativev1.NativeStateV1 {
	return &nativev1.NativeStateV1{
		Network:      testNetwork(),
		TvmStateHash: "tvm-cell-sha256:" + strings.Repeat("c", 64),
		Reference: &nativev1.ChainReference{
			Workchain: 0, Account: "0:" + strings.Repeat("d", 64),
			LogicalTime: 42, TransactionHash: "sha256:" + strings.Repeat("e", 64),
			ContractCodeHash: testRegistryCode, FinalizedCheckpoint: 100,
		},
		State: &nativev1.NativeStateV1_Agent{Agent: agent},
	}
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

func testPolicy() DescriptorPolicy {
	return DescriptorPolicy{
		MaxEnvelopeBytes:   128 << 10,
		MaxLifetimeSeconds: 24 * 60 * 60,
		AllowHTTPSEndpoint: true,
	}
}

func testPolicyDigest(t *testing.T) string {
	t.Helper()
	digest, err := testPolicy().Digest()
	if err != nil {
		t.Fatalf("policy digest: %v", err)
	}
	return digest
}

const testInboxDigest = "sha256:" + "4c4c4c4c4c4c4c4c4c4c4c4c4c4c4c4c4c4c4c4c4c4c4c4c4c4c4c4c4c4c4c4c"

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
		AllowedOutboundEventClasses:   []string{"agent.task", "text"},
		NotBeforeUnix:                 baseUnix,
		ExpiresAtUnix:                 baseUnix + 86_400,
		MaximumSessionLifetimeSeconds: 3600,
		ContactDescriptorPolicyDigest: testPolicyDigest(t),
		InboxAdmissionPolicyDigest:    testInboxDigest,
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
		MailboxRelaySetDigest:      EmptyRelaySetDigest(),
		InboxAdmissionPolicyDigest: testInboxDigest,
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
	return stubResolver{states: map[string]*nativev1.NativeStateV1{
		delegation.AgentID: nativeState(&nativev1.AgentStateV1{
			AgentId:           delegation.AgentID,
			Policy:            &nativev1.ControllerPolicyV1{Threshold: 1},
			DelegationDigests: []string{digest},
		}),
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
	resolvedDelegation, resolvedDescriptor, err := Resolve(liveResolver(t, delegation), testNetwork(), testChain(), delegationJSON, descriptorJSON, testPolicy(), now)
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
	if err := Bind(delegation, decoded, testPolicy(), time.Unix(int64(baseUnix)+60, 0)); err != nil {
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
			if err := Bind(delegation, descriptor, testPolicy(), now); err == nil {
				t.Fatalf("expected %q to be rejected", name)
			}
		})
	}
}

func TestBindEnforcesTimeBounds(t *testing.T) {
	key := endpointKey(t, 0x11)
	delegation := testDelegation(t, key)
	descriptor := signedDescriptor(t, delegation, key)

	if err := Bind(delegation, descriptor, testPolicy(), time.Unix(int64(descriptor.IssuedAtUnix), 0)); err != nil {
		t.Fatalf("issued_at must be inclusive: %v", err)
	}
	if err := Bind(delegation, descriptor, testPolicy(), time.Unix(int64(descriptor.ExpiresAtUnix)-1, 0)); err != nil {
		t.Fatalf("last valid second rejected: %v", err)
	}
	if err := Bind(delegation, descriptor, testPolicy(), time.Unix(int64(descriptor.ExpiresAtUnix), 0)); err == nil {
		t.Fatal("expired descriptor accepted")
	}
	if err := Bind(delegation, descriptor, testPolicy(), time.Unix(int64(descriptor.IssuedAtUnix)-1, 0)); err == nil {
		t.Fatal("descriptor accepted before it was issued")
	}
	if err := Bind(delegation, descriptor, testPolicy(), time.Unix(int64(delegation.ExpiresAtUnix), 0)); err == nil {
		t.Fatal("descriptor accepted under an expired delegation")
	}
	if err := Bind(delegation, descriptor, testPolicy(), time.Time{}); err == nil {
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
		"bad relay digest":     func(d *Descriptor) { d.MailboxRelaySetDigest = "sha256:zz" },
		"missing inbox policy": func(d *Descriptor) { d.InboxAdmissionPolicyDigest = "" },
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

func signedLocator(t *testing.T, descriptor Descriptor, key ed25519.PrivateKey, reference string) Locator {
	t.Helper()
	locator, err := NewLocator(descriptor, reference, baseUnix, descriptor.ExpiresAtUnix)
	if err != nil {
		t.Fatalf("new locator: %v", err)
	}
	signed, err := SignLocator(locator, key)
	if err != nil {
		t.Fatalf("sign locator: %v", err)
	}
	return signed
}

func TestLocatorCommitsExactlyOneDescriptor(t *testing.T) {
	key := endpointKey(t, 0x11)
	delegation := testDelegation(t, key)
	descriptor := signedDescriptor(t, delegation, key)
	locator := signedLocator(t, descriptor, key, "https://directory.example/descriptor")

	encoded, err := EncodeLocator(locator)
	if err != nil {
		t.Fatalf("encode locator: %v", err)
	}
	// The published value has to fit what TOS Core will actually store.
	if len(encoded) > MaxDHTValueBytes {
		t.Fatalf("locator exceeds the network limit: %d bytes", len(encoded))
	}
	if len(encoded) > MaxLocatorBytes {
		t.Fatalf("locator exceeds its own bound: %d bytes", len(encoded))
	}
	decoded, err := DecodeLocator(encoded)
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

// The largest locator this protocol can produce must still fit the network
// limit, or a legal record would be unpublishable.
func TestLargestLocatorFitsTheNetworkLimit(t *testing.T) {
	key := endpointKey(t, 0x11)
	delegation := testDelegation(t, key)
	descriptor := signedDescriptor(t, delegation, key)
	reference := "https://directory.example/" + strings.Repeat("p", MaxDescriptorLocatorBytes-len("https://directory.example/"))
	locator := signedLocator(t, descriptor, key, reference)
	encoded, err := EncodeLocator(locator)
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	if len(encoded) > MaxDHTValueBytes {
		t.Fatalf("the largest locator does not fit the network limit: %d bytes", len(encoded))
	}
	if _, err := DecodeLocator(encoded); err != nil {
		t.Fatalf("decode largest: %v", err)
	}
}

// TOS Core refuses a key description whose identifier is not the short
// identifier of the publishing key, so the key is derived from the endpoint
// key and from nothing else.
func TestLocatorKeyIsDerivedFromTheEndpointKey(t *testing.T) {
	key := endpointKey(t, 0x11)
	delegation := testDelegation(t, key)
	dhtKey, err := LocatorKey(delegation)
	if err != nil {
		t.Fatalf("locator key: %v", err)
	}
	if dhtKey.Name != LocatorKeyName || len(dhtKey.Name) > 127 {
		t.Fatalf("unexpected key name: %q", dhtKey.Name)
	}
	if dhtKey.Index > MaxLocatorKeyIndex {
		t.Fatalf("key index %d is outside what the network accepts", dhtKey.Index)
	}
	public, ok := key.Public().(ed25519.PublicKey)
	if !ok {
		t.Fatal("unexpected public key type")
	}
	expected, err := EndpointKeyID(public)
	if err != nil {
		t.Fatalf("key id: %v", err)
	}
	if dhtKey.ID != expected {
		t.Fatal("the DHT key is not the endpoint key short identifier")
	}
	// The short identifier is SHA-256 over the boxed TL public key.
	boxed := make([]byte, 4, 36)
	binary.LittleEndian.PutUint32(boxed, ed25519PublicKeyTL)
	boxed = append(boxed, public...)
	if expected != sha256.Sum256(boxed) {
		t.Fatal("the short identifier does not follow the TL encoding")
	}
	other := endpointKey(t, 0x22)
	otherPublic, ok := other.Public().(ed25519.PublicKey)
	if !ok {
		t.Fatal("unexpected public key type")
	}
	otherID, err := EndpointKeyID(otherPublic)
	if err != nil {
		t.Fatalf("key id: %v", err)
	}
	if otherID == expected {
		t.Fatal("two endpoints share a DHT key")
	}
	if _, err := EndpointKeyID(make(ed25519.PublicKey, ed25519.PublicKeySize)); err == nil {
		t.Fatal("a zero key produced a DHT key")
	}
}

// The signature update rule keeps whichever value has the greater time to
// live, so a republish that does not extend the expiry is silently ignored by
// the network.
func TestRepublishMustExtendTheStoredExpiry(t *testing.T) {
	key := endpointKey(t, 0x11)
	delegation := testDelegation(t, key)
	descriptor := signedDescriptor(t, delegation, key)
	previous := signedLocator(t, descriptor, key, "https://directory.example/descriptor")

	same := previous
	if err := Republish(previous, same); err == nil {
		t.Fatal("a republish with an unchanged expiry was accepted")
	}
	shorter, err := NewLocator(descriptor, "https://directory.example/descriptor", baseUnix, previous.ExpiresAtUnix-1)
	if err != nil {
		t.Fatalf("new locator: %v", err)
	}
	shorter, err = SignLocator(shorter, key)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	if err := Republish(previous, shorter); err == nil {
		t.Fatal("a republish with a shorter expiry was accepted")
	}

	longer, err := NewLocator(descriptor, "https://directory.example/descriptor", baseUnix+1, previous.ExpiresAtUnix)
	if err != nil {
		t.Fatalf("new locator: %v", err)
	}
	_ = longer
	extended := previous
	extended.ExpiresAtUnix = previous.ExpiresAtUnix + 1
	extended, err = SignLocator(extended, key)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	if err := Republish(previous, extended); err != nil {
		t.Fatalf("an extending republish was refused: %v", err)
	}
	foreign := extended
	foreign.EndpointID = "mep_" + strings.Repeat("1", 64)
	foreign, err = SignLocator(foreign, key)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	if err := Republish(previous, foreign); err == nil {
		t.Fatal("a republish for another endpoint was accepted")
	}
}

func TestVerifyLocatorRejectsUnauthorizedValues(t *testing.T) {
	key := endpointKey(t, 0x11)
	otherKey := endpointKey(t, 0x22)
	delegation := testDelegation(t, key)
	descriptor := signedDescriptor(t, delegation, key)
	now := time.Unix(int64(baseUnix)+60, 0)

	foreign := signedLocator(t, descriptor, otherKey, "https://directory.example/descriptor")
	if err := VerifyLocator(delegation, foreign, now); err == nil {
		t.Fatal("a locator signed by another key was accepted")
	}

	elsewhere := signedLocator(t, descriptor, key, "https://directory.example/descriptor")
	elsewhere.EndpointID = "mep_" + strings.Repeat("1", 64)
	if err := VerifyLocator(delegation, elsewhere, now); err == nil {
		t.Fatal("a locator for another endpoint was accepted")
	}

	outliving := signedLocator(t, descriptor, key, "https://directory.example/descriptor")
	outliving.ExpiresAtUnix = delegation.ExpiresAtUnix + 1
	if err := VerifyLocator(delegation, outliving, now); err == nil {
		t.Fatal("a locator outliving its delegation was accepted")
	}

	valid := signedLocator(t, descriptor, key, "https://directory.example/descriptor")
	if err := VerifyLocator(delegation, valid, time.Unix(int64(valid.ExpiresAtUnix), 0)); err == nil {
		t.Fatal("an expired locator was accepted")
	}
	if err := VerifyLocator(delegation, valid, time.Unix(int64(valid.IssuedAtUnix)-1, 0)); err == nil {
		t.Fatal("a locator was accepted before it was issued")
	}
	if err := VerifyLocator(delegation, valid, time.Time{}); err == nil {
		t.Fatal("a zero clock was accepted")
	}
}

// A published lifetime longer than a day was previously declared and never
// enforced.
func TestLocatorLifetimeIsEnforced(t *testing.T) {
	key := endpointKey(t, 0x11)
	delegation := testDelegation(t, key)
	descriptor := signedDescriptor(t, delegation, key)
	long := Locator{
		EndpointID:        descriptor.EndpointID,
		DescriptorDigest:  "sha256:" + strings.Repeat("ab", 32),
		DescriptorLocator: "https://directory.example/descriptor",
		IssuedAtUnix:      baseUnix,
		ExpiresAtUnix:     baseUnix + MaxLocatorLifetimeSeconds + 1,
	}
	if err := ValidateLocator(long, false); err == nil {
		t.Fatal("a locator living longer than a day was accepted")
	}
	if _, err := SignLocator(long, key); err == nil {
		t.Fatal("an overlong locator was signed")
	}
	_ = delegation
}

func TestLocatorSizeBoundIsEnforcedOnDecode(t *testing.T) {
	if _, err := DecodeLocator(bytes.Repeat([]byte("x"), MaxLocatorBytes+1)); err == nil {
		t.Fatal("expected an oversized locator to be rejected before parsing")
	}
	if _, err := DecodeLocator(nil); err == nil {
		t.Fatal("expected an empty value to be rejected")
	}
	if _, err := DecodeLocator(bytes.Repeat([]byte{0}, 200)); err == nil {
		t.Fatal("expected an unversioned value to be rejected")
	}
}

// A delegated key lives online and may be taken. The policy the Agent
// committed to is what bounds what a taken key can advertise.
func TestCommittedPolicyBoundsADelegatedKey(t *testing.T) {
	key := endpointKey(t, 0x11)
	delegation := testDelegation(t, key)
	now := time.Unix(int64(baseUnix)+60, 0)

	// A descriptor inside the policy is fine.
	inside := signedDescriptor(t, delegation, key)
	if err := Bind(delegation, inside, testPolicy(), now); err != nil {
		t.Fatalf("a compliant descriptor was refused: %v", err)
	}

	// The same key, signing perfectly well, cannot exceed the committed bound.
	oversized := testDescriptor(t, delegation)
	oversized.MaximumEnvelopeBytes = MaxEnvelopeBytes
	signed, err := SignDescriptor(oversized, key)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	if err := Bind(delegation, signed, testPolicy(), now); err == nil {
		t.Fatal("a descriptor beyond the committed envelope bound was accepted")
	}

	// Nor can a caller swap in a policy the Agent never committed.
	permissive := testPolicy()
	permissive.MaxEnvelopeBytes = MaxEnvelopeBytes
	if err := Bind(delegation, signed, permissive, now); err == nil {
		t.Fatal("a substituted policy was accepted")
	}
}

func TestPolicyMustLeaveARouteOpen(t *testing.T) {
	closed := DescriptorPolicy{MaxEnvelopeBytes: 64 << 10, MaxLifetimeSeconds: 3600}
	if err := closed.Validate(); err == nil {
		t.Fatal("a policy permitting no route at all was accepted")
	}
	if _, err := closed.Digest(); err == nil {
		t.Fatal("an unusable policy produced a digest")
	}
	for name, policy := range map[string]DescriptorPolicy{
		"tiny envelope": {MaxEnvelopeBytes: 1, MaxLifetimeSeconds: 3600, AllowHTTPSEndpoint: true},
		"huge envelope": {MaxEnvelopeBytes: MaxEnvelopeBytes + 1, MaxLifetimeSeconds: 3600, AllowHTTPSEndpoint: true},
		"no lifetime":   {MaxEnvelopeBytes: 64 << 10, AllowHTTPSEndpoint: true},
		"long lifetime": {MaxEnvelopeBytes: 64 << 10, MaxLifetimeSeconds: MaxDescriptorLifetimeSeconds + 1, AllowHTTPSEndpoint: true},
	} {
		t.Run(name, func(t *testing.T) {
			if err := policy.Validate(); err == nil {
				t.Fatalf("expected %q to be refused", name)
			}
		})
	}
}

func TestPolicyCanRequireADirectRoute(t *testing.T) {
	key := endpointKey(t, 0x11)
	delegation := testDelegation(t, key)
	now := time.Unix(int64(baseUnix)+60, 0)

	strict := DescriptorPolicy{MaxEnvelopeBytes: 128 << 10, MaxLifetimeSeconds: 24 * 60 * 60, RequireADNL: true}
	digest, err := strict.Digest()
	if err != nil {
		t.Fatalf("digest: %v", err)
	}
	delegation.ContactDescriptorPolicyDigest = digest

	bootstrap := testDescriptor(t, delegation)
	bootstrap.ADNLID = ""
	signed, err := SignDescriptor(bootstrap, key)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	if err := Bind(delegation, signed, strict, now); err == nil {
		t.Fatal("a descriptor with no ADNL identity was accepted under a policy requiring one")
	}

	noHTTPS := testDescriptor(t, delegation)
	signedFull, err := SignDescriptor(noHTTPS, key)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	if err := Bind(delegation, signedFull, strict, now); err == nil {
		t.Fatal("an HTTPS endpoint was accepted under a policy that did not permit one")
	}
}

// An endpoint with no Relays publishes a value everyone computes the same way,
// rather than each implementer inventing a placeholder.
func TestEmptyRelaySetHasOneDigest(t *testing.T) {
	first := EmptyRelaySetDigest()
	if first != EmptyRelaySetDigest() {
		t.Fatal("the empty Relay set digest is not stable")
	}
	populated, err := RelaySetDigest([]string{"https://relay-a.example", "https://relay-b.example"})
	if err != nil {
		t.Fatalf("relay set: %v", err)
	}
	if populated == first {
		t.Fatal("a populated Relay set matches the empty one")
	}
	if _, err := RelaySetDigest([]string{"https://relay-b.example", "https://relay-a.example"}); err == nil {
		t.Fatal("an unsorted Relay set was accepted")
	}
	if _, err := RelaySetDigest([]string{"https://relay-a.example", "https://relay-a.example"}); err == nil {
		t.Fatal("a duplicated Relay was accepted")
	}
	if _, err := RelaySetDigest(make([]string, MaxCandidateRelays+1)); err == nil {
		t.Fatal("an oversized Relay set was accepted")
	}
}

// Until offline delivery exists no endpoint has Relays, so a descriptor
// without a Relay set is ordinary rather than incomplete.
func TestDescriptorWithoutRelaysIsValid(t *testing.T) {
	key := endpointKey(t, 0x11)
	delegation := testDelegation(t, key)
	descriptor := testDescriptor(t, delegation)
	descriptor.MailboxRelaySetDigest = ""
	signed, err := SignDescriptor(descriptor, key)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	if err := Bind(delegation, signed, testPolicy(), time.Unix(int64(baseUnix)+60, 0)); err != nil {
		t.Fatalf("a descriptor with no Relays was refused: %v", err)
	}
}
