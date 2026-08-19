package identity

import (
	"crypto/ed25519"
	"encoding/hex"
	"strings"
	"testing"
	"time"

	"github.com/tosnetwork/tos-messenger/internal/canon"
	nativev1 "github.com/tosnetwork/tos-service-protocol/gen/tos/service/v1"
)

type stubResolver struct {
	states map[string]*nativev1.NativeStateV1
	err    error
}

func (s stubResolver) ResolveAgent(agentID string) (*nativev1.NativeStateV1, bool, error) {
	if s.err != nil {
		return nil, false, s.err
	}
	state, found := s.states[agentID]
	return state, found, nil
}

const testRegistryCode = "tvm-cell-sha256:" + "abababababababababababababababababababababababababababababababab"

func testChain() ChainPolicy {
	return ChainPolicy{RegistryCodeHashes: []string{testRegistryCode}}
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

func testKey(t *testing.T) ed25519.PublicKey {
	t.Helper()
	raw, err := hex.DecodeString(strings.Repeat("1f", 32))
	if err != nil {
		t.Fatalf("decode key: %v", err)
	}
	return ed25519.PublicKey(raw)
}

func testDelegation(t *testing.T) Delegation {
	t.Helper()
	network := testNetwork()
	agentID := "agent_" + strings.Repeat("c", 64)
	key := testKey(t)
	endpointID, err := DeriveEndpointID(network, agentID, key)
	if err != nil {
		t.Fatalf("derive endpoint: %v", err)
	}
	return Delegation{
		Network:                       network,
		AgentID:                       agentID,
		EndpointID:                    endpointID,
		IdentityPublicKey:             key,
		ADNLID:                        "adnl:" + strings.Repeat("2e", 32),
		AllowedProtocolVersions:       []uint32{1, 2},
		AllowedOutboundEventClasses:   []string{"agent.task", "text"},
		NotBeforeUnix:                 1_800_000_000,
		ExpiresAtUnix:                 1_800_086_400,
		MaximumSessionLifetimeSeconds: 3600,
		ContactDescriptorPolicyDigest: "sha256:" + strings.Repeat("3d", 32),
		InboxAdmissionPolicyDigest:    "sha256:" + strings.Repeat("4c", 32),
	}
}

func liveAgent(t *testing.T, delegation Delegation) stubResolver {
	t.Helper()
	digest, err := Digest(delegation)
	if err != nil {
		t.Fatalf("digest: %v", err)
	}
	return stubResolver{states: map[string]*nativev1.NativeStateV1{
		delegation.AgentID: nativeState(&nativev1.AgentStateV1{
			AgentId:           delegation.AgentID,
			Policy:            &nativev1.ControllerPolicyV1{Threshold: 1},
			DelegationDigests: []string{"sha256:" + strings.Repeat("9", 64), digest},
		}),
	}}
}

func TestRoundTripPreservesDigest(t *testing.T) {
	delegation := testDelegation(t)
	encoded, err := EncodeJSON(delegation)
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	decoded, err := DecodeJSON(encoded)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	first, err := Digest(delegation)
	if err != nil {
		t.Fatalf("digest: %v", err)
	}
	second, err := Digest(decoded)
	if err != nil {
		t.Fatalf("digest: %v", err)
	}
	if first != second {
		t.Fatalf("digest changed across transport: %s != %s", first, second)
	}
	if !canon.DigestPattern.MatchString(first) {
		t.Fatalf("unexpected digest shape: %s", first)
	}
}

func TestDigestIsStable(t *testing.T) {
	// A fixed vector. A change here is a wire-format change and must be a
	// deliberate decision, not an accident of refactoring.
	const expected = "sha256:bee29335371a5eb8940a07494c8839b407cbffb55689118938d01688eb208f17"
	digest, err := Digest(testDelegation(t))
	if err != nil {
		t.Fatalf("digest: %v", err)
	}
	if digest != expected {
		t.Fatalf("canonical digest changed: got %s want %s", digest, expected)
	}
}

func TestEveryFieldChangesTheDigest(t *testing.T) {
	base := testDelegation(t)
	baseDigest, err := Digest(base)
	if err != nil {
		t.Fatalf("digest: %v", err)
	}
	otherKey := make(ed25519.PublicKey, ed25519.PublicKeySize)
	otherKey[0] = 0x2f
	mutations := map[string]func(*Delegation){
		"network id":       func(d *Delegation) { d.Network.NetworkId = "tos-other" },
		"genesis root":     func(d *Delegation) { d.Network.GenesisRootHash = strings.Repeat("c", 64) },
		"genesis file":     func(d *Delegation) { d.Network.GenesisFileHash = strings.Repeat("d", 64) },
		"adnl id":          func(d *Delegation) { d.ADNLID = "adnl:" + strings.Repeat("3e", 32) },
		"protocol version": func(d *Delegation) { d.AllowedProtocolVersions = []uint32{1, 3} },
		"event class":      func(d *Delegation) { d.AllowedOutboundEventClasses = []string{"approval", "text"} },
		"not before":       func(d *Delegation) { d.NotBeforeUnix = base.NotBeforeUnix + 1 },
		"expires at":       func(d *Delegation) { d.ExpiresAtUnix = base.ExpiresAtUnix + 1 },
		"session lifetime": func(d *Delegation) { d.MaximumSessionLifetimeSeconds = 7200 },
		"descriptor policy": func(d *Delegation) {
			d.ContactDescriptorPolicyDigest = "sha256:" + strings.Repeat("5b", 32)
		},
		"mailbox policy": func(d *Delegation) { d.InboxAdmissionPolicyDigest = "sha256:" + strings.Repeat("6a", 32) },
	}
	for name, mutate := range mutations {
		t.Run(name, func(t *testing.T) {
			mutated := testDelegation(t)
			mutate(&mutated)
			// A network mutation invalidates the derived endpoint identifier
			// by design, so re-derive it before asking about the digest.
			endpointID, err := DeriveEndpointID(mutated.Network, mutated.AgentID, mutated.IdentityPublicKey)
			if err != nil {
				t.Fatalf("derive: %v", err)
			}
			mutated.EndpointID = endpointID
			digest, err := Digest(mutated)
			if err != nil {
				t.Fatalf("digest: %v", err)
			}
			if digest == baseDigest {
				t.Fatalf("mutation %q did not change the digest", name)
			}
		})
	}
}

func TestEndpointIDMustBindItsKey(t *testing.T) {
	delegation := testDelegation(t)
	delegation.EndpointID = "mep_" + strings.Repeat("0", 64)
	if err := Validate(delegation); err == nil {
		t.Fatal("expected an endpoint identifier that does not bind its key to be rejected")
	}

	other := testDelegation(t)
	other.IdentityPublicKey = testKey(t)
	other.IdentityPublicKey[0] ^= 0xff
	if err := Validate(other); err == nil {
		t.Fatal("expected a substituted key to be rejected")
	}
}

func TestEndpointIDBindsNetworkAndAgent(t *testing.T) {
	network := testNetwork()
	key := testKey(t)
	first, err := DeriveEndpointID(network, "agent_"+strings.Repeat("c", 64), key)
	if err != nil {
		t.Fatalf("derive: %v", err)
	}
	second, err := DeriveEndpointID(network, "agent_"+strings.Repeat("d", 64), key)
	if err != nil {
		t.Fatalf("derive: %v", err)
	}
	other := testNetwork()
	other.NetworkId = "tos-other"
	third, err := DeriveEndpointID(other, "agent_"+strings.Repeat("c", 64), key)
	if err != nil {
		t.Fatalf("derive: %v", err)
	}
	if first == second || first == third || second == third {
		t.Fatal("endpoint identifier does not separate Agent and network")
	}
}

func TestDecodeRejectsMalformedTransport(t *testing.T) {
	valid, err := EncodeJSON(testDelegation(t))
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	cases := map[string][]byte{
		"unknown field":  []byte(string(valid[:len(valid)-1]) + `,"extra":1}`),
		"trailing json":  append(append([]byte{}, valid...), []byte(`{}`)...),
		"empty":          []byte(""),
		"wrong schema":   []byte(strings.Replace(string(valid), Schema, "tos.messaging.endpoint-delegation.v2", 1)),
		"short key":      []byte(strings.Replace(string(valid), hex.EncodeToString(testKey(t)), "00", 1)),
		"not an object":  []byte(`[]`),
		"null":           []byte(`null`),
		"truncated json": valid[:len(valid)/2],
	}
	for name, raw := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := DecodeJSON(raw); err == nil {
				t.Fatalf("expected %q to be rejected", name)
			}
		})
	}
}

func TestValidateRejectsBoundaryViolations(t *testing.T) {
	cases := map[string]func(*Delegation){
		"zero key":              func(d *Delegation) { d.IdentityPublicKey = make(ed25519.PublicKey, ed25519.PublicKeySize) },
		"nil network":           func(d *Delegation) { d.Network = nil },
		"empty network id":      func(d *Delegation) { d.Network.NetworkId = "" },
		"bad genesis root":      func(d *Delegation) { d.Network.GenesisRootHash = "zz" },
		"bad agent id":          func(d *Delegation) { d.AgentID = "agent_nothex" },
		"zero adnl id":          func(d *Delegation) { d.ADNLID = "adnl:" + strings.Repeat("0", 64) },
		"bad adnl id":           func(d *Delegation) { d.ADNLID = "adnl:zz" },
		"no versions":           func(d *Delegation) { d.AllowedProtocolVersions = nil },
		"zero version":          func(d *Delegation) { d.AllowedProtocolVersions = []uint32{0} },
		"unsorted versions":     func(d *Delegation) { d.AllowedProtocolVersions = []uint32{2, 1} },
		"duplicate versions":    func(d *Delegation) { d.AllowedProtocolVersions = []uint32{1, 1} },
		"too many versions":     func(d *Delegation) { d.AllowedProtocolVersions = manyVersions(MaxProtocolVersions + 1) },
		"no classes":            func(d *Delegation) { d.AllowedOutboundEventClasses = nil },
		"unsorted classes":      func(d *Delegation) { d.AllowedOutboundEventClasses = []string{"text", "agent.task"} },
		"duplicate classes":     func(d *Delegation) { d.AllowedOutboundEventClasses = []string{"text", "text"} },
		"bad class":             func(d *Delegation) { d.AllowedOutboundEventClasses = []string{"Text"} },
		"empty class":           func(d *Delegation) { d.AllowedOutboundEventClasses = []string{""} },
		"too many classes":      func(d *Delegation) { d.AllowedOutboundEventClasses = manyClasses(MaxEventClasses + 1) },
		"zero not before":       func(d *Delegation) { d.NotBeforeUnix = 0 },
		"inverted window":       func(d *Delegation) { d.ExpiresAtUnix = d.NotBeforeUnix - 1 },
		"empty window":          func(d *Delegation) { d.ExpiresAtUnix = d.NotBeforeUnix },
		"overlong window":       func(d *Delegation) { d.ExpiresAtUnix = d.NotBeforeUnix + MaxDelegationLifetimeSeconds + 1 },
		"short session":         func(d *Delegation) { d.MaximumSessionLifetimeSeconds = MinSessionLifetimeSeconds - 1 },
		"session over window":   func(d *Delegation) { d.MaximumSessionLifetimeSeconds = 90000 },
		"session over bound":    func(d *Delegation) { d.MaximumSessionLifetimeSeconds = MaxSessionLifetimeSeconds + 1 },
		"bad policy digest":     func(d *Delegation) { d.ContactDescriptorPolicyDigest = "sha256:zz" },
		"zero policy digest":    func(d *Delegation) { d.InboxAdmissionPolicyDigest = "sha256:" + strings.Repeat("0", 64) },
		"missing mailbox":       func(d *Delegation) { d.InboxAdmissionPolicyDigest = "" },
		"tvm digest not sha256": func(d *Delegation) { d.ContactDescriptorPolicyDigest = "tvm-cell-sha256:" + strings.Repeat("3d", 32) },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			delegation := testDelegation(t)
			mutate(&delegation)
			if err := Validate(delegation); err == nil {
				t.Fatalf("expected %q to be rejected", name)
			}
			if _, err := CanonicalBytes(delegation); err == nil {
				t.Fatalf("expected %q to produce no canonical bytes", name)
			}
			if _, err := EncodeJSON(delegation); err == nil {
				t.Fatalf("expected %q to be unencodable", name)
			}
		})
	}
}

func TestVerifyAcceptsCommittedDelegation(t *testing.T) {
	delegation := testDelegation(t)
	raw, err := EncodeJSON(delegation)
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	resolver := liveAgent(t, delegation)
	now := time.Unix(int64(delegation.NotBeforeUnix)+1, 0)
	verified, err := Verify(resolver, testNetwork(), testChain(), raw, now)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if verified.EndpointID != delegation.EndpointID {
		t.Fatalf("verified the wrong endpoint: %s", verified.EndpointID)
	}
}

func TestVerifyRejectsUnauthorizedDelegations(t *testing.T) {
	delegation := testDelegation(t)
	raw, err := EncodeJSON(delegation)
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	inside := time.Unix(int64(delegation.NotBeforeUnix)+1, 0)
	live := liveAgent(t, delegation)

	tombstoned := liveAgent(t, delegation)
	tombstoned.states[delegation.AgentID].GetAgent().Tombstoned = true

	uncommitted := liveAgent(t, delegation)
	uncommitted.states[delegation.AgentID].GetAgent().DelegationDigests = []string{"sha256:" + strings.Repeat("9", 64)}

	noPolicy := liveAgent(t, delegation)
	noPolicy.states[delegation.AgentID].GetAgent().Policy = nil

	otherNetwork := testNetwork()
	otherNetwork.NetworkId = "tos-other"

	cases := []struct {
		name     string
		resolver AgentResolver
		network  *nativev1.NetworkDomain
		now      time.Time
	}{
		{"tombstoned Agent", tombstoned, testNetwork(), inside},
		{"digest not committed", uncommitted, testNetwork(), inside},
		{"Agent without policy", noPolicy, testNetwork(), inside},
		{"unknown Agent", stubResolver{states: map[string]*nativev1.NativeStateV1{}}, testNetwork(), inside},
		{"network mismatch", live, otherNetwork, inside},
		{"before window", live, testNetwork(), time.Unix(int64(delegation.NotBeforeUnix)-1, 0)},
		{"after window", live, testNetwork(), time.Unix(int64(delegation.ExpiresAtUnix), 0)},
		{"zero clock", live, testNetwork(), time.Time{}},
		{"nil resolver", nil, testNetwork(), inside},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			if _, err := Verify(testCase.resolver, testCase.network, testChain(), raw, testCase.now); err == nil {
				t.Fatalf("expected %q to be rejected", testCase.name)
			}
		})
	}
}

func TestVerifyPropagatesResolverFailure(t *testing.T) {
	delegation := testDelegation(t)
	raw, err := EncodeJSON(delegation)
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	resolver := stubResolver{err: errChain}
	if _, err := Verify(resolver, testNetwork(), testChain(), raw, time.Unix(int64(delegation.NotBeforeUnix)+1, 0)); err == nil {
		t.Fatal("expected a finalized-read failure to be surfaced, not swallowed")
	}
}

func TestScopeChecksFailClosed(t *testing.T) {
	delegation := testDelegation(t)
	if !AllowsEventClass(delegation, "text") || !AllowsEventClass(delegation, "agent.task") {
		t.Fatal("expected delegated classes to be allowed")
	}
	for _, class := range []string{"", "approval", "TEXT", "text.", ".text", "text..reply"} {
		if AllowsEventClass(delegation, class) {
			t.Fatalf("expected class %q to be refused", class)
		}
	}
	if !AllowsProtocolVersion(delegation, 1) || !AllowsProtocolVersion(delegation, 2) {
		t.Fatal("expected delegated versions to be allowed")
	}
	if AllowsProtocolVersion(delegation, 0) || AllowsProtocolVersion(delegation, 3) {
		t.Fatal("expected undelegated versions to be refused")
	}
}

func TestCheckWindowBoundaries(t *testing.T) {
	delegation := testDelegation(t)
	if err := CheckWindow(delegation, time.Unix(int64(delegation.NotBeforeUnix), 0)); err != nil {
		t.Fatalf("not_before must be inclusive: %v", err)
	}
	if err := CheckWindow(delegation, time.Unix(int64(delegation.ExpiresAtUnix)-1, 0)); err != nil {
		t.Fatalf("last valid second rejected: %v", err)
	}
	if err := CheckWindow(delegation, time.Unix(int64(delegation.ExpiresAtUnix), 0)); err == nil {
		t.Fatal("expires_at must be exclusive")
	}
	if err := CheckWindow(delegation, time.Unix(-1, 0)); err == nil {
		t.Fatal("expected a negative clock to be rejected")
	}
}

func manyVersions(count int) []uint32 {
	versions := make([]uint32, count)
	for index := range versions {
		versions[index] = uint32(index + 1)
	}
	return versions
}

func manyClasses(count int) []string {
	classes := make([]string, count)
	for index := range classes {
		classes[index] = "c" + strings.Repeat("a", index+1)
	}
	return classes
}

var errChain = errorString("finalized read failed")

type errorString string

func (e errorString) Error() string { return string(e) }

// The resolver was asked about one Agent. If it answers about another, the
// delegation must not be authorized against that answer, however well formed
// it looks.
func TestVerifyRefusesStateForAnotherAgent(t *testing.T) {
	delegation := testDelegation(t)
	raw, err := EncodeJSON(delegation)
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	digest, err := Digest(delegation)
	if err != nil {
		t.Fatalf("digest: %v", err)
	}
	confused := stubResolver{states: map[string]*nativev1.NativeStateV1{
		delegation.AgentID: nativeState(&nativev1.AgentStateV1{
			AgentId:           "agent_" + strings.Repeat("e", 64),
			Policy:            &nativev1.ControllerPolicyV1{Threshold: 1},
			DelegationDigests: []string{digest},
		}),
	}}
	if _, err := Verify(confused, testNetwork(), testChain(), raw, time.Unix(int64(delegation.NotBeforeUnix)+1, 0)); err == nil {
		t.Fatal("a delegation was authorized against another Agent's state")
	}
}

// Every check the boundary repeats is one a correct resolver already made. The
// point is what happens when the resolver is not correct.
func TestChainStateIsReVerifiedAtTheBoundary(t *testing.T) {
	delegation := testDelegation(t)
	agent := &nativev1.AgentStateV1{
		AgentId: delegation.AgentID,
		Policy:  &nativev1.ControllerPolicyV1{Threshold: 1},
	}
	if _, err := CheckState(testChain(), testNetwork(), delegation.AgentID, nativeState(agent)); err != nil {
		t.Fatalf("a well-formed finalized state was refused: %v", err)
	}

	cases := map[string]func(*nativev1.NativeStateV1){
		"another network": func(s *nativev1.NativeStateV1) {
			s.Network = &nativev1.NetworkDomain{NetworkId: "tos-other",
				GenesisRootHash: strings.Repeat("a", 64), GenesisFileHash: strings.Repeat("b", 64)}
		},
		"no network":    func(s *nativev1.NativeStateV1) { s.Network = nil },
		"no state hash": func(s *nativev1.NativeStateV1) { s.TvmStateHash = "" },
		"no reference":  func(s *nativev1.NativeStateV1) { s.Reference = nil },
		"not finalized": func(s *nativev1.NativeStateV1) { s.Reference.FinalizedCheckpoint = 0 },
		"foreign registry": func(s *nativev1.NativeStateV1) {
			s.Reference.ContractCodeHash = "tvm-cell-sha256:" + strings.Repeat("9", 64)
		},
		"no account": func(s *nativev1.NativeStateV1) { s.Reference.Account = "" },
		"no transaction": func(s *nativev1.NativeStateV1) {
			s.Reference.TransactionHash = ""
		},
		"another Agent": func(s *nativev1.NativeStateV1) {
			s.GetAgent().AgentId = "agent_" + strings.Repeat("e", 64)
		},
		"tombstoned":   func(s *nativev1.NativeStateV1) { s.GetAgent().Tombstoned = true },
		"no policy":    func(s *nativev1.NativeStateV1) { s.GetAgent().Policy = nil },
		"not an Agent": func(s *nativev1.NativeStateV1) { s.State = nil },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			state := nativeState(&nativev1.AgentStateV1{
				AgentId: delegation.AgentID,
				Policy:  &nativev1.ControllerPolicyV1{Threshold: 1},
			})
			mutate(state)
			if _, err := CheckState(testChain(), testNetwork(), delegation.AgentID, state); err == nil {
				t.Fatalf("expected %q to be refused", name)
			}
		})
	}
	if _, err := CheckState(testChain(), testNetwork(), delegation.AgentID, nil); err == nil {
		t.Fatal("a missing state was accepted")
	}
}

// State older than a checkpoint the operator already knows about is a rollback,
// whatever it says about itself.
func TestStateOlderThanAKnownCheckpointIsRefused(t *testing.T) {
	delegation := testDelegation(t)
	policy := testChain()
	policy.MinFinalizedCheckpoint = 500
	state := nativeState(&nativev1.AgentStateV1{
		AgentId: delegation.AgentID,
		Policy:  &nativev1.ControllerPolicyV1{Threshold: 1},
	})
	if _, err := CheckState(policy, testNetwork(), delegation.AgentID, state); err == nil {
		t.Fatal("state finalized before the operator's known checkpoint was accepted")
	}
	state.Reference.FinalizedCheckpoint = 500
	if _, err := CheckState(policy, testNetwork(), delegation.AgentID, state); err != nil {
		t.Fatalf("state at the known checkpoint was refused: %v", err)
	}
}

func TestChainPolicyMustNameARegistry(t *testing.T) {
	for name, policy := range map[string]ChainPolicy{
		"empty":     {},
		"bad hash":  {RegistryCodeHashes: []string{"sha256:" + strings.Repeat("a", 64)}},
		"duplicate": {RegistryCodeHashes: []string{testRegistryCode, testRegistryCode}},
		"too many":  {RegistryCodeHashes: make([]string, MaxRegistryCodeHashes+1)},
	} {
		t.Run(name, func(t *testing.T) {
			if err := policy.Validate(); err == nil {
				t.Fatalf("expected %q to be refused", name)
			}
		})
	}
	if err := testChain().Validate(); err != nil {
		t.Fatalf("a policy naming one registry was refused: %v", err)
	}
}
