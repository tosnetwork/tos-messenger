package admission

import (
	"bytes"
	"crypto/ed25519"
	"errors"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/tosnetwork/tos-messenger/pkg/envelope"
	"github.com/tosnetwork/tos-messenger/pkg/eventlog"
	"github.com/tosnetwork/tos-messenger/pkg/fault"
	"github.com/tosnetwork/tos-messenger/pkg/identity"
	"github.com/tosnetwork/tos-messenger/pkg/payload"
	nativev1 "github.com/tosnetwork/tos-service-protocol/gen/tos/service/v1"
)

const (
	baseUnix = uint64(1_800_000_000)
	senderID = "agent_" + "2222222222222222222222222222222222222222222222222222222222222222"
	localID  = "agent_" + "7777777777777777777777777777777777777777777777777777777777777777"
	deviceID = "dev_" + "4444444444444444444444444444444444444444444444444444444444444444"
	convoID  = "conv_" + "1111111111111111111111111111111111111111111111111111111111111111"
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

func testDelegation(t *testing.T) (identity.Delegation, []byte) {
	t.Helper()
	key := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x11}, ed25519.SeedSize))
	public, ok := key.Public().(ed25519.PublicKey)
	if !ok {
		t.Fatal("unexpected public key type")
	}
	network := testNetwork()
	endpointID, err := identity.DeriveEndpointID(network, senderID, public)
	if err != nil {
		t.Fatalf("derive endpoint: %v", err)
	}
	delegation := identity.Delegation{
		Network:                       network,
		AgentID:                       senderID,
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
	encoded, err := identity.EncodeJSON(delegation)
	if err != nil {
		t.Fatalf("encode delegation: %v", err)
	}
	return delegation, encoded
}

// textBody is a real typed body. A test that sent arbitrary bytes would be
// testing a path the gate no longer has.
func textBody(t *testing.T, body string) []byte {
	t.Helper()
	encoded, err := payload.Encode(payload.Text{MediaType: "text/plain; charset=utf-8", Body: body})
	if err != nil {
		t.Fatalf("encode payload: %v", err)
	}
	return encoded
}

func testEvent(t *testing.T, delegation identity.Delegation, mutate func(*envelope.Event)) envelope.Event {
	t.Helper()
	event := envelope.Event{
		Network:          delegation.Network,
		ConversationID:   convoID,
		SenderAgentID:    delegation.AgentID,
		SenderEndpointID: delegation.EndpointID,
		SenderDeviceID:   deviceID,
		CreatedAtUnix:    baseUnix + 10,
		Kind:             "text",
		Content:          textBody(t, "hello"),
	}
	if mutate != nil {
		mutate(&event)
	}
	completed, err := envelope.NewEvent(event)
	if err != nil {
		t.Fatalf("new event: %v", err)
	}
	return completed
}

// testLocalDelegation is the recipient's own delegation: the one that says
// which inbox policy this endpoint publishes.
func testLocalDelegation(t *testing.T, policy ContactPolicy) identity.Delegation {
	t.Helper()
	key := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x77}, ed25519.SeedSize))
	public, ok := key.Public().(ed25519.PublicKey)
	if !ok {
		t.Fatal("unexpected public key type")
	}
	network := testNetwork()
	endpointID, err := identity.DeriveEndpointID(network, localID, public)
	if err != nil {
		t.Fatalf("derive endpoint: %v", err)
	}
	return identity.Delegation{
		Network:                       network,
		AgentID:                       localID,
		EndpointID:                    endpointID,
		IdentityPublicKey:             public,
		AllowedProtocolVersions:       []uint32{1},
		AllowedOutboundEventClasses:   []string{"text"},
		NotBeforeUnix:                 baseUnix,
		ExpiresAtUnix:                 baseUnix + 86_400,
		MaximumSessionLifetimeSeconds: 3600,
		ContactDescriptorPolicyDigest: "sha256:" + strings.Repeat("3d", 32),
		InboxAdmissionPolicyDigest:    policy.Digest(),
	}
}

func testGate(t *testing.T, policy ContactPolicy) (*Gate, *eventlog.Journal, identity.Delegation, []byte) {
	t.Helper()
	delegation, encoded := testDelegation(t)
	digest, err := identity.Digest(delegation)
	if err != nil {
		t.Fatalf("digest: %v", err)
	}
	journal, err := eventlog.Open(filepath.Join(t.TempDir(), "state"))
	if err != nil {
		t.Fatalf("journal: %v", err)
	}
	t.Cleanup(func() { _ = journal.Close() })

	gate, err := New(Config{
		Network: testNetwork(),
		Chain:   testChain(),
		Resolver: stubResolver{states: map[string]*nativev1.NativeStateV1{
			senderID: nativeState(&nativev1.AgentStateV1{
				AgentId:           senderID,
				Policy:            &nativev1.ControllerPolicyV1{Threshold: 1},
				DelegationDigests: []string{digest},
			}),
		}},
		Journal:         journal,
		Policy:          policy,
		LocalDelegation: testLocalDelegation(t, policy),
		InstallSalt:     bytes.Repeat([]byte{0x5a}, MinInstallSaltBytes),
	})
	if err != nil {
		t.Fatalf("gate: %v", err)
	}
	return gate, journal, delegation, encoded
}

func inbound(event envelope.Event, delegationJSON []byte) Inbound {
	return Inbound{
		Event:          event,
		DelegationJSON: delegationJSON,
		Route:          RouteRelay,
		ReceivedAtUnix: baseUnix + 60,
	}
}

func TestDelegatedEventIsAdmittedOnce(t *testing.T) {
	gate, _, delegation, encoded := testGate(t, OpenInbox{})
	event := testEvent(t, delegation, nil)

	decision, err := gate.Admit(inbound(event, encoded))
	if err != nil {
		t.Fatalf("admit: %v", err)
	}
	if decision.Outcome != Accepted {
		t.Fatalf("expected acceptance, got %q (%s)", decision.Outcome, decision.Code)
	}
	if decision.Event.EventID != event.EventID || decision.Delegation.EndpointID != delegation.EndpointID {
		t.Fatal("the decision returned a different event or delegation")
	}
	if decision.Record.Outcome != Accepted || decision.Record.Class != "text" ||
		decision.Record.Route != RouteRelay || decision.Record.EventID != event.EventID {
		t.Fatalf("unexpected record: %+v", decision.Record)
	}

	// A retry over any route is a successful at-least-once delivery, not a
	// failure, and the runtime must not be told twice.
	repeat, err := gate.Admit(inbound(event, encoded))
	if err != nil {
		t.Fatalf("admit: %v", err)
	}
	if repeat.Outcome != Duplicate {
		t.Fatalf("expected a duplicate, got %q", repeat.Outcome)
	}
	if repeat.Code != "" || repeat.Response.Code != "" {
		t.Fatalf("a duplicate was reported as a failure: %+v", repeat)
	}
}

// The ordering that matters most: a sender told to satisfy an admission policy
// must be able to resend the same event once they have. Claiming it first
// would turn their corrected attempt into a duplicate that is never delivered.
func TestAdmissionRefusalLeavesTheRemedyUsable(t *testing.T) {
	gate, journal, delegation, encoded := testGate(t, AllowList{})
	event := testEvent(t, delegation, nil)

	decision, err := gate.Admit(inbound(event, encoded))
	if err != nil {
		t.Fatalf("admit: %v", err)
	}
	if decision.Outcome != Rejected || decision.Code != fault.CodeAdmissionRequired {
		t.Fatalf("unexpected decision: %+v", decision)
	}
	if decision.Response.Code != fault.CodeAdmissionRequired {
		t.Fatal("a sender was not told what the inbox requires")
	}
	if _, found, err := journal.Lookup(event.EventID); err != nil || found {
		t.Fatalf("a refused event was written down: found=%v err=%v", found, err)
	}

	// The sender satisfies the policy and resends the identical event.
	admitted, _, _, _ := testGate(t, AllowList{Known: map[string]struct{}{senderID: {}}})
	second, err := admitted.Admit(inbound(event, encoded))
	if err != nil {
		t.Fatalf("admit: %v", err)
	}
	if second.Outcome != Accepted {
		t.Fatalf("the corrected resend was not delivered: %+v", second)
	}
}

// An owner is asked once. A resend finds the claim and is acknowledged rather
// than raising the same question again.
func TestHeldEventAsksTheOwnerOnce(t *testing.T) {
	gate, journal, delegation, encoded := testGate(t, AllowList{HoldUnknown: true})
	event := testEvent(t, delegation, nil)

	decision, err := gate.Admit(inbound(event, encoded))
	if err != nil {
		t.Fatalf("admit: %v", err)
	}
	if decision.Outcome != Held || decision.Code != fault.CodeApprovalRequired {
		t.Fatalf("unexpected decision: %+v", decision)
	}
	if decision.Response.Code != fault.CodeRejected {
		t.Fatalf("a hold was disclosed to the sender as %q", decision.Response.Code)
	}
	if _, found, err := journal.Lookup(event.EventID); err != nil || !found {
		t.Fatalf("a held event was not claimed: found=%v err=%v", found, err)
	}
	repeat, err := gate.Admit(inbound(event, encoded))
	if err != nil {
		t.Fatalf("admit: %v", err)
	}
	if repeat.Outcome != Duplicate {
		t.Fatalf("a resend asked the owner again: %+v", repeat)
	}
}

func TestDeniedSenderLearnsNothing(t *testing.T) {
	gate, journal, delegation, encoded := testGate(t, AllowList{
		Blocked: map[string]struct{}{senderID: {}},
	})
	event := testEvent(t, delegation, nil)

	decision, err := gate.Admit(inbound(event, encoded))
	if err != nil {
		t.Fatalf("admit: %v", err)
	}
	if decision.Outcome != Rejected {
		t.Fatalf("a blocked sender was admitted: %+v", decision)
	}
	if decision.Response.Code != fault.CodeRejected {
		t.Fatalf("being blocked was disclosed as %q", decision.Response.Code)
	}
	if _, found, err := journal.Lookup(event.EventID); err != nil || found {
		t.Fatalf("a blocked sender filled the journal: found=%v", found)
	}
}

func TestRejectionsAreClassified(t *testing.T) {
	_, _, delegation, encoded := testGate(t, OpenInbox{})

	cases := map[string]struct {
		event    func(*testing.T) envelope.Event
		received uint64
		expected fault.Code
	}{
		"another network": {
			event: func(t *testing.T) envelope.Event {
				return testEvent(t, delegation, func(e *envelope.Event) {
					e.Network = &nativev1.NetworkDomain{NetworkId: "tos-other",
						GenesisRootHash: strings.Repeat("a", 64), GenesisFileHash: strings.Repeat("b", 64)}
				})
			},
			received: baseUnix + 60,
			expected: fault.CodeNetworkMismatch,
		},
		"expired event": {
			event: func(t *testing.T) envelope.Event {
				return testEvent(t, delegation, func(e *envelope.Event) { e.ExpiresAtUnix = baseUnix + 20 })
			},
			received: baseUnix + 60,
			expected: fault.CodeEventOutsideWindow,
		},
		"dated far ahead": {
			event: func(t *testing.T) envelope.Event {
				return testEvent(t, delegation, func(e *envelope.Event) { e.CreatedAtUnix = baseUnix + 100_000 })
			},
			received: baseUnix + 60,
			expected: fault.CodeEventOutsideWindow,
		},
		"undelegated class": {
			event: func(t *testing.T) envelope.Event {
				return testEvent(t, delegation, func(e *envelope.Event) {
					e.Kind = "counterparty.approval.granted"
					e.PayloadSchema = ""
				})
			},
			received: baseUnix + 60,
			expected: fault.CodeClassNotDelegated,
		},
		"another sender": {
			event: func(t *testing.T) envelope.Event {
				return testEvent(t, delegation, func(e *envelope.Event) {
					e.SenderAgentID = "agent_" + strings.Repeat("9", 64)
				})
			},
			received: baseUnix + 60,
			expected: fault.CodeSenderMismatch,
		},
		"expired delegation": {
			event:    func(t *testing.T) envelope.Event { return testEvent(t, delegation, nil) },
			received: delegation.ExpiresAtUnix + 1,
			expected: fault.CodeDelegationExpired,
		},
	}
	for name, testCase := range cases {
		t.Run(name, func(t *testing.T) {
			gate, journal, _, _ := testGate(t, OpenInbox{})
			event := testCase.event(t)
			request := inbound(event, encoded)
			request.ReceivedAtUnix = testCase.received
			decision, err := gate.Admit(request)
			if err != nil {
				t.Fatalf("admit: %v", err)
			}
			if decision.Outcome != Rejected {
				t.Fatalf("expected a refusal, got %q", decision.Outcome)
			}
			if decision.Code != testCase.expected {
				t.Fatalf("expected %q, got %q", testCase.expected, decision.Code)
			}
			if _, found, err := journal.Lookup(event.EventID); err != nil || found {
				t.Fatalf("a refused event was written down: found=%v", found)
			}
		})
	}
}

// A recipient may publish a smaller bound than the protocol allows, and it is
// the published one that applies. An event above the protocol maximum cannot
// be constructed at all, so this is the only case the check can see.
func TestContentAboveThePublishedBoundIsRefused(t *testing.T) {
	atBound := textBody(t, "hi")
	overBound := textBody(t, strings.Repeat("x", 64))
	if len(overBound) <= len(atBound) {
		t.Fatal("the oversized body is not larger than the bound")
	}
	delegation, encoded := testDelegation(t)
	digest, err := identity.Digest(delegation)
	if err != nil {
		t.Fatalf("digest: %v", err)
	}
	journal, err := eventlog.Open(filepath.Join(t.TempDir(), "state"))
	if err != nil {
		t.Fatalf("journal: %v", err)
	}
	defer journal.Close()
	gate, err := New(Config{
		Network: testNetwork(),
		Chain:   testChain(),
		Resolver: stubResolver{states: map[string]*nativev1.NativeStateV1{
			senderID: nativeState(&nativev1.AgentStateV1{AgentId: senderID,
				Policy: &nativev1.ControllerPolicyV1{Threshold: 1}, DelegationDigests: []string{digest}}),
		}},
		Journal:         journal,
		Policy:          OpenInbox{},
		LocalDelegation: testLocalDelegation(t, OpenInbox{}),
		MaxContentBytes: len(atBound),
		InstallSalt:     bytes.Repeat([]byte{0x5a}, MinInstallSaltBytes),
	})
	if err != nil {
		t.Fatalf("gate: %v", err)
	}
	event := testEvent(t, delegation, func(e *envelope.Event) { e.Content = overBound })
	decision, err := gate.Admit(inbound(event, encoded))
	if err != nil {
		t.Fatalf("admit: %v", err)
	}
	if decision.Code != fault.CodeContentTooLarge {
		t.Fatalf("expected the published bound to apply, got %q", decision.Code)
	}
	small := testEvent(t, delegation, func(e *envelope.Event) { e.Content = atBound })
	if decision, err := gate.Admit(inbound(small, encoded)); err != nil {
		t.Fatalf("admit: %v", err)
	} else if decision.Outcome != Accepted {
		t.Fatalf("content at the bound was refused: %+v", decision)
	}
}

func TestUncommittedDelegationIsRefused(t *testing.T) {
	gate, _, delegation, _ := testGate(t, OpenInbox{})
	// A delegation the finalized Agent does not commit, presented in place of
	// the real one.
	forged := delegation
	forged.MaximumSessionLifetimeSeconds = 1800
	encoded, err := identity.EncodeJSON(forged)
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	decision, err := gate.Admit(inbound(testEvent(t, delegation, nil), encoded))
	if err != nil {
		t.Fatalf("admit: %v", err)
	}
	if decision.Code != fault.CodeDelegationUncommitted {
		t.Fatalf("expected an uncommitted delegation, got %q", decision.Code)
	}

	if decision, err := gate.Admit(inbound(testEvent(t, delegation, nil), []byte("{"))); err != nil {
		t.Fatalf("admit: %v", err)
	} else if decision.Code != fault.CodeDelegationUncommitted {
		t.Fatalf("a malformed delegation produced %q", decision.Code)
	}
}

// A content-addressed identifier cannot legitimately arrive bound to a
// different sender, so this branch is defence in depth. It is still reachable
// by anything that can write the journal, and it stays hidden from the peer.
func TestConflictingClaimIsHidden(t *testing.T) {
	gate, journal, delegation, encoded := testGate(t, OpenInbox{})
	event := testEvent(t, delegation, nil)

	if _, _, err := journal.Accept(eventlog.Entry{
		EventID:          event.EventID,
		SenderEndpointID: "mep_" + strings.Repeat("9", 64),
		ConversationID:   convoID,
		Payload:          []byte("seeded by another sender"),
		Admission:        eventlog.AdmissionAdmitted,
		ReceivedAtUnix:   baseUnix,
	}); err != nil {
		t.Fatalf("seed: %v", err)
	}
	decision, err := gate.Admit(inbound(event, encoded))
	if err != nil {
		t.Fatalf("admit: %v", err)
	}
	if decision.Outcome != Rejected || decision.Code != fault.CodeReplayed {
		t.Fatalf("unexpected decision: %+v", decision)
	}
	if decision.Response.Code != fault.CodeRejected {
		t.Fatalf("a replay outcome leaked as %q", decision.Response.Code)
	}
}

func TestRecordCarriesNoGraph(t *testing.T) {
	gate, _, delegation, encoded := testGate(t, OpenInbox{})
	event := testEvent(t, delegation, nil)
	decision, err := gate.Admit(inbound(event, encoded))
	if err != nil {
		t.Fatalf("admit: %v", err)
	}
	encodedRecord, err := EncodeRecordJSON(decision.Record)
	if err != nil {
		t.Fatalf("encode record: %v", err)
	}
	for _, leaked := range []string{senderID, delegation.EndpointID, convoID, "hello", deviceID} {
		if strings.Contains(string(encodedRecord), leaked) {
			t.Fatalf("the decision record leaks %q: %s", leaked, encodedRecord)
		}
	}
	if !strings.Contains(string(encodedRecord), decision.Record.SenderRef) {
		t.Fatal("the record carries no sender reference at all")
	}

	// The same sender on another install must not be recognisable across logs.
	other, _, _, _ := testGate(t, OpenInbox{})
	other.config.InstallSalt = bytes.Repeat([]byte{0x7b}, MinInstallSaltBytes)
	elsewhere, err := other.Admit(inbound(testEvent(t, delegation, nil), encoded))
	if err != nil {
		t.Fatalf("admit: %v", err)
	}
	if elsewhere.Record.SenderRef == decision.Record.SenderRef {
		t.Fatal("sender references correlate across installs")
	}
}

func TestGateRequiresEveryDependency(t *testing.T) {
	_, _, delegation, _ := testGate(t, OpenInbox{})
	digest, err := identity.Digest(delegation)
	if err != nil {
		t.Fatalf("digest: %v", err)
	}
	journal, err := eventlog.Open(filepath.Join(t.TempDir(), "state"))
	if err != nil {
		t.Fatalf("journal: %v", err)
	}
	defer journal.Close()
	resolver := stubResolver{states: map[string]*nativev1.NativeStateV1{
		senderID: nativeState(&nativev1.AgentStateV1{AgentId: senderID,
			Policy: &nativev1.ControllerPolicyV1{Threshold: 1}, DelegationDigests: []string{digest}}),
	}}
	complete := Config{
		Network: testNetwork(), Chain: testChain(), Resolver: resolver, Journal: journal,
		Policy: OpenInbox{}, LocalDelegation: testLocalDelegation(t, OpenInbox{}),
		InstallSalt: bytes.Repeat([]byte{1}, MinInstallSaltBytes),
	}
	cases := map[string]func(*Config){
		"no network":               func(c *Config) { c.Network = nil },
		"bad network":              func(c *Config) { c.Network = &nativev1.NetworkDomain{NetworkId: "x"} },
		"no resolver":              func(c *Config) { c.Resolver = nil },
		"no journal":               func(c *Config) { c.Journal = nil },
		"no policy":                func(c *Config) { c.Policy = nil },
		"no salt":                  func(c *Config) { c.InstallSalt = nil },
		"short salt":               func(c *Config) { c.InstallSalt = bytes.Repeat([]byte{1}, MinInstallSaltBytes-1) },
		"no delegation of its own": func(c *Config) { c.LocalDelegation = identity.Delegation{} },
		// The published digest and the policy actually in memory disagree.
		"policy this endpoint never published": func(c *Config) { c.Policy = AllowList{HoldUnknown: true} },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			config := complete
			mutate(&config)
			if _, err := New(config); err == nil {
				t.Fatalf("expected %q to be refused", name)
			}
		})
	}
	if _, err := New(complete); err != nil {
		t.Fatalf("expected a complete configuration to be accepted: %v", err)
	}
}

func TestAdmitRejectsUnusableInput(t *testing.T) {
	gate, _, delegation, encoded := testGate(t, OpenInbox{})
	event := testEvent(t, delegation, nil)

	noRoute := inbound(event, encoded)
	noRoute.Route = "carrier-pigeon"
	if _, err := gate.Admit(noRoute); err == nil {
		t.Fatal("an unknown route was accepted")
	}
	noTime := inbound(event, encoded)
	noTime.ReceivedAtUnix = 0
	if _, err := gate.Admit(noTime); err == nil {
		t.Fatal("a missing arrival time was accepted")
	}

	// A gate that trusted its caller's validation would be one bypass away
	// from admitting anything.
	forged := inbound(event, encoded)
	forged.Event.Content = []byte("substituted after validation")
	decision, err := gate.Admit(forged)
	if err != nil {
		t.Fatalf("admit: %v", err)
	}
	if decision.Outcome != Rejected {
		t.Fatal("an event whose identifier no longer matches its content was admitted")
	}

	var absent *Gate
	if _, err := absent.Admit(inbound(event, encoded)); err == nil {
		t.Fatal("a nil gate admitted an event")
	}
}

func TestUnknownEventKindIsRefused(t *testing.T) {
	gate, _, delegation, encoded := testGate(t, OpenInbox{})
	event := testEvent(t, delegation, func(e *envelope.Event) {
		e.Kind = "vendor.custom"
		e.PayloadSchema = "tos.messaging.payload.vendor-custom.v1"
	})
	decision, err := gate.Admit(inbound(event, encoded))
	if err != nil {
		t.Fatalf("admit: %v", err)
	}
	if decision.Code != fault.CodeUnknownEventKind {
		t.Fatalf("expected an unrecognised kind, got %q", decision.Code)
	}
}

func TestPolicySeesOnlySenderAndKind(t *testing.T) {
	var sawSender, sawKind string
	gate, _, delegation, encoded := testGate(t, policyFunc(func(sender, kind string) Admission {
		sawSender, sawKind = sender, kind
		return AdmitAllow
	}))
	event := testEvent(t, delegation, nil)
	if _, err := gate.Admit(inbound(event, encoded)); err != nil {
		t.Fatalf("admit: %v", err)
	}
	if sawSender != senderID || sawKind != "text" {
		t.Fatalf("policy saw %q/%q", sawSender, sawKind)
	}
}

type policyFunc func(string, string) Admission

func (p policyFunc) Admits(sender, kind string) Admission { return p(sender, kind) }

func (p policyFunc) Digest() string { return policyDigest("test-policy") }

// Acceptance means durably queued, not delivered. The event has to be
// recoverable from the journal alone, because the process that admitted it may
// not survive to hand it over.
func TestAcceptedEventIsRecoverableWithoutTheDecision(t *testing.T) {
	gate, journal, delegation, encoded := testGate(t, OpenInbox{})
	event := testEvent(t, delegation, nil)

	if _, err := gate.Admit(inbound(event, encoded)); err != nil {
		t.Fatalf("admit: %v", err)
	}
	pending, err := journal.ListPending(timeAt(baseUnix+61), 0)
	if err != nil {
		t.Fatalf("pending: %v", err)
	}
	if len(pending) != 1 || pending[0].EventID != event.EventID {
		t.Fatalf("the admitted event was not queued: %+v", pending)
	}
	payload, err := pending[0].Payload()
	if err != nil {
		t.Fatalf("payload: %v", err)
	}
	recovered, err := envelope.DecodeEventJSON(payload)
	if err != nil {
		t.Fatalf("decode recovered event: %v", err)
	}
	if recovered.EventID != event.EventID || string(recovered.Content) != string(event.Content) {
		t.Fatal("the recovered event is not the admitted one")
	}
}

func timeAt(seconds uint64) time.Time { return time.Unix(int64(seconds), 0) }

// An owner approval is this owner authorising something here. It is not a
// message a remote party may send, over any route, however well signed.
func TestOwnerApprovalFromTheNetworkIsRefused(t *testing.T) {
	gate, journal, delegation, encoded := testGate(t, OpenInbox{})
	for _, route := range []Route{RouteDirect, RouteTunnel, RouteRelay, RouteHTTPS} {
		t.Run(string(route), func(t *testing.T) {
			event := testEvent(t, delegation, func(e *envelope.Event) {
				e.Kind = "owner.approval.grant"
				e.PayloadSchema = ""
			})
			request := inbound(event, encoded)
			request.Route = route
			decision, err := gate.Admit(request)
			if err != nil {
				t.Fatalf("admit: %v", err)
			}
			if decision.Outcome != Rejected {
				t.Fatalf("a remote owner approval was admitted over %s", route)
			}
			if _, found, err := journal.Lookup(event.EventID); err != nil || found {
				t.Fatal("a remote owner approval was written down")
			}
		})
	}
}

// An event held for the owner must not reach the runtime's queue. Recording
// the hold only in the return value left it queued, and a runtime draining its
// inbox would have taken it before the owner saw the question.
func TestHeldEventDoesNotReachTheRuntimeQueue(t *testing.T) {
	gate, journal, delegation, encoded := testGate(t, AllowList{HoldUnknown: true})
	event := testEvent(t, delegation, nil)

	decision, err := gate.Admit(inbound(event, encoded))
	if err != nil {
		t.Fatalf("admit: %v", err)
	}
	if decision.Outcome != Held {
		t.Fatalf("unexpected outcome: %+v", decision)
	}

	pending, err := journal.ListPending(timeAt(baseUnix+61), 0)
	if err != nil {
		t.Fatalf("pending: %v", err)
	}
	if len(pending) != 0 {
		t.Fatalf("a held event was offered to the runtime: %+v", pending)
	}
	waiting, err := journal.ListAwaitingAdmission(0)
	if err != nil {
		t.Fatalf("awaiting: %v", err)
	}
	if len(waiting) != 1 || waiting[0].EventID != event.EventID {
		t.Fatalf("the held event is not waiting for the owner: %+v", waiting)
	}
	// Nor can a runtime take it by claiming it directly.
	if _, err := journal.ClaimForApplication(event.EventID,
		"lease_"+strings.Repeat("1", 64), timeAt(baseUnix+61), time.Minute); !errors.Is(err, eventlog.ErrNotAdmitted) {
		t.Fatalf("a held event was claimable: %v", err)
	}

	// Once the owner admits it, it becomes ordinary work.
	if _, err := journal.AdmitEvent(event.EventID, timeAt(baseUnix+62)); err != nil {
		t.Fatalf("admit event: %v", err)
	}
	pending, err = journal.ListPending(timeAt(baseUnix+63), 0)
	if err != nil {
		t.Fatalf("pending: %v", err)
	}
	if len(pending) != 1 {
		t.Fatalf("an admitted event did not reach the runtime: %+v", pending)
	}
}

// A denied event is never offered, and the decision is made once.
func TestDeniedEventIsNeverOffered(t *testing.T) {
	gate, journal, delegation, encoded := testGate(t, AllowList{HoldUnknown: true})
	event := testEvent(t, delegation, nil)
	if _, err := gate.Admit(inbound(event, encoded)); err != nil {
		t.Fatalf("admit: %v", err)
	}
	if _, err := journal.DenyEvent(event.EventID, fault.CodeAdmissionRequired, timeAt(baseUnix+62)); err != nil {
		t.Fatalf("deny: %v", err)
	}
	pending, err := journal.ListPending(timeAt(baseUnix+63), 0)
	if err != nil {
		t.Fatalf("pending: %v", err)
	}
	if len(pending) != 0 {
		t.Fatalf("a denied event was offered: %+v", pending)
	}
	if _, err := journal.AdmitEvent(event.EventID, timeAt(baseUnix+64)); err == nil {
		t.Fatal("a denied event was admitted afterwards")
	}
}

// A published inbox policy digest that nothing enforces is a claim. An
// installation must not be able to advertise one policy and run another.
func TestPolicyMustBeTheOnePublished(t *testing.T) {
	published := AllowList{Known: map[string]struct{}{senderID: {}}, HoldUnknown: true}
	running := AllowList{Known: map[string]struct{}{senderID: {}}}
	if published.Digest() == running.Digest() {
		t.Fatal("two policies with different answers for an unknown sender share a digest")
	}

	journal, err := eventlog.Open(filepath.Join(t.TempDir(), "state"))
	if err != nil {
		t.Fatalf("journal: %v", err)
	}
	defer journal.Close()
	config := Config{
		Network: testNetwork(), Chain: testChain(), Journal: journal,
		Resolver:        stubResolver{states: map[string]*nativev1.NativeStateV1{}},
		Policy:          running,
		LocalDelegation: testLocalDelegation(t, published),
		InstallSalt:     bytes.Repeat([]byte{1}, MinInstallSaltBytes),
	}
	if _, err := New(config); err == nil {
		t.Fatal("a gate ran a policy its endpoint never published")
	}
	config.Policy = published
	if _, err := New(config); err != nil {
		t.Fatalf("the published policy was refused: %v", err)
	}
}

// The digest commits the rule, not the roster. Adding a contact must not force
// the endpoint to republish its descriptor, because the pattern of those
// republications would leak the roster the policy keeps private.
func TestPolicyDigestDoesNotTrackTheRoster(t *testing.T) {
	empty := AllowList{HoldUnknown: true}
	populated := AllowList{
		Known:       map[string]struct{}{senderID: {}, localID: {}},
		Blocked:     map[string]struct{}{deviceID: {}},
		HoldUnknown: true,
	}
	if empty.Digest() != populated.Digest() {
		t.Fatal("the published policy digest changed when a contact was added")
	}
	open := OpenInbox{}
	if open.Digest() == empty.Digest() {
		t.Fatal("an open inbox and an allow list publish the same digest")
	}
}

// A kind is a contract about the body, not a label on it. Bytes that do not
// meet the contract are refused, and the refusal names the reason so a correct
// implementation can tell it from a network fault.
func TestBodyMustMatchItsKind(t *testing.T) {
	gate, journal, delegation, encoded := testGate(t, OpenInbox{})
	event := testEvent(t, delegation, func(e *envelope.Event) {
		e.Content = append(textBody(t, "hello"), 0x00)
	})
	decision, err := gate.Admit(inbound(event, encoded))
	if err != nil {
		t.Fatalf("admit: %v", err)
	}
	if decision.Code != fault.CodePayloadMalformed {
		t.Fatalf("a body that is not what its kind says was admitted as %q", decision.Code)
	}
	// A refusal before the claim leaves the sender's remedy usable.
	if pending, err := journal.ListPending(time.Unix(int64(baseUnix)+120, 0), 10); err != nil {
		t.Fatalf("list: %v", err)
	} else if len(pending) != 0 {
		t.Fatalf("a malformed body was written down: %+v", pending)
	}
}

// A sender who was never admitted must not learn whether their body parsed.
// That answer is a probe the recipient would be answering for a stranger.
func TestUnadmittedSenderLearnsNothingAboutTheirBody(t *testing.T) {
	gate, _, delegation, encoded := testGate(t, AllowList{
		Blocked: map[string]struct{}{senderID: {}},
	})
	event := testEvent(t, delegation, func(e *envelope.Event) {
		e.Content = append(textBody(t, "hello"), 0x00)
	})
	decision, err := gate.Admit(inbound(event, encoded))
	if err != nil {
		t.Fatalf("admit: %v", err)
	}
	if decision.Code != fault.CodeRejected {
		t.Fatalf("a blocked sender learned %q about their body", decision.Code)
	}
}
