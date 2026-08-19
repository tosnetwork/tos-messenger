package admission

import (
	"bytes"
	"crypto/ed25519"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/tosnetwork/tos-messenger/pkg/envelope"
	"github.com/tosnetwork/tos-messenger/pkg/eventlog"
	"github.com/tosnetwork/tos-messenger/pkg/fault"
	"github.com/tosnetwork/tos-messenger/pkg/identity"
	nativev1 "github.com/tosnetwork/tos-service-protocol/gen/tos/service/v1"
)

const (
	baseUnix = uint64(1_800_000_000)
	senderID = "agent_" + "2222222222222222222222222222222222222222222222222222222222222222"
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
		AllowedEventClasses:           []string{"text"},
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
		Content:          []byte("hello"),
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
		Journal:     journal,
		Policy:      policy,
		InstallSalt: bytes.Repeat([]byte{0x5a}, MinInstallSaltBytes),
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
		MaxContentBytes: 16,
		InstallSalt:     bytes.Repeat([]byte{0x5a}, MinInstallSaltBytes),
	})
	if err != nil {
		t.Fatalf("gate: %v", err)
	}
	event := testEvent(t, delegation, func(e *envelope.Event) {
		e.Content = bytes.Repeat([]byte{1}, 32)
	})
	decision, err := gate.Admit(inbound(event, encoded))
	if err != nil {
		t.Fatalf("admit: %v", err)
	}
	if decision.Code != fault.CodeContentTooLarge {
		t.Fatalf("expected the published bound to apply, got %q", decision.Code)
	}
	small := testEvent(t, delegation, func(e *envelope.Event) {
		e.Content = bytes.Repeat([]byte{1}, 16)
	})
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
		Policy: OpenInbox{}, InstallSalt: bytes.Repeat([]byte{1}, MinInstallSaltBytes),
	}
	cases := map[string]func(*Config){
		"no network":  func(c *Config) { c.Network = nil },
		"bad network": func(c *Config) { c.Network = &nativev1.NetworkDomain{NetworkId: "x"} },
		"no resolver": func(c *Config) { c.Resolver = nil },
		"no journal":  func(c *Config) { c.Journal = nil },
		"no policy":   func(c *Config) { c.Policy = nil },
		"no salt":     func(c *Config) { c.InstallSalt = nil },
		"short salt":  func(c *Config) { c.InstallSalt = bytes.Repeat([]byte{1}, MinInstallSaltBytes-1) },
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
