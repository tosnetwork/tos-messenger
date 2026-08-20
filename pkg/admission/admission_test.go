package admission

import (
	"bytes"
	"crypto/ed25519"
	"errors"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/tosnetwork/tos-messenger/pkg/e2ee"
	"github.com/tosnetwork/tos-messenger/pkg/envelope"
	"github.com/tosnetwork/tos-messenger/pkg/eventlog"
	"github.com/tosnetwork/tos-messenger/pkg/fault"
	"github.com/tosnetwork/tos-messenger/pkg/identity"
	"github.com/tosnetwork/tos-messenger/pkg/payload"
	"github.com/tosnetwork/tos-messenger/pkg/room"
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

// stubLocator stands in for the registry's addressing rules. The account it
// returns is the one the finalized state in these tests claims to come from,
// so the binding is exercised rather than bypassed.
var testAccount = "0:" + strings.Repeat("d", 64)

type stubLocator struct{ accounts map[string]string }

func (s stubLocator) Locate(codeHash, _ string) (string, error) {
	account, known := s.accounts[codeHash]
	if !known {
		return "", errors.New("no registry code configured")
	}
	return account, nil
}

func (s stubResolver) ResolveAgent(id string) (*nativev1.NativeStateV1, bool, error) {
	state, found := s.states[id]
	return state, found, nil
}

const testRegistryCode = "tvm-cell-sha256:" + "abababababababababababababababababababababababababababababababab"

func testChain() identity.ChainPolicy {
	return identity.ChainPolicy{
		RegistryCodeHashes: []string{testRegistryCode},
		Locator:            stubLocator{accounts: map[string]string{testRegistryCode: testAccount}},
	}
}

// A finalized native state shaped the way a correct resolver returns one.
func nativeState(agent *nativev1.AgentStateV1) *nativev1.NativeStateV1 {
	return &nativev1.NativeStateV1{
		Network:      testNetwork(),
		TvmStateHash: "tvm-cell-sha256:" + strings.Repeat("c", 64),
		Reference: &nativev1.ChainReference{
			Workchain: 0, Account: testAccount,
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
// which inbox policy this endpoint publishes. It is resolved against finalized
// state at start-up like any other, so the test resolver has to commit it.
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

// localState is the finalized Agent state that commits this endpoint's own
// delegation, so the gate can verify what it publishes rather than trust it.
func localState(t *testing.T, policy ContactPolicy) (identity.Delegation, []byte, *nativev1.NativeStateV1) {
	t.Helper()
	delegation := testLocalDelegation(t, policy)
	encoded, err := identity.EncodeJSON(delegation)
	if err != nil {
		t.Fatalf("encode local delegation: %v", err)
	}
	digest, err := identity.Digest(delegation)
	if err != nil {
		t.Fatalf("digest: %v", err)
	}
	return delegation, encoded, nativeState(&nativev1.AgentStateV1{
		AgentId:           localID,
		Policy:            &nativev1.ControllerPolicyV1{Threshold: 1},
		DelegationDigests: []string{digest},
	})
}

func testGate(t *testing.T, policy ContactPolicy) (*Gate, *eventlog.Journal, identity.Delegation, []byte) {
	t.Helper()
	return newTestGate(t, policy, nil)
}

// newTestGate builds a gate, optionally with a room-membership overlay. seed is
// nil for the common case that has nothing to do with rooms; otherwise it is
// called with a room ledger on the gate's own journal, to seed memberships
// before the gate judges against them.
func newTestGate(t *testing.T, policy ContactPolicy, seed func(*testing.T, *eventlog.RoomLedger)) (*Gate, *eventlog.Journal, identity.Delegation, []byte) {
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

	var rooms *eventlog.RoomLedger
	if seed != nil {
		rooms, err = journal.OpenRooms()
		if err != nil {
			t.Fatalf("rooms: %v", err)
		}
		seed(t, rooms)
	}

	local, localEncoded, localAgentState := localState(t, policy)
	gate, err := New(Config{
		Network: testNetwork(),
		Chain:   testChain(),
		Resolver: stubResolver{states: map[string]*nativev1.NativeStateV1{
			senderID: nativeState(&nativev1.AgentStateV1{
				AgentId:           senderID,
				Policy:            &nativev1.ControllerPolicyV1{Threshold: 1},
				DelegationDigests: []string{digest},
			}),
			localID: localAgentState,
		}},
		Journal:             journal,
		Devices:             mustDevices(t, journal),
		Rooms:               rooms,
		Policy:              policy,
		LocalDelegationJSON: localEncoded,
		LocalAgentID:        local.AgentID,
		LocalEndpointID:     local.EndpointID,
		Now:                 func() time.Time { return time.Unix(int64(baseUnix)+30, 0) },
		InstallSalt:         bytes.Repeat([]byte{0x5a}, MinInstallSaltBytes),
	})
	if err != nil {
		t.Fatalf("gate: %v", err)
	}
	return gate, journal, delegation, encoded
}

var overlayRoom = "room_" + strings.Repeat("a", 64)

func seedRoom(members ...string) func(*testing.T, *eventlog.RoomLedger) {
	return func(t *testing.T, rooms *eventlog.RoomLedger) {
		t.Helper()
		membership, err := room.Found(overlayRoom, members)
		if err != nil {
			t.Fatalf("found room: %v", err)
		}
		if _, err := rooms.Advance(membership, time.Unix(int64(baseUnix)+5, 0)); err != nil {
			t.Fatalf("advance room: %v", err)
		}
	}
}

// The room-membership overlay: an event addressed to a room whose sender this
// installation does not hold as a member is refused, and only that. An unknown
// room, or no overlay at all, is not a refusal -- the sender is judged only
// where this installation actually knows the membership.
func TestRoomMembershipOverlay(t *testing.T) {
	otherMember := "agent_" + strings.Repeat("7", 64)
	roomEvent := func(t *testing.T, delegation identity.Delegation) (envelope.Event, []byte) {
		event := testEvent(t, delegation, func(e *envelope.Event) { e.RoomID = overlayRoom })
		return event, nil
	}

	t.Run("member is admitted", func(t *testing.T) {
		gate, _, delegation, encoded := newTestGate(t, OpenInbox(), seedRoom(senderID, otherMember))
		event, _ := roomEvent(t, delegation)
		decision, err := gate.Admit(inbound(event, encoded))
		if err != nil {
			t.Fatalf("admit: %v", err)
		}
		if decision.Outcome != Accepted {
			t.Fatalf("a room member was refused: %q (%s)", decision.Outcome, decision.Code)
		}
	})

	t.Run("non-member is refused", func(t *testing.T) {
		// The room exists in the ledger but does not contain the sender.
		gate, _, delegation, encoded := newTestGate(t, OpenInbox(), seedRoom(otherMember))
		event, _ := roomEvent(t, delegation)
		decision, err := gate.Admit(inbound(event, encoded))
		if err != nil {
			t.Fatalf("admit: %v", err)
		}
		if decision.Outcome != Rejected || decision.Code != fault.CodeNotARoomMember {
			t.Fatalf("a non-member was not refused as such: %+v", decision)
		}
		if decision.Response.Code != fault.CodeNotARoomMember {
			t.Fatal("a non-member was not told why")
		}
	})

	t.Run("unknown room is admitted", func(t *testing.T) {
		// A room ledger exists but holds a different room; the addressed room is
		// unknown, which is not a non-membership.
		other := "room_" + strings.Repeat("b", 64)
		gate, _, delegation, encoded := newTestGate(t, OpenInbox(), seedRoom(otherMember))
		event := testEvent(t, delegation, func(e *envelope.Event) { e.RoomID = other })
		decision, err := gate.Admit(inbound(event, encoded))
		if err != nil {
			t.Fatalf("admit: %v", err)
		}
		if decision.Outcome != Accepted {
			t.Fatalf("an unknown room was refused rather than admitted: %+v", decision)
		}
	})

	t.Run("no overlay admits room events", func(t *testing.T) {
		// No room ledger configured: the overlay is off, and a room event passes
		// unchecked rather than being blocked.
		gate, _, delegation, encoded := testGate(t, OpenInbox())
		event, _ := roomEvent(t, delegation)
		decision, err := gate.Admit(inbound(event, encoded))
		if err != nil {
			t.Fatalf("admit: %v", err)
		}
		if decision.Outcome != Accepted {
			t.Fatalf("a room event was blocked with no overlay configured: %+v", decision)
		}
	})
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
	gate, _, delegation, encoded := testGate(t, OpenInbox())
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
	gate, journal, delegation, encoded := testGate(t, allowList(t, TellThem))
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
	admitted, _, _, _ := testGate(t, allowList(t, TellThem, senderID))
	second, err := admitted.Admit(inbound(event, encoded))
	if err != nil {
		t.Fatalf("admit: %v", err)
	}
	if second.Outcome != Accepted {
		t.Fatalf("the corrected resend was not delivered: %+v", second)
	}
}

// First-contact invitations are route-neutral authority. A token carried by a
// direct session and the same token carried through a Relay must make the same
// decision; changing route cannot mint or erase admission.
func TestAdmissionInviteHasDirectRelayParityAndIsOneShot(t *testing.T) {
	for _, firstRoute := range []Route{RouteDirect, RouteRelay} {
		t.Run(string(firstRoute), func(t *testing.T) {
			gate, journal, delegation, encoded := testGate(t, allowList(t, InviteOrAskOwner))
			event := testEvent(t, delegation, nil)
			local := testLocalDelegation(t, allowList(t, InviteOrAskOwner))
			var entropy [32]byte
			copy(entropy[:], bytes.Repeat([]byte{0x91}, len(entropy)))
			token, _, err := journal.CreateAdmissionInvite(
				entropy, local.EndpointID, senderID,
				time.Unix(int64(baseUnix)+600, 0), time.Unix(int64(baseUnix)+30, 0),
			)
			if err != nil {
				t.Fatal(err)
			}
			request := inbound(event, encoded)
			request.Route = firstRoute
			request.AdmissionToken = token
			decision, err := gate.Admit(request)
			if err != nil || decision.Outcome != Accepted {
				t.Fatalf("first route=%s decision=%+v err=%v", firstRoute, decision, err)
			}

			if firstRoute == RouteDirect {
				request.Route = RouteRelay
			} else {
				request.Route = RouteDirect
			}
			retry, err := gate.Admit(request)
			if err != nil || retry.Outcome != Duplicate {
				t.Fatalf("other-route retry=%+v err=%v", retry, err)
			}

			other := testEvent(t, delegation, func(e *envelope.Event) {
				e.Content = textBody(t, "another event")
			})
			request.Event = other
			spent, err := gate.Admit(request)
			if err != nil || spent.Outcome != Held || spent.Code != fault.CodeApprovalRequired {
				t.Fatalf("spent invite decision=%+v err=%v", spent, err)
			}
		})
	}

	for _, route := range []Route{RouteDirect, RouteRelay} {
		t.Run("invalid-"+string(route), func(t *testing.T) {
			gate, _, delegation, encoded := testGate(t, allowList(t, InviteOrAskOwner))
			request := inbound(testEvent(t, delegation, nil), encoded)
			request.Route = route
			request.AdmissionToken = "invite_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
			decision, err := gate.Admit(request)
			if err != nil || decision.Outcome != Held || decision.Code != fault.CodeApprovalRequired {
				t.Fatalf("invalid invite route=%s decision=%+v err=%v", route, decision, err)
			}
		})
	}
}

func TestMalformedEventDoesNotBurnAdmissionInvite(t *testing.T) {
	gate, journal, delegation, encoded := testGate(t, allowList(t, InviteOrAskOwner))
	local := testLocalDelegation(t, allowList(t, InviteOrAskOwner))
	var entropy [32]byte
	copy(entropy[:], bytes.Repeat([]byte{0x92}, len(entropy)))
	token, _, err := journal.CreateAdmissionInvite(
		entropy, local.EndpointID, senderID,
		time.Unix(int64(baseUnix)+600, 0), time.Unix(int64(baseUnix)+30, 0),
	)
	if err != nil {
		t.Fatal(err)
	}
	malformed := testEvent(t, delegation, func(e *envelope.Event) {
		e.Content = append(textBody(t, "bad"), 0)
	})
	request := inbound(malformed, encoded)
	request.AdmissionToken = token
	decision, err := gate.Admit(request)
	if err != nil || decision.Code != fault.CodePayloadMalformed {
		t.Fatalf("malformed decision=%+v err=%v", decision, err)
	}

	valid := testEvent(t, delegation, nil)
	request.Event = valid
	decision, err = gate.Admit(request)
	if err != nil || decision.Outcome != Accepted {
		t.Fatalf("valid retry decision=%+v err=%v", decision, err)
	}
}

// An owner is asked once. A resend finds the claim and is acknowledged rather
// than raising the same question again.
func TestHeldEventAsksTheOwnerOnce(t *testing.T) {
	gate, journal, delegation, encoded := testGate(t, allowList(t, AskTheOwner))
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
	gate, journal, delegation, encoded := testGate(t, blockList(t, senderID))
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
	_, _, delegation, encoded := testGate(t, OpenInbox())

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
			gate, journal, _, _ := testGate(t, OpenInbox())
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
	local, localEncoded, localAgentState := localState(t, OpenInbox())
	gate, err := New(Config{
		Network: testNetwork(),
		Chain:   testChain(),
		Resolver: stubResolver{states: map[string]*nativev1.NativeStateV1{
			senderID: nativeState(&nativev1.AgentStateV1{AgentId: senderID,
				Policy: &nativev1.ControllerPolicyV1{Threshold: 1}, DelegationDigests: []string{digest}}),
			localID: localAgentState,
		}},
		Journal:             journal,
		Devices:             mustDevices(t, journal),
		Policy:              OpenInbox(),
		LocalDelegationJSON: localEncoded,
		LocalAgentID:        local.AgentID,
		LocalEndpointID:     local.EndpointID,
		Now:                 func() time.Time { return time.Unix(int64(baseUnix)+30, 0) },
		MaxContentBytes:     len(atBound),
		InstallSalt:         bytes.Repeat([]byte{0x5a}, MinInstallSaltBytes),
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
	gate, _, delegation, _ := testGate(t, OpenInbox())
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
	gate, journal, delegation, encoded := testGate(t, OpenInbox())
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
	gate, _, delegation, encoded := testGate(t, OpenInbox())
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
	other, _, _, _ := testGate(t, OpenInbox())
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
	_, _, delegation, _ := testGate(t, OpenInbox())
	digest, err := identity.Digest(delegation)
	if err != nil {
		t.Fatalf("digest: %v", err)
	}
	journal, err := eventlog.Open(filepath.Join(t.TempDir(), "state"))
	if err != nil {
		t.Fatalf("journal: %v", err)
	}
	defer journal.Close()
	local, localEncoded, localAgentState := localState(t, OpenInbox())
	resolver := stubResolver{states: map[string]*nativev1.NativeStateV1{
		senderID: nativeState(&nativev1.AgentStateV1{AgentId: senderID,
			Policy: &nativev1.ControllerPolicyV1{Threshold: 1}, DelegationDigests: []string{digest}}),
		localID: localAgentState,
	}}
	complete := Config{
		Network: testNetwork(), Chain: testChain(), Resolver: resolver, Journal: journal,
		Devices: mustDevices(t, journal),
		Policy:  OpenInbox(), LocalDelegationJSON: localEncoded,
		LocalAgentID: local.AgentID, LocalEndpointID: local.EndpointID,
		Now:         func() time.Time { return time.Unix(int64(baseUnix)+30, 0) },
		InstallSalt: bytes.Repeat([]byte{1}, MinInstallSaltBytes),
	}
	cases := map[string]func(*Config){
		"no network":               func(c *Config) { c.Network = nil },
		"bad network":              func(c *Config) { c.Network = &nativev1.NetworkDomain{NetworkId: "x"} },
		"no resolver":              func(c *Config) { c.Resolver = nil },
		"no journal":               func(c *Config) { c.Journal = nil },
		"no device ledger":         func(c *Config) { c.Devices = nil },
		"no policy":                func(c *Config) { c.Policy = ContactPolicy{} },
		"no salt":                  func(c *Config) { c.InstallSalt = nil },
		"short salt":               func(c *Config) { c.InstallSalt = bytes.Repeat([]byte{1}, MinInstallSaltBytes-1) },
		"no delegation of its own": func(c *Config) { c.LocalDelegationJSON = nil },
		"another endpoint's delegation": func(c *Config) {
			c.LocalEndpointID = "mep_" + strings.Repeat("8", 64)
		},
		// The published digest and the policy actually in memory disagree.
		"policy this endpoint never published": func(c *Config) { c.Policy = allowList(t, AskTheOwner) },
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
	gate, _, delegation, encoded := testGate(t, OpenInbox())
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
	gate, _, delegation, encoded := testGate(t, OpenInbox())
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

// The policy is asked about a sender and a kind, and nothing else. A policy
// that could read the content would be making a content judgement this layer
// is not entitled to make -- and it is a closed type, so no caller can supply
// one that does.
func TestPolicySeesOnlySenderAndKind(t *testing.T) {
	known := allowList(t, TellThem, senderID)
	if known.Admits(senderID, "text") != AdmitAllow {
		t.Fatal("a known sender was not admitted")
	}
	if known.Admits(senderID, "agent.task.request") != AdmitAllow {
		t.Fatal("the answer depended on the kind for a known sender")
	}
	stranger := "agent_" + strings.Repeat("6", 64)
	if known.Admits(stranger, "text") != AdmitRequireAdmission {
		t.Fatal("a stranger was admitted by an allow list")
	}
	held := allowList(t, AskTheOwner)
	if held.Admits(stranger, "text") != AdmitHoldForApproval {
		t.Fatal("an unknown sender was not held")
	}
	if blockList(t, senderID).Admits(senderID, "text") != AdmitDeny {
		t.Fatal("a blocked sender was admitted")
	}
}

// The document is what the digest and the behaviour both come from, so an
// implementation cannot answer "allow everyone" while publishing the identity
// of an invite-only inbox.
func TestPolicyDocumentsAreClosed(t *testing.T) {
	for name, document := range map[string]InboxPolicyDocument{
		"unknown rule":               {Rule: "allow-everyone-called-bob"},
		"open inbox with a rule":     {Rule: RuleOpen, Unknown: AskTheOwner},
		"allow list with no rule":    {Rule: RuleAllowList},
		"allow list with a bad rule": {Rule: RuleAllowList, Unknown: "ask-the-sender"},
	} {
		t.Run(name, func(t *testing.T) {
			if err := document.Validate(); err == nil {
				t.Fatalf("expected %q to be refused", name)
			}
			if _, err := NewContactPolicy(document, Roster{}); err == nil {
				t.Fatalf("expected %q to build no policy", name)
			}
		})
	}
	// Two documents that answer differently publish different identities.
	tell, err := InboxPolicyDocument{Rule: RuleAllowList, Unknown: TellThem}.Digest()
	if err != nil {
		t.Fatalf("digest: %v", err)
	}
	ask, err := InboxPolicyDocument{Rule: RuleAllowList, Unknown: AskTheOwner}.Digest()
	if err != nil {
		t.Fatalf("digest: %v", err)
	}
	if tell == ask {
		t.Fatal("two policies with different answers share a digest")
	}
}

// Acceptance means durably queued, not delivered. The event has to be
// recoverable from the journal alone, because the process that admitted it may
// not survive to hand it over.
func TestAcceptedEventIsRecoverableWithoutTheDecision(t *testing.T) {
	gate, journal, delegation, encoded := testGate(t, OpenInbox())
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
	gate, journal, delegation, encoded := testGate(t, OpenInbox())
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
	gate, journal, delegation, encoded := testGate(t, allowList(t, AskTheOwner))
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
	waiting, err := journal.ListAwaitingAdmission(time.Unix(int64(baseUnix)+120, 0), 0)
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
	gate, journal, delegation, encoded := testGate(t, allowList(t, AskTheOwner))
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
	published := allowList(t, AskTheOwner, senderID)
	running := allowList(t, TellThem, senderID)
	if published.Digest() == running.Digest() {
		t.Fatal("two policies with different answers for an unknown sender share a digest")
	}

	journal, err := eventlog.Open(filepath.Join(t.TempDir(), "state"))
	if err != nil {
		t.Fatalf("journal: %v", err)
	}
	defer journal.Close()
	local, localEncoded, localAgentState := localState(t, published)
	config := Config{
		Network: testNetwork(), Chain: testChain(), Journal: journal,
		Resolver:            stubResolver{states: map[string]*nativev1.NativeStateV1{localID: localAgentState}},
		Devices:             mustDevices(t, journal),
		Policy:              running,
		LocalDelegationJSON: localEncoded,
		LocalAgentID:        local.AgentID,
		LocalEndpointID:     local.EndpointID,
		Now:                 func() time.Time { return time.Unix(int64(baseUnix)+30, 0) },
		InstallSalt:         bytes.Repeat([]byte{1}, MinInstallSaltBytes),
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
	empty := allowList(t, AskTheOwner)
	populated := allowList(t, AskTheOwner, senderID, localID)
	if empty.Digest() != populated.Digest() {
		t.Fatal("the published policy digest changed when a contact was added")
	}
	open := OpenInbox()
	if open.Digest() == empty.Digest() {
		t.Fatal("an open inbox and an allow list publish the same digest")
	}
}

// A kind is a contract about the body, not a label on it. Bytes that do not
// meet the contract are refused, and the refusal names the reason so a correct
// implementation can tell it from a network fault.
func TestBodyMustMatchItsKind(t *testing.T) {
	gate, journal, delegation, encoded := testGate(t, OpenInbox())
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
	gate, _, delegation, encoded := testGate(t, blockList(t, senderID))
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

// allowList builds a closed allow-list policy. The roster is private and is
// not part of the published document, so it is supplied separately.
func allowList(t *testing.T, unknown UnknownSenderRule, known ...string) ContactPolicy {
	t.Helper()
	roster := Roster{Known: map[string]struct{}{}, Blocked: map[string]struct{}{}}
	for _, agent := range known {
		roster.Known[agent] = struct{}{}
	}
	policy, err := NewContactPolicy(InboxPolicyDocument{Rule: RuleAllowList, Unknown: unknown}, roster)
	if err != nil {
		t.Fatalf("policy: %v", err)
	}
	return policy
}

func blockList(t *testing.T, blocked ...string) ContactPolicy {
	t.Helper()
	roster := Roster{Known: map[string]struct{}{}, Blocked: map[string]struct{}{}}
	for _, agent := range blocked {
		roster.Blocked[agent] = struct{}{}
	}
	policy, err := NewContactPolicy(InboxPolicyDocument{Rule: RuleAllowList, Unknown: TellThem}, roster)
	if err != nil {
		t.Fatalf("policy: %v", err)
	}
	return policy
}

// mustDevices opens the device ledger the gate requires.
func mustDevices(t *testing.T, journal *eventlog.Journal) *eventlog.DeviceLedger {
	t.Helper()
	devices, err := journal.OpenDevices()
	if err != nil {
		t.Fatalf("devices: %v", err)
	}
	return devices
}

// A device retired from its endpoint's published set is refused, and the
// refusal is the peer-visible CodeDeviceRevoked so a well-behaved sender
// learns its device was retired. A device the ledger has never seen still
// passes: the ledger is a revocation overlay, not an allow list.
func TestRevokedDeviceIsRefused(t *testing.T) {
	gate, journal, delegation, encoded := testGate(t, OpenInbox())
	devices := mustDevices(t, journal)

	// The sender publishes two devices — the one its events name, and a
	// second — then retires the first.
	endpointKey := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x11}, ed25519.SeedSize))
	full := deviceSet(t, delegation, endpointKey, map[string]uint64{
		deviceID: baseUnix, otherDevice: baseUnix,
	})
	committed, err := e2ee.SetDigest(full)
	if err != nil {
		t.Fatalf("digest: %v", err)
	}
	if _, err := devices.AdmitPublishedSet(delegation, committed, full, time.Unix(int64(baseUnix)+1, 0)); err != nil {
		t.Fatalf("publish: %v", err)
	}

	// While the sender's device is current, its event is admitted.
	event := testEvent(t, delegation, nil)
	if decision, err := gate.Admit(inbound(event, encoded)); err != nil {
		t.Fatalf("admit: %v", err)
	} else if decision.Outcome != Accepted {
		t.Fatalf("a current device was refused: %+v", decision)
	}

	// The sender retires that device: same bundles minus it, watermark held.
	retired := deviceSet(t, delegation, endpointKey, map[string]uint64{otherDevice: baseUnix})
	retiredDigest, err := e2ee.SetDigest(retired)
	if err != nil {
		t.Fatalf("digest: %v", err)
	}
	if _, err := devices.AdmitPublishedSet(delegation, retiredDigest, retired, time.Unix(int64(baseUnix)+2, 0)); err != nil {
		t.Fatalf("retire: %v", err)
	}

	// Now an event from the retired device is refused, and told why.
	replay := testEvent(t, delegation, nil)
	decision, err := gate.Admit(inbound(replay, encoded))
	if err != nil {
		t.Fatalf("admit: %v", err)
	}
	if decision.Code != fault.CodeDeviceRevoked {
		t.Fatalf("a revoked device was not refused as such: %q", decision.Code)
	}
	if !fault.PeerVisible(fault.CodeDeviceRevoked) {
		t.Fatal("a retired sender cannot learn its device was retired")
	}

	// A device the ledger never saw is not revoked: it passes.
	unseen := testEvent(t, delegation, func(e *envelope.Event) { e.SenderDeviceID = otherDevice })
	// otherDevice is current, so this admits; an entirely unknown device would
	// too, which the delegation authority covers.
	if decision, err := gate.Admit(inbound(unseen, encoded)); err != nil {
		t.Fatalf("admit: %v", err)
	} else if decision.Outcome != Accepted {
		t.Fatalf("a current second device was refused: %+v", decision)
	}
}

const otherDevice = "dev_" + "5555555555555555555555555555555555555555555555555555555555555555"

// deviceSet builds a signed prekey set for the delegated endpoint.
func deviceSet(t *testing.T, delegation identity.Delegation, endpointKey ed25519.PrivateKey,
	issued map[string]uint64) []e2ee.Bundle {
	t.Helper()
	bundles := make([]e2ee.Bundle, 0, len(issued))
	for device, at := range issued {
		bundle := e2ee.Bundle{
			Network: delegation.Network, AgentID: delegation.AgentID, EndpointID: delegation.EndpointID,
			DeviceID: device, AlgorithmID: "tos.messaging.e2ee.example-suite.v1",
			Material:      []byte(strings.Repeat("m", 32) + device[:8]),
			IssuedAtUnix:  at,
			ExpiresAtUnix: at + 86_400,
		}
		signed, err := e2ee.SignBundle(bundle, endpointKey)
		if err != nil {
			t.Fatalf("sign: %v", err)
		}
		bundles = append(bundles, signed)
	}
	return bundles
}
