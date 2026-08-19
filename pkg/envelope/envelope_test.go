package envelope

import (
	"bytes"
	"crypto/ed25519"
	"strings"
	"testing"
	"time"

	"github.com/tosnetwork/tos-messenger/pkg/identity"
	nativev1 "github.com/tosnetwork/tos-service-protocol/gen/tos/service/v1"
)

const baseUnix = uint64(1_800_000_000)

func testNetwork() *nativev1.NetworkDomain {
	return &nativev1.NetworkDomain{
		NetworkId:       "tos-local",
		GenesisRootHash: strings.Repeat("a", 64),
		GenesisFileHash: strings.Repeat("b", 64),
	}
}

func testRelayEnvelope(t *testing.T) RelayEnvelope {
	t.Helper()
	mailbox, err := MailboxID(bytes.Repeat([]byte{0x5a}, 32))
	if err != nil {
		t.Fatalf("mailbox: %v", err)
	}
	message, err := MessageID(bytes.Repeat([]byte{0x6b}, 32))
	if err != nil {
		t.Fatalf("message: %v", err)
	}
	return RelayEnvelope{
		OpaqueMailboxID: mailbox,
		MessageID:       message,
		Ciphertext:      bytes.Repeat([]byte{0x01, 0x02}, 64),
		ExpiresAtUnix:   baseUnix + 3600,
		StorageToken:    "quota-token.1",
	}
}

func TestRelayEnvelopeRoundTrip(t *testing.T) {
	original := testRelayEnvelope(t)
	encoded, err := EncodeRelayJSON(original)
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	decoded, err := DecodeRelayJSON(encoded)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if !bytes.Equal(decoded.Ciphertext, original.Ciphertext) ||
		decoded.OpaqueMailboxID != original.OpaqueMailboxID ||
		decoded.MessageID != original.MessageID ||
		decoded.ExpiresAtUnix != original.ExpiresAtUnix ||
		decoded.StorageToken != original.StorageToken {
		t.Fatal("relay envelope changed across transport")
	}
}

func TestRelayEnvelopeCarriesNoIdentity(t *testing.T) {
	encoded, err := EncodeRelayJSON(testRelayEnvelope(t))
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	// A Relay must not be handed anything that identifies the conversation.
	for _, leaked := range []string{"agent_", "mep_", "conv_", "evt_", "network_id", "quote", "receipt"} {
		if strings.Contains(string(encoded), leaked) {
			t.Fatalf("relay envelope leaks %q to the operator", leaked)
		}
	}
}

func TestDecodeRelayRejectsSizeDisagreement(t *testing.T) {
	encoded, err := EncodeRelayJSON(testRelayEnvelope(t))
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	tampered := strings.Replace(string(encoded), `"ciphertext_size":128`, `"ciphertext_size":64`, 1)
	if tampered == string(encoded) {
		t.Fatal("test did not modify the declared size")
	}
	if _, err := DecodeRelayJSON([]byte(tampered)); err == nil {
		t.Fatal("expected a declared size that disagrees with the body to be rejected")
	}
}

func TestValidateRelayRejectsMalformedEnvelopes(t *testing.T) {
	cases := map[string]func(*RelayEnvelope){
		"bad mailbox":     func(e *RelayEnvelope) { e.OpaqueMailboxID = "mbx_bad" },
		"bad message":     func(e *RelayEnvelope) { e.MessageID = "msg_bad" },
		"empty body":      func(e *RelayEnvelope) { e.Ciphertext = nil },
		"short body":      func(e *RelayEnvelope) { e.Ciphertext = bytes.Repeat([]byte{1}, MinCiphertextBytes-1) },
		"zero body":       func(e *RelayEnvelope) { e.Ciphertext = make([]byte, 64) },
		"oversized body":  func(e *RelayEnvelope) { e.Ciphertext = bytes.Repeat([]byte{1}, MaxCiphertextBytes+1) },
		"no expiry":       func(e *RelayEnvelope) { e.ExpiresAtUnix = 0 },
		"long token":      func(e *RelayEnvelope) { e.StorageToken = strings.Repeat("t", MaxStorageTokenBytes+1) },
		"malformed token": func(e *RelayEnvelope) { e.StorageToken = "token with spaces" },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			relayEnvelope := testRelayEnvelope(t)
			mutate(&relayEnvelope)
			if err := ValidateRelay(relayEnvelope); err == nil {
				t.Fatalf("expected %q to be rejected", name)
			}
			if _, err := EncodeRelayJSON(relayEnvelope); err == nil {
				t.Fatalf("expected %q to be unencodable", name)
			}
		})
	}
}

func TestAcceptedForStorageBoundsRetention(t *testing.T) {
	relayEnvelope := testRelayEnvelope(t)
	now := time.Unix(int64(baseUnix), 0)

	if err := AcceptedForStorage(relayEnvelope, now, 24*time.Hour); err != nil {
		t.Fatalf("expected a bounded envelope to be accepted: %v", err)
	}
	if err := AcceptedForStorage(relayEnvelope, now, 30*time.Minute); err == nil {
		t.Fatal("expected the operator retention bound to be enforced")
	}
	if err := AcceptedForStorage(relayEnvelope, time.Unix(int64(relayEnvelope.ExpiresAtUnix), 0), 24*time.Hour); err == nil {
		t.Fatal("expected an already expired envelope to be refused")
	}
	if err := AcceptedForStorage(relayEnvelope, now, 0); err == nil {
		t.Fatal("expected a missing retention bound to fail closed")
	}
	if err := AcceptedForStorage(relayEnvelope, time.Time{}, time.Hour); err == nil {
		t.Fatal("expected a zero clock to be rejected")
	}

	overlong := testRelayEnvelope(t)
	overlong.ExpiresAtUnix = baseUnix + MaxEnvelopeLifetimeSeconds + 1
	if err := AcceptedForStorage(overlong, now, 365*24*time.Hour); err == nil {
		t.Fatal("expected the protocol retention bound to be enforced")
	}
}

func TestIdentifierHelpersRejectWeakValues(t *testing.T) {
	for name, raw := range map[string][]byte{
		"short": bytes.Repeat([]byte{1}, 31),
		"long":  bytes.Repeat([]byte{1}, 33),
		"zero":  make([]byte, 32),
		"empty": nil,
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := MailboxID(raw); err == nil {
				t.Fatal("expected an invalid mailbox identifier to be rejected")
			}
			if _, err := MessageID(raw); err == nil {
				t.Fatal("expected an invalid message identifier to be rejected")
			}
			if _, err := ConversationID(raw); err == nil {
				t.Fatal("expected an invalid conversation identifier to be rejected")
			}
			if _, err := DeviceID(raw); err == nil {
				t.Fatal("expected an invalid device identifier to be rejected")
			}
		})
	}
}

func testDelegation(t *testing.T) identity.Delegation {
	t.Helper()
	key := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x11}, ed25519.SeedSize))
	public, ok := key.Public().(ed25519.PublicKey)
	if !ok {
		t.Fatal("unexpected public key type")
	}
	network := testNetwork()
	agentID := "agent_" + strings.Repeat("c", 64)
	endpointID, err := identity.DeriveEndpointID(network, agentID, public)
	if err != nil {
		t.Fatalf("derive endpoint: %v", err)
	}
	return identity.Delegation{
		Network:                       network,
		AgentID:                       agentID,
		EndpointID:                    endpointID,
		IdentityPublicKey:             public,
		AllowedProtocolVersions:       []uint32{1},
		AllowedEventClasses:           []string{"agent.task", "text"},
		NotBeforeUnix:                 baseUnix,
		ExpiresAtUnix:                 baseUnix + 86_400,
		MaximumSessionLifetimeSeconds: 3600,
		ContactDescriptorPolicyDigest: "sha256:" + strings.Repeat("3d", 32),
		MailboxPolicyDigest:           "sha256:" + strings.Repeat("4c", 32),
	}
}

func testEvent(t *testing.T) Event {
	t.Helper()
	delegation := testDelegation(t)
	conversationID, err := ConversationID(bytes.Repeat([]byte{0x7c}, 32))
	if err != nil {
		t.Fatalf("conversation: %v", err)
	}
	deviceID, err := DeviceID(bytes.Repeat([]byte{0x8d}, 32))
	if err != nil {
		t.Fatalf("device: %v", err)
	}
	event, err := NewEvent(Event{
		Network:          delegation.Network,
		ConversationID:   conversationID,
		SenderAgentID:    delegation.AgentID,
		SenderEndpointID: delegation.EndpointID,
		SenderDeviceID:   deviceID,
		CreatedAtUnix:    baseUnix + 10,
		Kind:             "text",
		Content:          []byte("hello"),
	})
	if err != nil {
		t.Fatalf("new event: %v", err)
	}
	return event
}

func TestEventIDIsContentAddressed(t *testing.T) {
	event := testEvent(t)
	encoded, err := EncodeEventJSON(event)
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	decoded, err := DecodeEventJSON(encoded)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if decoded.EventID != event.EventID {
		t.Fatal("event identifier changed across transport")
	}

	mutations := map[string]func(*Event){
		"content":        func(e *Event) { e.Content = []byte("goodbye") },
		"kind":           func(e *Event) { e.Kind = "agent.task.request" },
		"conversation":   func(e *Event) { e.ConversationID = "conv_" + strings.Repeat("1", 64) },
		"device":         func(e *Event) { e.SenderDeviceID = "dev_" + strings.Repeat("1", 64) },
		"created at":     func(e *Event) { e.CreatedAtUnix = baseUnix + 11 },
		"network":        func(e *Event) { e.Network.NetworkId = "tos-other" },
		"service bind":   func(e *Event) { e.ServiceBinding = "sha256:" + strings.Repeat("2b", 32) },
		"idempotency":    func(e *Event) { e.IdempotencyKey = strings.Repeat("f", 64) },
		"expiry":         func(e *Event) { e.ExpiresAtUnix = baseUnix + 3600 },
		"thread":         func(e *Event) { e.ThreadID = "thr_" + strings.Repeat("2", 64) },
		"room":           func(e *Event) { e.RoomID = "room_" + strings.Repeat("3", 64) },
		"reply":          func(e *Event) { e.ReplyToEventID = "evt_" + strings.Repeat("4", 64) },
		"causal parents": func(e *Event) { e.CausalParents = []string{"evt_" + strings.Repeat("5", 64)} },
		"attachments": func(e *Event) {
			e.AttachmentReferences = []string{"sha256:" + strings.Repeat("6a", 32)}
		},
	}
	for name, mutate := range mutations {
		t.Run(name, func(t *testing.T) {
			mutated := testEvent(t)
			mutate(&mutated)
			// The identifier still carries the original content, so validation
			// must refuse it rather than accept substituted content.
			if err := ValidateEvent(mutated); err == nil {
				t.Fatalf("mutation %q kept a stale event identifier", name)
			}
			completed, err := NewEvent(mutated)
			if err != nil {
				t.Fatalf("re-derive %q: %v", name, err)
			}
			if completed.EventID == event.EventID {
				t.Fatalf("mutation %q did not change the event identifier", name)
			}
		})
	}
}

func TestUnknownEventKindFailsClosed(t *testing.T) {
	event := testEvent(t)
	event.Kind = "vendor.custom"
	completed, err := NewEvent(event)
	if err != nil {
		t.Fatalf("new event: %v", err)
	}
	encoded, err := EncodeEventJSON(completed)
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	if _, err := DecodeEventJSON(encoded); err == nil {
		t.Fatal("expected an unrecognised event kind to be rejected by default")
	}
	forward, err := DecodeEventJSONForwardCompatible(encoded)
	if err != nil {
		t.Fatalf("forward compatible decode: %v", err)
	}
	if _, known := ClassOf(forward.Kind); known {
		t.Fatal("an unrecognised kind must not acquire a class")
	}
	if err := AdmittedBy(testDelegation(t), forward); err == nil {
		t.Fatal("an unrecognised kind must never be admitted by scope")
	}
}

func TestAdmittedByEnforcesDelegatedScope(t *testing.T) {
	delegation := testDelegation(t)
	event := testEvent(t)
	if err := AdmittedBy(delegation, event); err != nil {
		t.Fatalf("expected a delegated class to be admitted: %v", err)
	}

	undelegated := testEvent(t)
	undelegated.Kind = "approval.grant"
	undelegated, err := NewEvent(undelegated)
	if err != nil {
		t.Fatalf("new event: %v", err)
	}
	if err := AdmittedBy(delegation, undelegated); err == nil {
		t.Fatal("expected an undelegated class to be refused")
	}

	foreign := testEvent(t)
	foreign.SenderAgentID = "agent_" + strings.Repeat("d", 64)
	foreign, err = NewEvent(foreign)
	if err != nil {
		t.Fatalf("new event: %v", err)
	}
	if err := AdmittedBy(delegation, foreign); err == nil {
		t.Fatal("expected a foreign sender to be refused")
	}

	otherNetwork := testEvent(t)
	otherNetwork.Network = &nativev1.NetworkDomain{
		NetworkId:       "tos-other",
		GenesisRootHash: strings.Repeat("a", 64),
		GenesisFileHash: strings.Repeat("b", 64),
	}
	otherNetwork, err = NewEvent(otherNetwork)
	if err != nil {
		t.Fatalf("new event: %v", err)
	}
	if err := AdmittedBy(delegation, otherNetwork); err == nil {
		t.Fatal("expected a foreign network tuple to be refused")
	}
}

func TestEventValidationRejectsMalformedShapes(t *testing.T) {
	cases := map[string]func(*Event){
		"bad conversation":  func(e *Event) { e.ConversationID = "conv_bad" },
		"bad sender":        func(e *Event) { e.SenderAgentID = "agent_bad" },
		"bad endpoint":      func(e *Event) { e.SenderEndpointID = "mep_bad" },
		"bad device":        func(e *Event) { e.SenderDeviceID = "dev_bad" },
		"bad room":          func(e *Event) { e.RoomID = "room_bad" },
		"bad thread":        func(e *Event) { e.ThreadID = "thr_bad" },
		"bad reply":         func(e *Event) { e.ReplyToEventID = "evt_bad" },
		"no created at":     func(e *Event) { e.CreatedAtUnix = 0 },
		"expiry before":     func(e *Event) { e.ExpiresAtUnix = e.CreatedAtUnix - 1 },
		"bad kind":          func(e *Event) { e.Kind = "Text" },
		"empty kind":        func(e *Event) { e.Kind = "" },
		"bad idempotency":   func(e *Event) { e.IdempotencyKey = "zz" },
		"oversized content": func(e *Event) { e.Content = bytes.Repeat([]byte{1}, MaxContentBytes+1) },
		"bad attachment":    func(e *Event) { e.AttachmentReferences = []string{"sha256:zz"} },
		"unsorted parents": func(e *Event) {
			e.CausalParents = []string{"evt_" + strings.Repeat("b", 64), "evt_" + strings.Repeat("a", 64)}
		},
		"duplicate parents": func(e *Event) {
			e.CausalParents = []string{"evt_" + strings.Repeat("a", 64), "evt_" + strings.Repeat("a", 64)}
		},
		"too many parents": func(e *Event) { e.CausalParents = manyEvents(MaxCausalParents + 1) },
		"bad service bind": func(e *Event) { e.ServiceBinding = "sha256:zz" },
		"bad network": func(e *Event) {
			e.Network = &nativev1.NetworkDomain{NetworkId: "tos", GenesisRootHash: "zz", GenesisFileHash: "zz"}
		},
		"nil network":          func(e *Event) { e.Network = nil },
		"too many attachments": func(e *Event) { e.AttachmentReferences = manyDigests(MaxAttachmentReferences + 1) },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			event := testEvent(t)
			mutate(&event)
			if _, err := NewEvent(event); err == nil {
				t.Fatalf("expected %q to be rejected", name)
			}
		})
	}
}

func TestSelfReferenceIsRefused(t *testing.T) {
	event := testEvent(t)
	event.CausalParents = []string{event.EventID}
	if err := ValidateEvent(event); err == nil {
		t.Fatal("expected an event that is its own causal parent to be rejected")
	}
}

func TestDecodeEventRejectsMalformedTransport(t *testing.T) {
	valid, err := EncodeEventJSON(testEvent(t))
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	cases := map[string][]byte{
		"unknown field":  []byte(string(valid[:len(valid)-1]) + `,"extra":1}`),
		"trailing json":  append(append([]byte{}, valid...), []byte(`{}`)...),
		"wrong schema":   []byte(strings.Replace(string(valid), EventSchema, "tos.messaging.event.v2", 1)),
		"forged id":      []byte(strings.Replace(string(valid), testEvent(t).EventID, "evt_"+strings.Repeat("0", 64), 1)),
		"bad base64":     []byte(strings.Replace(string(valid), `"content_base64":"aGVsbG8="`, `"content_base64":"!!!!"`, 1)),
		"empty":          []byte(""),
		"array":          []byte(`[]`),
		"truncated json": valid[:len(valid)/2],
	}
	for name, raw := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := DecodeEventJSON(raw); err == nil {
				t.Fatalf("expected %q to be rejected", name)
			}
		})
	}
}

func TestKnownKindsAllHaveClasses(t *testing.T) {
	kinds := KnownKinds()
	if len(kinds) == 0 {
		t.Fatal("expected a non-empty typed event set")
	}
	for _, kind := range kinds {
		class, known := ClassOf(kind)
		if !known || class == "" {
			t.Fatalf("kind %q has no class", kind)
		}
		if !eventKindPattern.MatchString(kind) {
			t.Fatalf("kind %q is not a valid identifier", kind)
		}
	}
}

func manyEvents(count int) []string {
	events := make([]string, count)
	for index := range events {
		events[index] = "evt_" + strings.Repeat("0", 60) + pad(index)
	}
	return events
}

func manyDigests(count int) []string {
	digests := make([]string, count)
	for index := range digests {
		digests[index] = "sha256:" + strings.Repeat("0", 60) + pad(index)
	}
	return digests
}

func pad(value int) string {
	const digits = "0123456789abcdef"
	return string([]byte{
		digits[(value>>12)&0xf], digits[(value>>8)&0xf], digits[(value>>4)&0xf], digits[value&0xf],
	})
}
