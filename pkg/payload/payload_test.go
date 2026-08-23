package payload

import (
	"bytes"
	"crypto/ed25519"
	"encoding/hex"
	"strings"
	"testing"

	"github.com/tosnetwork/tos-messenger/internal/canon"
	"github.com/tosnetwork/tos-messenger/pkg/attachments"
	"github.com/tosnetwork/tos-messenger/pkg/negotiation"
)

// sample is a valid body for every kind, so the round trip is exercised over
// the whole vocabulary rather than over the two kinds a test author happened
// to pick.
func sample(kind string) Payload {
	switch kind {
	case "text":
		return Text{MediaType: "text/plain; charset=utf-8", Body: "hello"}
	case "conversation.invite":
		return ConversationInvite{Purpose: "buy a transcription", ExpiresAtUnix: 1_800_000_000}
	case "conversation.accept":
		return ConversationAccept{InviteEventID: "evt_" + strings.Repeat("1", 64)}
	case "presence.hint":
		return PresenceHint{State: "available", StaleAfterUnix: 1_800_000_000}
	case "agent.gift.address-request":
		return GiftAddressRequest{CanonicalRequest: []byte{0xa1, 0x01}}
	case "agent.gift.address-response":
		return GiftAddressResponse{CanonicalResponse: []byte{0xa1, 0x02}}
	case "agent.gift.signed-boc-offer":
		return GiftSignedBOCOffer{CanonicalOffer: []byte{0xa1, 0x03}}
	case "agent.task.request":
		return TaskRequest{TaskID: "task-1", CapabilityID: "cap_" + strings.Repeat("2", 64),
			InputDigest: "sha256:" + strings.Repeat("3", 64), DeadlineUnix: 1_800_000_000}
	case "agent.task.progress":
		return TaskProgress{TaskID: "task-1", Stage: "transcribing", PercentComplete: 40}
	case "agent.task.result":
		return TaskResult{TaskID: "task-1", Outcome: "succeeded",
			OutputDigest: "sha256:" + strings.Repeat("4", 64)}
	case "agent.task.status.request":
		return TaskStatusRequest{TaskID: "task-1"}
	case "negotiation.proposal":
		return NegotiationProposal{NegotiationID: "neg-1", Terms: sampleTerms()}
	case "negotiation.counterproposal":
		return NegotiationCounterproposal{NegotiationID: "neg-1", Terms: sampleTerms()}
	case "negotiation.withdraw":
		return NegotiationWithdraw{NegotiationID: "neg-1", Reason: "found another provider"}
	case "negotiation.intent.accept":
		return NegotiationIntentAccept{NegotiationID: "neg-1", Terms: sampleTerms()}
	case "negotiation.intent.reject":
		return NegotiationIntentReject{NegotiationID: "neg-1", Reason: "above budget"}
	case "counterparty.approval.request":
		return CounterpartyApprovalRequest{ApprovalID: "ap-1", Subject: "spend"}
	case "counterparty.approval.granted":
		return CounterpartyApprovalGranted{ApprovalID: "ap-1", DecidedAtUnix: 1_800_000_000}
	case "counterparty.approval.denied":
		return CounterpartyApprovalDenied{ApprovalID: "ap-1", DecidedAtUnix: 1_800_000_000}
	case "owner.approval.grant":
		return OwnerApprovalGrant{ApprovalID: "ap-1", EventID: "evt_" + strings.Repeat("5", 64),
			DecidedAtUnix: 1_800_000_000}
	case "owner.approval.deny":
		return OwnerApprovalDeny{ApprovalID: "ap-1", EventID: "evt_" + strings.Repeat("5", 64),
			DecidedAtUnix: 1_800_000_000}
	case "a2a.message":
		return A2AMessage{Foreign: Foreign{Protocol: "a2a", Version: "1", Body: []byte("{}")}}
	case "mcp.call":
		return MCPCall{Foreign: Foreign{Protocol: "mcp", Version: "1", Body: []byte("{}")}}
	case "mcp.result":
		return MCPResult{Foreign: Foreign{Protocol: "mcp", Version: "1", Body: []byte("{}")}}
	case "agent.packet":
		return AgentPacketMessage{Foreign: Foreign{Protocol: "agentpacket", Version: "1", Body: []byte("{}")}}
	case "artifact.offer":
		return ArtifactOffer{ArtifactDigest: "sha256:" + strings.Repeat("6", 64),
			MediaType: "application/pdf", SizeBytes: 4096}
	case "artifact.reference":
		return ArtifactReference{ArtifactDigest: "sha256:" + strings.Repeat("6", 64),
			Locator: "relay://mbx_" + strings.Repeat("7", 64)}
	case "artifact.encrypted":
		plaintext := []byte("private attachment")
		random := bytes.NewReader(bytes.Repeat([]byte{0x42}, attachments.KeyBytes+attachments.AttachmentIDBytes+attachments.NoncePrefixBytes))
		ref, chunks, err := attachments.Seal(random, plaintext, attachments.Metadata{Filename: "note.txt", MediaType: "text/plain", PlaintextDigest: canon.Digest(plaintext), ExpiresAtUnix: 1_900_000_000})
		if err != nil {
			panic(err)
		}
		raw, err := attachments.EncodeReferenceJSON(ref)
		if err != nil {
			panic(err)
		}
		digest, err := attachments.ManifestDigest(ref.Manifest)
		if err != nil {
			panic(err)
		}
		locator, err := attachments.HTTPSLocator("https://attachments.example", digest)
		if err != nil {
			panic(err)
		}
		endpointKey := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x51}, ed25519.SeedSize))
		storageKey := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x52}, ed25519.SeedSize))
		capabilityKey := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x53}, ed25519.SeedSize))
		grant, err := attachments.SignGrant(attachments.CapabilityGrant{NetworkID: "tos-local",
			GenesisRootHash: strings.Repeat("a", 64), GenesisFileHash: strings.Repeat("b", 64),
			AgentID: "agent_" + strings.Repeat("c", 64), EndpointID: "mep_" + strings.Repeat("d", 64),
			StoragePublicKeyHex:    hex.EncodeToString(storageKey.Public().(ed25519.PublicKey)),
			CapabilityPublicKeyHex: hex.EncodeToString(capabilityKey.Public().(ed25519.PublicKey)),
			ManifestDigest:         digest, ChunkDigests: append([]string(nil), ref.Manifest.ChunkDigests...),
			CiphertextBytes: uint64(len(chunks[0].Ciphertext)), RetainUntilUnix: ref.Metadata.ExpiresAtUnix,
			Operations: []attachments.Operation{attachments.OperationFetch}, IssuedAtUnix: 1_899_000_000,
			ExpiresAtUnix: 1_900_000_000}, endpointKey)
		if err != nil {
			panic(err)
		}
		grantJSON, err := attachments.EncodeGrantJSON(grant)
		if err != nil {
			panic(err)
		}
		return EncryptedAttachment{ManifestDigest: digest, ReferenceJSON: raw, Locator: locator,
			FetchGrantJSON: grantJSON, FetchCapabilityPrivateKeyHex: hex.EncodeToString(capabilityKey)}
	case "service.quote.reference":
		return QuoteReference{ChainReference: sampleChainReference()}
	case "service.escrow.reference":
		return EscrowReference{ChainReference: sampleChainReference()}
	case "service.receipt.reference":
		return ReceiptReference{ChainReference: sampleChainReference()}
	case "delivery.ack":
		return DeliveryAck{EventID: "evt_" + strings.Repeat("8", 64), ReceivedAtUnix: 1_800_000_000}
	case "application.ack":
		return ApplicationAck{EventID: "evt_" + strings.Repeat("8", 64), Outcome: "applied",
			DecidedAtUnix: 1_800_000_000}
	case "read.ack":
		return ReadAck{EventID: "evt_" + strings.Repeat("8", 64), ReadAtUnix: 1_800_000_000}
	case "device.history.segment":
		return DeviceHistorySegment{SourceDeviceID: "dev_" + strings.Repeat("1", 64),
			TargetDeviceID: "dev_" + strings.Repeat("2", 64), ConversationID: "conv_" + strings.Repeat("3", 64),
			Sequence: 1, Events: [][]byte{[]byte("historical Event JSON")}}
	case "room.invite":
		return RoomInvite{RoomID: "room_" + strings.Repeat("9", 64),
			InviteeAgentID: "agent_" + strings.Repeat("a", 64),
			Purpose:        "planning", ExpiresAtUnix: 1_800_000_000}
	case "room.membership.commit":
		return RoomMembershipCommit{RoomID: "room_" + strings.Repeat("9", 64), Epoch: 3,
			MembershipDigest: "sha256:" + strings.Repeat("b", 64), MemberCount: 4}
	case "room.message":
		return RoomMessage{RoomID: "room_" + strings.Repeat("9", 64), Epoch: 3,
			MediaType: "text/markdown", Body: "agenda"}
	case "room.moderation":
		return RoomModeration{RoomID: "room_" + strings.Repeat("9", 64), MembershipEpoch: 3,
			RolePolicyRevision: 2, TargetEventID: "evt_" + strings.Repeat("8", 64),
			DecisionRevision: 1, Action: "hide", Reason: "off topic"}
	}
	return nil
}

func sampleTerms() negotiation.Terms {
	return negotiation.Terms{
		CapabilityID:           "cap_" + strings.Repeat("2", 64),
		CapabilityVersion:      "1.0.0",
		CapabilityClass:        "transcription.audio",
		ProviderAgentID:        "agent_" + strings.Repeat("3", 64),
		ManifestDigest:         "sha256:" + strings.Repeat("4", 64),
		TransportBindingDigest: "sha256:" + strings.Repeat("5", 64),
		Price: negotiation.Money{
			Asset: negotiation.Asset{
				Network: negotiation.Network{
					ID:              "tos-local",
					GenesisRootHash: strings.Repeat("1", 64),
					GenesisFileHash: strings.Repeat("2", 64),
				},
				Workchain:      0,
				AccountID:      strings.Repeat("a", 64),
				MasterCodeHash: "tvm-cell-sha256:" + strings.Repeat("b", 64),
				WalletCodeHash: "tvm-cell-sha256:" + strings.Repeat("c", 64),
				Decimals:       2,
			},
			Atomic: "250",
		},
		EscrowTermsDigest:   "sha256:" + strings.Repeat("6", 64),
		DisputePolicyDigest: "sha256:" + strings.Repeat("7", 64),
		NotAfterUnix:        1_800_000_000,
	}
}

func sampleChainReference() ChainReference {
	return ChainReference{
		Account:     "0:" + strings.Repeat("c", 64),
		StateDigest: "sha256:" + strings.Repeat("d", 64),
	}
}

// Every kind must have a sample, or the round-trip test below is quietly
// covering less than it claims.
func TestEveryKindHasASample(t *testing.T) {
	for _, kind := range Kinds() {
		if sample(kind) == nil {
			t.Fatalf("no sample body for kind %q", kind)
		}
	}
}

func TestBodiesRoundTrip(t *testing.T) {
	for _, kind := range Kinds() {
		t.Run(kind, func(t *testing.T) {
			original := sample(kind)
			encoded, err := Encode(original)
			if err != nil {
				t.Fatalf("encode: %v", err)
			}
			decoded, err := Decode(kind, encoded)
			if err != nil {
				t.Fatalf("decode: %v", err)
			}
			again, err := Encode(decoded)
			if err != nil {
				t.Fatalf("re-encode: %v", err)
			}
			if !bytes.Equal(encoded, again) {
				t.Fatal("a body did not survive a round trip byte for byte")
			}
			schema, known := SchemaFor(kind)
			if !known || decoded.Schema() != schema {
				t.Fatalf("kind %q decoded to schema %q", kind, decoded.Schema())
			}
		})
	}
}

func TestEncryptedAttachmentV1HistoryRemainsDecodable(t *testing.T) {
	legacy := sample("artifact.encrypted").(EncryptedAttachment)
	legacy.schema = encryptedAttachmentV1Schema
	legacy.Locator = "relay://legacy-opaque-hint"
	encoded, err := Encode(legacy)
	if err != nil {
		t.Fatalf("encode legacy attachment: %v", err)
	}
	decoded, err := DecodeSchema("artifact.encrypted", encryptedAttachmentV1Schema, encoded)
	if err != nil {
		t.Fatalf("decode legacy attachment: %v", err)
	}
	attachment, ok := decoded.(EncryptedAttachment)
	if !ok || attachment.Schema() != encryptedAttachmentV1Schema || attachment.Locator != legacy.Locator {
		t.Fatalf("legacy attachment changed: %#v", decoded)
	}
	if _, err := Decode("artifact.encrypted", encoded); err == nil {
		t.Fatal("legacy bytes were guessed as the current schema")
	}
	if !SupportsSchema("artifact.encrypted", encryptedAttachmentV1Schema) ||
		SupportsSchema("artifact.encrypted", "tos.messaging.payload.encrypted-attachment.v999") {
		t.Fatal("attachment schema allow-list is wrong")
	}
}

func TestEncryptedAttachmentV2HistoryRemainsDecodable(t *testing.T) {
	current := sample("artifact.encrypted").(EncryptedAttachment)
	legacy := EncryptedAttachment{ManifestDigest: current.ManifestDigest, ReferenceJSON: current.ReferenceJSON,
		Locator: current.Locator, schema: encryptedAttachmentV2Schema}
	encoded, err := Encode(legacy)
	if err != nil {
		t.Fatalf("encode v2 attachment: %v", err)
	}
	decoded, err := DecodeSchema("artifact.encrypted", encryptedAttachmentV2Schema, encoded)
	if err != nil {
		t.Fatalf("decode v2 attachment: %v", err)
	}
	attachment := decoded.(EncryptedAttachment)
	if attachment.Schema() != encryptedAttachmentV2Schema || len(attachment.FetchGrantJSON) != 0 ||
		attachment.FetchCapabilityPrivateKeyHex != "" {
		t.Fatalf("v2 attachment acquired fetch authority: %#v", attachment)
	}
	if _, err := Decode("artifact.encrypted", encoded); err == nil {
		t.Fatal("v2 bytes were guessed as the current schema")
	}
}

func TestEncryptedAttachmentV3FetchAuthorityFailsClosed(t *testing.T) {
	valid := sample("artifact.encrypted").(EncryptedAttachment)
	cases := map[string]func(*EncryptedAttachment){
		"missing grant": func(value *EncryptedAttachment) { value.FetchGrantJSON = nil },
		"wrong private key": func(value *EncryptedAttachment) {
			value.FetchCapabilityPrivateKeyHex = strings.Repeat("0", ed25519.PrivateKeySize*2)
		},
		"extra operation": func(value *EncryptedAttachment) {
			grant, _ := attachments.DecodeGrantJSON(value.FetchGrantJSON)
			grant.Operations = []attachments.Operation{attachments.OperationFetch, attachments.OperationUpload}
			value.FetchGrantJSON, _ = attachments.EncodeGrantJSON(grant)
		},
		"ciphertext byte substitution": func(value *EncryptedAttachment) {
			grant, _ := attachments.DecodeGrantJSON(value.FetchGrantJSON)
			grant.CiphertextBytes++
			value.FetchGrantJSON, _ = attachments.EncodeGrantJSON(grant)
		},
		"retention substitution": func(value *EncryptedAttachment) {
			grant, _ := attachments.DecodeGrantJSON(value.FetchGrantJSON)
			grant.RetainUntilUnix--
			value.FetchGrantJSON, _ = attachments.EncodeGrantJSON(grant)
		},
		"chunk substitution": func(value *EncryptedAttachment) {
			grant, _ := attachments.DecodeGrantJSON(value.FetchGrantJSON)
			grant.ChunkDigests[0] = "sha256:" + strings.Repeat("9", 64)
			value.FetchGrantJSON, _ = attachments.EncodeGrantJSON(grant)
		},
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			changed := valid
			changed.ReferenceJSON = append([]byte(nil), valid.ReferenceJSON...)
			changed.FetchGrantJSON = append([]byte(nil), valid.FetchGrantJSON...)
			mutate(&changed)
			if err := changed.Validate(); err == nil {
				t.Fatal("invalid recipient fetch authority was accepted")
			}
		})
	}
}

// The body's own schema is part of its domain, so bytes that parse under one
// kind must not parse as another.
func TestBodiesDoNotCrossKinds(t *testing.T) {
	kinds := Kinds()
	for _, kind := range kinds {
		encoded, err := Encode(sample(kind))
		if err != nil {
			t.Fatalf("encode %q: %v", kind, err)
		}
		for _, other := range kinds {
			if other == kind {
				continue
			}
			if _, err := Decode(other, encoded); err == nil {
				t.Fatalf("a %q body parsed as %q", kind, other)
			}
		}
	}
}

// Trailing bytes would let one object have two encodings, and an object's
// identity is its bytes.
func TestTrailingBytesAreRefused(t *testing.T) {
	encoded, err := Encode(sample("text"))
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	if _, err := Decode("text", append(encoded, 0x00)); err == nil {
		t.Fatal("a body with trailing bytes was accepted")
	}
	if _, err := Decode("text", encoded[:len(encoded)-1]); err == nil {
		t.Fatal("a truncated body was accepted")
	}
}

// A length prefix a peer chooses is an allocation a peer chooses, so every
// bound is checked before the read.
func TestOversizedFieldsAreRefusedWithoutAllocating(t *testing.T) {
	buffer := bytes.NewBufferString(domainFor(Text{}.Schema()))
	buffer.Write([]byte{0xff, 0xff, 0xff, 0xff})
	if _, err := Decode("text", buffer.Bytes()); err == nil {
		t.Fatal("a body claiming four gigabytes of text was accepted")
	}
}

// A kind with no codec is refused rather than passed through: a build that let
// an unrecognised kind carry an uninterpreted body would be admitting exactly
// the events it cannot reason about.
func TestUnknownKindsHaveNoBody(t *testing.T) {
	if _, err := Decode("not.a.kind", nil); err == nil {
		t.Fatal("an unknown kind decoded a body")
	}
	if _, known := SchemaFor("not.a.kind"); known {
		t.Fatal("an unknown kind reported a schema")
	}
}

func TestInvalidBodiesAreRefused(t *testing.T) {
	cases := map[string]Payload{
		"text with no body":            Text{MediaType: "text/plain; charset=utf-8"},
		"text with an open media type": Text{MediaType: "text/html", Body: "x"},
		"progress past its scale":      TaskProgress{TaskID: "t", Stage: "s", PercentComplete: 101},
		"failure claiming an output": TaskResult{TaskID: "t", Outcome: "failed", Reason: "no",
			OutputDigest: "sha256:" + strings.Repeat("4", 64)},
		"failure with no reason": TaskResult{TaskID: "t", Outcome: "failed"},
		"zero digest":            ArtifactOffer{ArtifactDigest: "sha256:" + strings.Repeat("0", 64), MediaType: "application/pdf", SizeBytes: 1},
		"rejection with no reason": ApplicationAck{EventID: "evt_" + strings.Repeat("8", 64),
			Outcome: "rejected", DecidedAtUnix: 1},
		"read ack with no time": ReadAck{EventID: "evt_" + strings.Repeat("8", 64)},
		"room with no members": RoomMembershipCommit{RoomID: "room_" + strings.Repeat("9", 64),
			Epoch: 1, MembershipDigest: "sha256:" + strings.Repeat("b", 64)},
		"carried message with no body": A2AMessage{Foreign: Foreign{Protocol: "a2a", Version: "1"}},
		"A2A kind carrying MCP": A2AMessage{Foreign: Foreign{
			Protocol: "mcp", Version: "2025-06-18", Body: []byte("{}")}},
		"MCP call carrying A2A": MCPCall{Foreign: Foreign{
			Protocol: "a2a", Version: "1.0", Body: []byte("{}")}},
		"MCP result carrying A2A": MCPResult{Foreign: Foreign{
			Protocol: "a2a", Version: "1.0", Body: []byte("{}")}},
	}
	for name, value := range cases {
		t.Run(name, func(t *testing.T) {
			if err := value.Validate(); err == nil {
				t.Fatalf("expected %q to be refused", name)
			}
			if _, err := Encode(value); err == nil {
				t.Fatalf("expected %q to be unencodable", name)
			}
		})
	}
}
