package payload

import (
	"bytes"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"strings"
	"testing"
	"time"

	"github.com/tosnetwork/tos-messenger/internal/canon"
	"github.com/tosnetwork/tos-messenger/pkg/attachments"
	"github.com/tosnetwork/tos-messenger/pkg/negotiation"
	commerce "github.com/tosnetwork/tos-service-protocol/pkg/agentcommerce"
	protocolcodec "github.com/tosnetwork/tos-service-protocol/pkg/codec"
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
	case "intent.application":
		canonical, _ := commerce.CanonicalIntentApplication(commerce.IntentApplication{SchemaVersion: 1,
			IntentDigest: "sha256:" + strings.Repeat("9", 64), IntentIssuerAgentID: "agent:issuer", ApplicantAgentID: "agent:applicant",
			Message: "I can perform this bounded task.", ExpiresAtUnix: 1_800_000_000})
		return IntentApplication{CanonicalApplication: canonical}
	case "agreement.propose":
		body, canonical := sampleAgreementBody()
		digest, _ := commerce.AgreementBodyDigest(body)
		return AgreementPropose{AgreementBodyDigest: digest, CanonicalBody: canonical}
	case "agreement.accept":
		body, _ := sampleAgreementBody()
		digest, _ := commerce.AgreementBodyDigest(body)
		acceptance, _ := commerce.SignAgreementAcceptance(commerce.AgreementAcceptanceBody{AgreementID: body.AgreementID,
			AgreementVersion: body.Version, AgreementBodyDigest: digest, AcceptingSubject: body.AuthorizationPredicates[0].AuthoritySubject,
			AcceptedRoles: []string{"provider"}, PredicateIDs: []string{"predicate:provider"},
			EvidenceTargetProjectionDigests: []string{body.AuthorizationPredicates[0].EvidenceTargetProjectionDigest}, ExpiresAtUnix: body.ExpiresAtUnix},
			ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x61}, ed25519.SeedSize)))
		canonical, _ := commerce.EncodeSignedAgreementAcceptance(acceptance)
		return AgreementAccept{AgreementBodyDigest: digest, CanonicalAcceptance: canonical}
	case "agreement.evidence":
		body, _ := sampleAgreementBody()
		digest, _ := commerce.AgreementBodyDigest(body)
		acceptance, _ := commerce.SignAgreementAcceptance(commerce.AgreementAcceptanceBody{AgreementID: body.AgreementID,
			AgreementVersion: body.Version, AgreementBodyDigest: digest, AcceptingSubject: body.AuthorizationPredicates[0].AuthoritySubject,
			AcceptedRoles: []string{"provider"}, PredicateIDs: []string{"predicate:provider"},
			EvidenceTargetProjectionDigests: []string{body.AuthorizationPredicates[0].EvidenceTargetProjectionDigest}, ExpiresAtUnix: body.ExpiresAtUnix},
			ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x61}, ed25519.SeedSize)))
		evidence, _ := commerce.AgentSignatureEvidence(body, acceptance)
		canonical, _ := protocolcodec.Marshal(evidence)
		evidenceDigest, _ := protocolcodec.Digest("tos.agreement-authorization-evidence.v1", evidence)
		return AgreementEvidence{AgreementBodyDigest: digest, EvidenceDigest: evidenceDigest, CanonicalEvidence: canonical}
	case "agreement.provider-offer":
		offer := samplePaidDemandProviderOffer()
		canonical, _ := protocolcodec.Marshal(offer)
		digest, _ := commerce.ProviderOfferDigest(offer)
		return PaidDemandProviderOffer{AgreementBodyDigest: offer.Binding.AgreementBodyDigest,
			ProviderOfferDigest: digest, CanonicalOffer: canonical}
	case "agreement.withdraw":
		return AgreementWithdraw{AgreementBodyDigest: "sha256:" + strings.Repeat("a", 64), ProposalActionID: "sha256:" + strings.Repeat("b", 64), Reason: "terms changed"}
	case "agreement.delivery":
		return AgreementDelivery{AgreementBodyDigest: "sha256:" + strings.Repeat("a", 64), ObligationID: "deliverable:report",
			DeliverableManifestDigest: "sha256:" + strings.Repeat("c", 64)}
	case "commerce.profile-event":
		event := commerce.CommerceProfileEventV1{SchemaVersion: 1, ProfileURI: "tos.test.profile.v1", ProfileVersion: 1,
			ObjectKind: "test.object", ObjectContentType: "application/vnd.tos.test+cbor",
			ObjectDigest: "sha256:" + strings.Repeat("d", 64), ObjectSizeBytes: 1, CarriageKind: "inline",
			CanonicalObjectBytes: []byte{0x01}, CreatedAtUnix: 1_700_000_000, ExpiresAtUnix: 1_700_003_600}
		canonical, _ := commerce.CanonicalCommerceProfileEventV1(event, time.Unix(1_700_000_000, 0))
		return CommerceProfileEvent{ObjectDigest: event.ObjectDigest, CanonicalEvent: canonical}
	case "private.handoff.challenge":
		challenge, _, _ := samplePrivateHandoff()
		canonical, _ := protocolcodec.Marshal(challenge)
		digest, _ := commerce.PrivateHandoffChallengeDigest(challenge.Body)
		return PrivateHandoffChallenge{ChallengeDigest: digest, CanonicalChallenge: canonical}
	case "private.handoff.authorization":
		challenge, authorization, _ := samplePrivateHandoff()
		canonical, _ := protocolcodec.Marshal(authorization)
		challengeDigest, _ := commerce.PrivateHandoffChallengeDigest(challenge.Body)
		authorizationDigest, _ := commerce.PrivateHandoffAuthorizationDigest(authorization.Body)
		return PrivateHandoffAuthorization{ChallengeDigest: challengeDigest, AuthorizationDigest: authorizationDigest, CanonicalAuthorization: canonical}
	case "private.handoff.acknowledgement":
		challenge, authorization, receiverKey := samplePrivateHandoff()
		challengeDigest, _ := commerce.PrivateHandoffChallengeDigest(challenge.Body)
		authorizationDigest, _ := commerce.PrivateHandoffAuthorizationDigest(authorization.Body)
		manifestDigest, _ := protocolcodec.Digest("tos.private-content-manifest.v1", authorization.Body.Manifest)
		record := commerce.AcceptedPrivateContentRecord{SchemaVersion: 1, HandoffID: challenge.Body.HandoffID, ChallengeDigest: challengeDigest,
			AuthorizationDigest: authorizationDigest, UploadActionID: "sha256:" + strings.Repeat("d", 64),
			SenderDisclosureActionID: authorization.Body.SenderDisclosureActionID, ContentDigest: authorization.Body.Manifest.ContentDigest,
			ContentManifestDigest: manifestDigest,
			PlaintextBytes:        authorization.Body.Manifest.PlaintextBytes, ImmutableObjectDigest: authorization.Body.Manifest.ContentDigest,
			RetentionPolicyDigest: challenge.Body.RetentionPolicyDigest, AcceptedAtUnix: challenge.Body.IssuedAtUnix, DeleteNotAfterUnix: challenge.Body.ExpiresAtUnix}
		ack, _ := commerce.SignPrivateHandoffAcknowledgement(record, challenge.Body.ReceiverAgentID, receiverKey)
		canonical, _ := protocolcodec.Marshal(ack)
		digest, _ := commerce.PrivateHandoffAcknowledgementDigest(ack)
		return PrivateHandoffAcknowledgement{ChallengeDigest: challengeDigest, AcknowledgementDigest: digest, CanonicalAcknowledgement: canonical}
	case "private.handoff.status":
		return PrivateHandoffStatus{HandoffID: "handoff:test", ActionID: "sha256:" + strings.Repeat("a", 64), State: "accepted", EvidenceDigest: "sha256:" + strings.Repeat("b", 64)}
	case "private.handoff.delete":
		return PrivateHandoffDelete{HandoffID: "handoff:test", ContentManifestDigest: "sha256:" + strings.Repeat("a", 64),
			RetentionPolicyDigest: "sha256:" + strings.Repeat("b", 64), DeleteActionID: "sha256:" + strings.Repeat("c", 64)}
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

func samplePaidDemandProviderOffer() commerce.SignedProviderOffer {
	key := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x72}, ed25519.SeedSize))
	digest := func(octet string) string { return "sha256:" + strings.Repeat(octet, 64) }
	binding := commerce.PaidDemandQuoteBindingBody{SchemaVersion: 1, NetworkContext: "tos:test",
		AgreementBodyDigest: digest("1"), AgreementObligationIDs: []string{"pay", "work"},
		AgreementAuthorizationPredicateIDs:  []string{"buyer", "provider"},
		AgreementAuthorizationTargetDigests: []string{digest("2"), digest("3")},
		EvidenceProfileURI:                  commerce.EvidenceProfilePaidDemandQuote, EvidenceProfileVersion: 1,
		EvidenceProfileDigest: commerce.PaidDemandQuoteProfileDigest(), DemandMutationDigest: digest("4"),
		ProviderOfferID: "offer:test", ProviderAgentID: "agent:provider", BuyerAgentID: "agent:buyer",
		BuyerWallet: "0:" + strings.Repeat("5", 64), ProviderWallet: "0:" + strings.Repeat("6", 64),
		NativeQuoteTermsProjectionDigest: "tvm-cell-sha256:" + strings.Repeat("7", 64), AcceptByUnix: 1_800_000_000}
	context := commerce.ProviderProofContext{SchemaVersion: 1, NetworkContext: binding.NetworkContext,
		ProviderAgentID: binding.ProviderAgentID, Purpose: "provider-offer.sign",
		PublicKey: "ed25519:" + hex.EncodeToString(key.Public().(ed25519.PublicKey)), AgentGeneration: 1,
		ControllerPolicyDigest: digest("8"), DelegationDigest: digest("9"), ScopeBoundsDigest: digest("a"),
		OwnerMandateDigest: digest("b"), IssuanceAuthorityReferenceDigest: digest("c"),
		ValidFromUnix: 1_700_000_000, ExpiresAtUnix: binding.AcceptByUnix}
	offer, _ := commerce.SignProviderOffer(binding, context, key)
	return offer
}

func samplePrivateHandoff() (commerce.SignedPrivateHandoffChallenge, commerce.SignedPrivateHandoffAuthorization, ed25519.PrivateKey) {
	digest := func(value string) string {
		hash := sha256.Sum256([]byte(value))
		return "sha256:" + hex.EncodeToString(hash[:])
	}
	receiverSigning := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x31}, ed25519.SeedSize))
	senderSigning := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x32}, ed25519.SeedSize))
	receiverEncryption, err := ecdh.X25519().NewPrivateKey(bytes.Repeat([]byte{0x33}, 32))
	if err != nil {
		panic(err)
	}
	challenge, err := commerce.SignPrivateHandoffChallenge(commerce.PrivateHandoffChallengeBody{SchemaVersion: 1,
		HandoffID: "handoff:test", AgreementBodyDigest: digest("agreement"), ObligationID: "obligation:input", SenderAgentID: "agent:sender",
		ReceiverAgentID: "agent:receiver", Direction: "input", PurposeDigest: digest("purpose"), IngressProfileURI: "tos.private-ingress.v1",
		IngressInstanceID: "ingress:test", ReceiverEncryptionPublicKey: base64.RawURLEncoding.EncodeToString(receiverEncryption.PublicKey().Bytes()),
		MaximumPlaintextBytes: 1024, MaximumCiphertextBytes: 1040, MaximumFiles: 1, AcceptedMediaTypes: []string{"application/octet-stream"},
		RetentionPolicyDigest: digest("retention"), IssuedAtUnix: 1_700_000_000, ExpiresAtUnix: 1_700_003_600,
		DeleteNotAfterUnix: 1_700_086_400}, receiverSigning)
	if err != nil {
		panic(err)
	}
	plaintext := []byte("private input")
	plainHash := sha256.Sum256(plaintext)
	manifest := commerce.PrivateContentManifest{ContentDigest: "sha256:" + hex.EncodeToString(plainHash[:]), MediaType: "application/octet-stream",
		FileCount: 1, CanonicalPaths: []string{"input.bin"}, PlaintextBytes: uint64(len(plaintext)), MaximumExpandedBytes: uint64(len(plaintext)),
		CompressionProfileURI: "tos.compression.none.v1"}
	authorizationID := digest("content-upload-action")
	_, authorization, err := commerce.SealPrivateContent(challenge, manifest, plaintext, authorizationID, senderSigning)
	if err != nil {
		panic(err)
	}
	return challenge, authorization, receiverSigning
}

func sampleAgreementBody() (commerce.AgentAgreementBody, []byte) {
	profileDigest := commerce.AgentSignatureProfileDigest()
	body := commerce.AgentAgreementBody{SchemaVersion: 1, AgreementID: "agreement:test", Version: 1, NetworkContext: "tos:testnet",
		Participants: []commerce.AgreementParticipant{{AgentID: "agent:buyer", Roles: []string{"buyer"}}, {AgentID: "agent:test", Roles: []string{"provider"}}}, TermsContentType: "text/plain",
		Terms: []byte("perform a bounded task"), Obligations: []commerce.AgreementObligation{{ObligationID: "deliverable:1", Kind: "deliverable",
			ObligorAgentID: "agent:test", SubjectContentType: "text/plain", Subject: []byte("result"), ConfidentialityPolicy: "participants",
			CancellationPolicy: "before-start", DisputePolicy: "manual", AuthorizationPredicateIDs: []string{"predicate:provider"}}},
		AuthorizationPredicates: []commerce.AgreementAuthorizationPredicate{{PredicateID: "predicate:provider",
			AuthoritySubject: commerce.AgreementAuthoritySubject{SubjectKind: "agent", SubjectNamespace: "tos.agent", SubjectIdentifier: "agent:test"},
			RoleScope:        []string{"provider"}, ObligationIDs: []string{"deliverable:1"}, EvidenceProfileURI: commerce.EvidenceProfileAgentSignature,
			EvidenceProfileVersion: 1, EvidenceProfileDigest: profileDigest, ExpiresAtUnix: 1_800_000_000}},
		ValidFromUnix: 1_700_000_000, ExpiresAtUnix: 1_800_000_000}
	var err error
	body, err = commerce.PrepareAgreementTargets(body)
	if err != nil {
		panic(err)
	}
	canonical, err := protocolcodec.Marshal(body)
	if err != nil {
		panic(err)
	}
	return body, canonical
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
