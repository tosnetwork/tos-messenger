package localapi

import (
	"crypto/ed25519"
	"strings"
	"testing"

	commerce "github.com/tosnetwork/tos-service-protocol/pkg/agentcommerce"
	"github.com/tosnetwork/tos-service-protocol/pkg/codec"
)

func TestOperationPrivateSendEffectReDerivesPayloadIdentity(t *testing.T) {
	digest := func(fill string) string { return "sha256:" + strings.Repeat(fill, 64) }
	actor := "agent:sender"
	assertion, err := codec.Marshal(commerce.ActionResolutionReferencePayloadV1{
		StableActionID: digest("1"), ExactRequestDigest: digest("2"), AuthorizedActionDigest: digest("3"),
		ActionResolutionDigest: digest("4"), ResolutionState: commerce.ActionRejected, ResolutionStateRevision: 1})
	if err != nil {
		t.Fatal(err)
	}
	event, err := commerce.BuildOperationOutcomeEventV1(commerce.OutcomeObservation,
		commerce.OutcomeSubjectRefV1{SubjectProfileURI: "tos.subject.semantic-action.v1", SubjectID: digest("1")}, nil,
		commerce.OutcomeProfileActionResolutionReference, assertion,
		commerce.EmptyOutcomeEvidenceManifestV1("unverified_reference"), commerce.EmptyOutcomeExtensionSetV1())
	if err != nil {
		t.Fatal(err)
	}
	contentID, eventPayload, err := commerce.OperationOutcomeEventContentIDV1(event)
	if err != nil {
		t.Fatal(err)
	}
	key := ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize))
	body := commerce.AgentOperationBodyV1{SchemaVersion: 1, NetworkID: "tos:test", OpcodeNamespace: "OPERATION", OpcodeName: "OUTCOME", OpcodeVersion: 1,
		ActorAgentID: actor, AuthorizationRef: commerce.ProfileRefV1{ProfileURI: "tos.identity.agent-key.v1", ProfileVersion: 1, ProfileDigest: digest("5")},
		AudienceDescriptor: "named-recipient", ObjectID: contentID, OrderingDomain: digest("6"), Epoch: 1, Sequence: 1,
		CreatedAtUnix: 1_900_000_000, PayloadProfile: commerce.OperationOutcomeProfileRefV1(), PayloadDigest: contentID, PayloadSize: uint64(len(eventPayload))}
	body.OperationID, err = commerce.DeriveAgentOperationIDV1(body)
	if err != nil {
		t.Fatal(err)
	}
	envelope, err := commerce.SignAgentOperationV1(body, actor, key, []byte("proof"))
	if err != nil {
		t.Fatal(err)
	}
	envelopeBytes, envelopeDigest, err := commerce.MarshalAgentOperationEnvelopeV1(envelope)
	if err != nil {
		t.Fatal(err)
	}
	recipients := []string{"agent:recipient"}
	recipientSetDigest, err := codec.Digest("tos.messenger-recipient-set.v1", recipients)
	if err != nil {
		t.Fatal(err)
	}
	private := commerce.OperationPrivateRequestV1{SchemaVersion: 1, RecipientSetDigest: recipientSetDigest,
		RecipientAgentIDs: recipients, MembershipEpoch: 1, AudiencePolicyDigest: digest("7"), OperationID: body.OperationID,
		OperationEnvelopeDigest: envelopeDigest, ConversationScopeDigest: digest("8"),
		TransportProfile:  commerce.ProfileRefV1{ProfileURI: "tos.messenger.operation-outcome.v1", ProfileVersion: 1, ProfileDigest: digest("9")},
		OperationEnvelope: envelopeBytes, EventPayload: eventPayload,
		Artifacts: commerce.OperationOutcomeArtifactBundleV1{AssertionPayload: assertion,
			EvidenceManifest: commerce.EmptyOutcomeEvidenceManifestV1("unverified_reference"),
			ExtensionSet:     commerce.EmptyOutcomeExtensionSetV1(), AuthorityProofs: []commerce.OutcomeAuthorityProofMaterialV1{}}}
	privateBytes, err := codec.Marshal(private)
	if err != nil {
		t.Fatal(err)
	}
	action := commerce.AuthorizedAction{OwnerID: "owner:test", AgentID: actor, ActionKind: "operation.private-send"}
	fields, err := commerce.OperationPrivateSendSemanticFieldsV1(action.OwnerID, action.AgentID, private)
	if err != nil {
		t.Fatal(err)
	}
	effect := commerce.MessengerEffectRequestV1{SchemaVersion: 1, RecipientAgentIDs: recipients, EventKind: "operation.outcome",
		ContentType: "application/vnd.tos.operation-outcome-private+cbor", Payload: privateBytes}
	if err := validateOperationPrivateSendEffect(action, effect, fields); err != nil {
		t.Fatalf("valid operation private-send rejected: %v", err)
	}

	substitutedFields := make(map[string]commerce.SemanticValue, len(fields))
	for name, value := range fields {
		substitutedFields[name] = value
	}
	substitutedFields["operation_id"] = commerce.Digest32(digest("a"))
	if err := validateOperationPrivateSendEffect(action, effect, substitutedFields); err == nil {
		t.Fatal("Messenger accepted semantic fields for a different Operation")
	}
	substitutedEffect := effect
	substitutedEffect.RecipientAgentIDs = []string{"agent:other"}
	if err := validateOperationPrivateSendEffect(action, substitutedEffect, fields); err == nil {
		t.Fatal("Messenger accepted a recipient outside the private request")
	}
	impersonating := action
	impersonating.AgentID = "agent:other"
	if err := validateOperationPrivateSendEffect(impersonating, effect, fields); err == nil {
		t.Fatal("Messenger accepted an Operation issued by another Agent")
	}
}
