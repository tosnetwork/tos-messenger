package payload

import (
	"bytes"
	"errors"
	"time"

	"github.com/tosnetwork/tos-messenger/internal/canon"
	commerce "github.com/tosnetwork/tos-service-protocol/pkg/agentcommerce"
	protocolcodec "github.com/tosnetwork/tos-service-protocol/pkg/codec"
)

const MaxPrivateHandoffControlBytes = 96 << 10

type PrivateHandoffChallenge struct {
	ChallengeDigest    string
	CanonicalChallenge []byte
}

func (PrivateHandoffChallenge) Schema() string {
	return "tos.messaging.payload.private-handoff-challenge.v1"
}
func (value PrivateHandoffChallenge) Validate() error {
	if !canon.ValidDigest(value.ChallengeDigest) || len(value.CanonicalChallenge) == 0 || len(value.CanonicalChallenge) > MaxPrivateHandoffControlBytes {
		return errors.New("private handoff challenge payload is invalid")
	}
	var challenge commerce.SignedPrivateHandoffChallenge
	if err := protocolcodec.Unmarshal(value.CanonicalChallenge, &challenge); err != nil {
		return err
	}
	if err := commerce.ValidatePrivateHandoffChallenge(challenge.Body, time.Unix(int64(challenge.Body.IssuedAtUnix), 0).UTC()); err != nil {
		return err
	}
	digest, err := commerce.PrivateHandoffChallengeDigest(challenge.Body)
	if err != nil || digest != value.ChallengeDigest {
		return errors.New("private handoff challenge digest mismatch")
	}
	return nil
}
func (value PrivateHandoffChallenge) encode(buffer *bytes.Buffer) {
	canon.Text(buffer, value.ChallengeDigest)
	canon.Bytes(buffer, value.CanonicalChallenge)
}
func decodePrivateHandoffChallenge(reader *canon.Reader) Payload {
	return PrivateHandoffChallenge{ChallengeDigest: reader.Text(MaxDigestBytes), CanonicalChallenge: reader.Bytes(MaxPrivateHandoffControlBytes)}
}

type PrivateHandoffAuthorization struct {
	ChallengeDigest        string
	AuthorizationDigest    string
	CanonicalAuthorization []byte
}

func (PrivateHandoffAuthorization) Schema() string {
	return "tos.messaging.payload.private-handoff-authorization.v1"
}
func (value PrivateHandoffAuthorization) Validate() error {
	if !canon.ValidDigest(value.ChallengeDigest) || !canon.ValidDigest(value.AuthorizationDigest) ||
		len(value.CanonicalAuthorization) == 0 || len(value.CanonicalAuthorization) > MaxPrivateHandoffControlBytes {
		return errors.New("private handoff authorization payload is invalid")
	}
	var authorization commerce.SignedPrivateHandoffAuthorization
	if err := protocolcodec.Unmarshal(value.CanonicalAuthorization, &authorization); err != nil {
		return err
	}
	digest, err := commerce.PrivateHandoffAuthorizationDigest(authorization.Body)
	if err != nil || digest != value.AuthorizationDigest || authorization.Body.ChallengeDigest != value.ChallengeDigest {
		return errors.New("private handoff authorization digest mismatch")
	}
	return nil
}
func (value PrivateHandoffAuthorization) encode(buffer *bytes.Buffer) {
	canon.Text(buffer, value.ChallengeDigest)
	canon.Text(buffer, value.AuthorizationDigest)
	canon.Bytes(buffer, value.CanonicalAuthorization)
}
func decodePrivateHandoffAuthorization(reader *canon.Reader) Payload {
	return PrivateHandoffAuthorization{ChallengeDigest: reader.Text(MaxDigestBytes), AuthorizationDigest: reader.Text(MaxDigestBytes),
		CanonicalAuthorization: reader.Bytes(MaxPrivateHandoffControlBytes)}
}

type PrivateHandoffAcknowledgement struct {
	ChallengeDigest          string
	AcknowledgementDigest    string
	CanonicalAcknowledgement []byte
}

func (PrivateHandoffAcknowledgement) Schema() string {
	return "tos.messaging.payload.private-handoff-acknowledgement.v1"
}
func (value PrivateHandoffAcknowledgement) Validate() error {
	if !canon.ValidDigest(value.ChallengeDigest) || !canon.ValidDigest(value.AcknowledgementDigest) ||
		len(value.CanonicalAcknowledgement) == 0 || len(value.CanonicalAcknowledgement) > MaxPrivateHandoffControlBytes {
		return errors.New("private handoff acknowledgement payload is invalid")
	}
	var acknowledgement commerce.SignedPrivateHandoffAcknowledgement
	if err := protocolcodec.Unmarshal(value.CanonicalAcknowledgement, &acknowledgement); err != nil {
		return err
	}
	digest, err := commerce.PrivateHandoffAcknowledgementDigest(acknowledgement)
	if err != nil || digest != value.AcknowledgementDigest || acknowledgement.Record.ChallengeDigest != value.ChallengeDigest {
		return errors.New("private handoff acknowledgement digest mismatch")
	}
	return nil
}
func (value PrivateHandoffAcknowledgement) encode(buffer *bytes.Buffer) {
	canon.Text(buffer, value.ChallengeDigest)
	canon.Text(buffer, value.AcknowledgementDigest)
	canon.Bytes(buffer, value.CanonicalAcknowledgement)
}
func decodePrivateHandoffAcknowledgement(reader *canon.Reader) Payload {
	return PrivateHandoffAcknowledgement{ChallengeDigest: reader.Text(MaxDigestBytes), AcknowledgementDigest: reader.Text(MaxDigestBytes),
		CanonicalAcknowledgement: reader.Bytes(MaxPrivateHandoffControlBytes)}
}

type PrivateHandoffStatus struct {
	HandoffID      string
	ActionID       string
	State          string
	EvidenceDigest string
}

func (PrivateHandoffStatus) Schema() string { return "tos.messaging.payload.private-handoff-status.v1" }
func (value PrivateHandoffStatus) Validate() error {
	if err := requireText("private handoff ID", value.HandoffID, MaxShortTextBytes); err != nil {
		return err
	}
	if err := requireDigest("private handoff action ID", value.ActionID); err != nil {
		return err
	}
	if err := requireMatch("private handoff state", value.State, tokenPattern); err != nil {
		return err
	}
	return optionalDigest("private handoff evidence", value.EvidenceDigest)
}
func (value PrivateHandoffStatus) encode(buffer *bytes.Buffer) {
	canon.Text(buffer, value.HandoffID)
	canon.Text(buffer, value.ActionID)
	canon.Text(buffer, value.State)
	canon.Text(buffer, value.EvidenceDigest)
}
func decodePrivateHandoffStatus(reader *canon.Reader) Payload {
	return PrivateHandoffStatus{HandoffID: reader.Text(MaxShortTextBytes), ActionID: reader.Text(MaxDigestBytes), State: reader.Text(MaxShortTextBytes), EvidenceDigest: reader.Text(MaxDigestBytes)}
}

type PrivateHandoffDelete struct {
	HandoffID             string
	ContentManifestDigest string
	RetentionPolicyDigest string
	DeleteActionID        string
}

func (PrivateHandoffDelete) Schema() string { return "tos.messaging.payload.private-handoff-delete.v1" }
func (value PrivateHandoffDelete) Validate() error {
	if err := requireText("private handoff ID", value.HandoffID, MaxShortTextBytes); err != nil {
		return err
	}
	for name, digest := range map[string]string{"content manifest": value.ContentManifestDigest, "retention policy": value.RetentionPolicyDigest, "delete action": value.DeleteActionID} {
		if err := requireDigest(name, digest); err != nil {
			return err
		}
	}
	return nil
}
func (value PrivateHandoffDelete) encode(buffer *bytes.Buffer) {
	canon.Text(buffer, value.HandoffID)
	canon.Text(buffer, value.ContentManifestDigest)
	canon.Text(buffer, value.RetentionPolicyDigest)
	canon.Text(buffer, value.DeleteActionID)
}
func decodePrivateHandoffDelete(reader *canon.Reader) Payload {
	return PrivateHandoffDelete{HandoffID: reader.Text(MaxShortTextBytes), ContentManifestDigest: reader.Text(MaxDigestBytes),
		RetentionPolicyDigest: reader.Text(MaxDigestBytes), DeleteActionID: reader.Text(MaxDigestBytes)}
}
