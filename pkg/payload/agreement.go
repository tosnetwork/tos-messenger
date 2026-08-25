package payload

import (
	"bytes"
	"errors"

	"github.com/tosnetwork/tos-messenger/internal/canon"
	commerce "github.com/tosnetwork/tos-service-protocol/pkg/agentcommerce"
	protocolcodec "github.com/tosnetwork/tos-service-protocol/pkg/codec"
)

const MaxAgreementPromotionBytes = 96 << 10

// AgreementPropose carries an exact canonical Agreement body. It is distinct
// from negotiation.proposal: only this typed promotion can be considered by an
// Agreement coordinator, and the receiving Agent still has to authorize its
// own body-bound predicates.
type AgreementPropose struct {
	AgreementBodyDigest string
	CanonicalBody       []byte
}

func (AgreementPropose) Schema() string { return "tos.messaging.payload.agreement-propose.v1" }

func (proposal AgreementPropose) Validate() error {
	if !canon.ValidDigest(proposal.AgreementBodyDigest) || len(proposal.CanonicalBody) == 0 || len(proposal.CanonicalBody) > MaxAgreementPromotionBytes {
		return errors.New("Agreement proposal is invalid or oversized")
	}
	var body commerce.AgentAgreementBody
	if err := protocolcodec.Unmarshal(proposal.CanonicalBody, &body); err != nil {
		return err
	}
	if err := commerce.ValidateAgreementBody(body); err != nil {
		return err
	}
	digest, err := commerce.AgreementBodyDigest(body)
	if err != nil || digest != proposal.AgreementBodyDigest {
		return errors.New("Agreement proposal digest mismatch")
	}
	return nil
}

func (proposal AgreementPropose) encode(buffer *bytes.Buffer) {
	canon.Text(buffer, proposal.AgreementBodyDigest)
	canon.Bytes(buffer, proposal.CanonicalBody)
}

func decodeAgreementPropose(reader *canon.Reader) Payload {
	return AgreementPropose{AgreementBodyDigest: reader.Text(MaxDigestBytes), CanonicalBody: reader.Bytes(MaxAgreementPromotionBytes)}
}

// AgreementAccept carries the exact signed acceptance object. Its Agent
// signature and body-bound predicate targets are verified by the Agreement
// coordinator using finalized Agent state; Messenger does structural parsing
// so prose can never be confused with this event.
type AgreementAccept struct {
	AgreementBodyDigest string
	CanonicalAcceptance []byte
}

func (AgreementAccept) Schema() string { return "tos.messaging.payload.agreement-accept.v1" }

func (acceptance AgreementAccept) Validate() error {
	if !canon.ValidDigest(acceptance.AgreementBodyDigest) || len(acceptance.CanonicalAcceptance) == 0 || len(acceptance.CanonicalAcceptance) > MaxAgreementPromotionBytes {
		return errors.New("Agreement acceptance is invalid or oversized")
	}
	decoded, err := commerce.DecodeSignedAgreementAcceptance(acceptance.CanonicalAcceptance)
	if err != nil {
		return err
	}
	if decoded.Body.AgreementBodyDigest != acceptance.AgreementBodyDigest {
		return errors.New("Agreement acceptance digest mismatch")
	}
	return nil
}

func (acceptance AgreementAccept) encode(buffer *bytes.Buffer) {
	canon.Text(buffer, acceptance.AgreementBodyDigest)
	canon.Bytes(buffer, acceptance.CanonicalAcceptance)
}

func decodeAgreementAccept(reader *canon.Reader) Payload {
	return AgreementAccept{AgreementBodyDigest: reader.Text(MaxDigestBytes), CanonicalAcceptance: reader.Bytes(MaxAgreementPromotionBytes)}
}

// AgreementEvidence carries a profile-qualified authorization evidence object
// (for example a finalized chain acceptance). It is not an ordinary chat
// acceptance and remains subject to the receiver's installed profile verifier.
type AgreementEvidence struct {
	AgreementBodyDigest string
	EvidenceDigest      string
	CanonicalEvidence   []byte
}

func (AgreementEvidence) Schema() string { return "tos.messaging.payload.agreement-evidence.v1" }

func (evidence AgreementEvidence) Validate() error {
	if !canon.ValidDigest(evidence.AgreementBodyDigest) || !canon.ValidDigest(evidence.EvidenceDigest) ||
		len(evidence.CanonicalEvidence) == 0 || len(evidence.CanonicalEvidence) > MaxAgreementPromotionBytes {
		return errors.New("Agreement evidence is invalid or oversized")
	}
	var decoded commerce.AgreementAuthorizationEvidence
	if err := protocolcodec.Unmarshal(evidence.CanonicalEvidence, &decoded); err != nil ||
		decoded.AgreementBodyDigest != evidence.AgreementBodyDigest {
		return errors.New("Agreement evidence body mismatch")
	}
	digest, err := protocolcodec.Digest("tos.agreement-authorization-evidence.v1", decoded)
	if err != nil || digest != evidence.EvidenceDigest {
		return errors.New("Agreement evidence digest mismatch")
	}
	return nil
}

func (evidence AgreementEvidence) encode(buffer *bytes.Buffer) {
	canon.Text(buffer, evidence.AgreementBodyDigest)
	canon.Text(buffer, evidence.EvidenceDigest)
	canon.Bytes(buffer, evidence.CanonicalEvidence)
}

func decodeAgreementEvidence(reader *canon.Reader) Payload {
	return AgreementEvidence{AgreementBodyDigest: reader.Text(MaxDigestBytes), EvidenceDigest: reader.Text(MaxDigestBytes),
		CanonicalEvidence: reader.Bytes(MaxAgreementPromotionBytes)}
}

// PaidDemandProviderOffer transports the exact signed offer needed to build
// the deterministic pending escrow. Messenger validates structure and digest;
// delegated Provider authority is verified by the receiving Agent.
type PaidDemandProviderOffer struct {
	AgreementBodyDigest string
	ProviderOfferDigest string
	CanonicalOffer      []byte
}

func (PaidDemandProviderOffer) Schema() string {
	return "tos.messaging.payload.paid-demand-provider-offer.v1"
}

func (offer PaidDemandProviderOffer) Validate() error {
	if !canon.ValidDigest(offer.AgreementBodyDigest) || !canon.ValidDigest(offer.ProviderOfferDigest) ||
		len(offer.CanonicalOffer) == 0 || len(offer.CanonicalOffer) > MaxAgreementPromotionBytes {
		return errors.New("Paid Demand Provider Offer is invalid or oversized")
	}
	var decoded commerce.SignedProviderOffer
	if err := protocolcodec.Unmarshal(offer.CanonicalOffer, &decoded); err != nil ||
		decoded.Binding.AgreementBodyDigest != offer.AgreementBodyDigest {
		return errors.New("Paid Demand Provider Offer Agreement mismatch")
	}
	digest, err := commerce.ProviderOfferDigest(decoded)
	if err != nil || digest != offer.ProviderOfferDigest {
		return errors.New("Paid Demand Provider Offer digest mismatch")
	}
	return nil
}

func (offer PaidDemandProviderOffer) encode(buffer *bytes.Buffer) {
	canon.Text(buffer, offer.AgreementBodyDigest)
	canon.Text(buffer, offer.ProviderOfferDigest)
	canon.Bytes(buffer, offer.CanonicalOffer)
}

func decodePaidDemandProviderOffer(reader *canon.Reader) Payload {
	return PaidDemandProviderOffer{AgreementBodyDigest: reader.Text(MaxDigestBytes), ProviderOfferDigest: reader.Text(MaxDigestBytes),
		CanonicalOffer: reader.Bytes(MaxAgreementPromotionBytes)}
}

type AgreementWithdraw struct {
	AgreementBodyDigest string
	ProposalActionID    string
	Reason              string
}

func (AgreementWithdraw) Schema() string { return "tos.messaging.payload.agreement-withdraw.v1" }

func (withdrawal AgreementWithdraw) Validate() error {
	if !canon.ValidDigest(withdrawal.AgreementBodyDigest) || !canon.ValidDigest(withdrawal.ProposalActionID) {
		return errors.New("Agreement withdrawal does not bind its exact proposal")
	}
	return requireText("Agreement withdrawal reason", withdrawal.Reason, MaxShortTextBytes)
}

func (withdrawal AgreementWithdraw) encode(buffer *bytes.Buffer) {
	canon.Text(buffer, withdrawal.AgreementBodyDigest)
	canon.Text(buffer, withdrawal.ProposalActionID)
	canon.Text(buffer, withdrawal.Reason)
}

func decodeAgreementWithdraw(reader *canon.Reader) Payload {
	return AgreementWithdraw{AgreementBodyDigest: reader.Text(MaxDigestBytes), ProposalActionID: reader.Text(MaxDigestBytes), Reason: reader.Text(MaxShortTextBytes)}
}

// AgreementDelivery announces an immutable deliverable manifest for one exact
// obligation. It is evidence of release through Messenger, not evidence that
// the beneficiary accepted the work or that payment is due unless the
// Agreement's acceptance rule says so.
type AgreementDelivery struct {
	AgreementBodyDigest       string
	ObligationID              string
	DeliverableManifestDigest string
}

func (AgreementDelivery) Schema() string { return "tos.messaging.payload.agreement-delivery.v1" }

func (delivery AgreementDelivery) Validate() error {
	if !canon.ValidDigest(delivery.AgreementBodyDigest) || !canon.ValidDigest(delivery.DeliverableManifestDigest) {
		return errors.New("Agreement delivery digest is invalid")
	}
	return requireText("Agreement delivery obligation", delivery.ObligationID, MaxShortTextBytes)
}

func (delivery AgreementDelivery) encode(buffer *bytes.Buffer) {
	canon.Text(buffer, delivery.AgreementBodyDigest)
	canon.Text(buffer, delivery.ObligationID)
	canon.Text(buffer, delivery.DeliverableManifestDigest)
}

func decodeAgreementDelivery(reader *canon.Reader) Payload {
	return AgreementDelivery{AgreementBodyDigest: reader.Text(MaxDigestBytes), ObligationID: reader.Text(MaxShortTextBytes),
		DeliverableManifestDigest: reader.Text(MaxDigestBytes)}
}
