package payload

import "github.com/tosnetwork/tos-messenger/internal/canon"

// codecs binds every event kind to the body it carries.
//
// The table is the contract. A kind that appears in the event vocabulary and
// not here would be a kind whose body nothing can interpret, so the two tables
// are checked against each other rather than maintained in parallel by hand.
var codecs = map[string]codec{
	"text":                {schema: Text{}.Schema(), decode: decodeText},
	"conversation.invite": {schema: ConversationInvite{}.Schema(), decode: decodeConversationInvite},
	"conversation.accept": {schema: ConversationAccept{}.Schema(), decode: decodeConversationAccept},
	"presence.hint":       {schema: PresenceHint{}.Schema(), decode: decodePresenceHint},

	"agent.gift.address-request":  {schema: GiftAddressRequest{}.Schema(), decode: decodeGiftAddressRequest},
	"agent.gift.address-response": {schema: GiftAddressResponse{}.Schema(), decode: decodeGiftAddressResponse},
	"agent.gift.signed-boc-offer": {schema: GiftSignedBOCOffer{}.Schema(), decode: decodeGiftSignedBOCOffer},

	"agent.task.request":        {schema: TaskRequest{}.Schema(), decode: decodeTaskRequest},
	"agent.task.progress":       {schema: TaskProgress{}.Schema(), decode: decodeTaskProgress},
	"agent.task.result":         {schema: TaskResult{}.Schema(), decode: decodeTaskResult},
	"agent.task.status.request": {schema: TaskStatusRequest{}.Schema(), decode: decodeTaskStatusRequest},

	"negotiation.proposal":            {schema: NegotiationProposal{}.Schema(), decode: decodeNegotiationProposal},
	"negotiation.counterproposal":     {schema: NegotiationCounterproposal{}.Schema(), decode: decodeNegotiationCounterproposal},
	"negotiation.withdraw":            {schema: NegotiationWithdraw{}.Schema(), decode: decodeNegotiationWithdraw},
	"negotiation.intent.accept":       {schema: NegotiationIntentAccept{}.Schema(), decode: decodeNegotiationIntentAccept},
	"negotiation.intent.reject":       {schema: NegotiationIntentReject{}.Schema(), decode: decodeNegotiationIntentReject},
	"intent.application":              {schema: IntentApplication{}.Schema(), decode: decodeIntentApplication},
	"agreement.propose":               {schema: AgreementPropose{}.Schema(), decode: decodeAgreementPropose},
	"agreement.accept":                {schema: AgreementAccept{}.Schema(), decode: decodeAgreementAccept},
	"agreement.evidence":              {schema: AgreementEvidence{}.Schema(), decode: decodeAgreementEvidence},
	"agreement.withdraw":              {schema: AgreementWithdraw{}.Schema(), decode: decodeAgreementWithdraw},
	"agreement.delivery":              {schema: AgreementDelivery{}.Schema(), decode: decodeAgreementDelivery},
	"agreement.provider-offer":        {schema: PaidDemandProviderOffer{}.Schema(), decode: decodePaidDemandProviderOffer},
	"commerce.profile-event":          {schema: CommerceProfileEvent{}.Schema(), decode: decodeCommerceProfileEvent},
	"operation.outcome":               {schema: OperationOutcome{}.Schema(), decode: decodeOperationOutcome},
	"private.handoff.challenge":       {schema: PrivateHandoffChallenge{}.Schema(), decode: decodePrivateHandoffChallenge},
	"private.handoff.authorization":   {schema: PrivateHandoffAuthorization{}.Schema(), decode: decodePrivateHandoffAuthorization},
	"private.handoff.acknowledgement": {schema: PrivateHandoffAcknowledgement{}.Schema(), decode: decodePrivateHandoffAcknowledgement},
	"private.handoff.status":          {schema: PrivateHandoffStatus{}.Schema(), decode: decodePrivateHandoffStatus},
	"private.handoff.delete":          {schema: PrivateHandoffDelete{}.Schema(), decode: decodePrivateHandoffDelete},

	"counterparty.approval.request": {schema: CounterpartyApprovalRequest{}.Schema(), decode: decodeCounterpartyApprovalRequest},
	"counterparty.approval.granted": {schema: CounterpartyApprovalGranted{}.Schema(), decode: decodeCounterpartyApprovalGranted},
	"counterparty.approval.denied":  {schema: CounterpartyApprovalDenied{}.Schema(), decode: decodeCounterpartyApprovalDenied},

	"owner.approval.grant": {schema: OwnerApprovalGrant{}.Schema(), decode: decodeOwnerApprovalGrant},
	"owner.approval.deny":  {schema: OwnerApprovalDeny{}.Schema(), decode: decodeOwnerApprovalDeny},

	"a2a.message":  {schema: A2AMessage{}.Schema(), decode: decodeA2AMessage},
	"mcp.call":     {schema: MCPCall{}.Schema(), decode: decodeMCPCall},
	"mcp.result":   {schema: MCPResult{}.Schema(), decode: decodeMCPResult},
	"agent.packet": {schema: AgentPacketMessage{}.Schema(), decode: decodeAgentPacketMessage},

	"artifact.offer":     {schema: ArtifactOffer{}.Schema(), decode: decodeArtifactOffer},
	"artifact.reference": {schema: ArtifactReference{}.Schema(), decode: decodeArtifactReference},
	"artifact.encrypted": {schema: EncryptedAttachment{}.Schema(), decode: decodeEncryptedAttachment,
		legacy: map[string]func(*canon.Reader) Payload{encryptedAttachmentV1Schema: decodeEncryptedAttachmentV1,
			encryptedAttachmentV2Schema: decodeEncryptedAttachmentV2}},

	"service.quote.reference":   {schema: QuoteReference{}.Schema(), decode: decodeQuoteReference},
	"service.escrow.reference":  {schema: EscrowReference{}.Schema(), decode: decodeEscrowReference},
	"service.receipt.reference": {schema: ReceiptReference{}.Schema(), decode: decodeReceiptReference},

	"delivery.ack":           {schema: DeliveryAck{}.Schema(), decode: decodeDeliveryAck},
	"application.ack":        {schema: ApplicationAck{}.Schema(), decode: decodeApplicationAck},
	"read.ack":               {schema: ReadAck{}.Schema(), decode: decodeReadAck},
	"device.history.segment": {schema: DeviceHistorySegment{}.Schema(), decode: decodeDeviceHistorySegment},

	"room.invite":            {schema: RoomInvite{}.Schema(), decode: decodeRoomInvite},
	"room.membership.commit": {schema: RoomMembershipCommit{}.Schema(), decode: decodeRoomMembershipCommit},
	"room.message":           {schema: RoomMessage{}.Schema(), decode: decodeRoomMessage},
	"room.moderation":        {schema: RoomModeration{}.Schema(), decode: decodeRoomModeration},
}
