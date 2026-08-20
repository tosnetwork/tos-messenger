package payload

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

	"agent.task.request":        {schema: TaskRequest{}.Schema(), decode: decodeTaskRequest},
	"agent.task.progress":       {schema: TaskProgress{}.Schema(), decode: decodeTaskProgress},
	"agent.task.result":         {schema: TaskResult{}.Schema(), decode: decodeTaskResult},
	"agent.task.status.request": {schema: TaskStatusRequest{}.Schema(), decode: decodeTaskStatusRequest},

	"negotiation.proposal":        {schema: NegotiationProposal{}.Schema(), decode: decodeNegotiationProposal},
	"negotiation.counterproposal": {schema: NegotiationCounterproposal{}.Schema(), decode: decodeNegotiationCounterproposal},
	"negotiation.withdraw":        {schema: NegotiationWithdraw{}.Schema(), decode: decodeNegotiationWithdraw},
	"negotiation.intent.accept":   {schema: NegotiationIntentAccept{}.Schema(), decode: decodeNegotiationIntentAccept},
	"negotiation.intent.reject":   {schema: NegotiationIntentReject{}.Schema(), decode: decodeNegotiationIntentReject},

	"counterparty.approval.request": {schema: CounterpartyApprovalRequest{}.Schema(), decode: decodeCounterpartyApprovalRequest},
	"counterparty.approval.granted": {schema: CounterpartyApprovalGranted{}.Schema(), decode: decodeCounterpartyApprovalGranted},
	"counterparty.approval.denied":  {schema: CounterpartyApprovalDenied{}.Schema(), decode: decodeCounterpartyApprovalDenied},

	"owner.approval.grant": {schema: OwnerApprovalGrant{}.Schema(), decode: decodeOwnerApprovalGrant},
	"owner.approval.deny":  {schema: OwnerApprovalDeny{}.Schema(), decode: decodeOwnerApprovalDeny},

	"a2a.message": {schema: A2AMessage{}.Schema(), decode: decodeA2AMessage},
	"mcp.call":    {schema: MCPCall{}.Schema(), decode: decodeMCPCall},
	"mcp.result":  {schema: MCPResult{}.Schema(), decode: decodeMCPResult},

	"artifact.offer":     {schema: ArtifactOffer{}.Schema(), decode: decodeArtifactOffer},
	"artifact.reference": {schema: ArtifactReference{}.Schema(), decode: decodeArtifactReference},

	"service.quote.reference":   {schema: QuoteReference{}.Schema(), decode: decodeQuoteReference},
	"service.escrow.reference":  {schema: EscrowReference{}.Schema(), decode: decodeEscrowReference},
	"service.receipt.reference": {schema: ReceiptReference{}.Schema(), decode: decodeReceiptReference},

	"delivery.ack":    {schema: DeliveryAck{}.Schema(), decode: decodeDeliveryAck},
	"application.ack": {schema: ApplicationAck{}.Schema(), decode: decodeApplicationAck},
	"read.ack":        {schema: ReadAck{}.Schema(), decode: decodeReadAck},

	"room.invite":            {schema: RoomInvite{}.Schema(), decode: decodeRoomInvite},
	"room.membership.commit": {schema: RoomMembershipCommit{}.Schema(), decode: decodeRoomMembershipCommit},
	"room.message":           {schema: RoomMessage{}.Schema(), decode: decodeRoomMessage},
}
