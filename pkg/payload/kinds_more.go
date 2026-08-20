package payload

import (
	"bytes"
	"errors"

	"github.com/tosnetwork/tos-messenger/internal/canon"
	"github.com/tosnetwork/tos-messenger/internal/ids"
	"github.com/tosnetwork/tos-messenger/pkg/attachments"
)

// CounterpartyApprovalRequest asks the other party to approve something on
// their own side. It is a request, and the answer that comes back is that
// party's account of their own decision, not authority here.
type CounterpartyApprovalRequest struct {
	ApprovalID string
	Subject    string
	Detail     string
}

// Schema implements Payload.
func (CounterpartyApprovalRequest) Schema() string {
	return "tos.messaging.payload.counterparty-approval-request.v1"
}

// Validate implements Payload.
func (c CounterpartyApprovalRequest) Validate() error {
	if err := requireText("approval identifier", c.ApprovalID, MaxShortTextBytes); err != nil {
		return err
	}
	if err := requireMatch("subject", c.Subject, tokenPattern); err != nil {
		return err
	}
	return optionalText("detail", c.Detail, MaxShortTextBytes)
}

func (c CounterpartyApprovalRequest) encode(buffer *bytes.Buffer) {
	canon.Text(buffer, c.ApprovalID)
	canon.Text(buffer, c.Subject)
	canon.Text(buffer, c.Detail)
}

func decodeCounterpartyApprovalRequest(reader *canon.Reader) Payload {
	return CounterpartyApprovalRequest{
		ApprovalID: reader.Text(MaxShortTextBytes),
		Subject:    reader.Text(MaxShortTextBytes),
		Detail:     reader.Text(MaxShortTextBytes),
	}
}

// CounterpartyApprovalGranted reports what the other party decided.
//
// It authorises nothing here. A remote Agent saying "approved" is information
// about their side; anything that needed authority on this side still needs an
// owner approval, which is a kind that cannot arrive from the network at all.
type CounterpartyApprovalGranted struct {
	ApprovalID    string
	DecidedAtUnix uint64
}

// Schema implements Payload.
func (CounterpartyApprovalGranted) Schema() string {
	return "tos.messaging.payload.counterparty-approval-granted.v1"
}

// Validate implements Payload.
func (c CounterpartyApprovalGranted) Validate() error {
	if err := requireText("approval identifier", c.ApprovalID, MaxShortTextBytes); err != nil {
		return err
	}
	return requireTime("decision time", c.DecidedAtUnix)
}

func (c CounterpartyApprovalGranted) encode(buffer *bytes.Buffer) {
	canon.Text(buffer, c.ApprovalID)
	canon.Uint64(buffer, c.DecidedAtUnix)
}

func decodeCounterpartyApprovalGranted(reader *canon.Reader) Payload {
	return CounterpartyApprovalGranted{
		ApprovalID:    reader.Text(MaxShortTextBytes),
		DecidedAtUnix: reader.Uint64(),
	}
}

// CounterpartyApprovalDenied reports a refusal on the other side.
type CounterpartyApprovalDenied struct {
	ApprovalID    string
	DecidedAtUnix uint64
	Reason        string
}

// Schema implements Payload.
func (CounterpartyApprovalDenied) Schema() string {
	return "tos.messaging.payload.counterparty-approval-denied.v1"
}

// Validate implements Payload.
func (c CounterpartyApprovalDenied) Validate() error {
	if err := requireText("approval identifier", c.ApprovalID, MaxShortTextBytes); err != nil {
		return err
	}
	if err := requireTime("decision time", c.DecidedAtUnix); err != nil {
		return err
	}
	return optionalText("reason", c.Reason, MaxShortTextBytes)
}

func (c CounterpartyApprovalDenied) encode(buffer *bytes.Buffer) {
	canon.Text(buffer, c.ApprovalID)
	canon.Uint64(buffer, c.DecidedAtUnix)
	canon.Text(buffer, c.Reason)
}

func decodeCounterpartyApprovalDenied(reader *canon.Reader) Payload {
	return CounterpartyApprovalDenied{
		ApprovalID:    reader.Text(MaxShortTextBytes),
		DecidedAtUnix: reader.Uint64(),
		Reason:        reader.Text(MaxShortTextBytes),
	}
}

// OwnerApprovalGrant is this owner authorising an action here.
//
// It is local-only: the kind is not expressible on the wire, and the codec
// exists so the local interface has the same typed contract as everything
// else, not so the body can travel.
type OwnerApprovalGrant struct {
	ApprovalID    string
	EventID       string
	DecidedAtUnix uint64
}

// Schema implements Payload.
func (OwnerApprovalGrant) Schema() string {
	return "tos.messaging.payload.owner-approval-grant.v1"
}

// Validate implements Payload.
func (o OwnerApprovalGrant) Validate() error {
	if err := requireText("approval identifier", o.ApprovalID, MaxShortTextBytes); err != nil {
		return err
	}
	if err := requireEvent("approved event", o.EventID); err != nil {
		return err
	}
	return requireTime("decision time", o.DecidedAtUnix)
}

func (o OwnerApprovalGrant) encode(buffer *bytes.Buffer) {
	canon.Text(buffer, o.ApprovalID)
	canon.Text(buffer, o.EventID)
	canon.Uint64(buffer, o.DecidedAtUnix)
}

func decodeOwnerApprovalGrant(reader *canon.Reader) Payload {
	return OwnerApprovalGrant{
		ApprovalID:    reader.Text(MaxShortTextBytes),
		EventID:       reader.Text(MaxShortTextBytes),
		DecidedAtUnix: reader.Uint64(),
	}
}

// OwnerApprovalDeny is this owner refusing an action here.
type OwnerApprovalDeny struct {
	ApprovalID    string
	EventID       string
	DecidedAtUnix uint64
	Reason        string
}

// Schema implements Payload.
func (OwnerApprovalDeny) Schema() string {
	return "tos.messaging.payload.owner-approval-deny.v1"
}

// Validate implements Payload.
func (o OwnerApprovalDeny) Validate() error {
	if err := requireText("approval identifier", o.ApprovalID, MaxShortTextBytes); err != nil {
		return err
	}
	if err := requireEvent("refused event", o.EventID); err != nil {
		return err
	}
	if err := requireTime("decision time", o.DecidedAtUnix); err != nil {
		return err
	}
	return optionalText("reason", o.Reason, MaxShortTextBytes)
}

func (o OwnerApprovalDeny) encode(buffer *bytes.Buffer) {
	canon.Text(buffer, o.ApprovalID)
	canon.Text(buffer, o.EventID)
	canon.Uint64(buffer, o.DecidedAtUnix)
	canon.Text(buffer, o.Reason)
}

func decodeOwnerApprovalDeny(reader *canon.Reader) Payload {
	return OwnerApprovalDeny{
		ApprovalID:    reader.Text(MaxShortTextBytes),
		EventID:       reader.Text(MaxShortTextBytes),
		DecidedAtUnix: reader.Uint64(),
		Reason:        reader.Text(MaxShortTextBytes),
	}
}

// Foreign carries a message belonging to a protocol this one does not define.
//
// The wrapper is typed even though the body is not: naming the protocol and
// its version is what lets a recipient decide whether it can interpret the
// body at all, instead of guessing from the bytes. The body itself stays
// opaque and untrusted, which is the honest description of somebody else's
// message.
type Foreign struct {
	Protocol string
	Version  string
	Body     []byte
}

func (f Foreign) validate() error {
	if err := requireMatch("protocol", f.Protocol, protocolPattern); err != nil {
		return err
	}
	if err := requireText("protocol version", f.Version, MaxShortTextBytes); err != nil {
		return err
	}
	if len(f.Body) == 0 {
		return errors.New("a carried message has no body")
	}
	if len(f.Body) > MaxOpaqueBytes {
		return errors.New("a carried message exceeds its bound")
	}
	return nil
}

func (f Foreign) encode(buffer *bytes.Buffer) {
	canon.Text(buffer, f.Protocol)
	canon.Text(buffer, f.Version)
	canon.Bytes(buffer, f.Body)
}

func decodeForeign(reader *canon.Reader) Foreign {
	return Foreign{
		Protocol: reader.Text(MaxShortTextBytes),
		Version:  reader.Text(MaxShortTextBytes),
		Body:     reader.Bytes(MaxOpaqueBytes),
	}
}

// A2AMessage carries an agent-to-agent protocol message.
type A2AMessage struct{ Foreign }

// Schema implements Payload.
func (A2AMessage) Schema() string { return "tos.messaging.payload.a2a-message.v1" }

// Validate implements Payload.
func (a A2AMessage) Validate() error { return a.Foreign.validate() }

func decodeA2AMessage(reader *canon.Reader) Payload {
	return A2AMessage{Foreign: decodeForeign(reader)}
}

// MCPCall carries a tool-protocol call.
type MCPCall struct{ Foreign }

// Schema implements Payload.
func (MCPCall) Schema() string { return "tos.messaging.payload.mcp-call.v1" }

// Validate implements Payload.
func (m MCPCall) Validate() error { return m.Foreign.validate() }

func decodeMCPCall(reader *canon.Reader) Payload {
	return MCPCall{Foreign: decodeForeign(reader)}
}

// MCPResult carries a tool-protocol result.
type MCPResult struct{ Foreign }

// Schema implements Payload.
func (MCPResult) Schema() string { return "tos.messaging.payload.mcp-result.v1" }

// Validate implements Payload.
func (m MCPResult) Validate() error { return m.Foreign.validate() }

func decodeMCPResult(reader *canon.Reader) Payload {
	return MCPResult{Foreign: decodeForeign(reader)}
}

// ArtifactOffer says an artifact exists and what it is, without moving it.
type ArtifactOffer struct {
	ArtifactDigest string
	MediaType      string
	SizeBytes      uint64
	Description    string
}

// Schema implements Payload.
func (ArtifactOffer) Schema() string { return "tos.messaging.payload.artifact-offer.v1" }

// Validate implements Payload.
func (a ArtifactOffer) Validate() error {
	if err := requireDigest("artifact digest", a.ArtifactDigest); err != nil {
		return err
	}
	if err := requireText("media type", a.MediaType, MaxShortTextBytes); err != nil {
		return err
	}
	if a.SizeBytes == 0 {
		return errors.New("an offered artifact has no size")
	}
	return optionalText("description", a.Description, MaxShortTextBytes)
}

func (a ArtifactOffer) encode(buffer *bytes.Buffer) {
	canon.Text(buffer, a.ArtifactDigest)
	canon.Text(buffer, a.MediaType)
	canon.Uint64(buffer, a.SizeBytes)
	canon.Text(buffer, a.Description)
}

func decodeArtifactOffer(reader *canon.Reader) Payload {
	return ArtifactOffer{
		ArtifactDigest: reader.Text(MaxDigestBytes),
		MediaType:      reader.Text(MaxShortTextBytes),
		SizeBytes:      reader.Uint64(),
		Description:    reader.Text(MaxShortTextBytes),
	}
}

// ArtifactReference points at an artifact by digest and says where a copy may
// be fetched. The locator is a hint; the digest is the artifact's identity, so
// a wrong locator produces a failed fetch rather than the wrong bytes.
type ArtifactReference struct {
	ArtifactDigest string
	Locator        string
}

// Schema implements Payload.
func (ArtifactReference) Schema() string {
	return "tos.messaging.payload.artifact-reference.v1"
}

// Validate implements Payload.
func (a ArtifactReference) Validate() error {
	if err := requireDigest("artifact digest", a.ArtifactDigest); err != nil {
		return err
	}
	return requireText("locator", a.Locator, MaxShortTextBytes)
}

func (a ArtifactReference) encode(buffer *bytes.Buffer) {
	canon.Text(buffer, a.ArtifactDigest)
	canon.Text(buffer, a.Locator)
}

func decodeArtifactReference(reader *canon.Reader) Payload {
	return ArtifactReference{
		ArtifactDigest: reader.Text(MaxDigestBytes),
		Locator:        reader.Text(MaxShortTextBytes),
	}
}

// EncryptedAttachment carries the secret attachment Reference inside E2EE and
// an untrusted retrieval hint. The outer Event must repeat ManifestDigest in
// attachment_references; envelope validation enforces that equality.
type EncryptedAttachment struct {
	ManifestDigest string
	ReferenceJSON  []byte
	Locator        string
}

func (EncryptedAttachment) Schema() string {
	return "tos.messaging.payload.encrypted-attachment.v1"
}

func (a EncryptedAttachment) Validate() error {
	if err := requireDigest("attachment manifest digest", a.ManifestDigest); err != nil {
		return err
	}
	if len(a.ReferenceJSON) == 0 || len(a.ReferenceJSON) > MaxOpaqueBytes {
		return errors.New("invalid encrypted attachment reference size")
	}
	reference, err := attachments.DecodeReferenceJSON(a.ReferenceJSON)
	if err != nil {
		return err
	}
	digest, err := attachments.ManifestDigest(reference.Manifest)
	if err != nil || digest != a.ManifestDigest {
		return errors.New("encrypted attachment reference does not match its manifest digest")
	}
	return requireText("attachment locator", a.Locator, MaxShortTextBytes)
}

func (a EncryptedAttachment) encode(buffer *bytes.Buffer) {
	canon.Text(buffer, a.ManifestDigest)
	canon.Bytes(buffer, a.ReferenceJSON)
	canon.Text(buffer, a.Locator)
}

func decodeEncryptedAttachment(reader *canon.Reader) Payload {
	return EncryptedAttachment{ManifestDigest: reader.Text(MaxDigestBytes), ReferenceJSON: reader.Bytes(MaxOpaqueBytes), Locator: reader.Text(MaxShortTextBytes)}
}

// ChainReference points at finalized state. It carries no authority of its
// own: the recipient resolves the reference against the chain, and what the
// chain says is what is true. A reference that disagreed with finalized state
// would simply be wrong, not persuasive.
type ChainReference struct {
	Account     string
	StateDigest string
}

func (c ChainReference) validate() error {
	if err := requireText("account", c.Account, MaxShortTextBytes); err != nil {
		return err
	}
	return requireDigest("state digest", c.StateDigest)
}

func (c ChainReference) encode(buffer *bytes.Buffer) {
	canon.Text(buffer, c.Account)
	canon.Text(buffer, c.StateDigest)
}

func decodeChainReference(reader *canon.Reader) ChainReference {
	return ChainReference{
		Account:     reader.Text(MaxShortTextBytes),
		StateDigest: reader.Text(MaxDigestBytes),
	}
}

// QuoteReference points at an Accepted Quote in finalized state.
type QuoteReference struct{ ChainReference }

// Schema implements Payload.
func (QuoteReference) Schema() string { return "tos.messaging.payload.quote-reference.v1" }

// Validate implements Payload.
func (q QuoteReference) Validate() error { return q.ChainReference.validate() }

func decodeQuoteReference(reader *canon.Reader) Payload {
	return QuoteReference{ChainReference: decodeChainReference(reader)}
}

// EscrowReference points at an escrow in finalized state.
type EscrowReference struct{ ChainReference }

// Schema implements Payload.
func (EscrowReference) Schema() string { return "tos.messaging.payload.escrow-reference.v1" }

// Validate implements Payload.
func (e EscrowReference) Validate() error { return e.ChainReference.validate() }

func decodeEscrowReference(reader *canon.Reader) Payload {
	return EscrowReference{ChainReference: decodeChainReference(reader)}
}

// ReceiptReference points at a Receipt in finalized state.
type ReceiptReference struct{ ChainReference }

// Schema implements Payload.
func (ReceiptReference) Schema() string { return "tos.messaging.payload.receipt-reference.v1" }

// Validate implements Payload.
func (r ReceiptReference) Validate() error { return r.ChainReference.validate() }

func decodeReceiptReference(reader *canon.Reader) Payload {
	return ReceiptReference{ChainReference: decodeChainReference(reader)}
}

// DeliveryAck says an event arrived. It says nothing about whether the
// recipient's runtime did anything with it, which is what ApplicationAck is
// for: collapsing the two would let "received" be read as "acted on".
type DeliveryAck struct {
	EventID        string
	ReceivedAtUnix uint64
}

// Schema implements Payload.
func (DeliveryAck) Schema() string { return "tos.messaging.payload.delivery-ack.v1" }

// Validate implements Payload.
func (d DeliveryAck) Validate() error {
	if err := requireEvent("acknowledged event", d.EventID); err != nil {
		return err
	}
	return requireTime("arrival time", d.ReceivedAtUnix)
}

func (d DeliveryAck) encode(buffer *bytes.Buffer) {
	canon.Text(buffer, d.EventID)
	canon.Uint64(buffer, d.ReceivedAtUnix)
}

func decodeDeliveryAck(reader *canon.Reader) Payload {
	return DeliveryAck{
		EventID:        reader.Text(MaxShortTextBytes),
		ReceivedAtUnix: reader.Uint64(),
	}
}

// applicationOutcomes is the closed set an application acknowledgement may
// report.
var applicationOutcomes = map[string]struct{}{
	"applied": {}, "rejected": {}, "held-for-approval": {},
}

// ApplicationAck says what the recipient's runtime did with an event.
type ApplicationAck struct {
	EventID       string
	Outcome       string
	DecidedAtUnix uint64
	Reason        string
}

// Schema implements Payload.
func (ApplicationAck) Schema() string { return "tos.messaging.payload.application-ack.v1" }

// Validate implements Payload.
func (a ApplicationAck) Validate() error {
	if err := requireEvent("acknowledged event", a.EventID); err != nil {
		return err
	}
	if err := requireMember("application outcome", a.Outcome, applicationOutcomes); err != nil {
		return err
	}
	if err := requireTime("decision time", a.DecidedAtUnix); err != nil {
		return err
	}
	if a.Outcome == "rejected" {
		return requireText("reason", a.Reason, MaxShortTextBytes)
	}
	return optionalText("reason", a.Reason, MaxShortTextBytes)
}

func (a ApplicationAck) encode(buffer *bytes.Buffer) {
	canon.Text(buffer, a.EventID)
	canon.Text(buffer, a.Outcome)
	canon.Uint64(buffer, a.DecidedAtUnix)
	canon.Text(buffer, a.Reason)
}

func decodeApplicationAck(reader *canon.Reader) Payload {
	return ApplicationAck{
		EventID:       reader.Text(MaxShortTextBytes),
		Outcome:       reader.Text(MaxShortTextBytes),
		DecidedAtUnix: reader.Uint64(),
		Reason:        reader.Text(MaxShortTextBytes),
	}
}

// ReadAck is optional user-facing read state. It is distinct from delivery and
// application acceptance: reading is a UI action and grants no authority. A
// sender that does not negotiate or want read state simply never emits it.
type ReadAck struct {
	EventID    string
	ReadAtUnix uint64
}

// Schema implements Payload.
func (ReadAck) Schema() string { return "tos.messaging.payload.read-ack.v1" }

// Validate implements Payload.
func (r ReadAck) Validate() error {
	if err := requireEvent("read event", r.EventID); err != nil {
		return err
	}
	return requireTime("read time", r.ReadAtUnix)
}

func (r ReadAck) encode(buffer *bytes.Buffer) {
	canon.Text(buffer, r.EventID)
	canon.Uint64(buffer, r.ReadAtUnix)
}

func decodeReadAck(reader *canon.Reader) Payload {
	return ReadAck{EventID: reader.Text(MaxShortTextBytes), ReadAtUnix: reader.Uint64()}
}

// RoomInvite invites an Agent into a room.
type RoomInvite struct {
	RoomID         string
	InviteeAgentID string
	Purpose        string
	ExpiresAtUnix  uint64
}

// Schema implements Payload.
func (RoomInvite) Schema() string { return "tos.messaging.payload.room-invite.v1" }

// Validate implements Payload.
func (r RoomInvite) Validate() error {
	if err := requireMatch("room", r.RoomID, ids.Room); err != nil {
		return err
	}
	if err := requireMatch("invitee", r.InviteeAgentID, ids.Agent); err != nil {
		return err
	}
	if err := requireText("purpose", r.Purpose, MaxShortTextBytes); err != nil {
		return err
	}
	return requireTime("invitation expiry", r.ExpiresAtUnix)
}

func (r RoomInvite) encode(buffer *bytes.Buffer) {
	canon.Text(buffer, r.RoomID)
	canon.Text(buffer, r.InviteeAgentID)
	canon.Text(buffer, r.Purpose)
	canon.Uint64(buffer, r.ExpiresAtUnix)
}

func decodeRoomInvite(reader *canon.Reader) Payload {
	return RoomInvite{
		RoomID:         reader.Text(MaxShortTextBytes),
		InviteeAgentID: reader.Text(MaxShortTextBytes),
		Purpose:        reader.Text(MaxShortTextBytes),
		ExpiresAtUnix:  reader.Uint64(),
	}
}

// RoomMembershipCommit states the room's membership at a point in the room's
// own ordering.
//
// Membership is committed as a digest over the member set rather than as the
// set itself, and the epoch is what makes two commits comparable. Without an
// epoch, an older membership replayed later would look like a current one.
type RoomMembershipCommit struct {
	RoomID           string
	Epoch            uint64
	MembershipDigest string
	MemberCount      uint32
}

// Schema implements Payload.
func (RoomMembershipCommit) Schema() string {
	return "tos.messaging.payload.room-membership-commit.v1"
}

// Validate implements Payload.
func (r RoomMembershipCommit) Validate() error {
	if err := requireMatch("room", r.RoomID, ids.Room); err != nil {
		return err
	}
	if r.Epoch == 0 {
		return errors.New("a membership commit has no epoch")
	}
	if err := requireDigest("membership digest", r.MembershipDigest); err != nil {
		return err
	}
	if r.MemberCount == 0 {
		return errors.New("a room with no members is not a room")
	}
	return nil
}

func (r RoomMembershipCommit) encode(buffer *bytes.Buffer) {
	canon.Text(buffer, r.RoomID)
	canon.Uint64(buffer, r.Epoch)
	canon.Text(buffer, r.MembershipDigest)
	canon.Uint32(buffer, r.MemberCount)
}

func decodeRoomMembershipCommit(reader *canon.Reader) Payload {
	return RoomMembershipCommit{
		RoomID:           reader.Text(MaxShortTextBytes),
		Epoch:            reader.Uint64(),
		MembershipDigest: reader.Text(MaxDigestBytes),
		MemberCount:      reader.Uint32(),
	}
}

// RoomMessage is text addressed to a room rather than to one counterparty.
//
// It names the membership epoch it was written under, so a recipient can tell
// whether the sender believed the same membership the recipient does.
type RoomMessage struct {
	RoomID    string
	Epoch     uint64
	MediaType string
	Body      string
}

// Schema implements Payload.
func (RoomMessage) Schema() string { return "tos.messaging.payload.room-message.v1" }

// Validate implements Payload.
func (r RoomMessage) Validate() error {
	if err := requireMatch("room", r.RoomID, ids.Room); err != nil {
		return err
	}
	if r.Epoch == 0 {
		return errors.New("a room message names no membership epoch")
	}
	if err := requireMember("media type", r.MediaType, mediaTypes); err != nil {
		return err
	}
	return requireText("body", r.Body, MaxTextBytes)
}

func (r RoomMessage) encode(buffer *bytes.Buffer) {
	canon.Text(buffer, r.RoomID)
	canon.Uint64(buffer, r.Epoch)
	canon.Text(buffer, r.MediaType)
	canon.Text(buffer, r.Body)
}

func decodeRoomMessage(reader *canon.Reader) Payload {
	return RoomMessage{
		RoomID:    reader.Text(MaxShortTextBytes),
		Epoch:     reader.Uint64(),
		MediaType: reader.Text(MaxShortTextBytes),
		Body:      reader.Text(MaxTextBytes),
	}
}
