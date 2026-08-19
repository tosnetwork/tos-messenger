package payload

import (
	"bytes"
	"errors"

	"github.com/tosnetwork/tos-messenger/internal/canon"
	"github.com/tosnetwork/tos-messenger/internal/ids"
	"github.com/tosnetwork/tos-messenger/pkg/negotiation"
)

// Text is a message meant for a person or an Agent to read.
//
// The media type is a closed set. A sender that could name any media type
// would be choosing how the recipient renders their words, which is a
// rendering instruction from a stranger.
type Text struct {
	MediaType string
	Body      string
	// ReplyToEventID is optional and names an event in the same conversation.
	ReplyToEventID string
}

// Schema implements Payload.
func (Text) Schema() string { return "tos.messaging.payload.text.v1" }

// Validate implements Payload.
func (t Text) Validate() error {
	if err := requireMember("media type", t.MediaType, mediaTypes); err != nil {
		return err
	}
	if err := requireText("body", t.Body, MaxTextBytes); err != nil {
		return err
	}
	return optionalMatch("reply-to event", t.ReplyToEventID, ids.Event)
}

func (t Text) encode(buffer *bytes.Buffer) {
	canon.Text(buffer, t.MediaType)
	canon.Text(buffer, t.Body)
	canon.Text(buffer, t.ReplyToEventID)
}

func decodeText(reader *canon.Reader) Payload {
	return Text{
		MediaType:      reader.Text(MaxShortTextBytes),
		Body:           reader.Text(MaxTextBytes),
		ReplyToEventID: reader.Text(MaxShortTextBytes),
	}
}

// ConversationInvite proposes a conversation and says what it is for.
type ConversationInvite struct {
	Purpose string
	// ExpiresAtUnix bounds how long the invitation stands. An invitation that
	// never expires is a standing permission nobody remembers granting.
	ExpiresAtUnix uint64
}

// Schema implements Payload.
func (ConversationInvite) Schema() string {
	return "tos.messaging.payload.conversation-invite.v1"
}

// Validate implements Payload.
func (c ConversationInvite) Validate() error {
	if err := requireText("purpose", c.Purpose, MaxShortTextBytes); err != nil {
		return err
	}
	return requireTime("invitation expiry", c.ExpiresAtUnix)
}

func (c ConversationInvite) encode(buffer *bytes.Buffer) {
	canon.Text(buffer, c.Purpose)
	canon.Uint64(buffer, c.ExpiresAtUnix)
}

func decodeConversationInvite(reader *canon.Reader) Payload {
	return ConversationInvite{
		Purpose:       reader.Text(MaxShortTextBytes),
		ExpiresAtUnix: reader.Uint64(),
	}
}

// ConversationAccept answers a specific invitation.
type ConversationAccept struct {
	InviteEventID string
}

// Schema implements Payload.
func (ConversationAccept) Schema() string {
	return "tos.messaging.payload.conversation-accept.v1"
}

// Validate implements Payload.
func (c ConversationAccept) Validate() error {
	return requireEvent("invitation event", c.InviteEventID)
}

func (c ConversationAccept) encode(buffer *bytes.Buffer) {
	canon.Text(buffer, c.InviteEventID)
}

func decodeConversationAccept(reader *canon.Reader) Payload {
	return ConversationAccept{InviteEventID: reader.Text(MaxShortTextBytes)}
}

// presenceStates is the closed set a hint may declare.
var presenceStates = map[string]struct{}{
	"available": {}, "busy": {}, "away": {},
}

// PresenceHint is a hint, not a fact. It says what the sender believes about
// its own availability and until when that belief should be considered stale.
type PresenceHint struct {
	State          string
	StaleAfterUnix uint64
}

// Schema implements Payload.
func (PresenceHint) Schema() string { return "tos.messaging.payload.presence-hint.v1" }

// Validate implements Payload.
func (p PresenceHint) Validate() error {
	if err := requireMember("presence state", p.State, presenceStates); err != nil {
		return err
	}
	return requireTime("presence staleness", p.StaleAfterUnix)
}

func (p PresenceHint) encode(buffer *bytes.Buffer) {
	canon.Text(buffer, p.State)
	canon.Uint64(buffer, p.StaleAfterUnix)
}

func decodePresenceHint(reader *canon.Reader) Payload {
	return PresenceHint{
		State:          reader.Text(MaxShortTextBytes),
		StaleAfterUnix: reader.Uint64(),
	}
}

// TaskRequest asks the recipient to perform work.
//
// It names what is being asked for and commits the input by digest. It does
// not carry authority to spend: what may be paid is the mandate's business,
// and a task request that could move money would be an instruction channel
// with a wallet attached.
type TaskRequest struct {
	TaskID       string
	CapabilityID string
	InputDigest  string
	DeadlineUnix uint64
	// AcceptedQuoteRef optionally names the finalized commitment this work is
	// being done under. It is a reference to chain state, never a substitute
	// for it.
	AcceptedQuoteRef string
}

// Schema implements Payload.
func (TaskRequest) Schema() string { return "tos.messaging.payload.task-request.v1" }

// Validate implements Payload.
func (t TaskRequest) Validate() error {
	if err := requireText("task identifier", t.TaskID, MaxShortTextBytes); err != nil {
		return err
	}
	if err := requireMatch("capability", t.CapabilityID, ids.Capability); err != nil {
		return err
	}
	if err := requireDigest("input digest", t.InputDigest); err != nil {
		return err
	}
	if err := requireTime("task deadline", t.DeadlineUnix); err != nil {
		return err
	}
	return optionalDigest("accepted quote reference", t.AcceptedQuoteRef)
}

func (t TaskRequest) encode(buffer *bytes.Buffer) {
	canon.Text(buffer, t.TaskID)
	canon.Text(buffer, t.CapabilityID)
	canon.Text(buffer, t.InputDigest)
	canon.Uint64(buffer, t.DeadlineUnix)
	canon.Text(buffer, t.AcceptedQuoteRef)
}

func decodeTaskRequest(reader *canon.Reader) Payload {
	return TaskRequest{
		TaskID:           reader.Text(MaxShortTextBytes),
		CapabilityID:     reader.Text(MaxShortTextBytes),
		InputDigest:      reader.Text(MaxDigestBytes),
		DeadlineUnix:     reader.Uint64(),
		AcceptedQuoteRef: reader.Text(MaxDigestBytes),
	}
}

// TaskProgress reports how far along the work is.
type TaskProgress struct {
	TaskID string
	Stage  string
	// PercentComplete is bounded to 0..100. A progress report that can exceed
	// its own scale is one nothing downstream can display or reason about.
	PercentComplete uint32
	Note            string
}

// Schema implements Payload.
func (TaskProgress) Schema() string { return "tos.messaging.payload.task-progress.v1" }

// Validate implements Payload.
func (t TaskProgress) Validate() error {
	if err := requireText("task identifier", t.TaskID, MaxShortTextBytes); err != nil {
		return err
	}
	if err := requireMatch("stage", t.Stage, tokenPattern); err != nil {
		return err
	}
	if t.PercentComplete > 100 {
		return errors.New("progress exceeds its own scale")
	}
	return optionalText("note", t.Note, MaxShortTextBytes)
}

func (t TaskProgress) encode(buffer *bytes.Buffer) {
	canon.Text(buffer, t.TaskID)
	canon.Text(buffer, t.Stage)
	canon.Uint32(buffer, t.PercentComplete)
	canon.Text(buffer, t.Note)
}

func decodeTaskProgress(reader *canon.Reader) Payload {
	return TaskProgress{
		TaskID:          reader.Text(MaxShortTextBytes),
		Stage:           reader.Text(MaxShortTextBytes),
		PercentComplete: reader.Uint32(),
		Note:            reader.Text(MaxShortTextBytes),
	}
}

// taskOutcomes is the closed set a result may declare.
var taskOutcomes = map[string]struct{}{
	"succeeded": {}, "failed": {}, "refused": {},
}

// TaskResult reports the end of the work and commits its output by digest.
//
// The digest is a commitment, not a receipt. A Receipt is signed by the
// execution authority an Accepted Quote named, and this message is not that.
type TaskResult struct {
	TaskID       string
	Outcome      string
	OutputDigest string
	Reason       string
}

// Schema implements Payload.
func (TaskResult) Schema() string { return "tos.messaging.payload.task-result.v1" }

// Validate implements Payload.
func (t TaskResult) Validate() error {
	if err := requireText("task identifier", t.TaskID, MaxShortTextBytes); err != nil {
		return err
	}
	if err := requireMember("task outcome", t.Outcome, taskOutcomes); err != nil {
		return err
	}
	if t.Outcome == "succeeded" {
		if err := requireDigest("output digest", t.OutputDigest); err != nil {
			return err
		}
		return optionalText("reason", t.Reason, MaxShortTextBytes)
	}
	// A result that did not succeed must say why, and must not claim an output
	// it did not produce.
	if t.OutputDigest != "" {
		return errors.New("a task that did not succeed reported an output")
	}
	return requireText("reason", t.Reason, MaxShortTextBytes)
}

func (t TaskResult) encode(buffer *bytes.Buffer) {
	canon.Text(buffer, t.TaskID)
	canon.Text(buffer, t.Outcome)
	canon.Text(buffer, t.OutputDigest)
	canon.Text(buffer, t.Reason)
}

func decodeTaskResult(reader *canon.Reader) Payload {
	return TaskResult{
		TaskID:       reader.Text(MaxShortTextBytes),
		Outcome:      reader.Text(MaxShortTextBytes),
		OutputDigest: reader.Text(MaxDigestBytes),
		Reason:       reader.Text(MaxShortTextBytes),
	}
}

// TaskStatusRequest asks for the current state of a task.
type TaskStatusRequest struct {
	TaskID string
}

// Schema implements Payload.
func (TaskStatusRequest) Schema() string {
	return "tos.messaging.payload.task-status-request.v1"
}

// Validate implements Payload.
func (t TaskStatusRequest) Validate() error {
	return requireText("task identifier", t.TaskID, MaxShortTextBytes)
}

func (t TaskStatusRequest) encode(buffer *bytes.Buffer) { canon.Text(buffer, t.TaskID) }

func decodeTaskStatusRequest(reader *canon.Reader) Payload {
	return TaskStatusRequest{TaskID: reader.Text(MaxShortTextBytes)}
}

// terms carries the negotiated terms in canonical form. It is the same shape
// the negotiation state machine works with, so a proposal on the wire and a
// proposal in memory cannot drift apart.
func encodeTerms(buffer *bytes.Buffer, terms negotiation.Terms) {
	canon.Text(buffer, terms.CapabilityID)
	canon.Text(buffer, terms.CapabilityVersion)
	canon.Text(buffer, terms.CapabilityClass)
	canon.Text(buffer, terms.Total.Asset)
	canon.Uint64(buffer, terms.Total.Units)
	buffer.WriteByte(terms.Total.Decimals)
	canon.Uint64(buffer, terms.NotAfterUnix)
}

func decodeTerms(reader *canon.Reader) negotiation.Terms {
	return negotiation.Terms{
		CapabilityID:      reader.Text(MaxShortTextBytes),
		CapabilityVersion: reader.Text(MaxShortTextBytes),
		CapabilityClass:   reader.Text(MaxShortTextBytes),
		Total: negotiation.Amount{
			Asset:    reader.Text(MaxShortTextBytes),
			Units:    reader.Uint64(),
			Decimals: reader.Uint8(),
		},
		NotAfterUnix: reader.Uint64(),
	}
}

// NegotiationProposal offers terms. It commits nothing: an intent agreed in
// conversation is not a finalized commitment, and nothing in this package can
// make it one.
type NegotiationProposal struct {
	NegotiationID string
	Terms         negotiation.Terms
}

// Schema implements Payload.
func (NegotiationProposal) Schema() string {
	return "tos.messaging.payload.negotiation-proposal.v1"
}

// Validate implements Payload.
func (n NegotiationProposal) Validate() error {
	if err := requireText("negotiation identifier", n.NegotiationID, MaxShortTextBytes); err != nil {
		return err
	}
	return n.Terms.Validate()
}

func (n NegotiationProposal) encode(buffer *bytes.Buffer) {
	canon.Text(buffer, n.NegotiationID)
	encodeTerms(buffer, n.Terms)
}

func decodeNegotiationProposal(reader *canon.Reader) Payload {
	return NegotiationProposal{
		NegotiationID: reader.Text(MaxShortTextBytes),
		Terms:         decodeTerms(reader),
	}
}

// NegotiationCounterproposal answers a proposal with different terms.
type NegotiationCounterproposal struct {
	NegotiationID string
	Terms         negotiation.Terms
}

// Schema implements Payload.
func (NegotiationCounterproposal) Schema() string {
	return "tos.messaging.payload.negotiation-counterproposal.v1"
}

// Validate implements Payload.
func (n NegotiationCounterproposal) Validate() error {
	if err := requireText("negotiation identifier", n.NegotiationID, MaxShortTextBytes); err != nil {
		return err
	}
	return n.Terms.Validate()
}

func (n NegotiationCounterproposal) encode(buffer *bytes.Buffer) {
	canon.Text(buffer, n.NegotiationID)
	encodeTerms(buffer, n.Terms)
}

func decodeNegotiationCounterproposal(reader *canon.Reader) Payload {
	return NegotiationCounterproposal{
		NegotiationID: reader.Text(MaxShortTextBytes),
		Terms:         decodeTerms(reader),
	}
}

// NegotiationWithdraw ends an exchange without agreement.
type NegotiationWithdraw struct {
	NegotiationID string
	Reason        string
}

// Schema implements Payload.
func (NegotiationWithdraw) Schema() string {
	return "tos.messaging.payload.negotiation-withdraw.v1"
}

// Validate implements Payload.
func (n NegotiationWithdraw) Validate() error {
	if err := requireText("negotiation identifier", n.NegotiationID, MaxShortTextBytes); err != nil {
		return err
	}
	return requireText("reason", n.Reason, MaxShortTextBytes)
}

func (n NegotiationWithdraw) encode(buffer *bytes.Buffer) {
	canon.Text(buffer, n.NegotiationID)
	canon.Text(buffer, n.Reason)
}

func decodeNegotiationWithdraw(reader *canon.Reader) Payload {
	return NegotiationWithdraw{
		NegotiationID: reader.Text(MaxShortTextBytes),
		Reason:        reader.Text(MaxShortTextBytes),
	}
}

// NegotiationIntentAccept says the sender intends to proceed on exactly these
// terms. It restates the terms rather than referring to them, so that what was
// accepted cannot be argued about later.
type NegotiationIntentAccept struct {
	NegotiationID string
	Terms         negotiation.Terms
}

// Schema implements Payload.
func (NegotiationIntentAccept) Schema() string {
	return "tos.messaging.payload.negotiation-intent-accept.v1"
}

// Validate implements Payload.
func (n NegotiationIntentAccept) Validate() error {
	if err := requireText("negotiation identifier", n.NegotiationID, MaxShortTextBytes); err != nil {
		return err
	}
	return n.Terms.Validate()
}

func (n NegotiationIntentAccept) encode(buffer *bytes.Buffer) {
	canon.Text(buffer, n.NegotiationID)
	encodeTerms(buffer, n.Terms)
}

func decodeNegotiationIntentAccept(reader *canon.Reader) Payload {
	return NegotiationIntentAccept{
		NegotiationID: reader.Text(MaxShortTextBytes),
		Terms:         decodeTerms(reader),
	}
}

// NegotiationIntentReject declines to proceed.
type NegotiationIntentReject struct {
	NegotiationID string
	Reason        string
}

// Schema implements Payload.
func (NegotiationIntentReject) Schema() string {
	return "tos.messaging.payload.negotiation-intent-reject.v1"
}

// Validate implements Payload.
func (n NegotiationIntentReject) Validate() error {
	if err := requireText("negotiation identifier", n.NegotiationID, MaxShortTextBytes); err != nil {
		return err
	}
	return requireText("reason", n.Reason, MaxShortTextBytes)
}

func (n NegotiationIntentReject) encode(buffer *bytes.Buffer) {
	canon.Text(buffer, n.NegotiationID)
	canon.Text(buffer, n.Reason)
}

func decodeNegotiationIntentReject(reader *canon.Reader) Payload {
	return NegotiationIntentReject{
		NegotiationID: reader.Text(MaxShortTextBytes),
		Reason:        reader.Text(MaxShortTextBytes),
	}
}
