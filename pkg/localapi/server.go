package localapi

import (
	"bufio"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"net"
	"sort"
	"time"

	"github.com/tosnetwork/tos-messenger/internal/canon"
	"github.com/tosnetwork/tos-messenger/internal/ids"
	"github.com/tosnetwork/tos-messenger/internal/localwire"
	"github.com/tosnetwork/tos-messenger/pkg/attachmentadmission"
	"github.com/tosnetwork/tos-messenger/pkg/dispatch"
	"github.com/tosnetwork/tos-messenger/pkg/envelope"
	"github.com/tosnetwork/tos-messenger/pkg/eventlog"
	"github.com/tosnetwork/tos-messenger/pkg/fault"
	"github.com/tosnetwork/tos-messenger/pkg/firewall"
	"github.com/tosnetwork/tos-messenger/pkg/identity"
	"github.com/tosnetwork/tos-messenger/pkg/negotiation"
	"github.com/tosnetwork/tos-messenger/pkg/payload"
	nativev1 "github.com/tosnetwork/tos-service-protocol/gen/tos/service/v1"
)

// DefaultRequestTimeout bounds how long one call may hold a connection.
const DefaultRequestTimeout = 30 * time.Second

// Config wires one server.
type Config struct {
	Journal    *eventlog.Journal
	Dispatcher *dispatch.Dispatcher
	// Policy is what the Agent may reach unattended. It is required: a server
	// with no policy would answer every firewall question with whatever the
	// zero value happened to mean.
	Policy firewall.Policy
	// OwnerKey is the public key the owner signs decisions with. It is
	// required, and it must not be reachable by the Agent runtime: it is the
	// only thing that distinguishes the owner from anything else running under
	// the same Unix user.
	OwnerKey ed25519.PublicKey
	// LocalEndpointID scopes every admission invite minted by this server.
	LocalEndpointID string
	// ChallengeLifetime bounds how long an unanswered decision challenge
	// stands.
	ChallengeLifetime time.Duration
	Now               func() time.Time
	Timeout           time.Duration
	QuoteResolver     AddressedQuoteResolver
	Network           *nativev1.NetworkDomain
	// DeviceIDs is the complete, sorted current Endpoint roster. An empty
	// roster disables owner-authorized history export.
	DeviceIDs []string
	// AttachmentAdmitter is optional. When absent, encrypted attachment Events
	// remain daemon-reserved and no runtime can obtain their secret payload.
	AttachmentAdmitter AttachmentAdmitter
}

type AttachmentAdmitter interface {
	Admit(context.Context, envelope.Event) (attachmentadmission.Result, error)
}

// AddressedQuoteResolver treats a runtime-supplied escrow address only as a
// candidate locator and returns a Quote only after reading that exact account
// from finalized, code-authenticated chain state.
type AddressedQuoteResolver interface {
	ResolveAcceptedQuoteAt(ctx context.Context, commitment, escrowAddress,
		capabilityClass string) (negotiation.VerifiedAcceptedQuote, bool, error)
}

// Server answers calls on the owner-private socket.
type Server struct {
	config     Config
	challenges *challenges
}

// NewServer builds a server.
func NewServer(config Config) (*Server, error) {
	if config.Journal == nil {
		return nil, errors.New("the local API requires a durable journal")
	}
	if config.Dispatcher == nil {
		return nil, errors.New("the local API requires a dispatcher")
	}
	if err := config.Policy.Validate(); err != nil {
		return nil, err
	}
	if len(config.OwnerKey) != ed25519.PublicKeySize || canon.IsZero(config.OwnerKey) {
		return nil, errors.New("the local API requires the owner's public key")
	}
	if !identity.EndpointPattern.MatchString(config.LocalEndpointID) {
		return nil, errors.New("the local API requires its local endpoint identifier")
	}
	if config.Now == nil {
		config.Now = time.Now
	}
	if config.Timeout == 0 {
		config.Timeout = DefaultRequestTimeout
	}
	if config.Timeout < 0 {
		return nil, errors.New("invalid local API timeout")
	}
	if config.QuoteResolver != nil {
		if _, err := negotiation.NetworkFromDomain(config.Network); err != nil {
			return nil, errors.New("a Quote resolver needs the daemon network binding")
		}
	} else if config.Network != nil {
		return nil, errors.New("a local API network binding requires a Quote resolver")
	}
	if len(config.DeviceIDs) > 0 {
		if !sort.StringsAreSorted(config.DeviceIDs) {
			return nil, errors.New("device-history roster must be sorted")
		}
		localDeviceID := config.Dispatcher.LocalIdentity().DeviceID
		foundLocal := false
		for index, deviceID := range config.DeviceIDs {
			if !ids.Device.MatchString(deviceID) || index > 0 && config.DeviceIDs[index-1] == deviceID {
				return nil, errors.New("invalid device-history roster")
			}
			foundLocal = foundLocal || deviceID == localDeviceID
		}
		if !foundLocal {
			return nil, errors.New("device-history roster omits the local device")
		}
		config.DeviceIDs = append([]string(nil), config.DeviceIDs...)
	}
	return &Server{config: config, challenges: newChallenges(config.ChallengeLifetime)}, nil
}

// Serve accepts connections for one principal until the listener is closed.
//
// A principal belongs to a listener rather than to a request, so a caller
// cannot choose which one it speaks for. The runtime reaches the daemon
// through a socket that has no approval operations on it at all.
func (s *Server) Serve(ctx context.Context, listener net.Listener, principal Principal) error {
	if _, known := permitted[principal]; !known {
		return errors.New("unknown local principal")
	}
	for {
		connection, err := listener.Accept()
		if err != nil {
			return err
		}
		go s.serveConnection(ctx, connection, principal)
	}
}

func (s *Server) serveConnection(ctx context.Context, connection net.Conn, principal Principal) {
	defer connection.Close()
	if err := localwire.VerifyPeer(connection); err != nil {
		// A caller this daemon cannot identify learns nothing about why.
		return
	}
	reader := bufio.NewReader(connection)
	for {
		if err := connection.SetDeadline(s.config.Now().Add(s.config.Timeout)); err != nil {
			return
		}
		body, err := ReadFrame(reader)
		if err != nil {
			return
		}
		response := s.handle(ctx, principal, body)
		encoded, err := EncodeResponse(response)
		if err != nil {
			return
		}
		if _, err := connection.Write(encoded); err != nil {
			return
		}
	}
}

// Handle answers one request for one principal. It is exported so a caller can
// drive the API in process, which is what a test and a single-binary
// deployment both want.
func (s *Server) Handle(ctx context.Context, principal Principal, raw []byte) Response {
	return s.handle(ctx, principal, raw)
}

func (s *Server) handle(ctx context.Context, principal Principal, raw []byte) Response {
	request, err := DecodeRequest(raw)
	if err != nil {
		return refuse(fault.CodeInternal, err)
	}
	if !Permits(principal, request.Op) {
		// Said plainly: this is not a capability this connection has, and no
		// amount of asking changes that.
		return refuse(fault.CodeClassNotDelegated,
			errors.New(string(principal)+" may not perform "+string(request.Op)))
	}
	if err := ctx.Err(); err != nil {
		return refuse(fault.CodeInternal, err)
	}
	now := s.config.Now()
	if err := s.authoriseDecision(request, now); err != nil {
		return refuse(fault.CodeNotAuthentic, err)
	}
	switch request.Op {
	case OpPending:
		return s.pending(request, now)
	case OpClaim:
		return s.claim(request, now)
	case OpComplete:
		return s.complete(request, now)
	case OpReject:
		return s.reject(request, now)
	case OpQueue:
		return s.queue(request)
	case OpCompose:
		return s.compose(request)
	case OpPendingAttachments:
		return s.pendingAttachments(request, now)
	case OpClaimAttachment:
		return s.claimAttachment(ctx, request, now)
	case OpAwaitingAdmission:
		return s.awaitingAdmission(request, now)
	case OpAdmit:
		return s.admit(request, now)
	case OpRefuse:
		return s.refuseEvent(request, now)
	case OpApprove:
		return s.approve(request, now)
	case OpDeny:
		return s.deny(request, now)
	case OpRequestAction:
		return s.requestAction(request, now)
	case OpActionStatus:
		return s.actionStatus(request)
	case OpClaimAction:
		return s.claimAction(request, now)
	case OpPendingActions:
		return s.pendingActions(request, now)
	case OpGrantAction:
		return s.grantAction(request, now)
	case OpDenyAction:
		return s.denyAction(request, now)
	case OpPlaceMandate:
		return s.placeMandate(request, now)
	case OpRevokeMandate:
		return s.revokeMandate(request, now)
	case OpListMandates:
		return s.listMandates()
	case OpChallenge:
		return s.challenge(now)
	case OpCreateAdmissionInvite:
		return s.createAdmissionInvite(request, now)
	case OpRecordEscrowLocation:
		return s.recordEscrowLocation(request)
	case OpVerifyAcceptedQuote:
		return s.verifyAcceptedQuote(ctx, request)
	case OpExportDeviceHistory:
		return s.exportDeviceHistory(request)
	case OpListDeviceHistory:
		return s.listDeviceHistory(request)
	}
	return refuse(fault.CodeInternal, errors.New("unknown local operation"))
}

func (s *Server) verifyAcceptedQuote(ctx context.Context, request Request) Response {
	if s.config.QuoteResolver == nil {
		return refuse(fault.CodeClassNotDelegated, errors.New("finalized Quote verification is not configured"))
	}
	quote, found, err := s.config.QuoteResolver.ResolveAcceptedQuoteAt(
		ctx, request.QuoteCommitment, request.EscrowAddress, request.CapabilityClass)
	if err == nil && !found {
		err = errors.New("the funded escrow is not finalized")
	}
	if err == nil {
		quote, err = negotiation.MatchAcceptedQuote(
			quote, request.QuoteCommitment, *toTerms(request.ExpectedQuoteTerms), s.config.Network)
	}
	if err == nil && quote.Reference.Account != request.EscrowAddress {
		err = errors.New("the finalized Quote evidence names another escrow account")
	}
	if err != nil {
		return refuse(fault.CodeNotAuthentic, err)
	}
	return Response{OK: true, FinalizedQuote: &FinalizedQuoteEvidence{
		Commitment: quote.Commitment, EscrowAccount: quote.Reference.Account,
		TransactionHash: quote.Reference.TransactionHash, ContractCodeHash: quote.Reference.ContractCodeHash,
		FinalizedCheckpoint: quote.Reference.FinalizedCheckpoint, FinalizedAtUnix: quote.FinalizedAtUnix,
	}}
}

func (s *Server) recordEscrowLocation(request Request) Response {
	fresh, err := s.config.Journal.RecordEscrowLocation(
		request.QuoteCommitment, request.EscrowAddress, request.CapabilityClass)
	if err != nil {
		return refuse(fault.CodeInternal, err)
	}
	return Response{OK: true, Fresh: fresh}
}

func (s *Server) createAdmissionInvite(request Request, now time.Time) Response {
	var entropy [32]byte
	if _, err := rand.Read(entropy[:]); err != nil {
		return refuse(fault.CodeInternal, errors.New("generate admission invite"))
	}
	token, _, err := s.config.Journal.CreateAdmissionInvite(
		entropy, s.config.LocalEndpointID, request.InvitedAgentID,
		time.Unix(int64(request.InviteExpiresAtUnix), 0), now,
	)
	if err != nil {
		return refuse(fault.CodeInternal, err)
	}
	return Response{OK: true, AdmissionToken: token}
}

func (s *Server) pending(request Request, now time.Time) Response {
	limit := request.Limit
	if limit == 0 || limit > MaxEventsPerResponse {
		limit = MaxEventsPerResponse
	}
	// Fetch the complete bounded journal view before filtering. Otherwise a
	// page filled by daemon-owned typed packets could hide ordinary messages
	// that follow it from the runtime indefinitely.
	records, err := s.config.Journal.ListPending(now, 0)
	if err != nil {
		return refuse(fault.CodeInternal, err)
	}
	events := make([]PendingEvent, 0, len(records))
	for _, record := range records {
		event, err := pendingEvent(record)
		if err != nil {
			// A damaged record is skipped rather than failing the listing: one
			// unreadable event must not stop every other one from being
			// delivered.
			continue
		}
		decoded, err := envelope.DecodeEventJSON(event.Event)
		if err != nil || daemonApplicationKind(decoded.Kind) {
			continue
		}
		events = append(events, event)
		if len(events) == limit {
			break
		}
	}
	return Response{OK: true, Events: events}
}

func (s *Server) claim(request Request, now time.Time) Response {
	record, err := s.config.Journal.ClaimForApplicationExceptKinds(request.EventID, request.LeaseID, now,
		time.Duration(request.LeaseSeconds)*time.Second, []string{"agent.packet", "device.history.segment", "artifact.encrypted"})
	if err != nil {
		return refuse(claimCode(err), err)
	}
	event, err := pendingEvent(record)
	if err != nil {
		return refuse(fault.CodeInternal, err)
	}
	return Response{OK: true, Event: &event}
}

func daemonApplicationKind(kind string) bool {
	return kind == "agent.packet" || kind == "device.history.segment" || kind == "artifact.encrypted"
}

func (s *Server) pendingAttachments(request Request, now time.Time) Response {
	if s.config.AttachmentAdmitter == nil {
		return refuse(fault.CodeClassNotDelegated, errors.New("attachment admission is not configured"))
	}
	limit := request.Limit
	if limit == 0 || limit > MaxEventsPerResponse {
		limit = MaxEventsPerResponse
	}
	records, err := s.config.Journal.ListPending(now, 0)
	if err != nil {
		return refuse(fault.CodeInternal, err)
	}
	offers := make([]PendingAttachment, 0, len(records))
	for _, record := range records {
		pending, pendingErr := pendingEvent(record)
		if pendingErr != nil {
			continue
		}
		event, decodeErr := envelope.DecodeEventJSON(pending.Event)
		if decodeErr != nil || event.Kind != "artifact.encrypted" ||
			event.PayloadSchema != (payload.EncryptedAttachment{}).Schema() {
			continue
		}
		offers = append(offers, PendingAttachment{EventID: pending.EventID, SenderEndpointID: pending.SenderEndpointID,
			ConversationID: pending.ConversationID, ReceivedAtUnix: pending.ReceivedAtUnix})
		if len(offers) == limit {
			break
		}
	}
	return Response{OK: true, Attachments: offers}
}

func (s *Server) claimAttachment(ctx context.Context, request Request, now time.Time) Response {
	if s.config.AttachmentAdmitter == nil {
		return refuse(fault.CodeClassNotDelegated, errors.New("attachment admission is not configured"))
	}
	record, err := s.config.Journal.ClaimForApplicationKind(request.EventID, request.LeaseID, now,
		time.Duration(request.LeaseSeconds)*time.Second, "artifact.encrypted")
	if err != nil {
		return refuse(claimCode(err), err)
	}
	raw, err := record.Payload()
	if err != nil {
		return refuse(fault.CodeInternal, err)
	}
	event, err := envelope.DecodeEventJSON(raw)
	if err != nil || event.EventID != record.EventID || event.SenderEndpointID != record.SenderEndpointID ||
		event.ConversationID != record.ConversationID || event.PayloadSchema != (payload.EncryptedAttachment{}).Schema() {
		return refuse(fault.CodeNotAuthentic, errors.New("stored attachment Event conflicts with its journal binding"))
	}
	admitted, err := s.config.AttachmentAdmitter.Admit(ctx, event)
	if err != nil {
		return refuse(fault.CodeInternal, errors.New("attachment admission failed: "+err.Error()))
	}
	scans := make([]AttachmentScan, 0, len(admitted.Report.Scans))
	for _, scan := range admitted.Report.Scans {
		scans = append(scans, AttachmentScan{ScannerID: scan.ScannerID, ScannerDigest: scan.ScannerDigest})
	}
	return Response{OK: true, Attachment: &AdmittedAttachment{EventID: event.EventID,
		SenderAgentID: event.SenderAgentID, SenderEndpointID: event.SenderEndpointID,
		SenderDeviceID: event.SenderDeviceID, ConversationID: event.ConversationID, RoomID: event.RoomID,
		ReplyToEventID: event.ReplyToEventID, ReceivedAtUnix: record.ReceivedAtUnix,
		Filename: admitted.Metadata.Filename, MediaType: admitted.Metadata.MediaType,
		PlaintextDigest: admitted.Report.PlaintextDigest, SizeBytes: admitted.Report.SizeBytes,
		Body: admitted.Body, Scans: scans}}
}

func (s *Server) complete(request Request, now time.Time) Response {
	if _, err := s.config.Journal.CompleteApplication(request.EventID, request.LeaseID, now); err != nil {
		return refuse(claimCode(err), err)
	}
	return Response{OK: true}
}

func (s *Server) reject(request Request, now time.Time) Response {
	code := request.Code
	if code == "" {
		code = fault.CodeInternal
	}
	if _, err := s.config.Journal.RejectApplication(request.EventID, request.LeaseID, code, now); err != nil {
		return refuse(claimCode(err), err)
	}
	return Response{OK: true}
}

func (s *Server) queue(request Request) Response {
	// The runtime submits an encoded event, which is decoded and validated
	// here rather than trusted: the daemon owns what goes on the wire.
	event, err := envelope.DecodeEventJSON(request.Event)
	if err != nil {
		return refuse(fault.CodeUnknownEventKind, err)
	}
	fresh, _, err := s.config.Dispatcher.Queue(event, request.SessionID,
		request.RecipientEndpointID, request.ExpiresAtUnix)
	if err != nil {
		return refuse(fault.CodeInternal, err)
	}
	return Response{OK: true, Fresh: fresh}
}

func (s *Server) compose(request Request) Response {
	event, fresh, err := s.config.Dispatcher.ComposeAndQueue(dispatch.ComposeRequest{
		ConversationID: request.ConversationID, RoomID: request.RoomID,
		ReplyToEventID: request.ReplyToEventID, MembershipEpoch: request.MembershipEpoch,
		MediaType: request.MediaType, Body: request.Body, IdempotencyKey: request.IdempotencyKey,
		SessionID: request.SessionID, RecipientEndpointID: request.RecipientEndpointID,
		ExpiresAtUnix: request.ExpiresAtUnix,
	})
	if err != nil {
		return refuse(fault.CodeInternal, err)
	}
	return Response{OK: true, Fresh: fresh, EventID: event.EventID}
}

func (s *Server) exportDeviceHistory(request Request) Response {
	found := false
	for _, deviceID := range s.config.DeviceIDs {
		found = found || deviceID == request.TargetDeviceID
	}
	if !found || request.TargetDeviceID == s.config.Dispatcher.LocalIdentity().DeviceID {
		return refuse(fault.CodeDeviceRevoked, errors.New("history target is not another current device"))
	}
	event, segment, fresh, err := s.config.Dispatcher.ComposeHistoryAndQueue(dispatch.HistoryRequest{
		TargetDeviceID: request.TargetDeviceID, ConversationID: request.ConversationID,
		Sequence: request.HistorySequence, PreviousSegmentDigest: request.PreviousSegmentDigest,
		AfterCreatedAtUnix: request.AfterCreatedAtUnix, AfterEventID: request.AfterEventID,
		Limit: request.Limit, IdempotencyKey: request.IdempotencyKey, ExpiresAtUnix: request.ExpiresAtUnix,
	})
	if err != nil {
		return refuse(fault.CodeInternal, err)
	}
	last, err := envelope.DecodeEventJSON(segment.Events[len(segment.Events)-1])
	if err != nil {
		return refuse(fault.CodeInternal, err)
	}
	return Response{OK: true, Fresh: fresh, EventID: event.EventID,
		HistorySegmentDigest: canon.Digest(event.Content), LastEventCreatedAt: last.CreatedAtUnix, LastEventID: last.EventID}
}

func (s *Server) listDeviceHistory(request Request) Response {
	limit := request.Limit
	if limit == 0 {
		limit = MaxHistoryEventsPerResponse
	}
	events, err := s.config.Journal.History(request.ConversationID, limit)
	if err != nil {
		return refuse(fault.CodeInternal, err)
	}
	history := make([]json.RawMessage, 0, len(events))
	for _, event := range events {
		encoded, err := envelope.EncodeEventJSON(event)
		if err != nil {
			return refuse(fault.CodeInternal, err)
		}
		history = append(history, encoded)
	}
	return Response{OK: true, History: history}
}

// awaitingAdmission lists what the owner has yet to decide about.
func (s *Server) awaitingAdmission(request Request, now time.Time) Response {
	limit := request.Limit
	if limit == 0 || limit > MaxEventsPerResponse {
		limit = MaxEventsPerResponse
	}
	records, err := s.config.Journal.ListAwaitingAdmission(now, limit)
	if err != nil {
		return refuse(fault.CodeInternal, err)
	}
	events := make([]PendingEvent, 0, len(records))
	for _, record := range records {
		event, err := pendingEvent(record)
		if err != nil {
			continue
		}
		events = append(events, event)
	}
	return Response{OK: true, Events: events}
}

// admit is the owner letting an inbound event reach the runtime.
func (s *Server) admit(request Request, now time.Time) Response {
	if _, err := s.config.Journal.AdmitEvent(request.EventID, now); err != nil {
		return refuse(claimCode(err), err)
	}
	return Response{OK: true}
}

// refuseEvent is the owner refusing one. It is never offered to a runtime.
func (s *Server) refuseEvent(request Request, now time.Time) Response {
	code := request.Code
	if code == "" {
		code = fault.CodeRejected
	}
	if _, err := s.config.Journal.DenyEvent(request.EventID, code, now); err != nil {
		return refuse(claimCode(err), err)
	}
	return Response{OK: true}
}

// approve is the owner releasing a held outbound delivery.
//
// This operation exists on this socket and nowhere else. The matching event
// kinds are refused on every network route, so a remote party cannot reach
// this decision by sending a message, however well signed.
func (s *Server) approve(request Request, now time.Time) Response {
	if _, err := s.config.Journal.Resume(request.EventID, now); err != nil {
		return refuse(claimCode(err), err)
	}
	return Response{OK: true}
}

func (s *Server) deny(request Request, now time.Time) Response {
	if _, err := s.config.Journal.Abandon(request.EventID, now); err != nil {
		return refuse(claimCode(err), err)
	}
	return Response{OK: true}
}

func pendingEvent(record eventlog.Record) (PendingEvent, error) {
	payload, err := record.Payload()
	if err != nil {
		return PendingEvent{}, err
	}
	if !json.Valid(payload) {
		return PendingEvent{}, errors.New("stored event is not a document")
	}
	return PendingEvent{
		EventID:          record.EventID,
		SenderEndpointID: record.SenderEndpointID,
		ConversationID:   record.ConversationID,
		ReceivedAtUnix:   record.ReceivedAtUnix,
		Event:            json.RawMessage(payload),
	}, nil
}

// claimCode maps the journal's own outcomes onto the shared vocabulary, so a
// runtime distinguishes "somebody else holds this" from "this never existed".
func claimCode(err error) fault.Code {
	switch {
	case errors.Is(err, eventlog.ErrUnknown):
		return fault.CodeUnknownEventKind
	case errors.Is(err, eventlog.ErrLeaseMismatch), errors.Is(err, eventlog.ErrNotPending),
		errors.Is(err, eventlog.ErrNotAdmitted):
		return fault.CodeReplayed
	case errors.Is(err, eventlog.ErrApplicationKind):
		return fault.CodeClassNotDelegated
	default:
		return fault.CodeInternal
	}
}

func refuse(code fault.Code, err error) Response {
	detail := ""
	if err != nil {
		detail = err.Error()
	}
	// Detail is local. This socket has one caller and it is the owner's own
	// runtime, so the reason is useful here in a way it never is to a peer.
	return Response{OK: false, Code: code, Detail: detail}
}

// requestAction puts one proposed action to the firewall.
//
// The identifier is derived from the action, never taken from the request. A
// runtime that could name an identifier without presenting the action could
// have a harmless one approved and perform a different one under the same
// permission.
func (s *Server) requestAction(request Request, now time.Time) Response {
	action, err := toAction(*request.Action)
	if err != nil {
		return refuse(fault.CodeInternal, err)
	}
	var decision firewall.Decision
	var mandate negotiation.Mandate
	if action.Effect == firewall.EffectSpend {
		resolved, resolveErr := s.spendMandate(request, now)
		if resolveErr != nil {
			return refuse(fault.CodeInternal, resolveErr)
		}
		mandate = resolved
		decision, err = firewall.EvaluateSpend(s.config.Policy, mandate, action, now)
	} else {
		decision, err = firewall.Evaluate(s.config.Policy, action)
	}
	if err != nil {
		return refuse(fault.CodeInternal, err)
	}
	if decision.Outcome == firewall.Refuse {
		// A refusal is a result, not a local failure.
		return Response{Schema: ResponseSchema, OK: true, Decision: string(decision.Outcome),
			Detail: decision.Reason}
	}
	actionID, err := firewall.ActionID(action)
	if err != nil {
		return refuse(fault.CodeInternal, err)
	}
	if decision.Outcome == firewall.Allow {
		// An allowed spend or tool call is authorised once, not indefinitely. The grant is
		// recorded the way an owner's would be and consumed by ClaimAction, so
		// one decision -- human or policy -- backs one execution. The action
		// identifier commits the terms, which is what makes a second identical
		// purchase a replay rather than a coincidence. Tool calls use the
		// runtime's explicit idempotency key for the same distinction. Weaker
		// effects remain inline: a repeated reply is a nuisance, while a repeated
		// external invocation or payment is an uncontrolled side effect.
		if action.Effect == firewall.EffectSpend {
			// One purchase is authorised once, keyed on the economic execution --
			// the mandate and the terms -- not on the action identifier, which a
			// re-described replay of the same purchase would change. A purchase
			// already bound to another action is not authorised a second time.
			executionID, err := negotiation.ExecutionID(request.MandateID, *action.Terms)
			if err != nil {
				return refuse(fault.CodeInternal, err)
			}
			bound, fresh, err := s.config.Journal.ClaimEconomicExecution(executionID, actionID, now)
			if err != nil {
				return refuse(fault.CodeInternal, err)
			}
			if !fresh && bound != actionID {
				return Response{Schema: ResponseSchema, OK: true, ActionID: actionID,
					Decision: string(firewall.Refuse),
					Detail:   "this purchase is already authorised under another action"}
			}
			// Bound the sum of distinct purchases under this mandate against its
			// MaxTotal. The per-spend ceiling the firewall already applied stops
			// one oversized purchase; without a durable cross-action total,
			// several purchases each inside that ceiling could still commit more
			// than the mandate allows. The reservation is keyed by the economic
			// execution, so it is idempotent across a re-described same purchase
			// and accumulates once per distinct purchase. It is written durably
			// BEFORE the auto-authorization, so a crash between the two can only
			// leave a hold with no authorization -- an over-count, the safe
			// direction -- never an authorization the budget never counted. The
			// hold becomes a spend when the grant is claimed, and is freed if the
			// purchase is later denied or abandoned.
			if err := s.reserveMandateBudget(request.MandateID, mandate, executionID, action.Terms.Price); err != nil {
				if !errors.Is(err, negotiation.ErrBudgetExceeded) {
					return refuse(fault.CodeInternal, err)
				}
				// The purchase does not fit the mandate's durable total, so it is
				// not auto-authorised. The owner may still decide, so this
				// escalates rather than refusing, and holds no budget until they
				// approve it.
				return s.escalateSpend(request, action, actionID, decision.Provenance,
					"would exceed the mandate's remaining budget", now)
			}
			approval, err := s.config.Journal.RecordAutoAuthorization(eventlog.ApprovalRequest{
				ActionID: actionID, Effect: string(action.Effect), Summary: action.Summary,
				Reason:  "allowed by policy, inside the owner's mandate",
				Origins: toApprovalOrigins(decision.Provenance), Terms: action.Terms,
				MandateID: request.MandateID, AskedAt: uint64(now.Unix()),
			})
			if err != nil {
				return refuse(fault.CodeInternal, err)
			}
			return Response{Schema: ResponseSchema, OK: true, ActionID: actionID,
				Decision: string(decision.Outcome), Detail: decision.Reason,
				State: string(approval.State)}
		}
		if action.Effect == firewall.EffectToolCall {
			bound, _, err := s.config.Journal.ClaimToolExecution(action.IdempotencyKey, actionID, now)
			if err != nil {
				return refuse(fault.CodeInternal, err)
			}
			if bound != actionID {
				return Response{Schema: ResponseSchema, OK: true, ActionID: actionID,
					Decision: string(firewall.Refuse), Detail: "this tool invocation key is already bound to another action"}
			}
			approval, err := s.config.Journal.RecordAutoAuthorization(eventlog.ApprovalRequest{
				ActionID: actionID, Effect: string(action.Effect), Summary: action.Summary,
				IdempotencyKey: action.IdempotencyKey,
				Reason:         "allowed by policy", Origins: toApprovalOrigins(decision.Provenance),
				AskedAt: uint64(now.Unix()),
			})
			if err != nil {
				return refuse(fault.CodeInternal, err)
			}
			return Response{Schema: ResponseSchema, OK: true, ActionID: actionID,
				Decision: string(decision.Outcome), Detail: decision.Reason,
				State: string(approval.State)}
		}
		return Response{Schema: ResponseSchema, OK: true, ActionID: actionID,
			Decision: string(decision.Outcome), Detail: decision.Reason, Authorised: true}
	}
	// The decision requires an owner. A spend that still fits its mandate holds
	// its slice of the budget while it waits, so concurrent spends cannot
	// oversubscribe MaxTotal behind a pending one; a spend that will not fit is
	// put to the owner without a hold, who may approve it over budget.
	if action.Effect == firewall.EffectSpend {
		executionID, err := negotiation.ExecutionID(request.MandateID, *action.Terms)
		if err != nil {
			return refuse(fault.CodeInternal, err)
		}
		if err := s.reserveMandateBudget(request.MandateID, mandate, executionID, action.Terms.Price); err != nil {
			if !errors.Is(err, negotiation.ErrBudgetExceeded) {
				return refuse(fault.CodeInternal, err)
			}
		}
		return s.escalateSpend(request, action, actionID, decision.Provenance, decision.Reason, now)
	}
	if action.Effect == firewall.EffectToolCall {
		bound, _, err := s.config.Journal.ClaimToolExecution(action.IdempotencyKey, actionID, now)
		if err != nil {
			return refuse(fault.CodeInternal, err)
		}
		if bound != actionID {
			return Response{Schema: ResponseSchema, OK: true, ActionID: actionID,
				Decision: string(firewall.Refuse), Detail: "this tool invocation key is already bound to another action"}
		}
	}
	approval, err := s.config.Journal.RequestApproval(eventlog.ApprovalRequest{
		ActionID: actionID, Effect: string(action.Effect), Summary: action.Summary,
		IdempotencyKey: action.IdempotencyKey,
		Reason:         decision.Reason, Origins: toApprovalOrigins(decision.Provenance),
		Terms: action.Terms, AskedAt: uint64(now.Unix()),
	})
	if err != nil {
		return refuse(fault.CodeInternal, err)
	}
	return Response{Schema: ResponseSchema, OK: true, ActionID: actionID,
		Decision: string(decision.Outcome), Detail: decision.Reason,
		State: string(approval.State)}
}

// reserveMandateBudget holds a purchase's price against its mandate's durable
// total, keyed by the economic execution so it is idempotent across a
// re-described same purchase. It returns negotiation.ErrBudgetExceeded when the
// hold would carry the mandate past MaxTotal, which the caller escalates rather
// than treating as a failure.
func (s *Server) reserveMandateBudget(mandateID string, mandate negotiation.Mandate,
	executionID string, price negotiation.Money) error {
	ledger, err := s.config.Journal.OpenMandateBudgetLedger(mandateID, mandate.MaxTotal.Asset)
	if err != nil {
		return err
	}
	budget, err := negotiation.OpenBudget(mandate.MaxTotal, ledger)
	if err != nil {
		return err
	}
	return budget.Reserve(executionID, price)
}

// escalateSpend puts a spend to the owner. The reservation, if any, was taken by
// the caller before this record is written, so the durable hold always precedes
// the owner-visible question a crash could otherwise strand.
func (s *Server) escalateSpend(request Request, action firewall.Action, actionID string,
	provenance []firewall.Origin, reason string, now time.Time) Response {
	approval, err := s.config.Journal.RequestApproval(eventlog.ApprovalRequest{
		ActionID: actionID, Effect: string(action.Effect), Summary: action.Summary,
		Reason: reason, Origins: toApprovalOrigins(provenance), Terms: action.Terms,
		MandateID: request.MandateID, AskedAt: uint64(now.Unix()),
	})
	if err != nil {
		return refuse(fault.CodeInternal, err)
	}
	return Response{Schema: ResponseSchema, OK: true, ActionID: actionID,
		Decision: string(firewall.RequireOwnerApproval), Detail: reason,
		State: string(approval.State)}
}

// actionStatus reads where a request has got to. It changes nothing, so a
// runtime may poll it without consuming anything.
func (s *Server) actionStatus(request Request) Response {
	approval, found, err := s.config.Journal.LookupApproval(request.ActionID)
	if err != nil {
		return refuse(fault.CodeInternal, err)
	}
	if !found {
		return Response{Schema: ResponseSchema, OK: true, ActionID: request.ActionID,
			Detail: "no decision was ever asked for about this action"}
	}
	return Response{Schema: ResponseSchema, OK: true, ActionID: request.ActionID,
		State: string(approval.State), Detail: approval.DenialReason}
}

// claimAction consumes a granted authorisation, once.
//
// The state change is durable before the runtime is told it may proceed, so a
// crash between the two loses the permission rather than reusing it. Losing a
// permission costs the owner one more decision; reusing one spends their
// authority on something they never saw.
func (s *Server) claimAction(request Request, now time.Time) Response {
	approval, err := s.config.Journal.SpendApproval(request.ActionID, now)
	if err != nil {
		if errors.Is(err, eventlog.ErrApprovalNotGranted) || errors.Is(err, eventlog.ErrApprovalUnknown) {
			return Response{Schema: ResponseSchema, OK: true, ActionID: request.ActionID,
				Authorised: false, Detail: err.Error()}
		}
		return refuse(fault.CodeInternal, err)
	}
	// A spent purchase turns its standing budget hold into a committed amount, so
	// the mandate records it as spent rather than a reservation that could still
	// be released. This runs after the durable spend, so a crash between them
	// leaves an uncommitted hold -- an over-count, the safe direction -- not an
	// executed spend the budget forgot. It is a no-op for anything holding no
	// reservation.
	if err := s.config.Journal.CommitMandateReservation(approval); err != nil {
		return refuse(fault.CodeInternal, err)
	}
	return Response{Schema: ResponseSchema, OK: true, ActionID: request.ActionID,
		State: string(approval.State), Authorised: true}
}

func (s *Server) pendingActions(request Request, now time.Time) Response {
	waiting, err := s.config.Journal.ListPendingApprovals(now, request.Limit)
	if err != nil {
		return refuse(fault.CodeInternal, err)
	}
	actions := make([]WaitingAction, 0, len(waiting))
	for _, approval := range waiting {
		// The owner is never shown -- and must never sign -- an action whose
		// stored structured fields do not reproduce its identifier. A mismatch
		// means the summary and the identifier disagree about what is being
		// approved, which is exactly the substitution this record exists to
		// prevent, so it is surfaced as a fault rather than presented.
		if !approvalReproducesID(approval) {
			return refuse(fault.CodeInternal,
				errors.New("a pending approval's stored action does not reproduce its identifier"))
		}
		actions = append(actions, WaitingAction{
			ActionID: approval.ActionID, Effect: approval.Effect, Summary: approval.Summary,
			IdempotencyKey: approval.IdempotencyKey,
			Reason:         approval.Reason, Origins: fromApprovalOrigins(approval.Origins),
			Terms: approval.Terms, AskedAtUnix: approval.AskedAtUnix,
		})
	}
	return Response{Schema: ResponseSchema, OK: true, Actions: actions}
}

func (s *Server) grantAction(request Request, now time.Time) Response {
	approval, err := s.config.Journal.GrantAction(request.ActionID, now)
	if err != nil {
		return refuse(fault.CodeInternal, err)
	}
	return Response{Schema: ResponseSchema, OK: true, ActionID: request.ActionID,
		State: string(approval.State)}
}

func (s *Server) denyAction(request Request, now time.Time) Response {
	approval, err := s.config.Journal.DenyAction(request.ActionID, request.Reason, now)
	if err != nil {
		return refuse(fault.CodeInternal, err)
	}
	// A refused purchase frees the hold it was holding, so the mandate can spend
	// that amount on something the owner does approve. The release follows the
	// durable denial and is idempotent, so a crash between them leaves a hold the
	// next release would clear -- an over-count, the safe direction.
	if err := s.config.Journal.ReleaseMandateReservation(approval); err != nil {
		return refuse(fault.CodeInternal, err)
	}
	return Response{Schema: ResponseSchema, OK: true, ActionID: request.ActionID,
		State: string(approval.State)}
}

func toAction(proposed ProposedAction) (firewall.Action, error) {
	origins := make([]firewall.Origin, 0, len(proposed.Derived))
	for _, origin := range proposed.Derived {
		origins = append(origins, firewall.Origin{
			AgentID: origin.AgentID, EndpointID: origin.EndpointID, DeviceID: origin.DeviceID,
			EventID: origin.EventID, ConversationID: origin.ConversationID,
			Kind: origin.Kind, ReceivedAtUnix: origin.ReceivedAtUnix,
		})
	}
	action := firewall.Action{
		Effect: firewall.Effect(proposed.Effect), Summary: proposed.Summary,
		IdempotencyKey: proposed.IdempotencyKey,
		DerivedFrom:    origins, Terms: toTerms(proposed.Terms),
	}
	return action, nil
}

func toApprovalOrigins(origins []firewall.Origin) []eventlog.ApprovalOrigin {
	stored := make([]eventlog.ApprovalOrigin, 0, len(origins))
	for _, origin := range origins {
		stored = append(stored, eventlog.ApprovalOrigin{
			AgentID: origin.AgentID, EndpointID: origin.EndpointID, DeviceID: origin.DeviceID,
			EventID: origin.EventID, ConversationID: origin.ConversationID, Kind: origin.Kind,
			ReceivedAtUnix: origin.ReceivedAtUnix,
		})
	}
	return stored
}

func fromApprovalOrigins(origins []eventlog.ApprovalOrigin) []ActionOrigin {
	shown := make([]ActionOrigin, 0, len(origins))
	for _, origin := range origins {
		shown = append(shown, ActionOrigin{
			AgentID: origin.AgentID, EndpointID: origin.EndpointID, DeviceID: origin.DeviceID,
			EventID: origin.EventID, ConversationID: origin.ConversationID, Kind: origin.Kind,
			ReceivedAtUnix: origin.ReceivedAtUnix,
		})
	}
	return shown
}

// firewallOrigins reconstructs the provenance in the form the action identifier
// is derived from, so a stored approval can be re-identified from what it holds.
func firewallOrigins(origins []eventlog.ApprovalOrigin) []firewall.Origin {
	rebuilt := make([]firewall.Origin, 0, len(origins))
	for _, origin := range origins {
		rebuilt = append(rebuilt, firewall.Origin{
			AgentID: origin.AgentID, EndpointID: origin.EndpointID, DeviceID: origin.DeviceID,
			EventID: origin.EventID, ConversationID: origin.ConversationID, Kind: origin.Kind,
			ReceivedAtUnix: origin.ReceivedAtUnix,
		})
	}
	return rebuilt
}

// approvalReproducesID recomputes the action identifier from the structured
// fields a stored approval holds and reports whether it matches the identifier
// on record. It is the daemon's own check that what the owner is shown -- and
// what a signature would commit to -- is the action the identifier names, not a
// gentler description substituted for a harsher one.
func approvalReproducesID(approval eventlog.Approval) bool {
	action := firewall.Action{
		Effect:         firewall.Effect(approval.Effect),
		Summary:        approval.Summary,
		IdempotencyKey: approval.IdempotencyKey,
		DerivedFrom:    firewallOrigins(approval.Origins),
		Terms:          approval.Terms,
	}
	recomputed, err := firewall.ActionID(action)
	if err != nil {
		return false
	}
	return recomputed == approval.ActionID
}

func (s *Server) placeMandate(request Request, now time.Time) Response {
	stored, err := s.config.Journal.PlaceMandate(eventlog.StoredMandate{
		Objective: request.Mandate.Objective, Authority: request.Mandate.Authority,
		CapabilityClass:      request.Mandate.CapabilityClass,
		AssetNetworkID:       request.Mandate.Asset.NetworkID,
		AssetGenesisRootHash: request.Mandate.Asset.GenesisRootHash,
		AssetGenesisFileHash: request.Mandate.Asset.GenesisFileHash,
		Workchain:            request.Mandate.Asset.Workchain,
		AssetAccountID:       request.Mandate.Asset.AccountID,
		AssetMasterCodeHash:  request.Mandate.Asset.MasterCodeHash,
		AssetWalletCodeHash:  request.Mandate.Asset.WalletCodeHash,
		AssetDecimals:        request.Mandate.Asset.Decimals,
		MaxTotalAtomic:       request.Mandate.MaxTotalAtomic,
		ApprovalAboveAtomic:  request.Mandate.ApprovalAboveAtomic,
		MaxCounteroffers:     request.Mandate.MaxCounteroffers,
		ExpiresAtUnix:        request.Mandate.ExpiresAtUnix,
	}, now)
	if err != nil {
		return refuse(fault.CodeInternal, err)
	}
	// A mandate that does not describe a usable authorisation is refused here
	// rather than at the moment a spend is judged, so the owner learns about it
	// while they are the one holding it.
	if _, err := toMandate(stored); err != nil {
		return refuse(fault.CodeInternal, err)
	}
	return Response{Schema: ResponseSchema, OK: true, MandateID: stored.MandateID}
}

func (s *Server) revokeMandate(request Request, now time.Time) Response {
	stored, err := s.config.Journal.RevokeMandate(request.MandateID, now)
	if err != nil {
		return refuse(fault.CodeInternal, err)
	}
	return Response{Schema: ResponseSchema, OK: true, MandateID: stored.MandateID}
}

func (s *Server) listMandates() Response {
	stored, err := s.config.Journal.ListMandates()
	if err != nil {
		return refuse(fault.CodeInternal, err)
	}
	held := make([]HeldMandate, 0, len(stored))
	for _, mandate := range stored {
		held = append(held, HeldMandate{
			MandateID: mandate.MandateID, Objective: mandate.Objective,
			Authority: mandate.Authority, CapabilityClass: mandate.CapabilityClass,
			Asset:               assetIdentityOf(mandate),
			MaxTotalAtomic:      mandate.MaxTotalAtomic,
			ApprovalAboveAtomic: mandate.ApprovalAboveAtomic,
			MaxCounteroffers:    mandate.MaxCounteroffers, ExpiresAtUnix: mandate.ExpiresAtUnix,
			PlacedAtUnix: mandate.PlacedAtUnix, RevokedAtUnix: mandate.RevokedAtUnix,
		})
	}
	return Response{Schema: ResponseSchema, OK: true, Mandates: held}
}

// spendMandate resolves the standing authorisation a proposed spend names.
//
// The mandate comes from the store, never from the request. A runtime that
// could supply the mandate it is judged against would be setting its own
// ceiling, which is the one thing a mandate exists to prevent.
func (s *Server) spendMandate(request Request, now time.Time) (negotiation.Mandate, error) {
	stored, found, err := s.config.Journal.LookupMandate(request.MandateID)
	if err != nil {
		return negotiation.Mandate{}, err
	}
	if !found {
		return negotiation.Mandate{}, eventlog.ErrMandateUnknown
	}
	if stored.RevokedAtUnix != 0 {
		return negotiation.Mandate{}, eventlog.ErrMandateRevoked
	}
	_ = now
	return toMandate(stored)
}

func assetIdentityOf(stored eventlog.StoredMandate) AssetIdentity {
	return AssetIdentity{
		NetworkID:       stored.AssetNetworkID,
		GenesisRootHash: stored.AssetGenesisRootHash,
		GenesisFileHash: stored.AssetGenesisFileHash,
		Workchain:       stored.Workchain, AccountID: stored.AssetAccountID,
		MasterCodeHash: stored.AssetMasterCodeHash,
		WalletCodeHash: stored.AssetWalletCodeHash,
		Decimals:       stored.AssetDecimals,
	}
}

func toAsset(identity AssetIdentity) negotiation.Asset {
	return negotiation.Asset{
		Network: negotiation.Network{
			ID:              identity.NetworkID,
			GenesisRootHash: identity.GenesisRootHash,
			GenesisFileHash: identity.GenesisFileHash,
		},
		Workchain: identity.Workchain, AccountID: identity.AccountID,
		MasterCodeHash: identity.MasterCodeHash, WalletCodeHash: identity.WalletCodeHash,
		Decimals: identity.Decimals,
	}
}

func toMandate(stored eventlog.StoredMandate) (negotiation.Mandate, error) {
	asset := toAsset(assetIdentityOf(stored))
	mandate := negotiation.Mandate{
		Objective:        stored.Objective,
		Authority:        negotiation.Authority(stored.Authority),
		CapabilityClass:  stored.CapabilityClass,
		MaxTotal:         negotiation.Money{Asset: asset, Atomic: stored.MaxTotalAtomic},
		ApprovalAbove:    negotiation.Money{Asset: asset, Atomic: stored.ApprovalAboveAtomic},
		MaxCounteroffers: stored.MaxCounteroffers,
		ExpiresAtUnix:    stored.ExpiresAtUnix,
	}
	if err := mandate.Validate(); err != nil {
		return negotiation.Mandate{}, err
	}
	return mandate, nil
}

func toTerms(terms *PurchaseTerms) *negotiation.Terms {
	if terms == nil {
		return nil
	}
	return &negotiation.Terms{
		CapabilityID:           terms.CapabilityID,
		CapabilityVersion:      terms.CapabilityVersion,
		CapabilityClass:        terms.CapabilityClass,
		ProviderAgentID:        terms.ProviderAgentID,
		ManifestDigest:         terms.ManifestDigest,
		TransportBindingDigest: terms.TransportBindingDigest,
		Price:                  negotiation.Money{Asset: toAsset(terms.Asset), Atomic: terms.PriceAtomic},
		EscrowTermsDigest:      terms.EscrowTermsDigest,
		DisputePolicyDigest:    terms.DisputePolicyDigest,
		NotAfterUnix:           terms.NotAfterUnix,
	}
}
