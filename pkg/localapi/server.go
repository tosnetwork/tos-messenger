package localapi

import (
	"bufio"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"net"
	"time"

	"github.com/tosnetwork/tos-messenger/internal/canon"
	"github.com/tosnetwork/tos-messenger/pkg/dispatch"
	"github.com/tosnetwork/tos-messenger/pkg/envelope"
	"github.com/tosnetwork/tos-messenger/pkg/eventlog"
	"github.com/tosnetwork/tos-messenger/pkg/fault"
	"github.com/tosnetwork/tos-messenger/pkg/firewall"
	"github.com/tosnetwork/tos-messenger/pkg/negotiation"
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
	// ChallengeLifetime bounds how long an unanswered decision challenge
	// stands.
	ChallengeLifetime time.Duration
	Now               func() time.Time
	Timeout           time.Duration
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
	if config.Now == nil {
		config.Now = time.Now
	}
	if config.Timeout == 0 {
		config.Timeout = DefaultRequestTimeout
	}
	if config.Timeout < 0 {
		return nil, errors.New("invalid local API timeout")
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
	if err := verifyPeer(connection); err != nil {
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
	case OpAwaitingAdmission:
		return s.awaitingAdmission(request)
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
		return s.pendingActions(request)
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
	}
	return refuse(fault.CodeInternal, errors.New("unknown local operation"))
}

func (s *Server) pending(request Request, now time.Time) Response {
	limit := request.Limit
	if limit == 0 || limit > MaxEventsPerResponse {
		limit = MaxEventsPerResponse
	}
	records, err := s.config.Journal.ListPending(now, limit)
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
		events = append(events, event)
	}
	return Response{OK: true, Events: events}
}

func (s *Server) claim(request Request, now time.Time) Response {
	record, err := s.config.Journal.ClaimForApplication(request.EventID, request.LeaseID, now,
		time.Duration(request.LeaseSeconds)*time.Second)
	if err != nil {
		return refuse(claimCode(err), err)
	}
	event, err := pendingEvent(record)
	if err != nil {
		return refuse(fault.CodeInternal, err)
	}
	return Response{OK: true, Event: &event}
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

// awaitingAdmission lists what the owner has yet to decide about.
func (s *Server) awaitingAdmission(request Request) Response {
	limit := request.Limit
	if limit == 0 || limit > MaxEventsPerResponse {
		limit = MaxEventsPerResponse
	}
	records, err := s.config.Journal.ListAwaitingAdmission(limit)
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
	if action.Effect == firewall.EffectSpend {
		mandate, resolveErr := s.spendMandate(request, now)
		if resolveErr != nil {
			return refuse(fault.CodeInternal, resolveErr)
		}
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
		return Response{Schema: ResponseSchema, OK: true, ActionID: actionID,
			Decision: string(decision.Outcome), Detail: decision.Reason, Authorised: true}
	}
	approval, err := s.config.Journal.RequestApproval(eventlog.ApprovalRequest{
		ActionID: actionID, Effect: string(action.Effect), Summary: action.Summary,
		Reason: decision.Reason, Origins: toApprovalOrigins(decision.Provenance),
		AskedAt: uint64(now.Unix()),
	})
	if err != nil {
		return refuse(fault.CodeInternal, err)
	}
	return Response{Schema: ResponseSchema, OK: true, ActionID: actionID,
		Decision: string(decision.Outcome), Detail: decision.Reason,
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
	return Response{Schema: ResponseSchema, OK: true, ActionID: request.ActionID,
		State: string(approval.State), Authorised: true}
}

func (s *Server) pendingActions(request Request) Response {
	waiting, err := s.config.Journal.ListPendingApprovals(request.Limit)
	if err != nil {
		return refuse(fault.CodeInternal, err)
	}
	actions := make([]WaitingAction, 0, len(waiting))
	for _, approval := range waiting {
		actions = append(actions, WaitingAction{
			ActionID: approval.ActionID, Effect: approval.Effect, Summary: approval.Summary,
			Reason: approval.Reason, Origins: fromApprovalOrigins(approval.Origins),
			AskedAtUnix: approval.AskedAtUnix,
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
		DerivedFrom: origins, Terms: toTerms(proposed.Terms),
	}
	return action, nil
}

func toApprovalOrigins(origins []firewall.Origin) []eventlog.ApprovalOrigin {
	stored := make([]eventlog.ApprovalOrigin, 0, len(origins))
	for _, origin := range origins {
		stored = append(stored, eventlog.ApprovalOrigin{
			AgentID: origin.AgentID, EndpointID: origin.EndpointID, EventID: origin.EventID,
			ConversationID: origin.ConversationID, Kind: origin.Kind,
		})
	}
	return stored
}

func fromApprovalOrigins(origins []eventlog.ApprovalOrigin) []ActionOrigin {
	shown := make([]ActionOrigin, 0, len(origins))
	for _, origin := range origins {
		shown = append(shown, ActionOrigin{
			AgentID: origin.AgentID, EndpointID: origin.EndpointID, EventID: origin.EventID,
			ConversationID: origin.ConversationID, Kind: origin.Kind,
		})
	}
	return shown
}

func (s *Server) placeMandate(request Request, now time.Time) Response {
	stored, err := s.config.Journal.PlaceMandate(eventlog.StoredMandate{
		Objective: request.Mandate.Objective, Authority: request.Mandate.Authority,
		CapabilityClass:  request.Mandate.CapabilityClass,
		MaxTotalAsset:    request.Mandate.Asset,
		MaxTotalUnits:    request.Mandate.MaxTotalUnits,
		MaxTotalDecimals: request.Mandate.Decimals,
		ApprovalAsset:    request.Mandate.Asset,
		ApprovalUnits:    request.Mandate.ApprovalAbove,
		ApprovalDecimals: request.Mandate.Decimals,
		MaxCounteroffers: request.Mandate.MaxCounteroffers,
		ExpiresAtUnix:    request.Mandate.ExpiresAtUnix,
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
			Asset: mandate.MaxTotalAsset, Decimals: mandate.MaxTotalDecimals,
			MaxTotalUnits: mandate.MaxTotalUnits, ApprovalAbove: mandate.ApprovalUnits,
			MaxCounteroffers: mandate.MaxCounteroffers, ExpiresAtUnix: mandate.ExpiresAtUnix,
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

func toMandate(stored eventlog.StoredMandate) (negotiation.Mandate, error) {
	mandate := negotiation.Mandate{
		Objective:       stored.Objective,
		Authority:       negotiation.Authority(stored.Authority),
		CapabilityClass: stored.CapabilityClass,
		MaxTotal: negotiation.Amount{
			Asset: stored.MaxTotalAsset, Units: stored.MaxTotalUnits, Decimals: stored.MaxTotalDecimals,
		},
		ApprovalAbove: negotiation.Amount{
			Asset: stored.ApprovalAsset, Units: stored.ApprovalUnits, Decimals: stored.ApprovalDecimals,
		},
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
		CapabilityID:      terms.CapabilityID,
		CapabilityVersion: terms.CapabilityVersion,
		CapabilityClass:   terms.CapabilityClass,
		Total: negotiation.Amount{
			Asset: terms.Asset, Units: terms.Units, Decimals: terms.Decimals,
		},
		NotAfterUnix: terms.NotAfterUnix,
	}
}
