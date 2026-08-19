package localapi

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"net"
	"time"

	"github.com/tosnetwork/tos-messenger/pkg/dispatch"
	"github.com/tosnetwork/tos-messenger/pkg/envelope"
	"github.com/tosnetwork/tos-messenger/pkg/eventlog"
	"github.com/tosnetwork/tos-messenger/pkg/fault"
)

// DefaultRequestTimeout bounds how long one call may hold a connection.
const DefaultRequestTimeout = 30 * time.Second

// Config wires one server.
type Config struct {
	Journal    *eventlog.Journal
	Dispatcher *dispatch.Dispatcher
	Now        func() time.Time
	Timeout    time.Duration
}

// Server answers calls on the owner-private socket.
type Server struct {
	config Config
}

// NewServer builds a server.
func NewServer(config Config) (*Server, error) {
	if config.Journal == nil {
		return nil, errors.New("the local API requires a durable journal")
	}
	if config.Dispatcher == nil {
		return nil, errors.New("the local API requires a dispatcher")
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
	return &Server{config: config}, nil
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
