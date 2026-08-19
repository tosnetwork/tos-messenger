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

// Serve accepts connections until the listener is closed.
func (s *Server) Serve(ctx context.Context, listener net.Listener) error {
	for {
		connection, err := listener.Accept()
		if err != nil {
			return err
		}
		go s.serveConnection(ctx, connection)
	}
}

func (s *Server) serveConnection(ctx context.Context, connection net.Conn) {
	defer connection.Close()
	if err := verifyPeer(connection); err != nil {
		// A caller this daemon cannot identify learns nothing about why.
		return
	}
	reader := bufio.NewReaderSize(connection, 4<<10)
	for {
		if err := connection.SetDeadline(s.config.Now().Add(s.config.Timeout)); err != nil {
			return
		}
		line, err := readFrame(reader)
		if err != nil {
			return
		}
		response := s.handle(ctx, line)
		encoded, err := EncodeResponse(response)
		if err != nil {
			return
		}
		if _, err := connection.Write(encoded); err != nil {
			return
		}
	}
}

func readFrame(reader *bufio.Reader) ([]byte, error) {
	line, err := reader.ReadSlice('\n')
	if err != nil {
		if errors.Is(err, bufio.ErrBufferFull) {
			return nil, errors.New("request exceeds its frame bound")
		}
		return nil, err
	}
	if len(line) > MaxFrameBytes {
		return nil, errors.New("request exceeds its frame bound")
	}
	return line, nil
}

// Handle answers one request. It is exported so a caller can drive the API in
// process, which is what a test and a single-binary deployment both want.
func (s *Server) Handle(ctx context.Context, raw []byte) Response {
	return s.handle(ctx, raw)
}

func (s *Server) handle(ctx context.Context, raw []byte) Response {
	request, err := DecodeRequest(raw)
	if err != nil {
		return refuse(fault.CodeInternal, err)
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

// approve is the owner authorising a held delivery.
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
	case errors.Is(err, eventlog.ErrLeaseMismatch), errors.Is(err, eventlog.ErrNotPending):
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
