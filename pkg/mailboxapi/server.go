package mailboxapi

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"net"
	"time"

	"github.com/tosnetwork/tos-messenger/internal/localwire"
	"github.com/tosnetwork/tos-messenger/pkg/envelope"
	"github.com/tosnetwork/tos-messenger/pkg/mailbox"
)

const DefaultTimeout = 30 * time.Second

type Server struct {
	store   *mailbox.AuthenticatedStore
	now     func() time.Time
	timeout time.Duration
}

func NewServer(store *mailbox.AuthenticatedStore, now func() time.Time, timeout time.Duration) (*Server, error) {
	if store == nil {
		return nil, errors.New("Mailbox service needs an authenticated store")
	}
	if now == nil {
		now = time.Now
	}
	if timeout == 0 {
		timeout = DefaultTimeout
	}
	if timeout < time.Second || timeout > time.Minute {
		return nil, errors.New("Mailbox service timeout is outside its bound")
	}
	return &Server{store: store, now: now, timeout: timeout}, nil
}

// ListenUnix supplies a private local carrier for deployment and acceptance.
// The request protocol itself relies on cryptographic grants and is suitable
// for the network carrier selected after M0-R.
func ListenUnix(path string) (net.Listener, error) { return localwire.Listen(path) }

func (s *Server) Serve(ctx context.Context, listener net.Listener) error {
	if s == nil || ctx == nil || listener == nil {
		return errors.New("Mailbox service needs a server and listener")
	}
	go func() { <-ctx.Done(); _ = listener.Close() }()
	for {
		connection, err := listener.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return err
		}
		go s.serveConnection(ctx, connection)
	}
}

func (s *Server) serveConnection(ctx context.Context, connection net.Conn) {
	defer connection.Close()
	deadline := s.now().Add(s.timeout)
	if d, ok := ctx.Deadline(); ok && d.Before(deadline) {
		deadline = d
	}
	if connection.SetDeadline(deadline) != nil {
		return
	}
	raw, err := ReadRequestFrame(bufio.NewReader(connection))
	if err != nil {
		return
	}
	response := s.Handle(ctx, raw)
	framed, err := encodeResponse(response)
	if err != nil {
		return
	}
	for len(framed) > 0 {
		n, err := connection.Write(framed)
		if err != nil || n <= 0 || n > len(framed) {
			return
		}
		framed = framed[n:]
	}
}

func (s *Server) Handle(ctx context.Context, raw []byte) Response {
	if s == nil || ctx == nil {
		return refusal(CodeInternal, "Mailbox service is unavailable")
	}
	request, err := DecodeRequest(raw)
	if err != nil {
		return refusal(CodeInvalid, err.Error())
	}
	grant, err := mailbox.DecodeGrantJSON(request.Grant)
	if err != nil {
		return refusal(CodeInvalid, err.Error())
	}
	access, err := mailbox.DecodeAccessRequestJSON(request.Access)
	if err != nil {
		return refusal(CodeInvalid, err.Error())
	}
	now := s.now()
	switch request.Op {
	case OpDeposit:
		value, decodeErr := envelope.DecodeRelayJSON(request.Envelope)
		if decodeErr != nil {
			return refusal(CodeInvalid, decodeErr.Error())
		}
		fresh, ack, callErr := s.store.Put(ctx, grant, access, value, now)
		if callErr != nil {
			return refusal(classify(callErr), callErr.Error())
		}
		rawAck, encodeErr := mailbox.EncodeAckJSON(ack)
		if encodeErr != nil {
			return refusal(CodeInternal, encodeErr.Error())
		}
		return Response{Schema: ResponseSchema, OK: true, Fresh: fresh, Ack: rawAck}
	case OpRead:
		values, callErr := s.store.List(ctx, grant, access, now, request.Limit)
		if callErr != nil {
			return refusal(classify(callErr), callErr.Error())
		}
		rawValues := make([]json.RawMessage, 0, len(values))
		for _, value := range values {
			encoded, encodeErr := envelope.EncodeRelayJSON(value)
			if encodeErr != nil {
				return refusal(CodeInternal, encodeErr.Error())
			}
			rawValues = append(rawValues, encoded)
		}
		return Response{Schema: ResponseSchema, OK: true, Envelopes: &rawValues}
	case OpDelete:
		deleted, callErr := s.store.Delete(ctx, grant, access, request.MessageID, request.CiphertextDigest, now)
		if callErr != nil {
			return refusal(classify(callErr), callErr.Error())
		}
		return Response{Schema: ResponseSchema, OK: true, Deleted: &deleted}
	default:
		return refusal(CodeInvalid, "unknown Mailbox service operation")
	}
}

func refusal(code Code, detail string) Response {
	return Response{Schema: ResponseSchema, OK: false, Code: code, Detail: detail}
}
func classify(err error) Code {
	if errors.Is(err, mailbox.ErrConflict) {
		return CodeConflict
	}
	if errors.Is(err, mailbox.ErrQuota) {
		return CodeQuota
	}
	return CodeDenied
}
