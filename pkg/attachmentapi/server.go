package attachmentapi

import (
	"bufio"
	"context"
	"errors"
	"io"
	"mime"
	"net"
	"net/http"
	"time"

	"github.com/tosnetwork/tos-messenger/internal/localwire"
	"github.com/tosnetwork/tos-messenger/pkg/attachments"
)

const DefaultTimeout = 30 * time.Second

type Server struct {
	store   *attachments.AuthenticatedStore
	now     func() time.Time
	timeout time.Duration
}

func NewServer(store *attachments.AuthenticatedStore, now func() time.Time, timeout time.Duration) (*Server, error) {
	if store == nil {
		return nil, errors.New("attachment service needs an authenticated store")
	}
	if now == nil {
		now = time.Now
	}
	if timeout == 0 {
		timeout = DefaultTimeout
	}
	if timeout < time.Second || timeout > time.Minute {
		return nil, errors.New("attachment service timeout is outside its bound")
	}
	return &Server{store: store, now: now, timeout: timeout}, nil
}

func ListenUnix(path string) (net.Listener, error) { return localwire.Listen(path) }

func (s *Server) Serve(ctx context.Context, listener net.Listener) error {
	if s == nil || ctx == nil || listener == nil {
		return errors.New("attachment service needs a server and listener")
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
	if value, ok := ctx.Deadline(); ok && value.Before(deadline) {
		deadline = value
	}
	if connection.SetDeadline(deadline) != nil {
		return
	}
	raw, err := ReadRequestFrame(bufio.NewReader(connection))
	if err != nil {
		return
	}
	responseRaw, err := EncodeResponse(s.Handle(ctx, raw))
	if err != nil {
		return
	}
	framed, err := FrameResponse(responseRaw)
	if err != nil {
		return
	}
	for len(framed) > 0 {
		n, writeErr := connection.Write(framed)
		if writeErr != nil || n <= 0 || n > len(framed) {
			return
		}
		framed = framed[n:]
	}
}

func (s *Server) Handle(ctx context.Context, raw []byte) Response {
	if s == nil || s.store == nil || ctx == nil {
		return refusal(CodeInternal, "attachment service is unavailable")
	}
	request, err := DecodeRequest(raw)
	if err != nil {
		return refusal(CodeInvalid, err.Error())
	}
	grant, err := attachments.DecodeGrantJSON(request.Grant)
	if err != nil {
		return refusal(CodeInvalid, err.Error())
	}
	access, err := attachments.DecodeAccessRequestJSON(request.Access)
	if err != nil {
		return refusal(CodeInvalid, err.Error())
	}
	now := s.now()
	switch request.Op {
	case OpUpload:
		chunks, decodeErr := DecodeChunks(request.Chunks)
		if decodeErr != nil {
			return refusal(CodeInvalid, decodeErr.Error())
		}
		ack, complete, callErr := s.store.Upload(ctx, grant, access, chunks, now)
		if callErr != nil {
			return refusal(classify(callErr), callErr.Error())
		}
		response := Response{Schema: ResponseSchema, OK: true, Complete: boolPointer(complete)}
		if complete {
			response.Ack, callErr = attachments.EncodeStoredAckJSON(ack)
			if callErr != nil {
				return refusal(CodeInternal, callErr.Error())
			}
		}
		return response
	case OpFetch:
		chunks, callErr := s.store.Fetch(ctx, grant, access, request.Digests, now)
		if callErr != nil {
			return refusal(classify(callErr), callErr.Error())
		}
		wire, encodeErr := EncodeChunks(chunks)
		if encodeErr != nil {
			return refusal(CodeInternal, encodeErr.Error())
		}
		return Response{Schema: ResponseSchema, OK: true, Chunks: &wire}
	case OpDelete:
		ack, callErr := s.store.Delete(ctx, grant, access, now)
		if callErr != nil {
			return refusal(classify(callErr), callErr.Error())
		}
		rawAck, encodeErr := attachments.EncodeDeleteAckJSON(ack)
		if encodeErr != nil {
			return refusal(CodeInternal, encodeErr.Error())
		}
		return Response{Schema: ResponseSchema, OK: true, Ack: rawAck}
	default:
		return refusal(CodeInvalid, "unknown attachment service operation")
	}
}

// ServeHTTP is the public-HTTPS adapter. TLS is mandatory, redirects and DNS
// policy are enforced by the client, and the path must commit the same manifest
// as the signed grant before the operation reaches authorization.
func (s *Server) ServeHTTP(w http.ResponseWriter, request *http.Request) {
	if request.Method != http.MethodPost || request.TLS == nil || request.URL.RawQuery != "" || request.URL.Fragment != "" || request.Header.Get("Content-Encoding") != "" {
		http.Error(w, "invalid attachment HTTPS request", http.StatusBadRequest)
		return
	}
	mediaType, params, err := mime.ParseMediaType(request.Header.Get("Content-Type"))
	if err != nil || mediaType != "application/json" || len(params) != 0 {
		http.Error(w, "attachment request must be application/json", http.StatusUnsupportedMediaType)
		return
	}
	raw, err := io.ReadAll(io.LimitReader(request.Body, int64(MaxRequestBytes)+1))
	if err != nil || len(raw) == 0 || len(raw) > int(MaxRequestBytes) {
		http.Error(w, "attachment request is outside its bound", http.StatusRequestEntityTooLarge)
		return
	}
	decoded, err := DecodeRequest(raw)
	if err != nil {
		http.Error(w, "invalid attachment request", http.StatusBadRequest)
		return
	}
	grant, err := attachments.DecodeGrantJSON(decoded.Grant)
	if err != nil {
		http.Error(w, "invalid attachment grant", http.StatusBadRequest)
		return
	}
	want, err := attachments.HTTPSLocator("https://"+request.Host, grant.ManifestDigest)
	if err != nil {
		http.Error(w, "invalid attachment HTTPS authority", http.StatusBadRequest)
		return
	}
	parsed, err := attachments.ParseHTTPSLocator(want, grant.ManifestDigest)
	if err != nil {
		http.Error(w, "invalid attachment HTTPS path", http.StatusBadRequest)
		return
	}
	if parsed.Path != request.URL.Path {
		http.Error(w, "attachment path does not match its grant", http.StatusBadRequest)
		return
	}
	responseRaw, err := EncodeResponse(s.Handle(request.Context(), raw))
	if err != nil {
		http.Error(w, "attachment response failed", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(responseRaw)
}

func refusal(code Code, detail string) Response {
	return Response{Schema: ResponseSchema, OK: false, Code: code, Detail: detail}
}

func classify(err error) Code {
	switch {
	case errors.Is(err, attachments.ErrStoreConflict):
		return CodeConflict
	case errors.Is(err, attachments.ErrStoreQuota):
		return CodeQuota
	case errors.Is(err, attachments.ErrLeaseNotFound):
		return CodeMissing
	default:
		return CodeDenied
	}
}

func boolPointer(value bool) *bool { return &value }

var _ http.Handler = (*Server)(nil)
