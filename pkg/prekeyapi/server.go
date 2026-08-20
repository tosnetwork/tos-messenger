package prekeyapi

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"net"
	"time"

	"github.com/tosnetwork/tos-messenger/internal/localwire"
	"github.com/tosnetwork/tos-messenger/pkg/e2ee"
	"github.com/tosnetwork/tos-messenger/pkg/eventlog"
	"github.com/tosnetwork/tos-messenger/pkg/identity"
)

const DefaultRequestTimeout = 30 * time.Second

type Config struct {
	Delegation identity.Delegation
	Journal    *eventlog.Journal
	Now        func() time.Time
	Timeout    time.Duration
}

type Server struct {
	config        Config
	contributions *eventlog.PrekeyContributionLedger
	publications  *eventlog.PrekeyPublicationLedger
}

func NewServer(config Config) (*Server, error) {
	if config.Journal == nil {
		return nil, errors.New("prekey device API requires a durable journal")
	}
	raw, err := identity.EncodeJSON(config.Delegation)
	if err != nil {
		return nil, err
	}
	delegation, err := identity.DecodeJSON(raw)
	if err != nil {
		return nil, err
	}
	config.Delegation = delegation
	if config.Now == nil {
		config.Now = time.Now
	}
	if config.Timeout == 0 {
		config.Timeout = DefaultRequestTimeout
	}
	if config.Timeout < 0 {
		return nil, errors.New("invalid prekey device API timeout")
	}
	contributions, err := config.Journal.OpenPrekeyContributions()
	if err != nil {
		return nil, err
	}
	publications, err := config.Journal.OpenPrekeyPublications()
	if err != nil {
		return nil, err
	}
	return &Server{config: config, contributions: contributions, publications: publications}, nil
}

// Listen creates the private Unix socket used only for public prekey
// contributions.
func Listen(path string) (net.Listener, error) { return localwire.Listen(path) }

// Serve handles bounded same-user connections until the listener is closed.
func (s *Server) Serve(ctx context.Context, listener net.Listener) error {
	if s == nil || ctx == nil || listener == nil {
		return errors.New("prekey device API needs a server and listener")
	}
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
	if localwire.VerifyPeer(connection) != nil {
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
		response := s.Handle(ctx, body)
		encoded, err := encodeResponse(response)
		if err != nil {
			return
		}
		if _, err := connection.Write(encoded); err != nil {
			return
		}
	}
}

// Handle processes an unframed request body for in-process composition and
// tests. Socket callers receive the same result through Serve.
func (s *Server) Handle(ctx context.Context, raw []byte) Response {
	if s == nil || ctx == nil {
		return refusal(CodeInternal, "prekey device API is unavailable")
	}
	request, err := DecodeRequest(raw)
	if err != nil {
		return refusal(CodeInvalidRequest, err.Error())
	}
	if err := ctx.Err(); err != nil {
		return refusal(CodeInternal, err.Error())
	}
	now := s.config.Now()
	switch request.Op {
	case OpCurrentGeneration:
		collection, found, err := s.contributions.CurrentPrekeyCollection(s.config.Delegation, now)
		if err != nil {
			return refusal(CodeInternal, err.Error())
		}
		if !found {
			return refusal(CodeNoGeneration, "no prekey generation is planned")
		}
		return Response{OK: true, Generation: generationFromCollection(collection)}
	case OpSubmitContribution:
		bundle, err := e2ee.DecodeBundleJSON(request.Bundle)
		if err != nil {
			return refusal(CodeInvalidRequest, err.Error())
		}
		canonical, err := e2ee.EncodeBundleJSON(bundle)
		if err != nil || !bytes.Equal(canonical, request.Bundle) {
			return refusal(CodeInvalidRequest, "prekey contribution is not canonical JSON")
		}
		collection, fresh, err := s.contributions.AddPrekeyContribution(s.config.Delegation, bundle, now)
		if err != nil {
			return refusal(contributionCode(err), err.Error())
		}
		response := Response{OK: true, Generation: generationFromCollection(collection), ContributionFresh: fresh}
		if !collection.Complete {
			return response
		}
		publication, publicationFresh, err := s.contributions.FinalizePrekeyCollection(
			s.config.Delegation, s.publications, now,
		)
		if err != nil {
			return refusal(contributionCode(err), err.Error())
		}
		response.Generation.FinalizedSetDigest = publication.SetDigest
		response.PublicationFresh = publicationFresh
		return response
	}
	return refusal(CodeInvalidRequest, "unknown prekey device operation")
}

func generationFromCollection(collection eventlog.PrekeyCollection) *Generation {
	return &Generation{
		EndpointID: collection.EndpointID, DeviceIDs: append([]string(nil), collection.Plan.DeviceIDs...),
		AlgorithmID: collection.Plan.AlgorithmID, IssuedAtUnix: collection.Plan.IssuedAtUnix,
		ExpiresAtUnix: collection.Plan.ExpiresAtUnix, ContributionCount: len(collection.Contributions),
		Complete: collection.Complete, FinalizedSetDigest: collection.FinalizedSetDigest,
	}
}

func contributionCode(err error) Code {
	if errors.Is(err, eventlog.ErrPrekeyEquivocation) || errors.Is(err, e2ee.ErrSetEquivocation) ||
		errors.Is(err, e2ee.ErrSetRollback) {
		return CodeConflict
	}
	return CodeNotAccepted
}

func refusal(code Code, detail string) Response {
	return Response{OK: false, Code: code, Detail: detail}
}
