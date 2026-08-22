// Package protocolbridge delivers admitted foreign-protocol events to
// protocol-specific, owner-private local consumers.
package protocolbridge

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"path/filepath"
	"time"

	"github.com/tosnetwork/tos-messenger/pkg/envelope"
	"github.com/tosnetwork/tos-messenger/pkg/payload"
)

const (
	DefaultTimeout   = 30 * time.Second
	maxResponseBytes = 4096
	eventContentType = "application/vnd.tos.messaging.event.v2+json"
	a2aReceiverPath  = "/v1/a2a-event"
	mcpReceiverPath  = "/v1/mcp-event"
)

// Profile fixes both the accepted event kinds and the local HTTP endpoint.
// It is deliberately not an arbitrary string supplied by configuration.
type Profile string

const (
	ProfileA2A Profile = "a2a"
	ProfileMCP Profile = "mcp"
)

// UnixReceiver posts one complete canonical Event. The consumer can therefore
// recompute EventID and independently enforce sender and conversation policy.
type UnixReceiver struct {
	client  *http.Client
	profile Profile
	path    string
}

func NewUnixReceiver(socketPath string, profile Profile, timeout time.Duration) (*UnixReceiver, error) {
	if !filepath.IsAbs(socketPath) || filepath.Clean(socketPath) != socketPath {
		return nil, errors.New("protocol receiver socket must be a clean absolute path")
	}
	if timeout == 0 {
		timeout = DefaultTimeout
	}
	if timeout < time.Second || timeout > 5*time.Minute {
		return nil, errors.New("protocol receiver timeout is outside 1s..5m")
	}
	path := ""
	switch profile {
	case ProfileA2A:
		path = a2aReceiverPath
	case ProfileMCP:
		path = mcpReceiverPath
	default:
		return nil, errors.New("unknown protocol receiver profile")
	}
	transport := &http.Transport{
		Proxy: nil,
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, "unix", socketPath)
		},
	}
	return &UnixReceiver{
		client: &http.Client{Transport: transport, Timeout: timeout}, profile: profile, path: path,
	}, nil
}

func (r *UnixReceiver) Receive(ctx context.Context, event envelope.Event) error {
	if r == nil || r.client == nil || ctx == nil {
		return errors.New("invalid Unix protocol receiver")
	}
	if !r.accepts(event.Kind) {
		return errors.New("event kind does not match protocol receiver profile")
	}
	// Decode once more at the last trust boundary. This catches a caller that
	// constructs an Event without passing it through normal admission.
	if _, err := payload.Decode(event.Kind, event.Content); err != nil {
		return errors.New("invalid protocol event payload: " + err.Error())
	}
	wire, err := envelope.EncodeEventJSON(event)
	if err != nil {
		return err
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, "http://unix"+r.path, bytes.NewReader(wire))
	if err != nil {
		return err
	}
	request.Header.Set("Content-Type", eventContentType)
	response, err := r.client.Do(request)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	read, readErr := io.Copy(io.Discard, io.LimitReader(response.Body, maxResponseBytes+1))
	if readErr != nil || read > maxResponseBytes {
		return errors.New("read protocol receiver response")
	}
	if response.StatusCode != http.StatusAccepted {
		return errors.New("local protocol consumer rejected event")
	}
	return nil
}

func (r *UnixReceiver) accepts(kind string) bool {
	switch r.profile {
	case ProfileA2A:
		return kind == "a2a.message"
	case ProfileMCP:
		return kind == "mcp.call" || kind == "mcp.result"
	default:
		return false
	}
}
