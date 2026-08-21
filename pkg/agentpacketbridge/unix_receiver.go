package agentpacketbridge

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"path/filepath"
	"time"

	"github.com/tosnetwork/tos-service-protocol/pkg/agentpacket"
)

const (
	DefaultUnixReceiverTimeout = 30 * time.Second
	unixReceiverPath           = "/v1/agent-packet"
	maxUnixReceiverResponse    = 4096
)

// UnixReceiver delivers a canonical, already Messenger-verified packet to an
// owner-private local provider socket. The provider must independently verify
// finalized packet authority before invoking its Execution Gate.
type UnixReceiver struct {
	client *http.Client
}

func NewUnixReceiver(socketPath string, timeout time.Duration) (*UnixReceiver, error) {
	if !filepath.IsAbs(socketPath) || filepath.Clean(socketPath) != socketPath {
		return nil, errors.New("Agent Packet receiver socket must be a clean absolute path")
	}
	if timeout == 0 {
		timeout = DefaultUnixReceiverTimeout
	}
	if timeout < time.Second || timeout > 5*time.Minute {
		return nil, errors.New("Agent Packet receiver timeout is outside 1s..5m")
	}
	transport := &http.Transport{
		Proxy: nil,
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, "unix", socketPath)
		},
	}
	return &UnixReceiver{client: &http.Client{Transport: transport, Timeout: timeout}}, nil
}

func (r *UnixReceiver) Receive(ctx context.Context, packet agentpacket.Packet) error {
	if r == nil || r.client == nil || ctx == nil {
		return errors.New("invalid Unix Agent Packet receiver")
	}
	wire, err := agentpacket.EncodeJSON(packet)
	if err != nil {
		return err
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, "http://unix"+unixReceiverPath,
		bytes.NewReader(wire))
	if err != nil {
		return err
	}
	request.Header.Set("Content-Type", "application/json")
	response, err := r.client.Do(request)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	read, readErr := io.Copy(io.Discard, io.LimitReader(response.Body, maxUnixReceiverResponse+1))
	if readErr != nil || read > maxUnixReceiverResponse {
		return errors.New("read Agent Packet receiver response")
	}
	if response.StatusCode != http.StatusAccepted {
		return errors.New("local OpenFox provider rejected Agent Packet")
	}
	return nil
}
