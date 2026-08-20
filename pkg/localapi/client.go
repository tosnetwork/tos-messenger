package localapi

import (
	"bufio"
	"context"
	"errors"
	"net"
	"path/filepath"
	"time"
)

const DefaultClientTimeout = 10 * time.Second

// Client is a bounded caller for one daemon-local authority socket.
// Operation permissions remain a property of the socket selected by the
// daemon; this type deliberately cannot choose or elevate a principal.
type Client struct {
	path    string
	timeout time.Duration
}

func NewClient(path string, timeout time.Duration) (*Client, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return nil, errors.New("local API socket path must be absolute and clean")
	}
	if timeout == 0 {
		timeout = DefaultClientTimeout
	}
	if timeout < time.Second || timeout > time.Minute {
		return nil, errors.New("local API timeout is outside its bound")
	}
	return &Client{path: path, timeout: timeout}, nil
}

func (c *Client) Call(ctx context.Context, request Request) (Response, error) {
	if c == nil {
		return Response{}, errors.New("no local API client")
	}
	framed, err := EncodeRequest(request)
	if err != nil {
		return Response{}, err
	}
	dialer := net.Dialer{Timeout: c.timeout}
	connection, err := dialer.DialContext(ctx, "unix", c.path)
	if err != nil {
		return Response{}, errors.New("connect local API")
	}
	defer connection.Close()
	deadline := time.Now().Add(c.timeout)
	if contextDeadline, ok := ctx.Deadline(); ok && contextDeadline.Before(deadline) {
		deadline = contextDeadline
	}
	if err := connection.SetDeadline(deadline); err != nil {
		return Response{}, err
	}
	for len(framed) > 0 {
		written, writeErr := connection.Write(framed)
		if writeErr != nil {
			return Response{}, errors.New("write local API request")
		}
		if written <= 0 || written > len(framed) {
			return Response{}, errors.New("short local API write")
		}
		framed = framed[written:]
	}
	raw, err := ReadFrame(bufio.NewReader(connection))
	if err != nil {
		return Response{}, errors.New("read local API response")
	}
	response, err := DecodeResponse(raw)
	if err != nil {
		return Response{}, err
	}
	if !response.OK {
		return response, errors.New("local API refused " + string(response.Code) + ": " + response.Detail)
	}
	return response, nil
}
