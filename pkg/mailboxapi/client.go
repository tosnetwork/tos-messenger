package mailboxapi

import (
	"bufio"
	"context"
	"errors"
	"net"
	"path/filepath"
	"time"
)

type Client struct {
	path    string
	timeout time.Duration
}

func NewUnixClient(path string, timeout time.Duration) (*Client, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return nil, errors.New("Mailbox service socket path must be absolute and clean")
	}
	if timeout == 0 {
		timeout = DefaultTimeout
	}
	if timeout < time.Second || timeout > time.Minute {
		return nil, errors.New("Mailbox client timeout is outside its bound")
	}
	return &Client{path: path, timeout: timeout}, nil
}

func (c *Client) Call(ctx context.Context, request Request) (Response, error) {
	if c == nil || ctx == nil {
		return Response{}, errors.New("invalid Mailbox service client")
	}
	framed, err := EncodeRequest(request)
	if err != nil {
		return Response{}, err
	}
	dialer := net.Dialer{Timeout: c.timeout}
	connection, err := dialer.DialContext(ctx, "unix", c.path)
	if err != nil {
		return Response{}, errors.New("connect Mailbox service")
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
			return Response{}, errors.New("write Mailbox request")
		}
		if written <= 0 || written > len(framed) {
			return Response{}, errors.New("short Mailbox request write")
		}
		framed = framed[written:]
	}
	raw, err := ReadResponseFrame(bufio.NewReader(connection))
	if err != nil {
		return Response{}, errors.New("read Mailbox response")
	}
	response, err := DecodeResponse(raw)
	if err != nil {
		return Response{}, err
	}
	if !response.OK {
		return response, errors.New("Mailbox service refused " + string(response.Code) + ": " + response.Detail)
	}
	return response, nil
}
