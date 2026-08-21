// Package signerapi implements the narrow local client used to keep the
// delegated Endpoint private key outside the Messenger daemon.
package signerapi

import (
	"bufio"
	"bytes"
	"crypto"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"io"
	"net"
	"path/filepath"
	"time"

	"github.com/tosnetwork/tos-messenger/internal/localwire"
)

const (
	RequestSchema  = "tos.messaging.endpoint-sign-request.v1"
	ResponseSchema = "tos.messaging.endpoint-sign-response.v1"
	// MaxFrameBytes covers the maximum 512-chunk attachment capability grant
	// while remaining a strict local signing bound.
	MaxFrameBytes  = 512 << 10
	DefaultTimeout = 10 * time.Second
)

type request struct {
	Schema  string `json:"schema"`
	Message []byte `json:"message_base64"`
}

type response struct {
	Schema    string `json:"schema"`
	OK        bool   `json:"ok"`
	Signature []byte `json:"signature_base64,omitempty"`
	Detail    string `json:"detail,omitempty"`
}

// Client implements crypto.Signer by sending an exact un-hashed message to a
// separately custodied local Endpoint signer. The delegated public key is
// pinned locally and every returned 64-byte signature is verified before use.
type Client struct {
	path    string
	public  ed25519.PublicKey
	timeout time.Duration
}

func NewClient(path string, public ed25519.PublicKey, timeout time.Duration) (*Client, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path || len(public) != ed25519.PublicKeySize {
		return nil, errors.New("endpoint signer needs a socket and 32-byte public key")
	}
	if timeout == 0 {
		timeout = DefaultTimeout
	}
	if timeout < time.Second || timeout > time.Minute {
		return nil, errors.New("endpoint signer timeout is outside its bound")
	}
	return &Client{path: path, public: append(ed25519.PublicKey(nil), public...), timeout: timeout}, nil
}

func (c *Client) Public() crypto.PublicKey {
	if c == nil {
		return nil
	}
	return append(ed25519.PublicKey(nil), c.public...)
}

func (c *Client) Sign(_ io.Reader, message []byte, opts crypto.SignerOpts) ([]byte, error) {
	if c == nil {
		return nil, errors.New("no Endpoint signer client")
	}
	if opts == nil || opts.HashFunc() != crypto.Hash(0) || len(message) == 0 || len(message) > MaxFrameBytes/2 {
		return nil, errors.New("Endpoint signer accepts one bounded raw Ed25519 message")
	}
	body, err := json.Marshal(request{Schema: RequestSchema, Message: append([]byte(nil), message...)})
	if err != nil {
		return nil, err
	}
	connection, err := net.DialTimeout("unix", c.path, c.timeout)
	if err != nil {
		return nil, errors.New("connect Endpoint signer")
	}
	defer connection.Close()
	if err := connection.SetDeadline(time.Now().Add(c.timeout)); err != nil {
		return nil, err
	}
	if err := localwire.WriteFrame(connection, body, MaxFrameBytes); err != nil {
		return nil, errors.New("write Endpoint signing request")
	}
	raw, err := localwire.ReadFrame(bufio.NewReader(connection), MaxFrameBytes)
	if err != nil {
		return nil, errors.New("read Endpoint signing response")
	}
	decoded, err := decodeResponse(raw)
	if err != nil {
		return nil, err
	}
	if !decoded.OK {
		return nil, errors.New("Endpoint signer refused: " + decoded.Detail)
	}
	if len(decoded.Signature) != ed25519.SignatureSize || !ed25519.Verify(c.public, message, decoded.Signature) {
		return nil, errors.New("Endpoint signer returned an invalid signature")
	}
	return append([]byte(nil), decoded.Signature...), nil
}

func decodeResponse(raw []byte) (response, error) {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	var value response
	if err := decoder.Decode(&value); err != nil {
		return response{}, errors.New("decode Endpoint signing response")
	}
	if err := decoder.Decode(new(any)); !errors.Is(err, io.EOF) {
		return response{}, errors.New("Endpoint signing response has trailing JSON")
	}
	if value.Schema != ResponseSchema {
		return response{}, errors.New("unsupported Endpoint signing response schema")
	}
	if value.OK {
		if value.Detail != "" || len(value.Signature) != ed25519.SignatureSize {
			return response{}, errors.New("invalid successful Endpoint signing response")
		}
	} else if value.Detail == "" || len(value.Signature) != 0 {
		return response{}, errors.New("invalid refused Endpoint signing response")
	}
	return value, nil
}
