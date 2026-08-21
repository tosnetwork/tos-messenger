package attachmentapi

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"mime"
	"net"
	"net/http"
	"path/filepath"
	"time"

	"github.com/tosnetwork/tos-messenger/internal/safehttps"
	"github.com/tosnetwork/tos-messenger/pkg/attachments"
)

type Caller interface {
	Call(context.Context, Request) (Response, error)
}

type UnixClient struct {
	path    string
	timeout time.Duration
}

func NewUnixClient(path string, timeout time.Duration) (*UnixClient, error) {
	if !cleanAbsolute(path) {
		return nil, errors.New("attachment service socket path must be absolute and clean")
	}
	if timeout == 0 {
		timeout = DefaultTimeout
	}
	if timeout < time.Second || timeout > time.Minute {
		return nil, errors.New("attachment client timeout is outside its bound")
	}
	return &UnixClient{path: path, timeout: timeout}, nil
}

func (c *UnixClient) Call(ctx context.Context, request Request) (Response, error) {
	if c == nil || ctx == nil {
		return Response{}, errors.New("invalid attachment service client")
	}
	raw, err := EncodeRequest(request)
	if err != nil {
		return Response{}, err
	}
	framed, err := FrameRequest(raw)
	if err != nil {
		return Response{}, err
	}
	dialer := net.Dialer{Timeout: c.timeout}
	connection, err := dialer.DialContext(ctx, "unix", c.path)
	if err != nil {
		return Response{}, errors.New("connect attachment service")
	}
	defer connection.Close()
	deadline := time.Now().Add(c.timeout)
	if value, ok := ctx.Deadline(); ok && value.Before(deadline) {
		deadline = value
	}
	if err := connection.SetDeadline(deadline); err != nil {
		return Response{}, err
	}
	if err := writeAll(connection, framed); err != nil {
		return Response{}, errors.New("write attachment request")
	}
	responseRaw, err := ReadResponseFrame(bufio.NewReader(connection))
	if err != nil {
		return Response{}, errors.New("read attachment response")
	}
	return decodeCallResponse(responseRaw)
}

type HTTPSConfig struct {
	RequestTimeout time.Duration
	ConnectTimeout time.Duration
	Resolver       safehttps.IPResolver
}

type HTTPSClient struct {
	locator  string
	manifest string
	client   *http.Client
}

func NewHTTPSClient(locator, manifestDigest string, config HTTPSConfig) (*HTTPSClient, error) {
	parsed, err := attachments.ParseHTTPSLocator(locator, manifestDigest)
	if err != nil {
		return nil, err
	}
	requestTimeout := config.RequestTimeout
	if requestTimeout == 0 {
		requestTimeout = DefaultTimeout
	}
	connectTimeout := config.ConnectTimeout
	if connectTimeout == 0 {
		connectTimeout = 5 * time.Second
	}
	client, err := safehttps.NewClient(safehttps.Config{RequestTimeout: requestTimeout, ConnectTimeout: connectTimeout,
		Resolver: config.Resolver, MaxIdleConns: 8, MaxPerHost: 2,
		RedirectError: "attachment HTTPS redirects are refused"})
	if err != nil {
		return nil, err
	}
	return &HTTPSClient{locator: parsed.String(), manifest: manifestDigest, client: client}, nil
}

func (c *HTTPSClient) Call(ctx context.Context, request Request) (Response, error) {
	if c == nil || c.client == nil || ctx == nil {
		return Response{}, errors.New("invalid attachment HTTPS client")
	}
	grant, err := attachments.DecodeGrantJSON(request.Grant)
	if err != nil || grant.ManifestDigest != c.manifest {
		return Response{}, errors.New("attachment HTTPS request does not match its locator")
	}
	raw, err := EncodeRequest(request)
	if err != nil {
		return Response{}, err
	}
	httpRequest, err := http.NewRequestWithContext(ctx, http.MethodPost, c.locator, bytes.NewReader(raw))
	if err != nil {
		return Response{}, err
	}
	httpRequest.Header.Set("Content-Type", "application/json")
	httpRequest.Header.Set("Accept", "application/json")
	response, err := c.client.Do(httpRequest)
	if err != nil {
		return Response{}, err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return Response{}, fmt.Errorf("attachment HTTPS service returned status %d", response.StatusCode)
	}
	mediaType, params, err := mime.ParseMediaType(response.Header.Get("Content-Type"))
	if err != nil || mediaType != "application/json" || len(params) != 0 || response.Header.Get("Content-Encoding") != "" {
		return Response{}, errors.New("invalid attachment HTTPS response media type")
	}
	if response.ContentLength > int64(MaxResponseBytes) {
		return Response{}, errors.New("attachment HTTPS response exceeds its bound")
	}
	responseRaw, err := io.ReadAll(io.LimitReader(response.Body, int64(MaxResponseBytes)+1))
	if err != nil || len(responseRaw) > int(MaxResponseBytes) {
		return Response{}, errors.New("read bounded attachment HTTPS response")
	}
	return decodeCallResponse(responseRaw)
}

func (c *HTTPSClient) CloseIdleConnections() {
	if c != nil && c.client != nil {
		c.client.CloseIdleConnections()
	}
}

// GrantClient owns one independent capability key. It signs a fresh nonce per
// attempt and independently verifies every storage ACK and fetched digest.
type GrantClient struct {
	caller Caller
	grant  attachments.CapabilityGrant
	key    ed25519.PrivateKey
	now    func() time.Time
	rng    io.Reader
}

func NewGrantClient(caller Caller, grant attachments.CapabilityGrant, key ed25519.PrivateKey, now func() time.Time, rng io.Reader) (*GrantClient, error) {
	if caller == nil || len(key) != ed25519.PrivateKeySize {
		return nil, errors.New("invalid attachment grant client")
	}
	if _, err := attachments.GrantCanonicalBytes(grant); err != nil {
		return nil, err
	}
	public, err := hex.DecodeString(grant.CapabilityPublicKeyHex)
	if err != nil || !key.Public().(ed25519.PublicKey).Equal(ed25519.PublicKey(public)) {
		return nil, errors.New("attachment capability key does not match its grant")
	}
	if now == nil {
		now = time.Now
	}
	if rng == nil {
		rng = rand.Reader
	}
	return &GrantClient{caller: caller, grant: grant, key: append(ed25519.PrivateKey(nil), key...), now: now, rng: rng}, nil
}

func (c *GrantClient) Upload(ctx context.Context, chunks []attachments.Chunk) (attachments.StoredAck, error) {
	if c == nil || ctx == nil || len(chunks) != len(c.grant.ChunkDigests) {
		return attachments.StoredAck{}, errors.New("invalid complete attachment upload")
	}
	var final attachments.StoredAck
	for start := 0; start < len(chunks); start += MaxBatchChunks {
		end := start + MaxBatchChunks
		if end > len(chunks) {
			end = len(chunks)
		}
		batch := chunks[start:end]
		bodyDigest, err := attachments.UploadBodyDigest(c.grant, batch)
		if err != nil {
			return attachments.StoredAck{}, err
		}
		response, err := c.call(ctx, OpUpload, attachments.OperationUpload, bodyDigest, batch, nil)
		if err != nil {
			return attachments.StoredAck{}, err
		}
		if response.Complete == nil {
			return attachments.StoredAck{}, errors.New("attachment upload response has no completion state")
		}
		if *response.Complete {
			final, err = attachments.DecodeStoredAckJSON(response.Ack)
			if err != nil || c.verifyStoredAck(final) != nil {
				return attachments.StoredAck{}, errors.New("invalid attachment upload acknowledgement")
			}
		}
	}
	if final.Schema == "" {
		return attachments.StoredAck{}, errors.New("attachment upload did not publish its complete lease")
	}
	return final, nil
}

func (c *GrantClient) Fetch(ctx context.Context, digests []string) ([]attachments.Chunk, error) {
	if c == nil || ctx == nil || len(digests) == 0 || len(digests) > len(c.grant.ChunkDigests) {
		return nil, errors.New("invalid attachment fetch")
	}
	result := make([]attachments.Chunk, 0, len(digests))
	positions := make(map[string]uint32, len(c.grant.ChunkDigests))
	for index, digest := range c.grant.ChunkDigests {
		positions[digest] = uint32(index)
	}
	for start := 0; start < len(digests); start += MaxBatchChunks {
		end := start + MaxBatchChunks
		if end > len(digests) {
			end = len(digests)
		}
		batch := digests[start:end]
		bodyDigest, err := attachments.FetchBodyDigest(c.grant, batch)
		if err != nil {
			return nil, err
		}
		response, err := c.call(ctx, OpFetch, attachments.OperationFetch, bodyDigest, nil, batch)
		if err != nil {
			return nil, err
		}
		if response.Chunks == nil {
			return nil, errors.New("attachment fetch response has no chunks")
		}
		chunks, err := DecodeChunks(*response.Chunks)
		if err != nil || len(chunks) != len(batch) {
			return nil, errors.New("invalid attachment fetch response")
		}
		for index, chunk := range chunks {
			if chunk.Digest != batch[index] || chunk.Index != positions[chunk.Digest] {
				return nil, errors.New("attachment fetch response substituted an object")
			}
		}
		result = append(result, chunks...)
	}
	return result, nil
}

func (c *GrantClient) Delete(ctx context.Context) (attachments.DeleteAck, error) {
	if c == nil || ctx == nil {
		return attachments.DeleteAck{}, errors.New("invalid attachment deletion")
	}
	bodyDigest, err := attachments.DeleteBodyDigest(c.grant)
	if err != nil {
		return attachments.DeleteAck{}, err
	}
	response, err := c.call(ctx, OpDelete, attachments.OperationDelete, bodyDigest, nil, nil)
	if err != nil {
		return attachments.DeleteAck{}, err
	}
	ack, err := attachments.DecodeDeleteAckJSON(response.Ack)
	if err != nil || c.verifyDeleteAck(ack) != nil {
		return attachments.DeleteAck{}, errors.New("invalid attachment deletion acknowledgement")
	}
	return ack, nil
}

func (c *GrantClient) call(ctx context.Context, op Operation, operation attachments.Operation, bodyDigest string,
	chunks []attachments.Chunk, digests []string) (Response, error) {
	now := c.now()
	if now.IsZero() || now.Unix() < 0 {
		return Response{}, errors.New("invalid attachment client time")
	}
	expires := now.Add(attachments.MaxRequestLifetime)
	if expires.Unix() > int64(c.grant.ExpiresAtUnix) {
		expires = time.Unix(int64(c.grant.ExpiresAtUnix), 0)
	}
	if !expires.After(now) {
		return Response{}, errors.New("attachment grant is expired")
	}
	nonce := make([]byte, 32)
	if _, err := io.ReadFull(c.rng, nonce); err != nil {
		return Response{}, errors.New("draw attachment request nonce")
	}
	grantDigest, err := attachments.GrantDigest(c.grant)
	if err != nil {
		return Response{}, err
	}
	access, err := attachments.SignAccessRequest(attachments.AccessRequest{GrantDigest: grantDigest,
		Operation: operation, BodyDigest: bodyDigest, NonceHex: hex.EncodeToString(nonce),
		IssuedAtUnix: uint64(now.Unix()), ExpiresAtUnix: uint64(expires.Unix())}, c.key)
	if err != nil {
		return Response{}, err
	}
	grantRaw, err := attachments.EncodeGrantJSON(c.grant)
	if err != nil {
		return Response{}, err
	}
	accessRaw, err := attachments.EncodeAccessRequestJSON(access)
	if err != nil {
		return Response{}, err
	}
	request := Request{Op: op, Grant: grantRaw, Access: accessRaw, Digests: append([]string(nil), digests...)}
	if len(chunks) > 0 {
		request.Chunks, err = EncodeChunks(chunks)
		if err != nil {
			return Response{}, err
		}
	}
	return c.caller.Call(ctx, request)
}

func (c *GrantClient) verifyStoredAck(ack attachments.StoredAck) error {
	storage, err := hex.DecodeString(c.grant.StoragePublicKeyHex)
	if err != nil {
		return err
	}
	grantDigest, err := attachments.GrantDigest(c.grant)
	if err != nil {
		return err
	}
	if err := attachments.VerifyStoredAck(ack, ed25519.PublicKey(storage)); err != nil || ack.GrantDigest != grantDigest ||
		ack.ManifestDigest != c.grant.ManifestDigest || ack.CiphertextBytes != c.grant.CiphertextBytes ||
		ack.RetainUntilUnix != c.grant.RetainUntilUnix || ack.StoredAtUnix < c.grant.IssuedAtUnix ||
		ack.StoredAtUnix >= c.grant.ExpiresAtUnix || len(ack.ChunkDigests) != len(c.grant.ChunkDigests) {
		return errors.New("attachment StoredAck does not match its grant")
	}
	for index := range ack.ChunkDigests {
		if ack.ChunkDigests[index] != c.grant.ChunkDigests[index] {
			return errors.New("attachment StoredAck changed its manifest")
		}
	}
	return nil
}

func (c *GrantClient) verifyDeleteAck(ack attachments.DeleteAck) error {
	storage, err := hex.DecodeString(c.grant.StoragePublicKeyHex)
	if err != nil {
		return err
	}
	grantDigest, err := attachments.GrantDigest(c.grant)
	if err != nil {
		return err
	}
	if err := attachments.VerifyDeleteAck(ack, ed25519.PublicKey(storage)); err != nil ||
		ack.GrantDigest != grantDigest || ack.ManifestDigest != c.grant.ManifestDigest ||
		ack.ObservedAtUnix < c.grant.IssuedAtUnix || ack.ObservedAtUnix >= c.grant.ExpiresAtUnix {
		return errors.New("attachment DeleteAck does not match its grant")
	}
	return nil
}

func decodeCallResponse(raw []byte) (Response, error) {
	response, err := DecodeResponse(raw)
	if err != nil {
		return Response{}, err
	}
	if !response.OK {
		return response, errors.New("attachment service refused " + string(response.Code) + ": " + response.Detail)
	}
	return response, nil
}

func writeAll(writer io.Writer, raw []byte) error {
	for len(raw) > 0 {
		n, err := writer.Write(raw)
		if err != nil || n <= 0 || n > len(raw) {
			return errors.New("short attachment service write")
		}
		raw = raw[n:]
	}
	return nil
}

func cleanAbsolute(path string) bool {
	return filepath.IsAbs(path) && filepath.Clean(path) == path
}

var _ Caller = (*UnixClient)(nil)
var _ Caller = (*HTTPSClient)(nil)
