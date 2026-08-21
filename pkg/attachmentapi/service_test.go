package attachmentapi

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/tosnetwork/tos-messenger/internal/canon"
	"github.com/tosnetwork/tos-messenger/pkg/attachments"
)

type fixedAuthority struct{ key ed25519.PublicKey }

func (a fixedAuthority) ResolveAttachmentEndpoint(context.Context, attachments.CapabilityGrant, time.Time) (ed25519.PublicKey, error) {
	return a.key, nil
}

type fixture struct {
	now           time.Time
	endpointKey   ed25519.PrivateKey
	storageKey    ed25519.PrivateKey
	capabilityKey ed25519.PrivateKey
	ref           attachments.Reference
	chunks        []attachments.Chunk
	grant         attachments.CapabilityGrant
}

func newFixture(t testing.TB, chunkCount int) fixture {
	t.Helper()
	now := time.Unix(1_800_000_000, 0)
	endpointKey := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x31}, ed25519.SeedSize))
	storageKey := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x32}, ed25519.SeedSize))
	capabilityKey := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x33}, ed25519.SeedSize))
	plaintext := bytes.Repeat([]byte("a"), (chunkCount-1)*attachments.DefaultChunkBytes+17)
	random := bytes.NewReader(bytes.Repeat([]byte{0x44}, attachments.KeyBytes+attachments.AttachmentIDBytes+attachments.NoncePrefixBytes))
	ref, chunks, err := attachments.Seal(random, plaintext, attachments.Metadata{Filename: "opaque.bin",
		MediaType: "application/octet-stream", PlaintextDigest: canon.Digest(plaintext), ExpiresAtUnix: uint64(now.Add(time.Hour).Unix())})
	if err != nil {
		t.Fatal(err)
	}
	manifestDigest, err := attachments.ManifestDigest(ref.Manifest)
	if err != nil {
		t.Fatal(err)
	}
	var ciphertextBytes uint64
	for _, chunk := range chunks {
		ciphertextBytes += uint64(len(chunk.Ciphertext))
	}
	grant, err := attachments.SignGrant(attachments.CapabilityGrant{
		NetworkID: "tos-local", GenesisRootHash: strings.Repeat("a", 64), GenesisFileHash: strings.Repeat("b", 64),
		AgentID: "agent_" + strings.Repeat("c", 64), EndpointID: "mep_" + strings.Repeat("d", 64),
		StoragePublicKeyHex:    hex.EncodeToString(storageKey.Public().(ed25519.PublicKey)),
		CapabilityPublicKeyHex: hex.EncodeToString(capabilityKey.Public().(ed25519.PublicKey)),
		ManifestDigest:         manifestDigest, ChunkDigests: append([]string(nil), ref.Manifest.ChunkDigests...),
		CiphertextBytes: ciphertextBytes, RetainUntilUnix: ref.Metadata.ExpiresAtUnix,
		Operations:   []attachments.Operation{attachments.OperationDelete, attachments.OperationFetch, attachments.OperationUpload},
		IssuedAtUnix: uint64(now.Add(-time.Minute).Unix()), ExpiresAtUnix: uint64(now.Add(2 * time.Hour).Unix()),
	}, endpointKey)
	if err != nil {
		t.Fatal(err)
	}
	return fixture{now: now, endpointKey: endpointKey, storageKey: storageKey,
		capabilityKey: capabilityKey, ref: ref, chunks: chunks, grant: grant}
}

func startService(t *testing.T, f fixture, root, socket string) (*attachments.Store, *UnixClient, context.CancelFunc, <-chan error) {
	t.Helper()
	store, err := attachments.OpenStore(root, attachments.DefaultStoreQuota())
	if err != nil {
		t.Fatal(err)
	}
	authenticated, err := attachments.NewAuthenticatedStore(store, fixedAuthority{f.endpointKey.Public().(ed25519.PublicKey)}, f.storageKey)
	if err != nil {
		t.Fatal(err)
	}
	server, err := NewServer(authenticated, func() time.Time { return f.now }, 0)
	if err != nil {
		t.Fatal(err)
	}
	listener, err := ListenUnix(socket)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- server.Serve(ctx, listener) }()
	client, err := NewUnixClient(socket, 10*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	return store, client, cancel, done
}

func TestUnixServiceInterruptedUploadFetchDeleteAndRestartReplay(t *testing.T) {
	f := newFixture(t, MaxBatchChunks+1)
	root := t.TempDir() + "/storage"
	socketDir := t.TempDir() + "/private"
	if err := os.Mkdir(socketDir, 0o700); err != nil {
		t.Fatal(err)
	}
	socket := socketDir + "/attachment.sock"
	store, caller, cancel, done := startService(t, f, root, socket)
	client, err := NewGrantClient(caller, f.grant, f.capabilityKey, func() time.Time { return f.now }, bytes.NewReader(nonceSequence(0x55, 16)))
	if err != nil {
		t.Fatal(err)
	}
	ack, err := client.Upload(context.Background(), f.chunks)
	if err != nil || !ack.Fresh || ack.ManifestDigest != f.grant.ManifestDigest {
		t.Fatalf("upload ack=%+v err=%v", ack, err)
	}
	fetched, err := client.Fetch(context.Background(), f.grant.ChunkDigests)
	if err != nil || len(fetched) != len(f.chunks) {
		t.Fatalf("fetch count=%d err=%v", len(fetched), err)
	}
	plaintext, err := attachments.Open(f.ref, fetched, attachments.DefaultPolicy(), f.now)
	if err != nil || len(plaintext) != (MaxBatchChunks)*attachments.DefaultChunkBytes+17 {
		t.Fatalf("open bytes=%d err=%v", len(plaintext), err)
	}

	replay := signedRequest(t, f, OpFetch, attachments.OperationFetch,
		mustFetchDigest(t, f.grant, f.grant.ChunkDigests[:1]), nil, f.grant.ChunkDigests[:1], 0x66)
	if response, err := caller.Call(context.Background(), replay); err != nil || response.Chunks == nil {
		t.Fatalf("initial replay request: %+v %v", response, err)
	}
	cancel()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}

	store, caller, cancel, done = startService(t, f, root, socket)
	defer func() { cancel(); <-done; _ = store.Close() }()
	if response, err := caller.Call(context.Background(), replay); err == nil || response.Code != CodeDenied {
		t.Fatalf("restart replay accepted: %+v %v", response, err)
	}
	client, err = NewGrantClient(caller, f.grant, f.capabilityKey, func() time.Time { return f.now }, bytes.NewReader(nonceSequence(0x77, 16)))
	if err != nil {
		t.Fatal(err)
	}
	deleteAck, err := client.Delete(context.Background())
	if err != nil || !deleteAck.Deleted || deleteAck.ManifestDigest != f.grant.ManifestDigest {
		t.Fatalf("delete ack=%+v err=%v", deleteAck, err)
	}
	if _, err := client.Fetch(context.Background(), f.grant.ChunkDigests[:1]); err == nil {
		t.Fatal("fetched after lease deletion")
	}
}

func TestServiceRefusesOperationBodyAuthorityAndShapeSubstitution(t *testing.T) {
	f := newFixture(t, 2)
	store, err := attachments.OpenStore(t.TempDir()+"/storage", attachments.DefaultStoreQuota())
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	authenticated, _ := attachments.NewAuthenticatedStore(store, fixedAuthority{f.endpointKey.Public().(ed25519.PublicKey)}, f.storageKey)
	server, _ := NewServer(authenticated, func() time.Time { return f.now }, 0)

	valid := signedRequest(t, f, OpUpload, attachments.OperationUpload,
		mustUploadDigest(t, f.grant, f.chunks[:1]), f.chunks[:1], nil, 0x11)
	raw, err := EncodeRequest(valid)
	if err != nil {
		t.Fatal(err)
	}
	if response := server.Handle(context.Background(), raw); !response.OK || response.Complete == nil || *response.Complete {
		t.Fatalf("first batch response=%+v", response)
	}

	changed := valid
	changed.Chunks = append([]WireChunk(nil), valid.Chunks...)
	changed.Chunks[0].CiphertextBase64 = changed.Chunks[0].CiphertextBase64[:len(changed.Chunks[0].CiphertextBase64)-4] + "AAAA"
	changedRaw, _ := jsonMarshal(changed)
	if response := server.Handle(context.Background(), changedRaw); response.OK || response.Code != CodeInvalid {
		t.Fatalf("ciphertext substitution response=%+v", response)
	}

	wrongOperation := signedRequest(t, f, OpFetch, attachments.OperationUpload,
		mustUploadDigest(t, f.grant, f.chunks[:1]), nil, f.grant.ChunkDigests[:1], 0x12)
	wrongRaw, _ := jsonMarshal(wrongOperation)
	if response := server.Handle(context.Background(), wrongRaw); response.OK || response.Code != CodeInvalid {
		t.Fatalf("operation substitution response=%+v", response)
	}

	otherStorage := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x71}, ed25519.SeedSize))
	otherGrant := f.grant
	otherGrant.StoragePublicKeyHex = hex.EncodeToString(otherStorage.Public().(ed25519.PublicKey))
	otherGrant.EndpointSignatureHex = ""
	otherGrant, _ = attachments.SignGrant(otherGrant, f.endpointKey)
	f.grant = otherGrant
	request := signedRequest(t, f, OpUpload, attachments.OperationUpload,
		mustUploadDigest(t, f.grant, f.chunks[1:]), f.chunks[1:], nil, 0x13)
	requestRaw, _ := EncodeRequest(request)
	if response := server.Handle(context.Background(), requestRaw); response.OK || response.Code != CodeDenied {
		t.Fatalf("storage substitution response=%+v", response)
	}

	notSeparated := f.grant
	notSeparated.StoragePublicKeyHex = notSeparated.CapabilityPublicKeyHex
	notSeparated.EndpointSignatureHex = ""
	if _, err := attachments.SignGrant(notSeparated, f.endpointKey); err == nil {
		t.Fatal("storage/capability key reuse accepted")
	}
}

func TestDeterministicAttachmentAuthenticationVector(t *testing.T) {
	f := newFixture(t, 2)
	grantDigest, _ := attachments.GrantDigest(f.grant)
	uploadDigest, _ := attachments.UploadBodyDigest(f.grant, f.chunks)
	fetchDigest, _ := attachments.FetchBodyDigest(f.grant, []string{f.grant.ChunkDigests[1]})
	deleteDigest, _ := attachments.DeleteBodyDigest(f.grant)
	want := map[string]string{
		"grant":  "sha256:96aa89cbea77ff69f1165aab8dc55abe273157d3c62c6a486a3497575213f6d5",
		"upload": "sha256:06044016c416f1646ff274092584980183067ab57b266a2caa5deca49c245586",
		"fetch":  "sha256:8ea37b98e15ba569b39a9d61c9c9497ce9fda734da6c73d775ccbbc8ab977ece",
		"delete": "sha256:1a69c46f6302e1caaf7601731e7e2432fe944169a081e24feb364a309f74f870",
	}
	for name, got := range map[string]string{"grant": grantDigest, "upload": uploadDigest, "fetch": fetchDigest, "delete": deleteDigest} {
		if got != want[name] {
			t.Fatalf("%s digest=%s want %s", name, got, want[name])
		}
	}
}

func TestHTTPSHandlerRequiresTLSAndExactManifestPath(t *testing.T) {
	f := newFixture(t, 1)
	store, err := attachments.OpenStore(t.TempDir()+"/storage", attachments.DefaultStoreQuota())
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	authenticated, _ := attachments.NewAuthenticatedStore(store, fixedAuthority{f.endpointKey.Public().(ed25519.PublicKey)}, f.storageKey)
	server, _ := NewServer(authenticated, func() time.Time { return f.now }, 0)
	request := signedRequest(t, f, OpUpload, attachments.OperationUpload,
		mustUploadDigest(t, f.grant, f.chunks), f.chunks, nil, 0x21)
	raw, _ := EncodeRequest(request)
	locator, _ := attachments.HTTPSLocator("https://attachments.example", f.grant.ManifestDigest)

	httpRequest := httptest.NewRequest(http.MethodPost, locator, bytes.NewReader(raw))
	httpRequest.TLS = &tls.ConnectionState{}
	httpRequest.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()
	server.ServeHTTP(response, httpRequest)
	if response.Code != http.StatusOK {
		t.Fatalf("HTTPS status=%d body=%s", response.Code, response.Body.String())
	}
	decoded, err := DecodeResponse(response.Body.Bytes())
	if err != nil || decoded.Complete == nil || !*decoded.Complete {
		t.Fatalf("HTTPS response=%+v err=%v", decoded, err)
	}

	for name, mutate := range map[string]func(*http.Request){
		"no TLS":     func(r *http.Request) { r.TLS = nil },
		"wrong path": func(r *http.Request) { r.URL.Path += "/other" },
		"query":      func(r *http.Request) { r.URL.RawQuery = "token=bearer" },
		"encoding":   func(r *http.Request) { r.Header.Set("Content-Encoding", "gzip") },
	} {
		t.Run(name, func(t *testing.T) {
			r := httptest.NewRequest(http.MethodPost, locator, bytes.NewReader(raw))
			r.TLS = &tls.ConnectionState{}
			r.Header.Set("Content-Type", "application/json")
			mutate(r)
			w := httptest.NewRecorder()
			server.ServeHTTP(w, r)
			if w.Code == http.StatusOK {
				t.Fatalf("accepted %s", name)
			}
		})
	}
}

func signedRequest(t testing.TB, f fixture, op Operation, operation attachments.Operation, bodyDigest string,
	chunks []attachments.Chunk, digests []string, nonce byte) Request {
	t.Helper()
	grantDigest, err := attachments.GrantDigest(f.grant)
	if err != nil {
		t.Fatal(err)
	}
	access, err := attachments.SignAccessRequest(attachments.AccessRequest{GrantDigest: grantDigest, Operation: operation,
		BodyDigest: bodyDigest, NonceHex: hex.EncodeToString(bytes.Repeat([]byte{nonce}, 32)),
		IssuedAtUnix: uint64(f.now.Unix()), ExpiresAtUnix: uint64(f.now.Add(time.Minute).Unix())}, f.capabilityKey)
	if err != nil {
		t.Fatal(err)
	}
	grantRaw, _ := attachments.EncodeGrantJSON(f.grant)
	accessRaw, _ := attachments.EncodeAccessRequestJSON(access)
	request := Request{Op: op, Grant: grantRaw, Access: accessRaw, Digests: append([]string(nil), digests...)}
	if len(chunks) > 0 {
		request.Chunks, err = EncodeChunks(chunks)
		if err != nil {
			t.Fatal(err)
		}
	}
	return request
}

func mustUploadDigest(t testing.TB, grant attachments.CapabilityGrant, chunks []attachments.Chunk) string {
	t.Helper()
	digest, err := attachments.UploadBodyDigest(grant, chunks)
	if err != nil {
		t.Fatal(err)
	}
	return digest
}

func mustFetchDigest(t testing.TB, grant attachments.CapabilityGrant, digests []string) string {
	t.Helper()
	digest, err := attachments.FetchBodyDigest(grant, digests)
	if err != nil {
		t.Fatal(err)
	}
	return digest
}

func jsonMarshal(value any) ([]byte, error) {
	return json.Marshal(value)
}

func nonceSequence(first byte, count int) []byte {
	raw := make([]byte, 0, count*32)
	for index := 0; index < count; index++ {
		raw = append(raw, bytes.Repeat([]byte{first + byte(index)}, 32)...)
	}
	return raw
}
