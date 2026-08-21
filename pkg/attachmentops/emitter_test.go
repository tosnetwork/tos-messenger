package attachmentops

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/tosnetwork/tos-messenger/internal/canon"
	"github.com/tosnetwork/tos-messenger/pkg/attachmentapi"
	"github.com/tosnetwork/tos-messenger/pkg/attachments"
	"github.com/tosnetwork/tos-messenger/pkg/dispatch"
	"github.com/tosnetwork/tos-messenger/pkg/envelope"
	"github.com/tosnetwork/tos-messenger/pkg/eventlog"
	"github.com/tosnetwork/tos-messenger/pkg/payload"
	"github.com/tosnetwork/tos-messenger/pkg/signerapi"
	nativev1 "github.com/tosnetwork/tos-service-protocol/gen/tos/service/v1"
)

type testAuthority struct{ endpoint ed25519.PublicKey }

func (a testAuthority) ResolveAttachmentEndpoint(context.Context, attachments.CapabilityGrant, time.Time) (ed25519.PublicKey, error) {
	return a.endpoint, nil
}

func TestMaximumStreamingShapeFitsV3EventAndExternalSignerBound(t *testing.T) {
	now := uint64(1_900_000_000)
	state := attachments.SealState{Key: bytes.Repeat([]byte{1}, attachments.KeyBytes),
		AttachmentID:   bytes.Repeat([]byte{2}, attachments.AttachmentIDBytes),
		NoncePrefix:    bytes.Repeat([]byte{3}, attachments.NoncePrefixBytes),
		Metadata:       attachments.Metadata{Filename: "maximum.bin", MediaType: "application/octet-stream", ExpiresAtUnix: now + 3600},
		PlaintextBytes: attachments.MaxPlaintextBytes, ChunkBytes: attachments.MaxChunkBytes}
	for index := 0; index < int(attachments.MaxPlaintextBytes/attachments.MaxChunkBytes); index++ {
		state.ChunkDigests = append(state.ChunkDigests, canon.Digest([]byte(fmt.Sprintf("chunk-%04d", index))))
	}
	ref, err := state.Reference()
	if err != nil {
		t.Fatal(err)
	}
	manifest, _ := attachments.ManifestDigest(ref.Manifest)
	endpoint := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{4}, ed25519.SeedSize))
	storage := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{5}, ed25519.SeedSize))
	capability := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{6}, ed25519.SeedSize))
	grant := attachments.CapabilityGrant{Schema: attachments.CapabilityGrantSchema, NetworkID: "tos-local", GenesisRootHash: strings.Repeat("a", 64),
		GenesisFileHash: strings.Repeat("b", 64), AgentID: "agent_" + strings.Repeat("c", 64),
		EndpointID: "mep_" + strings.Repeat("d", 64), StoragePublicKeyHex: hex.EncodeToString(storage.Public().(ed25519.PublicKey)),
		CapabilityPublicKeyHex: hex.EncodeToString(capability.Public().(ed25519.PublicKey)), ManifestDigest: manifest,
		ChunkDigests: append([]string(nil), state.ChunkDigests...), CiphertextBytes: attachments.MaxPlaintextBytes + uint64(len(state.ChunkDigests))*16,
		RetainUntilUnix: now + 3600, Operations: []attachments.Operation{attachments.OperationFetch},
		IssuedAtUnix: now, ExpiresAtUnix: now + 3600}
	preimage, err := attachments.GrantCanonicalBytes(grant)
	if err != nil || len(preimage) > signerapi.MaxFrameBytes/2 {
		t.Fatalf("maximum grant preimage bytes=%d err=%v", len(preimage), err)
	}
	grant, err = attachments.SignGrant(grant, endpoint)
	if err != nil {
		t.Fatal(err)
	}
	grantRaw, _ := attachments.EncodeGrantJSON(grant)
	refRaw, _ := attachments.EncodeReferenceJSON(ref)
	locator, _ := attachments.HTTPSLocator("https://storage.example", manifest)
	content, err := payload.Encode(payload.EncryptedAttachment{ManifestDigest: manifest, ReferenceJSON: refRaw,
		Locator: locator, FetchGrantJSON: grantRaw, FetchCapabilityPrivateKeyHex: hex.EncodeToString(capability)})
	if err != nil || len(content) > envelope.MaxContentBytes {
		t.Fatalf("maximum attachment payload bytes=%d err=%v", len(content), err)
	}
	if _, err := envelope.NewEvent(envelope.Event{Network: &nativev1.NetworkDomain{NetworkId: "tos-local",
		GenesisRootHash: strings.Repeat("a", 64), GenesisFileHash: strings.Repeat("b", 64)},
		ConversationID: "conv_" + strings.Repeat("e", 64), SenderAgentID: grant.AgentID, SenderEndpointID: grant.EndpointID,
		SenderDeviceID: "dev_" + strings.Repeat("f", 64), CreatedAtUnix: now, ExpiresAtUnix: now + 3600,
		Kind: "artifact.encrypted", Content: content, AttachmentReferences: []string{manifest}}); err != nil {
		t.Fatal(err)
	}
	state.Clear()
}

func TestEmitterStreamsRestartsUploadsBeforeQueueAndExactRetry(t *testing.T) {
	now := time.Unix(1_900_000_000, 0)
	endpointKey := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x21}, ed25519.SeedSize))
	storageKey := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x22}, ed25519.SeedSize))
	stateDir := filepath.Join(t.TempDir(), "messenger-state")
	journal, err := eventlog.Open(stateDir)
	if err != nil {
		t.Fatal(err)
	}
	defer journal.Close()
	dispatcher, err := dispatch.New(dispatch.Config{Journal: journal, Now: func() time.Time { return now },
		Identity:            dispatch.Identity{AgentID: "agent_" + strings.Repeat("a", 64), EndpointID: "mep_" + strings.Repeat("b", 64), DeviceID: "dev_" + strings.Repeat("c", 64)},
		Network:             &nativev1.NetworkDomain{NetworkId: "tos-local", GenesisRootHash: strings.Repeat("d", 64), GenesisFileHash: strings.Repeat("e", 64)},
		AllowedEventClasses: []string{"artifact"}})
	if err != nil {
		t.Fatal(err)
	}
	config := Config{Schema: ConfigSchema, StorageOrigin: "https://storage.example",
		StoragePublicKeyHex:  hex.EncodeToString(storageKey.Public().(ed25519.PublicKey)),
		EndpointSignerSocket: "/run/tos/endpoint-signer.sock", SignerTimeoutSeconds: 10,
		RetentionSeconds: 3600, MaxPlaintextBytes: 4 << 20, AllowedMediaTypes: []string{"text/plain"}}
	resources := Resources{Config: config, Signer: endpointKey, StorageKey: storageKey.Public().(ed25519.PublicKey),
		HTTPS: attachmentapi.HTTPSConfig{RequestTimeout: 10 * time.Second, ConnectTimeout: 5 * time.Second}}

	store, err := attachments.OpenStore(filepath.Join(t.TempDir(), "storage"), attachments.DefaultStoreQuota())
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	authenticated, err := attachments.NewAuthenticatedStore(store, testAuthority{endpointKey.Public().(ed25519.PublicKey)}, storageKey)
	if err != nil {
		t.Fatal(err)
	}
	server, err := attachmentapi.NewServer(authenticated, func() time.Time { return now }, 0)
	if err != nil {
		t.Fatal(err)
	}
	socketDir := t.TempDir()
	if err := os.Chmod(socketDir, 0o700); err != nil {
		t.Fatal(err)
	}
	socket := filepath.Join(socketDir, "attachment.sock")
	listener, err := attachmentapi.ListenUnix(socket)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = server.Serve(ctx, listener) }()
	caller, err := attachmentapi.NewUnixClient(socket, 10*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	newTestEmitter := func() *Emitter {
		emitter, err := newEmitter(resources, stateDir, dispatcher)
		if err != nil {
			t.Fatal(err)
		}
		emitter.now = func() time.Time { return now }
		emitter.caller = func(string, string) (attachmentapi.Caller, func(), error) { return caller, func() {}, nil }
		return emitter
	}

	body := bytes.Repeat([]byte("restart-safe attachment\n"), (attachments.MaxChunkBytes/24)+7)
	request := BeginRequest{ConversationID: "conv_" + strings.Repeat("1", 64), RoomID: "room_" + strings.Repeat("2", 64),
		MembershipEpoch: 7, IdempotencyKey: "idem_" + strings.Repeat("3", 64),
		SessionID: "ses_" + strings.Repeat("4", 64), RecipientEndpointID: "mep_" + strings.Repeat("5", 64),
		Filename: "evidence.txt", MediaType: "text/plain", PlaintextDigest: canon.Digest(body), PlaintextBytes: uint64(len(body))}
	emitter := newTestEmitter()
	progress, err := emitter.Begin(request)
	if err != nil || progress.Complete || progress.NextChunk != 0 {
		t.Fatalf("begin=%+v err=%v", progress, err)
	}
	preparedPath := emitter.byUpload[progress.UploadID]
	beforeChunk, err := emitter.readTransaction(preparedPath)
	if err != nil {
		t.Fatal(err)
	}
	firstEnd := attachments.MaxChunkBytes
	progress, err = emitter.Append(progress.UploadID, 0, body[:firstEnd])
	if err != nil || progress.NextChunk != 1 {
		t.Fatalf("first chunk=%+v err=%v", progress, err)
	}
	// Model the precise crash edge after ciphertext fsync and before the state
	// pointer advances. The replacement must recover the digest and SHA state
	// from the one bounded ciphertext record without any plaintext file.
	if err := emitter.writeState(preparedPath, beforeChunk, false); err != nil {
		t.Fatal(err)
	}
	beforeChunk.clear()

	// Reopen the transaction as a replacement daemon would and continue from
	// the ciphertext-only durable boundary.
	emitter = newTestEmitter()
	progress, err = emitter.Begin(request)
	if err != nil || progress.NextChunk != 1 {
		t.Fatalf("restart begin=%+v err=%v", progress, err)
	}
	progress, err = emitter.Append(progress.UploadID, 1, body[firstEnd:])
	if err != nil || progress.NextChunk != 2 {
		t.Fatalf("second chunk=%+v err=%v", progress, err)
	}
	progress, err = emitter.Commit(context.Background(), progress.UploadID)
	if err != nil || progress.Complete || progress.NextChunk != 1 {
		t.Fatalf("first commit step=%+v err=%v", progress, err)
	}
	intent, _ := emitter.intent(request)
	prepared, found, err := dispatcher.LookupComposition(request.IdempotencyKey, intent)
	if err != nil || !found {
		t.Fatalf("prepared composition found=%v err=%v", found, err)
	}
	if _, queued, err := journal.LookupDelivery(prepared.EventID); err != nil || queued {
		t.Fatalf("partial storage upload entered delivery queue: queued=%v err=%v", queued, err)
	}
	// A daemon restart must resume the transaction. The durable composition is
	// only preparation evidence until the final StoredAck and delivery enqueue.
	emitter = newTestEmitter()
	resumed, err := emitter.Begin(request)
	if err != nil || resumed.Complete || resumed.UploadID != progress.UploadID || resumed.NextChunk != 2 {
		t.Fatalf("prepared-only restart was misreported as complete: resumed=%+v err=%v", resumed, err)
	}
	progress, err = emitter.Commit(context.Background(), progress.UploadID)
	if err != nil || !progress.Complete || !strings.HasPrefix(progress.EventID, "evt_") {
		t.Fatalf("commit=%+v err=%v", progress, err)
	}
	delivery, found, err := journal.LookupDelivery(progress.EventID)
	if err != nil || !found {
		t.Fatalf("queued=%v delivery=%+v err=%v", found, delivery, err)
	}
	rawEvent, _ := delivery.Payload()
	event, err := envelope.DecodeEventJSON(rawEvent)
	if err != nil || event.Kind != "artifact.encrypted" || event.RoomID != request.RoomID {
		t.Fatalf("event=%+v err=%v", event, err)
	}
	decoded, err := payload.DecodeSchema(event.Kind, event.PayloadSchema, event.Content)
	attachment, ok := decoded.(payload.EncryptedAttachment)
	if err != nil || !ok {
		t.Fatalf("attachment=%T err=%v", decoded, err)
	}
	fetchGrant, fetchKey, err := attachment.FetchAccess()
	if err != nil {
		t.Fatal(err)
	}
	defer clear(fetchKey)
	fetchClient, err := attachmentapi.NewGrantClient(caller, fetchGrant, fetchKey, func() time.Time { return now }, nil)
	if err != nil {
		t.Fatal(err)
	}
	chunks, err := fetchClient.Fetch(context.Background(), fetchGrant.ChunkDigests)
	if err != nil {
		t.Fatal(err)
	}
	ref, _ := attachments.DecodeReferenceJSON(attachment.ReferenceJSON)
	opened, err := attachments.Open(ref, chunks, attachments.Policy{MaxPlaintextBytes: uint64(len(body)), AllowedMediaTypes: map[string]struct{}{"text/plain": {}}}, now)
	if err != nil || !bytes.Equal(opened, body) {
		t.Fatalf("opened=%d err=%v", len(opened), err)
	}
	clear(opened)

	retry, err := emitter.Begin(request)
	if err != nil || !retry.Complete || retry.EventID != progress.EventID || retry.UploadID != "" {
		t.Fatalf("retry=%+v err=%v", retry, err)
	}

	wrong := request
	wrong.IdempotencyKey = "idem_" + strings.Repeat("6", 64)
	wrong.PlaintextBytes = 5
	wrong.PlaintextDigest = "sha256:" + strings.Repeat("7", 64)
	started, err := emitter.Begin(wrong)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := emitter.Append(started.UploadID, 0, []byte("hello")); err != nil {
		t.Fatal(err)
	}
	if _, err := emitter.Commit(context.Background(), started.UploadID); err == nil {
		t.Fatal("committed a plaintext stream that did not match its declared digest")
	}
	restarted, err := emitter.Begin(wrong)
	if err != nil || restarted.UploadID == "" || restarted.UploadID == started.UploadID {
		t.Fatalf("digest mismatch did not reset transaction: old=%+v new=%+v err=%v", started, restarted, err)
	}
}
