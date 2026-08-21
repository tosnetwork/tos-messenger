package attachmentops

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/tosnetwork/tos-messenger/internal/canon"
	"github.com/tosnetwork/tos-messenger/internal/ids"
	"github.com/tosnetwork/tos-messenger/pkg/attachmentapi"
	"github.com/tosnetwork/tos-messenger/pkg/attachments"
	"github.com/tosnetwork/tos-messenger/pkg/dispatch"
	"github.com/tosnetwork/tos-messenger/pkg/payload"
)

const (
	transactionSchema = "tos.messaging.outbound-attachment-transaction.v1"
	outboxDir         = "attachment-outbox"
	stateName         = "state.json"
	maxStateBytes     = 2 << 20
)

var (
	idempotencyPattern = regexp.MustCompile(`^idem_[0-9a-f]{64}$`)
	uploadPattern      = regexp.MustCompile(`^attup_[0-9a-f]{64}$`)
	sessionPattern     = regexp.MustCompile(`^ses_[0-9a-f]{64}$`)
	chunkPattern       = regexp.MustCompile(`^[0-9]{8}\.bin$`)
	discardedPattern   = regexp.MustCompile(`^\.discarded-[0-9a-f]{64}-[0-9a-f]{64}$`)
)

type BeginRequest struct {
	ConversationID      string `json:"conversation_id"`
	RoomID              string `json:"room_id,omitempty"`
	ReplyToEventID      string `json:"reply_to_event_id,omitempty"`
	MembershipEpoch     uint64 `json:"membership_epoch,omitempty"`
	IdempotencyKey      string `json:"idempotency_key"`
	SessionID           string `json:"session_id"`
	RecipientEndpointID string `json:"recipient_endpoint_id"`
	Filename            string `json:"filename"`
	MediaType           string `json:"media_type"`
	PlaintextDigest     string `json:"plaintext_digest"`
	PlaintextBytes      uint64 `json:"plaintext_bytes"`
}

type Progress struct {
	UploadID  string
	NextChunk uint32
	Complete  bool
	EventID   string
}

type transaction struct {
	Schema         string                `json:"schema"`
	OperatorDigest string                `json:"operator_digest"`
	IntentDigest   string                `json:"intent_digest"`
	UploadID       string                `json:"upload_id"`
	Request        BeginRequest          `json:"request"`
	CreatedAtUnix  uint64                `json:"created_at_unix"`
	ExpiresAtUnix  uint64                `json:"expires_at_unix"`
	Seal           attachments.SealState `json:"seal"`

	ReferenceJSON      []byte                       `json:"reference_json,omitempty"`
	Locator            string                       `json:"locator,omitempty"`
	UploadGrant        *attachments.CapabilityGrant `json:"upload_grant,omitempty"`
	UploadKey          []byte                       `json:"upload_key_base64,omitempty"`
	FetchGrantJSON     []byte                       `json:"fetch_grant_json,omitempty"`
	FetchKey           []byte                       `json:"fetch_key_base64,omitempty"`
	PlaintextHashState []byte                       `json:"plaintext_hash_state_base64"`
	UploadedChunks     uint32                       `json:"uploaded_chunks,omitempty"`
}

type Emitter struct {
	resources      Resources
	root           string
	dispatcher     *dispatch.Dispatcher
	operatorDigest string
	now            func() time.Time
	rng            io.Reader
	caller         func(locator, manifest string) (attachmentapi.Caller, func(), error)

	mutex    sync.Mutex
	byUpload map[string]string
}

func newEmitter(resources Resources, stateDir string, dispatcher *dispatch.Dispatcher) (*Emitter, error) {
	if err := resources.Config.Validate(); err != nil {
		return nil, err
	}
	configuredStorage, _ := hex.DecodeString(resources.Config.StoragePublicKeyHex)
	var endpoint ed25519.PublicKey
	endpointOK := false
	if resources.Signer != nil {
		endpoint, endpointOK = resources.Signer.Public().(ed25519.PublicKey)
	}
	if !endpointOK || len(endpoint) != ed25519.PublicKeySize ||
		len(resources.StorageKey) != ed25519.PublicKeySize || !bytes.Equal(configuredStorage, resources.StorageKey) ||
		bytes.Equal(endpoint, resources.StorageKey) || dispatcher == nil ||
		!filepath.IsAbs(stateDir) || filepath.Clean(stateDir) != stateDir {
		return nil, errors.New("invalid attachment emitter resources")
	}
	resources.HTTPS, _ = resources.Config.httpsConfig()
	encoded, err := json.Marshal(resources.Config)
	if err != nil {
		return nil, err
	}
	root := filepath.Join(stateDir, outboxDir)
	if err := os.MkdirAll(root, 0o700); err != nil {
		return nil, errors.New("create attachment outbox")
	}
	if err := verifyPrivateDirectory(root); err != nil {
		return nil, err
	}
	emitter := &Emitter{resources: resources, root: root, dispatcher: dispatcher,
		operatorDigest: canon.Digest(encoded), now: time.Now, rng: rand.Reader, byUpload: make(map[string]string)}
	emitter.caller = func(locator, manifest string) (attachmentapi.Caller, func(), error) {
		client, err := attachmentapi.NewHTTPSClient(locator, manifest, emitter.resources.HTTPS)
		if err != nil {
			return nil, nil, err
		}
		return client, client.CloseIdleConnections, nil
	}
	if err := emitter.loadTransactions(); err != nil {
		return nil, err
	}
	return emitter, nil
}

// Begin binds exact plaintext evidence and the fixed operator route before
// any bytes are accepted. A completed retry returns the original Event ID and
// performs no new encryption, signing, or storage call.
func (e *Emitter) Begin(request BeginRequest) (Progress, error) {
	if e == nil {
		return Progress{}, errors.New("no attachment emitter")
	}
	intent, err := e.intent(request)
	if err != nil {
		return Progress{}, err
	}
	now := e.now()
	if now.IsZero() || now.Unix() < 0 {
		return Progress{}, errors.New("invalid attachment emission time")
	}
	e.mutex.Lock()
	defer e.mutex.Unlock()
	path := e.transactionPath(request.IdempotencyKey)
	if existing, err := e.readTransaction(path); err == nil {
		if existing.IntentDigest != intent {
			return Progress{}, errors.New("attachment idempotency intent conflicts")
		}
		if uint64(now.Unix()) < existing.ExpiresAtUnix {
			return progress(existing), nil
		}
		if err := e.destroy(path, &existing); err != nil {
			return Progress{}, err
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return Progress{}, err
	}
	// Composition is written before upload, while the delivery is written only
	// after the final StoredAck. A completed retry therefore needs both durable
	// records; a composition by itself may be a crash residue and must never be
	// reported as success.
	if event, found, err := e.dispatcher.LookupQueuedComposition(request.IdempotencyKey, intent); err != nil {
		return Progress{}, err
	} else if found {
		if event.Kind != "artifact.encrypted" {
			return Progress{}, errors.New("attachment idempotency names another Event kind")
		}
		return Progress{Complete: true, EventID: event.EventID}, nil
	}
	uploadID, err := randomID(e.rng, "attup_")
	if err != nil {
		return Progress{}, err
	}
	expires := uint64(now.Unix()) + e.resources.Config.RetentionSeconds
	if expires <= uint64(now.Unix()) {
		return Progress{}, errors.New("attachment retention overflow")
	}
	seal, err := attachments.NewSealStateWithChunkBytes(e.rng, request.PlaintextBytes, attachments.MaxChunkBytes, attachments.Metadata{
		Filename: request.Filename, MediaType: request.MediaType,
		PlaintextDigest: request.PlaintextDigest, ExpiresAtUnix: expires})
	if err != nil {
		return Progress{}, err
	}
	hashState, err := marshalHashState(sha256.New())
	if err != nil {
		seal.Clear()
		return Progress{}, err
	}
	tx := transaction{Schema: transactionSchema, OperatorDigest: e.operatorDigest, IntentDigest: intent,
		UploadID: uploadID, Request: request, CreatedAtUnix: uint64(now.Unix()), ExpiresAtUnix: expires, Seal: seal,
		PlaintextHashState: hashState}
	if err := os.Mkdir(path, 0o700); err != nil {
		tx.clear()
		return Progress{}, errors.New("create attachment transaction")
	}
	if err := e.writeState(path, tx, true); err != nil {
		tx.clear()
		_ = os.Remove(path)
		return Progress{}, err
	}
	e.byUpload[uploadID] = path
	return progress(tx), nil
}

// Append encrypts one exact sequential chunk and persists only ciphertext.
// A crash after the ciphertext fsync but before the state transition is
// reconciled from the authenticated digest on the next open/retry.
func (e *Emitter) Append(uploadID string, index uint32, plaintext []byte) (Progress, error) {
	if e == nil || !uploadPattern.MatchString(uploadID) || len(plaintext) == 0 || len(plaintext) > attachments.MaxChunkBytes {
		return Progress{}, errors.New("invalid attachment upload chunk")
	}
	e.mutex.Lock()
	defer e.mutex.Unlock()
	path, ok := e.byUpload[uploadID]
	if !ok {
		return Progress{}, errors.New("unknown attachment upload")
	}
	tx, err := e.readTransaction(path)
	if err != nil {
		return Progress{}, err
	}
	if tx.UploadID != uploadID || index != uint32(len(tx.Seal.ChunkDigests)) || tx.UploadGrant != nil {
		return Progress{}, errors.New("attachment chunk is out of sequence or already committed")
	}
	chunk, err := tx.Seal.SealNext(plaintext)
	if err != nil {
		return Progress{}, err
	}
	hasher := sha256.New()
	if err := unmarshalHashState(hasher, tx.PlaintextHashState); err != nil {
		clear(chunk.Ciphertext)
		return Progress{}, err
	}
	_, _ = hasher.Write(plaintext)
	hashState, err := marshalHashState(hasher)
	if err != nil {
		clear(chunk.Ciphertext)
		return Progress{}, err
	}
	chunkPath := filepath.Join(path, chunkName(index))
	if err := createSyncedFile(chunkPath, encodeChunkRecord(hashState, chunk.Ciphertext)); err != nil {
		clear(chunk.Ciphertext)
		return Progress{}, err
	}
	clear(chunk.Ciphertext)
	tx.PlaintextHashState = hashState
	if err := e.writeState(path, tx, false); err != nil {
		return Progress{}, err
	}
	return progress(tx), nil
}

// Commit signs distinct upload/fetch grants, durably prepares the exact Event,
// uploads bounded ciphertext batches, verifies the final StoredAck, and only
// then queues that Event. Every ordering edge is retry-safe.
func (e *Emitter) Commit(ctx context.Context, uploadID string) (Progress, error) {
	if e == nil || ctx == nil || !uploadPattern.MatchString(uploadID) {
		return Progress{}, errors.New("invalid attachment commit")
	}
	e.mutex.Lock()
	defer e.mutex.Unlock()
	path, ok := e.byUpload[uploadID]
	if !ok {
		return Progress{}, errors.New("unknown attachment upload")
	}
	tx, err := e.readTransaction(path)
	if err != nil {
		return Progress{}, err
	}
	if _, err := tx.Seal.Reference(); err != nil {
		return Progress{}, errors.New("attachment upload is incomplete: " + err.Error())
	}
	hasher := sha256.New()
	if err := unmarshalHashState(hasher, tx.PlaintextHashState); err != nil ||
		"sha256:"+hex.EncodeToString(hasher.Sum(nil)) != tx.Request.PlaintextDigest {
		if destroyErr := e.destroy(path, &tx); destroyErr != nil {
			return Progress{}, errors.New("attachment plaintext digest failed and transaction cleanup failed: " + destroyErr.Error())
		}
		return Progress{}, errors.New("attachment plaintext stream does not match its declared digest")
	}
	if tx.UploadGrant == nil {
		if err := e.prepare(&tx); err != nil {
			return Progress{}, err
		}
		if err := e.writeState(path, tx, false); err != nil {
			return Progress{}, err
		}
	}
	attachment := payload.EncryptedAttachment{ManifestDigest: tx.UploadGrant.ManifestDigest,
		ReferenceJSON: append([]byte(nil), tx.ReferenceJSON...), Locator: tx.Locator,
		FetchGrantJSON: append([]byte(nil), tx.FetchGrantJSON...), FetchCapabilityPrivateKeyHex: hex.EncodeToString(tx.FetchKey)}
	event, compositionFresh, err := e.dispatcher.PrepareEncryptedAttachment(dispatch.AttachmentRequest{
		ConversationID: tx.Request.ConversationID, RoomID: tx.Request.RoomID, ReplyToEventID: tx.Request.ReplyToEventID,
		IdempotencyKey: tx.Request.IdempotencyKey, IntentDigest: tx.IntentDigest,
		SessionID: tx.Request.SessionID, RecipientEndpointID: tx.Request.RecipientEndpointID,
		ExpiresAtUnix: tx.ExpiresAtUnix, Attachment: attachment})
	if err != nil {
		return Progress{}, err
	}
	if !compositionFresh {
		decoded, decodeErr := payload.DecodeSchema(event.Kind, event.PayloadSchema, event.Content)
		chosen, valid := decoded.(payload.EncryptedAttachment)
		if decodeErr != nil || !valid {
			return Progress{}, errors.New("stored attachment composition is invalid")
		}
		if chosen.ManifestDigest != tx.UploadGrant.ManifestDigest {
			if err := e.destroy(path, &tx); err != nil {
				return Progress{}, err
			}
			return Progress{Complete: true, EventID: event.EventID}, nil
		}
	}
	caller, closeCaller, err := e.caller(tx.Locator, tx.UploadGrant.ManifestDigest)
	if err != nil {
		return Progress{}, err
	}
	defer closeCaller()
	client, err := attachmentapi.NewGrantClient(caller, *tx.UploadGrant, ed25519.PrivateKey(tx.UploadKey), e.now, e.rng)
	if err != nil {
		return Progress{}, err
	}
	start := int(tx.UploadedChunks)
	end := start + 1
	if end > len(tx.Seal.ChunkDigests) {
		return Progress{}, errors.New("attachment upload progress exceeds its manifest")
	}
	batch, err := e.loadChunkRange(path, tx, start, end)
	if err != nil {
		return Progress{}, err
	}
	_, complete, err := client.UploadBatch(ctx, start, batch)
	for index := range batch {
		clear(batch[index].Ciphertext)
	}
	if err != nil {
		return Progress{}, err
	}
	if !complete {
		tx.UploadedChunks = uint32(end)
		if tx.UploadedChunks >= uint32(len(tx.Seal.ChunkDigests)) {
			return Progress{}, errors.New("attachment storage withheld its final acknowledgement")
		}
		if err := e.writeState(path, tx, false); err != nil {
			return Progress{}, err
		}
		return Progress{UploadID: tx.UploadID, NextChunk: tx.UploadedChunks}, nil
	}
	if _, err := e.dispatcher.QueuePreparedAttachment(event, tx.Request.SessionID,
		tx.Request.RecipientEndpointID, tx.ExpiresAtUnix); err != nil {
		return Progress{}, err
	}
	if err := e.destroy(path, &tx); err != nil {
		return Progress{}, err
	}
	return Progress{Complete: true, EventID: event.EventID}, nil
}

func (e *Emitter) prepare(tx *transaction) error {
	ref, err := tx.Seal.Reference()
	if err != nil {
		return err
	}
	manifestDigest, err := attachments.ManifestDigest(ref.Manifest)
	if err != nil {
		return err
	}
	referenceJSON, err := attachments.EncodeReferenceJSON(ref)
	if err != nil {
		return err
	}
	locator, err := attachments.HTTPSLocator(e.resources.Config.StorageOrigin, manifestDigest)
	if err != nil {
		return err
	}
	_, uploadKey, err := ed25519.GenerateKey(e.rng)
	if err != nil {
		return errors.New("generate attachment upload capability")
	}
	_, fetchKey, err := ed25519.GenerateKey(e.rng)
	if err != nil {
		clear(uploadKey)
		return errors.New("generate attachment fetch capability")
	}
	if bytes.Equal(uploadKey.Public().(ed25519.PublicKey), fetchKey.Public().(ed25519.PublicKey)) {
		clear(uploadKey)
		clear(fetchKey)
		return errors.New("attachment upload and fetch capability keys collided")
	}
	defer func() {
		clear(uploadKey)
		clear(fetchKey)
	}()
	base := attachments.CapabilityGrant{NetworkID: e.dispatcherNetworkID(), GenesisRootHash: e.dispatcherGenesisRoot(),
		GenesisFileHash: e.dispatcherGenesisFile(), AgentID: e.dispatcher.LocalIdentity().AgentID,
		EndpointID: e.dispatcher.LocalIdentity().EndpointID, StoragePublicKeyHex: hex.EncodeToString(e.resources.StorageKey),
		ManifestDigest: manifestDigest, ChunkDigests: append([]string(nil), ref.Manifest.ChunkDigests...),
		CiphertextBytes: ref.Manifest.PlaintextBytes + uint64(len(ref.Manifest.ChunkDigests))*16,
		RetainUntilUnix: tx.ExpiresAtUnix, IssuedAtUnix: tx.CreatedAtUnix, ExpiresAtUnix: tx.ExpiresAtUnix}
	upload := base
	upload.CapabilityPublicKeyHex = hex.EncodeToString(uploadKey.Public().(ed25519.PublicKey))
	upload.Operations = []attachments.Operation{attachments.OperationUpload}
	upload, err = attachments.SignGrantWithSigner(upload, e.resources.Signer, e.rng)
	if err != nil {
		return err
	}
	fetch := base
	fetch.CapabilityPublicKeyHex = hex.EncodeToString(fetchKey.Public().(ed25519.PublicKey))
	fetch.Operations = []attachments.Operation{attachments.OperationFetch}
	fetch, err = attachments.SignGrantWithSigner(fetch, e.resources.Signer, e.rng)
	if err != nil {
		return err
	}
	fetchRaw, err := attachments.EncodeGrantJSON(fetch)
	if err != nil {
		return err
	}
	tx.ReferenceJSON = referenceJSON
	tx.Locator = locator
	tx.UploadGrant = &upload
	tx.UploadKey = append([]byte(nil), uploadKey...)
	tx.FetchGrantJSON = fetchRaw
	tx.FetchKey = append([]byte(nil), fetchKey...)
	return nil
}

// Dispatcher network accessors are intentionally narrow; attachment grants
// must repeat the exact Event network and cannot take it from operator/model
// input.
func (e *Emitter) dispatcherNetworkID() string   { return e.dispatcher.Network().NetworkId }
func (e *Emitter) dispatcherGenesisRoot() string { return e.dispatcher.Network().GenesisRootHash }
func (e *Emitter) dispatcherGenesisFile() string { return e.dispatcher.Network().GenesisFileHash }

func (e *Emitter) intent(request BeginRequest) (string, error) {
	if !ids.Conversation.MatchString(request.ConversationID) ||
		request.RoomID != "" && !ids.Room.MatchString(request.RoomID) ||
		request.ReplyToEventID != "" && !ids.Event.MatchString(request.ReplyToEventID) ||
		!idempotencyPattern.MatchString(request.IdempotencyKey) || !sessionPattern.MatchString(request.SessionID) ||
		!ids.Endpoint.MatchString(request.RecipientEndpointID) || !canon.ValidDigest(request.PlaintextDigest) ||
		request.PlaintextBytes == 0 || request.PlaintextBytes > e.resources.Config.MaxPlaintextBytes {
		return "", errors.New("invalid outbound attachment intent")
	}
	if request.RoomID == "" && request.MembershipEpoch != 0 || request.RoomID != "" && request.MembershipEpoch == 0 {
		return "", errors.New("attachment room and membership epoch conflict")
	}
	allowed := false
	for _, value := range e.resources.Config.AllowedMediaTypes {
		allowed = allowed || value == request.MediaType
	}
	if !allowed {
		return "", errors.New("attachment media type is not enabled by the operator")
	}
	// NewSealState remains the single metadata/size validator. Fixed bytes make
	// this check deterministic without consuming production randomness.
	check, err := attachments.NewSealState(bytes.NewReader(bytes.Repeat([]byte{1}, attachments.KeyBytes+attachments.AttachmentIDBytes+attachments.NoncePrefixBytes)),
		request.PlaintextBytes, attachments.Metadata{Filename: request.Filename, MediaType: request.MediaType,
			PlaintextDigest: request.PlaintextDigest, ExpiresAtUnix: 1})
	if err != nil {
		return "", err
	}
	check.Clear()
	buffer := bytes.NewBufferString(canon.DomainOutboundAttachmentIntent)
	for _, value := range []string{e.operatorDigest, request.ConversationID, request.RoomID, request.ReplyToEventID,
		request.IdempotencyKey, request.SessionID, request.RecipientEndpointID, request.Filename,
		request.MediaType, request.PlaintextDigest} {
		canon.Text(buffer, value)
	}
	canon.Uint64(buffer, request.MembershipEpoch)
	canon.Uint64(buffer, request.PlaintextBytes)
	return canon.Digest(buffer.Bytes()), nil
}

func (e *Emitter) transactionPath(idempotencyKey string) string {
	return filepath.Join(e.root, idempotencyKey[len("idem_"):])
}

func (e *Emitter) loadTransactions() error {
	entries, err := os.ReadDir(e.root)
	if err != nil {
		return err
	}
	for _, entry := range entries {
		if discardedPattern.MatchString(entry.Name()) && entry.IsDir() {
			if err := removeDiscarded(filepath.Join(e.root, entry.Name())); err != nil {
				return err
			}
			continue
		}
		if !entry.IsDir() || len(entry.Name()) != 64 {
			return errors.New("attachment outbox contains an unknown entry")
		}
		path := filepath.Join(e.root, entry.Name())
		if err := verifyPrivateDirectory(path); err != nil {
			return err
		}
		tx, err := e.readTransaction(path)
		if err != nil {
			return err
		}
		if _, duplicate := e.byUpload[tx.UploadID]; duplicate {
			return errors.New("duplicate attachment upload identifier")
		}
		e.byUpload[tx.UploadID] = path
	}
	return nil
}

func (e *Emitter) readTransaction(path string) (transaction, error) {
	raw, err := readPrivateFile(filepath.Join(path, stateName), maxStateBytes)
	if err != nil {
		return transaction{}, err
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	var tx transaction
	if err := decoder.Decode(&tx); err != nil {
		return transaction{}, errors.New("decode attachment transaction")
	}
	if err := decoder.Decode(new(any)); !errors.Is(err, io.EOF) {
		return transaction{}, errors.New("attachment transaction has trailing content")
	}
	if tx.Schema != transactionSchema || tx.OperatorDigest != e.operatorDigest || !canon.ValidDigest(tx.IntentDigest) ||
		!uploadPattern.MatchString(tx.UploadID) || tx.CreatedAtUnix == 0 || tx.ExpiresAtUnix <= tx.CreatedAtUnix ||
		tx.ExpiresAtUnix-tx.CreatedAtUnix != e.resources.Config.RetentionSeconds ||
		attachments.ValidateSealState(tx.Seal) != nil {
		tx.clear()
		return transaction{}, errors.New("invalid attachment transaction header")
	}
	if err := e.reconcileOrphanChunk(path, &tx); err != nil {
		tx.clear()
		return transaction{}, err
	}
	if err := e.validateTransaction(tx, path); err != nil {
		tx.clear()
		return transaction{}, err
	}
	return tx, nil
}

func (e *Emitter) reconcileOrphanChunk(path string, tx *transaction) error {
	entries, err := os.ReadDir(path)
	if err != nil {
		return err
	}
	next := len(tx.Seal.ChunkDigests)
	orphan := false
	for _, entry := range entries {
		if entry.IsDir() || entry.Type()&os.ModeSymlink != 0 {
			return errors.New("attachment transaction contains a non-file object")
		}
		if entry.Name() == stateName {
			continue
		}
		if !chunkPattern.MatchString(entry.Name()) {
			return errors.New("attachment transaction contains an unknown object")
		}
		var index int
		if _, err := fmt.Sscanf(entry.Name(), "%08d.bin", &index); err != nil || index < 0 || index > next {
			return errors.New("attachment transaction contains a non-sequential chunk")
		}
		if index == next {
			if orphan {
				return errors.New("attachment transaction contains duplicate orphan chunks")
			}
			orphan = true
		}
	}
	if !orphan {
		return nil
	}
	if tx.UploadGrant != nil {
		return errors.New("prepared attachment transaction contains an orphan chunk")
	}
	record, err := readPrivateFile(filepath.Join(path, chunkName(uint32(next))), attachments.MaxChunkBytes+512)
	if err != nil {
		return err
	}
	defer clear(record)
	hashState, ciphertext, err := decodeChunkRecord(record)
	if err != nil {
		return err
	}
	wantPlain := int(tx.Seal.ChunkBytes)
	count := int((tx.Seal.PlaintextBytes + uint64(tx.Seal.ChunkBytes) - 1) / uint64(tx.Seal.ChunkBytes))
	if next >= count {
		return errors.New("attachment transaction has an excess ciphertext chunk")
	}
	if next == count-1 {
		wantPlain = int(tx.Seal.PlaintextBytes - uint64(next)*uint64(tx.Seal.ChunkBytes))
	}
	if len(ciphertext) != wantPlain+16 {
		return errors.New("attachment orphan ciphertext has an invalid length")
	}
	if hasher := sha256.New(); unmarshalHashState(hasher, hashState) != nil {
		return errors.New("attachment orphan has an invalid plaintext hash state")
	}
	tx.Seal.ChunkDigests = append(tx.Seal.ChunkDigests, canon.Digest(ciphertext))
	tx.PlaintextHashState = append([]byte(nil), hashState...)
	return e.writeState(path, *tx, false)
}

func (e *Emitter) validateTransaction(tx transaction, path string) error {
	if tx.Schema != transactionSchema || tx.OperatorDigest != e.operatorDigest || !canon.ValidDigest(tx.IntentDigest) ||
		!uploadPattern.MatchString(tx.UploadID) || tx.CreatedAtUnix == 0 || tx.ExpiresAtUnix <= tx.CreatedAtUnix ||
		tx.ExpiresAtUnix-tx.CreatedAtUnix != e.resources.Config.RetentionSeconds {
		return errors.New("invalid attachment transaction state")
	}
	intent, err := e.intent(tx.Request)
	if err != nil || intent != tx.IntentDigest {
		return errors.New("attachment transaction intent changed")
	}
	if err := attachments.ValidateSealState(tx.Seal); err != nil || tx.Seal.Metadata.ExpiresAtUnix != tx.ExpiresAtUnix {
		return errors.New("invalid attachment transaction sealing state")
	}
	if hasher := sha256.New(); unmarshalHashState(hasher, tx.PlaintextHashState) != nil {
		return errors.New("invalid attachment transaction plaintext hash state")
	}
	for index, digest := range tx.Seal.ChunkDigests {
		record, err := readPrivateFile(filepath.Join(path, chunkName(uint32(index))), attachments.MaxChunkBytes+512)
		state, ciphertext, decodeErr := decodeChunkRecord(record)
		if err != nil || decodeErr != nil || canon.Digest(ciphertext) != digest {
			clear(record)
			return errors.New("attachment transaction ciphertext changed")
		}
		if index == len(tx.Seal.ChunkDigests)-1 && !bytes.Equal(state, tx.PlaintextHashState) {
			clear(record)
			return errors.New("attachment transaction plaintext hash state changed")
		}
		clear(record)
	}
	prepared := tx.UploadGrant != nil || len(tx.UploadKey) != 0 || len(tx.FetchGrantJSON) != 0 || len(tx.FetchKey) != 0 || len(tx.ReferenceJSON) != 0 || tx.Locator != ""
	if tx.UploadedChunks > uint32(len(tx.Seal.ChunkDigests)) || tx.UploadedChunks != 0 && !prepared {
		return errors.New("invalid attachment storage upload progress")
	}
	if prepared {
		if tx.UploadGrant == nil || len(tx.UploadKey) != ed25519.PrivateKeySize || len(tx.FetchKey) != ed25519.PrivateKeySize ||
			len(tx.FetchGrantJSON) == 0 || len(tx.ReferenceJSON) == 0 || tx.Locator == "" {
			return errors.New("partial prepared attachment transaction")
		}
		ref, err := tx.Seal.Reference()
		if err != nil {
			return err
		}
		digest, _ := attachments.ManifestDigest(ref.Manifest)
		if tx.UploadGrant.ManifestDigest != digest {
			return errors.New("prepared attachment transaction changed manifest")
		}
		referenceRaw, err := attachments.EncodeReferenceJSON(ref)
		if err != nil || !bytes.Equal(referenceRaw, tx.ReferenceJSON) {
			return errors.New("prepared attachment transaction changed its secret reference")
		}
		wantLocator, err := attachments.HTTPSLocator(e.resources.Config.StorageOrigin, digest)
		if err != nil || wantLocator != tx.Locator {
			return errors.New("prepared attachment transaction changed its storage locator")
		}
		endpoint, ok := e.resources.Signer.Public().(ed25519.PublicKey)
		if !ok || attachments.VerifyGrant(*tx.UploadGrant, endpoint, e.resources.StorageKey,
			time.Unix(int64(tx.CreatedAtUnix), 0)) != nil || len(tx.UploadGrant.Operations) != 1 ||
			tx.UploadGrant.Operations[0] != attachments.OperationUpload ||
			!ed25519.PrivateKey(tx.UploadKey).Public().(ed25519.PublicKey).Equal(mustGrantCapability(tx.UploadGrant)) {
			return errors.New("invalid persisted attachment upload authority")
		}
		fetch, err := attachments.DecodeGrantJSON(tx.FetchGrantJSON)
		if err != nil || attachments.VerifyGrant(fetch, endpoint, e.resources.StorageKey,
			time.Unix(int64(tx.CreatedAtUnix), 0)) != nil || len(fetch.Operations) != 1 ||
			fetch.Operations[0] != attachments.OperationFetch ||
			!ed25519.PrivateKey(tx.FetchKey).Public().(ed25519.PublicKey).Equal(mustGrantCapability(&fetch)) ||
			!sameGrantLease(*tx.UploadGrant, fetch) {
			return errors.New("invalid persisted attachment fetch authority")
		}
	}
	return nil
}

func mustGrantCapability(grant *attachments.CapabilityGrant) ed25519.PublicKey {
	if grant == nil {
		return nil
	}
	raw, _ := hex.DecodeString(grant.CapabilityPublicKeyHex)
	return ed25519.PublicKey(raw)
}

func sameGrantLease(left, right attachments.CapabilityGrant) bool {
	if left.NetworkID != right.NetworkID || left.GenesisRootHash != right.GenesisRootHash ||
		left.GenesisFileHash != right.GenesisFileHash || left.AgentID != right.AgentID || left.EndpointID != right.EndpointID ||
		left.StoragePublicKeyHex != right.StoragePublicKeyHex || left.ManifestDigest != right.ManifestDigest ||
		left.CiphertextBytes != right.CiphertextBytes || left.RetainUntilUnix != right.RetainUntilUnix ||
		left.IssuedAtUnix != right.IssuedAtUnix || left.ExpiresAtUnix != right.ExpiresAtUnix ||
		len(left.ChunkDigests) != len(right.ChunkDigests) {
		return false
	}
	for index := range left.ChunkDigests {
		if left.ChunkDigests[index] != right.ChunkDigests[index] {
			return false
		}
	}
	return true
}

func (e *Emitter) writeState(path string, tx transaction, exclusive bool) error {
	encoded, err := json.Marshal(tx)
	if err != nil || len(encoded) > maxStateBytes {
		return errors.New("encode bounded attachment transaction")
	}
	target := filepath.Join(path, stateName)
	if exclusive {
		return createSyncedFile(target, encoded)
	}
	return replaceSyncedFile(target, encoded)
}

func (e *Emitter) loadChunkRange(path string, tx transaction, start, end int) ([]attachments.Chunk, error) {
	result := make([]attachments.Chunk, 0, end-start)
	for index := start; index < end; index++ {
		record, err := readPrivateFile(filepath.Join(path, chunkName(uint32(index))), attachments.MaxChunkBytes+512)
		_, ciphertext, decodeErr := decodeChunkRecord(record)
		if err != nil || decodeErr != nil || canon.Digest(ciphertext) != tx.Seal.ChunkDigests[index] {
			for offset := range result {
				clear(result[offset].Ciphertext)
			}
			clear(record)
			return nil, errors.New("load attachment ciphertext batch")
		}
		result = append(result, attachments.Chunk{Index: uint32(index), Digest: tx.Seal.ChunkDigests[index], Ciphertext: append([]byte(nil), ciphertext...)})
		clear(record)
	}
	return result, nil
}

func (e *Emitter) destroy(path string, tx *transaction) error {
	discarded := filepath.Join(e.root, ".discarded-"+filepath.Base(path)+"-"+strings.TrimPrefix(tx.UploadID, "attup_"))
	if err := os.Rename(path, discarded); err != nil {
		return err
	}
	if err := syncDirectory(e.root); err != nil {
		return err
	}
	delete(e.byUpload, tx.UploadID)
	tx.clear()
	return removeDiscarded(discarded)
}

func removeDiscarded(path string) error {
	entries, err := os.ReadDir(path)
	if err != nil {
		return err
	}
	for _, entry := range entries {
		if entry.IsDir() || entry.Type()&os.ModeSymlink != 0 || entry.Name() != stateName && !chunkPattern.MatchString(entry.Name()) {
			return errors.New("attachment transaction contains an unknown object")
		}
		if err := os.Remove(filepath.Join(path, entry.Name())); err != nil {
			return err
		}
	}
	if err := os.Remove(path); err != nil {
		return err
	}
	return syncDirectory(filepath.Dir(path))
}

func (tx *transaction) clear() {
	if tx == nil {
		return
	}
	tx.Seal.Clear()
	clear(tx.UploadKey)
	clear(tx.FetchKey)
	clear(tx.PlaintextHashState)
	clear(tx.ReferenceJSON)
	clear(tx.FetchGrantJSON)
	tx.UploadKey = nil
	tx.FetchKey = nil
	tx.PlaintextHashState = nil
	tx.ReferenceJSON = nil
	tx.FetchGrantJSON = nil
	tx.UploadGrant = nil
}

func progress(tx transaction) Progress {
	return Progress{UploadID: tx.UploadID, NextChunk: uint32(len(tx.Seal.ChunkDigests))}
}

func chunkName(index uint32) string { return fmt.Sprintf("%08d.bin", index) }

func randomID(rng io.Reader, prefix string) (string, error) {
	raw := make([]byte, 32)
	if _, err := io.ReadFull(rng, raw); err != nil || canon.IsZero(raw) {
		clear(raw)
		return "", errors.New("draw attachment upload identifier")
	}
	result := prefix + hex.EncodeToString(raw)
	clear(raw)
	return result, nil
}

func verifyPrivateDirectory(path string) error {
	info, err := os.Lstat(path)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm() != 0o700 {
		return errors.New("attachment outbox must be a private directory")
	}
	return nil
}

func readPrivateFile(path string, limit int) ([]byte, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm() != 0o600 || info.Size() <= 0 || info.Size() > int64(limit) {
		return nil, errors.New("attachment state object is not a bounded private file")
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	opened, err := file.Stat()
	if err != nil || !os.SameFile(info, opened) {
		return nil, errors.New("attachment state object changed while opened")
	}
	return io.ReadAll(io.LimitReader(file, int64(limit)+1))
}

func createSyncedFile(path string, body []byte) error {
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	if err := writeAndSync(file, body); err != nil {
		_ = os.Remove(path)
		return err
	}
	return syncDirectory(filepath.Dir(path))
}

func replaceSyncedFile(path string, body []byte) error {
	temporary, err := os.CreateTemp(filepath.Dir(path), ".attachment-transition-")
	if err != nil {
		return err
	}
	name := temporary.Name()
	defer os.Remove(name)
	if err := temporary.Chmod(0o600); err != nil {
		_ = temporary.Close()
		return err
	}
	if err := writeAndSync(temporary, body); err != nil {
		return err
	}
	if err := os.Rename(name, path); err != nil {
		return err
	}
	return syncDirectory(filepath.Dir(path))
}

func writeAndSync(file *os.File, body []byte) error {
	defer file.Close()
	for len(body) > 0 {
		written, err := file.Write(body)
		if err != nil || written <= 0 || written > len(body) {
			return errors.New("write attachment state")
		}
		body = body[written:]
	}
	return file.Sync()
}

func syncDirectory(path string) error {
	directory, err := os.Open(path)
	if err != nil {
		return err
	}
	defer directory.Close()
	return directory.Sync()
}

func marshalHashState(hasher interface{ Sum([]byte) []byte }) ([]byte, error) {
	marshaler, ok := hasher.(encoding.BinaryMarshaler)
	if !ok {
		return nil, errors.New("SHA-256 implementation cannot persist state")
	}
	state, err := marshaler.MarshalBinary()
	if err != nil || len(state) == 0 || len(state) > 256 {
		return nil, errors.New("marshal bounded SHA-256 state")
	}
	return state, nil
}

func unmarshalHashState(hasher interface{ Sum([]byte) []byte }, state []byte) error {
	unmarshaler, ok := hasher.(encoding.BinaryUnmarshaler)
	if !ok || len(state) == 0 || len(state) > 256 || unmarshaler.UnmarshalBinary(state) != nil {
		return errors.New("unmarshal bounded SHA-256 state")
	}
	return nil
}

func encodeChunkRecord(hashState, ciphertext []byte) []byte {
	result := make([]byte, 4+len(hashState)+len(ciphertext))
	binary.BigEndian.PutUint32(result[:4], uint32(len(hashState)))
	copy(result[4:], hashState)
	copy(result[4+len(hashState):], ciphertext)
	return result
}

func decodeChunkRecord(record []byte) ([]byte, []byte, error) {
	if len(record) < 4+1+16 {
		return nil, nil, errors.New("attachment ciphertext record is truncated")
	}
	length := int(binary.BigEndian.Uint32(record[:4]))
	if length < 1 || length > 256 || 4+length+16 > len(record) {
		return nil, nil, errors.New("attachment ciphertext record has an invalid hash state")
	}
	return record[4 : 4+length], record[4+length:], nil
}
