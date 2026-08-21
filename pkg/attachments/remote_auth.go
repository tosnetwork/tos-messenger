package attachments

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"sort"
	"time"

	"github.com/tosnetwork/tos-messenger/internal/canon"
	"github.com/tosnetwork/tos-messenger/internal/ids"
)

const (
	CapabilityGrantSchema = "tos.messaging.attachment-capability-grant.v1"
	AccessRequestSchema   = "tos.messaging.attachment-access-request.v1"
	MaxGrantBytes         = 256 << 10
	MaxAccessRequestBytes = 4096
	MaxGrantLifetime      = 30 * 24 * time.Hour
	MaxRequestLifetime    = 2 * time.Minute
	MaxRequestFutureSkew  = 30 * time.Second
)

type Operation string

const (
	OperationUpload Operation = "upload"
	OperationFetch  Operation = "fetch"
	OperationDelete Operation = "delete"
)

// CapabilityGrant binds an independent capability key to one storage
// operator and one exact opaque attachment lease. It contains no attachment
// key, filename, media type, or plaintext digest.
type CapabilityGrant struct {
	Schema                 string      `json:"schema"`
	NetworkID              string      `json:"network_id"`
	GenesisRootHash        string      `json:"genesis_root_hash"`
	GenesisFileHash        string      `json:"genesis_file_hash"`
	AgentID                string      `json:"agent_id"`
	EndpointID             string      `json:"messaging_endpoint_id"`
	StoragePublicKeyHex    string      `json:"storage_public_key_hex"`
	CapabilityPublicKeyHex string      `json:"capability_public_key_hex"`
	ManifestDigest         string      `json:"manifest_digest"`
	ChunkDigests           []string    `json:"chunk_digests"`
	CiphertextBytes        uint64      `json:"ciphertext_bytes"`
	RetainUntilUnix        uint64      `json:"retain_until_unix"`
	Operations             []Operation `json:"operations"`
	IssuedAtUnix           uint64      `json:"issued_at_unix"`
	ExpiresAtUnix          uint64      `json:"expires_at_unix"`
	EndpointSignatureHex   string      `json:"endpoint_signature_hex"`
}

// AccessRequest authorizes one exact operation body with a short-lived,
// durably single-use nonce. The same capability signature cannot cross an
// operation boundary or change an object list.
type AccessRequest struct {
	Schema                 string    `json:"schema"`
	GrantDigest            string    `json:"grant_digest"`
	Operation              Operation `json:"operation"`
	BodyDigest             string    `json:"body_digest"`
	NonceHex               string    `json:"nonce_hex"`
	IssuedAtUnix           uint64    `json:"issued_at_unix"`
	ExpiresAtUnix          uint64    `json:"expires_at_unix"`
	CapabilitySignatureHex string    `json:"capability_signature_hex"`
}

// FinalizedEndpointAuthority must resolve the current finalized delegation;
// neither a locator nor claims copied into the grant are authority.
type FinalizedEndpointAuthority interface {
	ResolveAttachmentEndpoint(context.Context, CapabilityGrant, time.Time) (ed25519.PublicKey, error)
}

type AuthenticatedStore struct {
	store      *Store
	authority  FinalizedEndpointAuthority
	storageKey ed25519.PrivateKey
}

func NewAuthenticatedStore(store *Store, authority FinalizedEndpointAuthority, storageKey ed25519.PrivateKey) (*AuthenticatedStore, error) {
	if store == nil || authority == nil || len(storageKey) != ed25519.PrivateKeySize {
		return nil, errors.New("invalid authenticated attachment store")
	}
	if err := store.usable(); err != nil {
		return nil, err
	}
	return &AuthenticatedStore{store: store, authority: authority,
		storageKey: append(ed25519.PrivateKey(nil), storageKey...)}, nil
}

func (s *AuthenticatedStore) StoragePublicKey() ed25519.PublicKey {
	if s == nil || len(s.storageKey) != ed25519.PrivateKeySize {
		return nil
	}
	return append(ed25519.PublicKey(nil), s.storageKey.Public().(ed25519.PublicKey)...)
}

func SignGrant(grant CapabilityGrant, endpointKey ed25519.PrivateKey) (CapabilityGrant, error) {
	if len(endpointKey) != ed25519.PrivateKeySize {
		return CapabilityGrant{}, errors.New("invalid attachment Endpoint signing key")
	}
	grant.Schema = CapabilityGrantSchema
	grant.EndpointSignatureHex = ""
	preimage, err := GrantCanonicalBytes(grant)
	if err != nil {
		return CapabilityGrant{}, err
	}
	storage, capability, _ := validateGrant(grant)
	endpointPublic := endpointKey.Public().(ed25519.PublicKey)
	if bytes.Equal(storage, capability) || bytes.Equal(storage, endpointPublic) || bytes.Equal(capability, endpointPublic) {
		return CapabilityGrant{}, errors.New("attachment Endpoint, storage, and capability keys must be distinct")
	}
	grant.EndpointSignatureHex = hex.EncodeToString(ed25519.Sign(endpointKey, preimage))
	return grant, nil
}

func VerifyGrant(grant CapabilityGrant, endpointKey, storageKey ed25519.PublicKey, now time.Time) error {
	preimage, err := GrantCanonicalBytes(grant)
	if err != nil {
		return err
	}
	if len(endpointKey) != ed25519.PublicKeySize || canon.IsZero(endpointKey) ||
		len(storageKey) != ed25519.PublicKeySize || canon.IsZero(storageKey) {
		return errors.New("invalid attachment authority key")
	}
	bound, err := decodeFixedHex(grant.StoragePublicKeyHex, ed25519.PublicKeySize)
	if err != nil {
		return err
	}
	if !bytes.Equal(bound, storageKey) {
		return errors.New("attachment grant names another storage operator")
	}
	capability, err := decodeFixedHex(grant.CapabilityPublicKeyHex, ed25519.PublicKeySize)
	if err != nil {
		return err
	}
	if bytes.Equal(bound, capability) || bytes.Equal(bound, endpointKey) || bytes.Equal(capability, endpointKey) {
		return errors.New("attachment Endpoint, storage, and capability keys are not separated")
	}
	if now.IsZero() || now.Unix() < 0 || uint64(now.Unix()) < grant.IssuedAtUnix || uint64(now.Unix()) >= grant.ExpiresAtUnix {
		return errors.New("attachment grant is outside its validity window")
	}
	signature, err := hex.DecodeString(grant.EndpointSignatureHex)
	if err != nil || len(signature) != ed25519.SignatureSize || !ed25519.Verify(endpointKey, preimage, signature) {
		return errors.New("invalid attachment grant signature")
	}
	return nil
}

func GrantCanonicalBytes(grant CapabilityGrant) ([]byte, error) {
	storage, capability, err := validateGrant(grant)
	if err != nil {
		return nil, err
	}
	b := bytes.NewBufferString(canon.DomainAttachmentCapabilityGrant)
	canon.Text(b, CapabilityGrantSchema)
	canon.Text(b, grant.NetworkID)
	if err := canon.Hash32(b, grant.GenesisRootHash); err != nil {
		return nil, err
	}
	if err := canon.Hash32(b, grant.GenesisFileHash); err != nil {
		return nil, err
	}
	canon.Text(b, grant.AgentID)
	canon.Text(b, grant.EndpointID)
	canon.Bytes(b, storage)
	canon.Bytes(b, capability)
	canon.Text(b, grant.ManifestDigest)
	canon.Uint32(b, uint32(len(grant.ChunkDigests)))
	for _, digest := range grant.ChunkDigests {
		canon.Text(b, digest)
	}
	canon.Uint64(b, grant.CiphertextBytes)
	canon.Uint64(b, grant.RetainUntilUnix)
	canon.Uint32(b, uint32(len(grant.Operations)))
	for _, operation := range grant.Operations {
		canon.Text(b, string(operation))
	}
	canon.Uint64(b, grant.IssuedAtUnix)
	canon.Uint64(b, grant.ExpiresAtUnix)
	return b.Bytes(), nil
}

func GrantDigest(grant CapabilityGrant) (string, error) {
	preimage, err := GrantCanonicalBytes(grant)
	if err != nil {
		return "", err
	}
	return canon.Digest(preimage), nil
}

func SignAccessRequest(request AccessRequest, capabilityKey ed25519.PrivateKey) (AccessRequest, error) {
	if len(capabilityKey) != ed25519.PrivateKeySize {
		return AccessRequest{}, errors.New("invalid attachment capability signing key")
	}
	request.Schema = AccessRequestSchema
	request.CapabilitySignatureHex = ""
	preimage, err := AccessRequestCanonicalBytes(request)
	if err != nil {
		return AccessRequest{}, err
	}
	request.CapabilitySignatureHex = hex.EncodeToString(ed25519.Sign(capabilityKey, preimage))
	return request, nil
}

func VerifyAccessRequest(grant CapabilityGrant, request AccessRequest, expected Operation, bodyDigest string, now time.Time) error {
	grantDigest, err := GrantDigest(grant)
	if err != nil {
		return err
	}
	preimage, err := AccessRequestCanonicalBytes(request)
	if err != nil {
		return err
	}
	if request.GrantDigest != grantDigest || request.Operation != expected || request.BodyDigest != bodyDigest {
		return errors.New("attachment request does not match its grant or operation body")
	}
	if !grantAllows(grant, expected) {
		return errors.New("attachment grant does not allow the operation")
	}
	if now.IsZero() || now.Unix() < 0 || uint64(now.Add(MaxRequestFutureSkew).Unix()) < request.IssuedAtUnix ||
		uint64(now.Unix()) >= request.ExpiresAtUnix || request.IssuedAtUnix < grant.IssuedAtUnix || request.ExpiresAtUnix > grant.ExpiresAtUnix {
		return errors.New("attachment request is outside its validity window")
	}
	capability, err := decodeFixedHex(grant.CapabilityPublicKeyHex, ed25519.PublicKeySize)
	if err != nil {
		return err
	}
	signature, err := hex.DecodeString(request.CapabilitySignatureHex)
	if err != nil || len(signature) != ed25519.SignatureSize || !ed25519.Verify(ed25519.PublicKey(capability), preimage, signature) {
		return errors.New("invalid attachment capability signature")
	}
	return nil
}

func AccessRequestCanonicalBytes(request AccessRequest) ([]byte, error) {
	if request.Schema != AccessRequestSchema || !canon.ValidDigest(request.GrantDigest) || !validOperation(request.Operation) ||
		!canon.ValidDigest(request.BodyDigest) || request.IssuedAtUnix == 0 || request.ExpiresAtUnix <= request.IssuedAtUnix ||
		request.ExpiresAtUnix-request.IssuedAtUnix > uint64(MaxRequestLifetime/time.Second) {
		return nil, errors.New("invalid attachment access request")
	}
	nonce, err := decodeFixedHex(request.NonceHex, 32)
	if err != nil || canon.IsZero(nonce) {
		return nil, errors.New("invalid attachment access nonce")
	}
	b := bytes.NewBufferString(canon.DomainAttachmentAccessRequest)
	canon.Text(b, AccessRequestSchema)
	canon.Text(b, request.GrantDigest)
	canon.Text(b, string(request.Operation))
	canon.Text(b, request.BodyDigest)
	canon.Bytes(b, nonce)
	canon.Uint64(b, request.IssuedAtUnix)
	canon.Uint64(b, request.ExpiresAtUnix)
	return b.Bytes(), nil
}

func UploadBodyDigest(grant CapabilityGrant, chunks []Chunk) (string, error) {
	if _, _, err := validateGrant(grant); err != nil {
		return "", err
	}
	if len(chunks) == 0 || len(chunks) > len(grant.ChunkDigests) {
		return "", errors.New("invalid attachment upload batch")
	}
	positions := make(map[string]uint32, len(grant.ChunkDigests))
	for index, digest := range grant.ChunkDigests {
		positions[digest] = uint32(index)
	}
	seen := make(map[string]struct{}, len(chunks))
	b := operationBody(OperationUpload)
	canon.Text(b, grant.ManifestDigest)
	canon.Uint64(b, grant.RetainUntilUnix)
	canon.Uint32(b, uint32(len(chunks)))
	var total uint64
	for _, chunk := range chunks {
		position, allowed := positions[chunk.Digest]
		if !allowed || chunk.Index != position ||
			len(chunk.Ciphertext) <= 16 || len(chunk.Ciphertext) > MaxChunkBytes+16 || canon.Digest(chunk.Ciphertext) != chunk.Digest {
			return "", errors.New("invalid attachment upload chunk")
		}
		if _, duplicate := seen[chunk.Digest]; duplicate {
			return "", errors.New("duplicate attachment upload chunk")
		}
		seen[chunk.Digest] = struct{}{}
		canon.Uint32(b, chunk.Index)
		canon.Text(b, chunk.Digest)
		canon.Uint64(b, uint64(len(chunk.Ciphertext)))
		total += uint64(len(chunk.Ciphertext))
	}
	if total > grant.CiphertextBytes {
		return "", errors.New("attachment upload byte count exceeds its grant")
	}
	return canon.Digest(b.Bytes()), nil
}

func FetchBodyDigest(grant CapabilityGrant, digests []string) (string, error) {
	if _, _, err := validateGrant(grant); err != nil {
		return "", err
	}
	if len(digests) == 0 || len(digests) > MaxChunks {
		return "", errors.New("invalid attachment fetch set")
	}
	allowed := make(map[string]struct{}, len(grant.ChunkDigests))
	for _, digest := range grant.ChunkDigests {
		allowed[digest] = struct{}{}
	}
	seen := make(map[string]struct{}, len(digests))
	b := operationBody(OperationFetch)
	canon.Text(b, grant.ManifestDigest)
	canon.Uint32(b, uint32(len(digests)))
	for _, digest := range digests {
		if _, ok := allowed[digest]; !ok {
			return "", errors.New("attachment fetch requests an object outside its grant")
		}
		if _, duplicate := seen[digest]; duplicate {
			return "", errors.New("attachment fetch repeats an object")
		}
		seen[digest] = struct{}{}
		canon.Text(b, digest)
	}
	return canon.Digest(b.Bytes()), nil
}

func DeleteBodyDigest(grant CapabilityGrant) (string, error) {
	if _, _, err := validateGrant(grant); err != nil {
		return "", err
	}
	b := operationBody(OperationDelete)
	canon.Text(b, grant.ManifestDigest)
	return canon.Digest(b.Bytes()), nil
}

func (s *AuthenticatedStore) Upload(ctx context.Context, grant CapabilityGrant, request AccessRequest, chunks []Chunk, now time.Time) (StoredAck, bool, error) {
	digest, err := UploadBodyDigest(grant, chunks)
	if err != nil {
		return StoredAck{}, false, err
	}
	if err := s.authorize(ctx, grant, request, OperationUpload, digest, now); err != nil {
		return StoredAck{}, false, err
	}
	if _, err := s.store.PutObjects(chunks); err != nil {
		return StoredAck{}, false, err
	}
	fresh, err := s.store.CommitOpaque(StorageLease{ManifestDigest: grant.ManifestDigest,
		ChunkDigests: grant.ChunkDigests, ExpiresAtUnix: grant.RetainUntilUnix}, grant.CiphertextBytes, now)
	if errors.Is(err, ErrLeaseNotFound) {
		return StoredAck{}, false, nil
	}
	if err != nil {
		return StoredAck{}, false, err
	}
	ack, err := SignStoredAck(StoredAck{GrantDigest: request.GrantDigest, ManifestDigest: grant.ManifestDigest,
		ChunkDigests: append([]string(nil), grant.ChunkDigests...), CiphertextBytes: grant.CiphertextBytes,
		StoredAtUnix: uint64(now.Unix()), RetainUntilUnix: grant.RetainUntilUnix, Fresh: fresh}, s.storageKey)
	return ack, true, err
}

func (s *AuthenticatedStore) Fetch(ctx context.Context, grant CapabilityGrant, request AccessRequest, digests []string, now time.Time) ([]Chunk, error) {
	digest, err := FetchBodyDigest(grant, digests)
	if err != nil {
		return nil, err
	}
	if err := s.authorize(ctx, grant, request, OperationFetch, digest, now); err != nil {
		return nil, err
	}
	chunks, expires, err := s.store.FetchOpaque(grant.ManifestDigest, digests, now)
	if err != nil {
		return nil, err
	}
	if expires != grant.RetainUntilUnix {
		return nil, errors.New("attachment lease retention conflicts with its grant")
	}
	return chunks, nil
}

func (s *AuthenticatedStore) Delete(ctx context.Context, grant CapabilityGrant, request AccessRequest, now time.Time) (DeleteAck, error) {
	digest, err := DeleteBodyDigest(grant)
	if err != nil {
		return DeleteAck{}, err
	}
	if err := s.authorize(ctx, grant, request, OperationDelete, digest, now); err != nil {
		return DeleteAck{}, err
	}
	deleted, err := s.store.Delete(grant.ManifestDigest)
	if err != nil {
		return DeleteAck{}, err
	}
	return SignDeleteAck(DeleteAck{GrantDigest: request.GrantDigest, ManifestDigest: grant.ManifestDigest,
		ObservedAtUnix: uint64(now.Unix()), Deleted: deleted}, s.storageKey)
}

func (s *AuthenticatedStore) authorize(ctx context.Context, grant CapabilityGrant, request AccessRequest,
	operation Operation, bodyDigest string, now time.Time) error {
	if s == nil || s.store == nil || s.authority == nil || ctx == nil {
		return errors.New("invalid authenticated attachment operation")
	}
	endpointKey, err := s.authority.ResolveAttachmentEndpoint(ctx, grant, now)
	if err != nil {
		return err
	}
	if err := VerifyGrant(grant, endpointKey, s.StoragePublicKey(), now); err != nil {
		return err
	}
	if err := VerifyAccessRequest(grant, request, operation, bodyDigest, now); err != nil {
		return err
	}
	return s.store.claimAccess(request, now)
}

func EncodeGrantJSON(grant CapabilityGrant) ([]byte, error) {
	if _, err := GrantCanonicalBytes(grant); err != nil {
		return nil, err
	}
	if signature, err := hex.DecodeString(grant.EndpointSignatureHex); err != nil || len(signature) != ed25519.SignatureSize {
		return nil, errors.New("invalid attachment grant signature encoding")
	}
	return json.Marshal(grant)
}

func DecodeGrantJSON(raw []byte) (CapabilityGrant, error) {
	var grant CapabilityGrant
	if err := strictAuthJSON(raw, MaxGrantBytes, &grant); err != nil {
		return CapabilityGrant{}, err
	}
	if _, err := GrantCanonicalBytes(grant); err != nil {
		return CapabilityGrant{}, err
	}
	if signature, err := hex.DecodeString(grant.EndpointSignatureHex); err != nil || len(signature) != ed25519.SignatureSize {
		return CapabilityGrant{}, errors.New("invalid attachment grant signature encoding")
	}
	return grant, nil
}

func EncodeAccessRequestJSON(request AccessRequest) ([]byte, error) {
	if _, err := AccessRequestCanonicalBytes(request); err != nil {
		return nil, err
	}
	if signature, err := hex.DecodeString(request.CapabilitySignatureHex); err != nil || len(signature) != ed25519.SignatureSize {
		return nil, errors.New("invalid attachment request signature encoding")
	}
	return json.Marshal(request)
}

func DecodeAccessRequestJSON(raw []byte) (AccessRequest, error) {
	var request AccessRequest
	if err := strictAuthJSON(raw, MaxAccessRequestBytes, &request); err != nil {
		return AccessRequest{}, err
	}
	if _, err := AccessRequestCanonicalBytes(request); err != nil {
		return AccessRequest{}, err
	}
	if signature, err := hex.DecodeString(request.CapabilitySignatureHex); err != nil || len(signature) != ed25519.SignatureSize {
		return AccessRequest{}, errors.New("invalid attachment request signature encoding")
	}
	return request, nil
}

func validateGrant(grant CapabilityGrant) ([]byte, []byte, error) {
	if grant.Schema != CapabilityGrantSchema || grant.NetworkID == "" || len(grant.NetworkID) > 128 ||
		!ids.Agent.MatchString(grant.AgentID) || !ids.Endpoint.MatchString(grant.EndpointID) ||
		!canon.HashPattern.MatchString(grant.GenesisRootHash) || !canon.HashPattern.MatchString(grant.GenesisFileHash) ||
		!validContentDigest(grant.ManifestDigest) || len(grant.ChunkDigests) == 0 || len(grant.ChunkDigests) > MaxChunks ||
		grant.CiphertextBytes == 0 || grant.CiphertextBytes > MaxPlaintextBytes+uint64(MaxChunks*16) ||
		grant.IssuedAtUnix == 0 || grant.RetainUntilUnix <= grant.IssuedAtUnix || grant.ExpiresAtUnix < grant.RetainUntilUnix ||
		grant.ExpiresAtUnix-grant.IssuedAtUnix > uint64(MaxGrantLifetime/time.Second) || len(grant.Operations) == 0 || len(grant.Operations) > 3 {
		return nil, nil, errors.New("invalid attachment capability grant")
	}
	seenDigests := make(map[string]struct{}, len(grant.ChunkDigests))
	for _, digest := range grant.ChunkDigests {
		if !validContentDigest(digest) {
			return nil, nil, errors.New("invalid attachment grant chunk digest")
		}
		if _, duplicate := seenDigests[digest]; duplicate {
			return nil, nil, errors.New("duplicate attachment grant chunk digest")
		}
		seenDigests[digest] = struct{}{}
	}
	if !sort.SliceIsSorted(grant.Operations, func(i, j int) bool { return grant.Operations[i] < grant.Operations[j] }) {
		return nil, nil, errors.New("attachment grant operations are not canonical")
	}
	for index, operation := range grant.Operations {
		if !validOperation(operation) || index > 0 && grant.Operations[index-1] == operation {
			return nil, nil, errors.New("invalid attachment grant operation")
		}
	}
	storage, err := decodeFixedHex(grant.StoragePublicKeyHex, ed25519.PublicKeySize)
	if err != nil || canon.IsZero(storage) {
		return nil, nil, errors.New("invalid attachment storage public key")
	}
	capability, err := decodeFixedHex(grant.CapabilityPublicKeyHex, ed25519.PublicKeySize)
	if err != nil || canon.IsZero(capability) {
		return nil, nil, errors.New("invalid attachment capability public key")
	}
	return storage, capability, nil
}

func grantAllows(grant CapabilityGrant, expected Operation) bool {
	for _, operation := range grant.Operations {
		if operation == expected {
			return true
		}
	}
	return false
}

func validOperation(operation Operation) bool {
	return operation == OperationUpload || operation == OperationFetch || operation == OperationDelete
}

func operationBody(operation Operation) *bytes.Buffer {
	b := bytes.NewBufferString(canon.DomainAttachmentOperationBody)
	canon.Text(b, string(operation))
	return b
}

func decodeFixedHex(value string, size int) ([]byte, error) {
	if len(value) != size*2 {
		return nil, errors.New("wrong hexadecimal length")
	}
	decoded, err := hex.DecodeString(value)
	if err != nil || hex.EncodeToString(decoded) != value {
		return nil, errors.New("non-canonical hexadecimal value")
	}
	return decoded, nil
}

func strictAuthJSON(raw []byte, limit int, target any) error {
	if len(raw) == 0 || len(raw) > limit {
		return errors.New("attachment authentication wire is outside its bound")
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return err
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return errors.New("attachment authentication wire has trailing JSON")
	}
	return nil
}
