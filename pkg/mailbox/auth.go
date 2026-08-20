package mailbox

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
	"github.com/tosnetwork/tos-messenger/pkg/envelope"
)

const (
	CapabilityGrantSchema = "tos.messaging.mailbox-capability-grant.v1"
	AccessRequestSchema   = "tos.messaging.mailbox-access-request.v1"
	MaxGrantBytes         = 8192
	MaxAccessRequestBytes = 4096
	MaxGrantLifetime      = 30 * 24 * time.Hour
	MaxRequestLifetime    = 2 * time.Minute
	MaxRequestFutureSkew  = 30 * time.Second
)

type Operation string

const (
	OperationDeposit Operation = "deposit"
	OperationRead    Operation = "read"
	OperationDelete  Operation = "delete"
)

// CapabilityGrant authorizes one independent capability key for a bounded
// subset of one mailbox at one Relay. The Endpoint signature is not Agent or
// commercial authority; a caller must still resolve that Endpoint as live.
type CapabilityGrant struct {
	Schema                 string      `json:"schema"`
	NetworkID              string      `json:"network_id"`
	GenesisRootHash        string      `json:"genesis_root_hash"`
	GenesisFileHash        string      `json:"genesis_file_hash"`
	AgentID                string      `json:"agent_id"`
	EndpointID             string      `json:"messaging_endpoint_id"`
	RelayPublicKeyHex      string      `json:"relay_public_key_hex"`
	MailboxID              string      `json:"opaque_mailbox_id"`
	CapabilityPublicKeyHex string      `json:"capability_public_key_hex"`
	Operations             []Operation `json:"operations"`
	IssuedAtUnix           uint64      `json:"issued_at_unix"`
	ExpiresAtUnix          uint64      `json:"expires_at_unix"`
	EndpointSignatureHex   string      `json:"endpoint_signature_hex"`
}

// AccessRequest binds a fresh capability signature to one exact operation
// body. BodyDigest prevents a valid read request from authorizing a delete or
// a deposit request from storing different ciphertext.
type AccessRequest struct {
	Schema                 string    `json:"schema"`
	GrantDigest            string    `json:"grant_digest"`
	Operation              Operation `json:"operation"`
	MailboxID              string    `json:"opaque_mailbox_id"`
	BodyDigest             string    `json:"body_digest"`
	NonceHex               string    `json:"nonce_hex"`
	IssuedAtUnix           uint64    `json:"issued_at_unix"`
	ExpiresAtUnix          uint64    `json:"expires_at_unix"`
	CapabilitySignatureHex string    `json:"capability_signature_hex"`
}

// FinalizedEndpointAuthority returns the currently authorized Endpoint key.
// Implementations must resolve finalized Agent/delegation state; a descriptor
// or the grant's own claims are not authority.
type FinalizedEndpointAuthority interface {
	ResolveMailboxEndpoint(ctx context.Context, grant CapabilityGrant, now time.Time) (ed25519.PublicKey, error)
}

type AuthenticatedStore struct {
	store     *Store
	authority FinalizedEndpointAuthority
}

func NewAuthenticatedStore(store *Store, authority FinalizedEndpointAuthority) (*AuthenticatedStore, error) {
	if store == nil || authority == nil {
		return nil, errors.New("invalid authenticated Mailbox store")
	}
	if err := store.usable(); err != nil {
		return nil, err
	}
	return &AuthenticatedStore{store: store, authority: authority}, nil
}

func SignGrant(grant CapabilityGrant, endpointKey ed25519.PrivateKey) (CapabilityGrant, error) {
	if len(endpointKey) != ed25519.PrivateKeySize {
		return CapabilityGrant{}, errors.New("invalid Endpoint signing key")
	}
	grant.Schema = CapabilityGrantSchema
	grant.EndpointSignatureHex = ""
	preimage, err := GrantCanonicalBytes(grant)
	if err != nil {
		return CapabilityGrant{}, err
	}
	grant.EndpointSignatureHex = hex.EncodeToString(ed25519.Sign(endpointKey, preimage))
	return grant, nil
}

func VerifyGrant(grant CapabilityGrant, endpointKey, relayKey ed25519.PublicKey, now time.Time) error {
	preimage, err := GrantCanonicalBytes(grant)
	if err != nil {
		return err
	}
	if len(endpointKey) != ed25519.PublicKeySize || canon.IsZero(endpointKey) ||
		len(relayKey) != ed25519.PublicKeySize || canon.IsZero(relayKey) {
		return errors.New("invalid Mailbox authority key")
	}
	boundRelay, _ := hex.DecodeString(grant.RelayPublicKeyHex)
	if !bytes.Equal(boundRelay, relayKey) {
		return errors.New("Mailbox grant names another Relay")
	}
	if now.IsZero() || now.Unix() < 0 || uint64(now.Unix()) < grant.IssuedAtUnix || uint64(now.Unix()) >= grant.ExpiresAtUnix {
		return errors.New("Mailbox grant is outside its validity window")
	}
	signature, err := hex.DecodeString(grant.EndpointSignatureHex)
	if err != nil || len(signature) != ed25519.SignatureSize || !ed25519.Verify(endpointKey, preimage, signature) {
		return errors.New("invalid Mailbox grant signature")
	}
	return nil
}

func GrantCanonicalBytes(grant CapabilityGrant) ([]byte, error) {
	root, file, relay, capability, err := validateGrant(grant)
	if err != nil {
		return nil, err
	}
	b := bytes.NewBufferString(canon.DomainMailboxCapabilityGrant)
	canon.Text(b, CapabilityGrantSchema)
	canon.Text(b, grant.NetworkID)
	canon.Bytes(b, root)
	canon.Bytes(b, file)
	canon.Text(b, grant.AgentID)
	canon.Text(b, grant.EndpointID)
	canon.Bytes(b, relay)
	canon.Text(b, grant.MailboxID)
	canon.Bytes(b, capability)
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
		return AccessRequest{}, errors.New("invalid Mailbox capability signing key")
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
	if request.GrantDigest != grantDigest || request.Operation != expected || request.MailboxID != grant.MailboxID || request.BodyDigest != bodyDigest {
		return errors.New("Mailbox request does not match its grant or operation body")
	}
	if !grantAllows(grant, expected) {
		return errors.New("Mailbox grant does not allow the operation")
	}
	if now.IsZero() || now.Unix() < 0 || uint64(now.Add(MaxRequestFutureSkew).Unix()) < request.IssuedAtUnix || uint64(now.Unix()) >= request.ExpiresAtUnix ||
		request.IssuedAtUnix < grant.IssuedAtUnix || request.ExpiresAtUnix > grant.ExpiresAtUnix {
		return errors.New("Mailbox request is outside its validity window")
	}
	capability, _ := hex.DecodeString(grant.CapabilityPublicKeyHex)
	signature, err := hex.DecodeString(request.CapabilitySignatureHex)
	if err != nil || len(signature) != ed25519.SignatureSize || !ed25519.Verify(ed25519.PublicKey(capability), preimage, signature) {
		return errors.New("invalid Mailbox capability signature")
	}
	return nil
}

func AccessRequestCanonicalBytes(request AccessRequest) ([]byte, error) {
	if request.Schema != AccessRequestSchema || !canon.ValidDigest(request.GrantDigest) || !validOperation(request.Operation) ||
		!ids.Mailbox.MatchString(request.MailboxID) || !canon.ValidDigest(request.BodyDigest) ||
		request.IssuedAtUnix == 0 || request.ExpiresAtUnix <= request.IssuedAtUnix ||
		request.ExpiresAtUnix-request.IssuedAtUnix > uint64(MaxRequestLifetime/time.Second) {
		return nil, errors.New("invalid Mailbox access request")
	}
	nonce, err := hex.DecodeString(request.NonceHex)
	if err != nil || len(nonce) != 32 || canon.IsZero(nonce) {
		return nil, errors.New("invalid Mailbox access nonce")
	}
	b := bytes.NewBufferString(canon.DomainMailboxAccessRequest)
	canon.Text(b, AccessRequestSchema)
	canon.Text(b, request.GrantDigest)
	canon.Text(b, string(request.Operation))
	canon.Text(b, request.MailboxID)
	canon.Text(b, request.BodyDigest)
	canon.Bytes(b, nonce)
	canon.Uint64(b, request.IssuedAtUnix)
	canon.Uint64(b, request.ExpiresAtUnix)
	return b.Bytes(), nil
}

func DepositBodyDigest(value envelope.RelayEnvelope) (string, error) {
	if err := envelope.ValidateRelay(value); err != nil {
		return "", err
	}
	b := operationBody(OperationDeposit)
	canon.Text(b, value.OpaqueMailboxID)
	canon.Text(b, value.MessageID)
	canon.Text(b, canon.Digest(value.Ciphertext))
	canon.Text(b, canon.Digest([]byte(value.StorageToken)))
	canon.Text(b, canon.Digest([]byte(value.AdmissionToken)))
	canon.Uint64(b, value.ExpiresAtUnix)
	return canon.Digest(b.Bytes()), nil
}

func ReadBodyDigest(mailboxID string, limit int) (string, error) {
	if !ids.Mailbox.MatchString(mailboxID) || limit < 1 || limit > MaxListResults {
		return "", errors.New("invalid Mailbox read body")
	}
	b := operationBody(OperationRead)
	canon.Text(b, mailboxID)
	canon.Uint32(b, uint32(limit))
	return canon.Digest(b.Bytes()), nil
}

func DeleteBodyDigest(mailboxID, messageID, ciphertextDigest string) (string, error) {
	if !ids.Mailbox.MatchString(mailboxID) || !ids.RelayMessage.MatchString(messageID) || !canon.ValidDigest(ciphertextDigest) {
		return "", errors.New("invalid Mailbox delete body")
	}
	b := operationBody(OperationDelete)
	canon.Text(b, mailboxID)
	canon.Text(b, messageID)
	canon.Text(b, ciphertextDigest)
	return canon.Digest(b.Bytes()), nil
}

func (s *AuthenticatedStore) Put(ctx context.Context, grant CapabilityGrant, request AccessRequest,
	value envelope.RelayEnvelope, now time.Time) (bool, StoredAck, error) {
	digest, err := DepositBodyDigest(value)
	if err != nil {
		return false, StoredAck{}, err
	}
	if err := s.authorize(ctx, grant, request, OperationDeposit, digest, now); err != nil {
		return false, StoredAck{}, err
	}
	return s.store.Put(value, now)
}

func (s *AuthenticatedStore) List(ctx context.Context, grant CapabilityGrant, request AccessRequest,
	now time.Time, limit int) ([]envelope.RelayEnvelope, error) {
	digest, err := ReadBodyDigest(grant.MailboxID, limit)
	if err != nil {
		return nil, err
	}
	if err := s.authorize(ctx, grant, request, OperationRead, digest, now); err != nil {
		return nil, err
	}
	return s.store.List(grant.MailboxID, now, limit)
}

func (s *AuthenticatedStore) Delete(ctx context.Context, grant CapabilityGrant, request AccessRequest,
	messageID, ciphertextDigest string, now time.Time) (bool, error) {
	digest, err := DeleteBodyDigest(grant.MailboxID, messageID, ciphertextDigest)
	if err != nil {
		return false, err
	}
	if err := s.authorize(ctx, grant, request, OperationDelete, digest, now); err != nil {
		return false, err
	}
	return s.store.Delete(grant.MailboxID, messageID, ciphertextDigest)
}

func (s *AuthenticatedStore) authorize(ctx context.Context, grant CapabilityGrant, request AccessRequest,
	operation Operation, bodyDigest string, now time.Time) error {
	endpointKey, err := s.authority.ResolveMailboxEndpoint(ctx, grant, now)
	if err != nil {
		return err
	}
	if err := VerifyGrant(grant, endpointKey, s.store.RelayPublicKey(), now); err != nil {
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
		return nil, errors.New("invalid Mailbox grant signature encoding")
	}
	return json.Marshal(grant)
}

func DecodeGrantJSON(raw []byte) (CapabilityGrant, error) {
	var grant CapabilityGrant
	if err := strictJSON(raw, MaxGrantBytes, &grant); err != nil {
		return CapabilityGrant{}, err
	}
	if _, err := GrantCanonicalBytes(grant); err != nil {
		return CapabilityGrant{}, err
	}
	if signature, err := hex.DecodeString(grant.EndpointSignatureHex); err != nil || len(signature) != ed25519.SignatureSize {
		return CapabilityGrant{}, errors.New("invalid Mailbox grant signature encoding")
	}
	return grant, nil
}

func EncodeAccessRequestJSON(request AccessRequest) ([]byte, error) {
	if _, err := AccessRequestCanonicalBytes(request); err != nil {
		return nil, err
	}
	if signature, err := hex.DecodeString(request.CapabilitySignatureHex); err != nil || len(signature) != ed25519.SignatureSize {
		return nil, errors.New("invalid Mailbox request signature encoding")
	}
	return json.Marshal(request)
}

func DecodeAccessRequestJSON(raw []byte) (AccessRequest, error) {
	var request AccessRequest
	if err := strictJSON(raw, MaxAccessRequestBytes, &request); err != nil {
		return AccessRequest{}, err
	}
	if _, err := AccessRequestCanonicalBytes(request); err != nil {
		return AccessRequest{}, err
	}
	if signature, err := hex.DecodeString(request.CapabilitySignatureHex); err != nil || len(signature) != ed25519.SignatureSize {
		return AccessRequest{}, errors.New("invalid Mailbox request signature encoding")
	}
	return request, nil
}

func validateGrant(grant CapabilityGrant) ([]byte, []byte, []byte, []byte, error) {
	if grant.Schema != CapabilityGrantSchema || grant.NetworkID == "" || len(grant.NetworkID) > 128 ||
		!ids.Agent.MatchString(grant.AgentID) || !ids.Endpoint.MatchString(grant.EndpointID) || !ids.Mailbox.MatchString(grant.MailboxID) ||
		len(grant.Operations) == 0 || len(grant.Operations) > 3 || grant.IssuedAtUnix == 0 || grant.ExpiresAtUnix <= grant.IssuedAtUnix ||
		grant.ExpiresAtUnix-grant.IssuedAtUnix > uint64(MaxGrantLifetime/time.Second) {
		return nil, nil, nil, nil, errors.New("invalid Mailbox capability grant")
	}
	if !sort.SliceIsSorted(grant.Operations, func(i, j int) bool { return grant.Operations[i] < grant.Operations[j] }) {
		return nil, nil, nil, nil, errors.New("Mailbox grant operations are not canonical")
	}
	for index, operation := range grant.Operations {
		if !validOperation(operation) || index > 0 && grant.Operations[index-1] == operation {
			return nil, nil, nil, nil, errors.New("invalid Mailbox grant operation")
		}
	}
	root, err := decodeFixedHex(grant.GenesisRootHash, 32)
	if err != nil {
		return nil, nil, nil, nil, errors.New("invalid genesis root hash")
	}
	file, err := decodeFixedHex(grant.GenesisFileHash, 32)
	if err != nil {
		return nil, nil, nil, nil, errors.New("invalid genesis file hash")
	}
	relay, err := decodeFixedHex(grant.RelayPublicKeyHex, ed25519.PublicKeySize)
	if err != nil || canon.IsZero(relay) {
		return nil, nil, nil, nil, errors.New("invalid Relay public key")
	}
	capability, err := decodeFixedHex(grant.CapabilityPublicKeyHex, ed25519.PublicKeySize)
	if err != nil || canon.IsZero(capability) {
		return nil, nil, nil, nil, errors.New("invalid capability public key")
	}
	return root, file, relay, capability, nil
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
	return operation == OperationDeposit || operation == OperationRead || operation == OperationDelete
}

func operationBody(operation Operation) *bytes.Buffer {
	b := bytes.NewBufferString(canon.DomainMailboxOperationBody)
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

func strictJSON(raw []byte, limit int, target any) error {
	if len(raw) == 0 || len(raw) > limit {
		return errors.New("Mailbox authentication wire is outside its bound")
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return err
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return errors.New("Mailbox authentication wire has trailing JSON")
	}
	return nil
}
