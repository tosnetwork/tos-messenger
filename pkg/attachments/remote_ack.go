package attachments

import (
	"bytes"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"errors"

	"github.com/tosnetwork/tos-messenger/internal/canon"
)

const (
	StoredAckSchema = "tos.messaging.attachment-stored-ack.v1"
	DeleteAckSchema = "tos.messaging.attachment-delete-ack.v1"
	MaxAckBytes     = 256 << 10
)

// StoredAck proves that one storage identity durably published the exact
// opaque lease. It is operational evidence, never a TOS commercial Receipt.
type StoredAck struct {
	Schema              string   `json:"schema"`
	GrantDigest         string   `json:"grant_digest"`
	ManifestDigest      string   `json:"manifest_digest"`
	ChunkDigests        []string `json:"chunk_digests"`
	CiphertextBytes     uint64   `json:"ciphertext_bytes"`
	StoredAtUnix        uint64   `json:"stored_at_unix"`
	RetainUntilUnix     uint64   `json:"retain_until_unix"`
	Fresh               bool     `json:"fresh"`
	StoragePublicKeyHex string   `json:"storage_public_key_hex"`
	StorageSignatureHex string   `json:"storage_signature_hex"`
}

// DeleteAck proves only that this storage process observed its local lease as
// deleted or already absent. It cannot prove destruction of backups, caches,
// another operator's copy, or ciphertext a recipient already downloaded.
type DeleteAck struct {
	Schema              string `json:"schema"`
	GrantDigest         string `json:"grant_digest"`
	ManifestDigest      string `json:"manifest_digest"`
	ObservedAtUnix      uint64 `json:"observed_at_unix"`
	Deleted             bool   `json:"deleted"`
	StoragePublicKeyHex string `json:"storage_public_key_hex"`
	StorageSignatureHex string `json:"storage_signature_hex"`
}

func StoredAckCanonicalBytes(ack StoredAck) ([]byte, error) {
	key, err := validateStoredAck(ack)
	if err != nil {
		return nil, err
	}
	b := bytes.NewBufferString(canon.DomainAttachmentStoredAck)
	canon.Text(b, StoredAckSchema)
	canon.Text(b, ack.GrantDigest)
	canon.Text(b, ack.ManifestDigest)
	canon.Uint32(b, uint32(len(ack.ChunkDigests)))
	for _, digest := range ack.ChunkDigests {
		canon.Text(b, digest)
	}
	canon.Uint64(b, ack.CiphertextBytes)
	canon.Uint64(b, ack.StoredAtUnix)
	canon.Uint64(b, ack.RetainUntilUnix)
	canon.Bool(b, ack.Fresh)
	canon.Bytes(b, key)
	return b.Bytes(), nil
}

func SignStoredAck(ack StoredAck, key ed25519.PrivateKey) (StoredAck, error) {
	if len(key) != ed25519.PrivateKeySize {
		return StoredAck{}, errors.New("invalid attachment storage signing key")
	}
	ack.Schema = StoredAckSchema
	ack.StoragePublicKeyHex = hex.EncodeToString(key.Public().(ed25519.PublicKey))
	ack.StorageSignatureHex = ""
	preimage, err := StoredAckCanonicalBytes(ack)
	if err != nil {
		return StoredAck{}, err
	}
	ack.StorageSignatureHex = hex.EncodeToString(ed25519.Sign(key, preimage))
	return ack, nil
}

func VerifyStoredAck(ack StoredAck, expectedStorage ed25519.PublicKey) error {
	preimage, err := StoredAckCanonicalBytes(ack)
	if err != nil {
		return err
	}
	key, err := decodeFixedHex(ack.StoragePublicKeyHex, ed25519.PublicKeySize)
	if err != nil {
		return err
	}
	if len(expectedStorage) != ed25519.PublicKeySize || !bytes.Equal(key, expectedStorage) {
		return errors.New("attachment StoredAck names another storage operator")
	}
	signature, err := hex.DecodeString(ack.StorageSignatureHex)
	if err != nil || len(signature) != ed25519.SignatureSize || !ed25519.Verify(ed25519.PublicKey(key), preimage, signature) {
		return errors.New("invalid attachment StoredAck signature")
	}
	return nil
}

func DeleteAckCanonicalBytes(ack DeleteAck) ([]byte, error) {
	if ack.Schema != DeleteAckSchema || !canon.ValidDigest(ack.GrantDigest) || !validContentDigest(ack.ManifestDigest) || ack.ObservedAtUnix == 0 {
		return nil, errors.New("invalid attachment DeleteAck")
	}
	key, err := decodeFixedHex(ack.StoragePublicKeyHex, ed25519.PublicKeySize)
	if err != nil || canon.IsZero(key) {
		return nil, errors.New("invalid attachment DeleteAck storage key")
	}
	b := bytes.NewBufferString(canon.DomainAttachmentDeleteAck)
	canon.Text(b, DeleteAckSchema)
	canon.Text(b, ack.GrantDigest)
	canon.Text(b, ack.ManifestDigest)
	canon.Uint64(b, ack.ObservedAtUnix)
	canon.Bool(b, ack.Deleted)
	canon.Bytes(b, key)
	return b.Bytes(), nil
}

func SignDeleteAck(ack DeleteAck, key ed25519.PrivateKey) (DeleteAck, error) {
	if len(key) != ed25519.PrivateKeySize {
		return DeleteAck{}, errors.New("invalid attachment storage signing key")
	}
	ack.Schema = DeleteAckSchema
	ack.StoragePublicKeyHex = hex.EncodeToString(key.Public().(ed25519.PublicKey))
	ack.StorageSignatureHex = ""
	preimage, err := DeleteAckCanonicalBytes(ack)
	if err != nil {
		return DeleteAck{}, err
	}
	ack.StorageSignatureHex = hex.EncodeToString(ed25519.Sign(key, preimage))
	return ack, nil
}

func VerifyDeleteAck(ack DeleteAck, expectedStorage ed25519.PublicKey) error {
	preimage, err := DeleteAckCanonicalBytes(ack)
	if err != nil {
		return err
	}
	key, err := decodeFixedHex(ack.StoragePublicKeyHex, ed25519.PublicKeySize)
	if err != nil {
		return err
	}
	if len(expectedStorage) != ed25519.PublicKeySize || !bytes.Equal(key, expectedStorage) {
		return errors.New("attachment DeleteAck names another storage operator")
	}
	signature, err := hex.DecodeString(ack.StorageSignatureHex)
	if err != nil || len(signature) != ed25519.SignatureSize || !ed25519.Verify(ed25519.PublicKey(key), preimage, signature) {
		return errors.New("invalid attachment DeleteAck signature")
	}
	return nil
}

func EncodeStoredAckJSON(ack StoredAck) ([]byte, error) {
	key, err := decodeFixedHex(ack.StoragePublicKeyHex, ed25519.PublicKeySize)
	if err != nil || VerifyStoredAck(ack, ed25519.PublicKey(key)) != nil {
		return nil, errors.New("invalid attachment StoredAck")
	}
	return json.Marshal(ack)
}

func DecodeStoredAckJSON(raw []byte) (StoredAck, error) {
	var ack StoredAck
	if err := strictAuthJSON(raw, MaxAckBytes, &ack); err != nil {
		return StoredAck{}, err
	}
	key, err := decodeFixedHex(ack.StoragePublicKeyHex, ed25519.PublicKeySize)
	if err != nil || VerifyStoredAck(ack, ed25519.PublicKey(key)) != nil {
		return StoredAck{}, errors.New("invalid attachment StoredAck")
	}
	return ack, nil
}

func EncodeDeleteAckJSON(ack DeleteAck) ([]byte, error) {
	key, err := decodeFixedHex(ack.StoragePublicKeyHex, ed25519.PublicKeySize)
	if err != nil || VerifyDeleteAck(ack, ed25519.PublicKey(key)) != nil {
		return nil, errors.New("invalid attachment DeleteAck")
	}
	return json.Marshal(ack)
}

func DecodeDeleteAckJSON(raw []byte) (DeleteAck, error) {
	var ack DeleteAck
	if err := strictAuthJSON(raw, MaxAckBytes, &ack); err != nil {
		return DeleteAck{}, err
	}
	key, err := decodeFixedHex(ack.StoragePublicKeyHex, ed25519.PublicKeySize)
	if err != nil || VerifyDeleteAck(ack, ed25519.PublicKey(key)) != nil {
		return DeleteAck{}, errors.New("invalid attachment DeleteAck")
	}
	return ack, nil
}

func validateStoredAck(ack StoredAck) ([]byte, error) {
	if ack.Schema != StoredAckSchema || !canon.ValidDigest(ack.GrantDigest) || !validContentDigest(ack.ManifestDigest) ||
		len(ack.ChunkDigests) == 0 || len(ack.ChunkDigests) > MaxChunks || ack.CiphertextBytes == 0 ||
		ack.CiphertextBytes > MaxPlaintextBytes+uint64(MaxChunks*16) || ack.StoredAtUnix == 0 || ack.RetainUntilUnix <= ack.StoredAtUnix {
		return nil, errors.New("invalid attachment StoredAck")
	}
	seen := make(map[string]struct{}, len(ack.ChunkDigests))
	for _, digest := range ack.ChunkDigests {
		if !validContentDigest(digest) {
			return nil, errors.New("invalid attachment StoredAck digest")
		}
		if _, duplicate := seen[digest]; duplicate {
			return nil, errors.New("duplicate attachment StoredAck digest")
		}
		seen[digest] = struct{}{}
	}
	key, err := decodeFixedHex(ack.StoragePublicKeyHex, ed25519.PublicKeySize)
	if err != nil || canon.IsZero(key) {
		return nil, errors.New("invalid attachment StoredAck storage key")
	}
	return key, nil
}
