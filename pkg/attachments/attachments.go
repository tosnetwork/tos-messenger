// Package attachments implements the route-neutral private attachment profile.
// It encrypts bounded, independently addressable chunks before any storage
// adapter sees them and provides an optional local opaque-ciphertext cache.
// Network storage and transport remain outside this package; commercial
// retention remains roadmap-locked.
package attachments

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"mime"
	"path/filepath"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/tosnetwork/tos-messenger/internal/canon"
)

const (
	Schema                   = "tos.messaging.encrypted-attachment.v1"
	Algorithm                = "AES-256-GCM"
	KeyBytes                 = 32
	AttachmentIDBytes        = 16
	NoncePrefixBytes         = 4
	DefaultChunkBytes        = 256 << 10
	MaxChunkBytes            = 1 << 20
	MaxPlaintextBytes uint64 = 512 << 20
	MaxChunks                = 2048
	MaxFilenameBytes         = 255
	MaxMediaTypeBytes        = 255
	MaxReferenceBytes        = 256 << 10
)

// Metadata remains inside the E2EE Messaging Event with Reference. A
// PlaintextDigest is optional because disclosing it enables equality tests.
type Metadata struct {
	Filename        string `json:"filename"`
	MediaType       string `json:"media_type"`
	PlaintextDigest string `json:"plaintext_digest,omitempty"`
	ExpiresAtUnix   uint64 `json:"expires_at_unix"`
}

// Manifest identifies ciphertext chunks. It contains size and a commitment to
// plaintext metadata, so it remains inside E2EE with Reference; an untrusted
// storage service receives only the individual ciphertext objects and digests.
type Manifest struct {
	Schema          string   `json:"schema"`
	Algorithm       string   `json:"algorithm"`
	AttachmentIDHex string   `json:"attachment_id_hex"`
	NoncePrefixHex  string   `json:"nonce_prefix_hex"`
	PlaintextBytes  uint64   `json:"plaintext_bytes"`
	ChunkBytes      uint32   `json:"chunk_bytes"`
	MetadataDigest  string   `json:"metadata_digest"`
	ChunkDigests    []string `json:"chunk_digests"`
}

// Reference is secret attachment material carried only inside E2EE. Its
// Manifest digest is what an outer Event lists in attachment_references.
type Reference struct {
	Manifest Manifest `json:"manifest"`
	KeyHex   string   `json:"key_hex"`
	Metadata Metadata `json:"metadata"`
}

// Chunk is one independently retrievable ciphertext object.
type Chunk struct {
	Index      uint32
	Digest     string
	Ciphertext []byte
}

// Policy is the recipient's local resource boundary. Attachment metadata is
// untrusted even though AEAD-authenticated, so a recipient chooses its own cap.
type Policy struct {
	MaxPlaintextBytes uint64
	AllowedMediaTypes map[string]struct{}
}

func DefaultPolicy() Policy { return Policy{MaxPlaintextBytes: MaxPlaintextBytes} }

// Seal creates a fresh key and nonce namespace and encrypts every chunk with
// AES-256-GCM. rng must be cryptographically secure; nil selects crypto/rand.
func Seal(rng io.Reader, plaintext []byte, metadata Metadata) (Reference, []Chunk, error) {
	if rng == nil {
		rng = rand.Reader
	}
	if len(plaintext) == 0 || uint64(len(plaintext)) > MaxPlaintextBytes {
		return Reference{}, nil, errors.New("invalid attachment size")
	}
	if err := validateMetadata(metadata); err != nil {
		return Reference{}, nil, err
	}
	if metadata.PlaintextDigest != "" && metadata.PlaintextDigest != canon.Digest(plaintext) {
		return Reference{}, nil, errors.New("declared plaintext digest does not match the attachment")
	}
	key := make([]byte, KeyBytes)
	attachmentID := make([]byte, AttachmentIDBytes)
	prefix := make([]byte, NoncePrefixBytes)
	if _, err := io.ReadFull(rng, key); err != nil {
		return Reference{}, nil, errors.New("draw attachment key")
	}
	if _, err := io.ReadFull(rng, attachmentID); err != nil {
		return Reference{}, nil, errors.New("draw attachment identifier")
	}
	if _, err := io.ReadFull(rng, prefix); err != nil {
		return Reference{}, nil, errors.New("draw attachment nonce prefix")
	}
	if canon.IsZero(key) || canon.IsZero(attachmentID) || canon.IsZero(prefix) {
		return Reference{}, nil, errors.New("random attachment material is all zero")
	}
	metadataDigest, err := MetadataDigest(metadata)
	if err != nil {
		return Reference{}, nil, err
	}
	count := (len(plaintext) + DefaultChunkBytes - 1) / DefaultChunkBytes
	block, err := aes.NewCipher(key)
	if err != nil {
		return Reference{}, nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return Reference{}, nil, err
	}
	chunks := make([]Chunk, 0, count)
	digests := make([]string, 0, count)
	for index := 0; index < count; index++ {
		start := index * DefaultChunkBytes
		end := start + DefaultChunkBytes
		if end > len(plaintext) {
			end = len(plaintext)
		}
		nonce := chunkNonce(prefix, uint64(index))
		aad := chunkAAD(attachmentID, metadataDigest, uint64(len(plaintext)), uint32(DefaultChunkBytes), uint32(count), uint32(index))
		sealed := aead.Seal(nil, nonce, plaintext[start:end], aad)
		digest := canon.Digest(sealed)
		chunks = append(chunks, Chunk{Index: uint32(index), Digest: digest, Ciphertext: sealed})
		digests = append(digests, digest)
	}
	manifest := Manifest{Schema: Schema, Algorithm: Algorithm, AttachmentIDHex: hex.EncodeToString(attachmentID), NoncePrefixHex: hex.EncodeToString(prefix), PlaintextBytes: uint64(len(plaintext)), ChunkBytes: DefaultChunkBytes, MetadataDigest: metadataDigest, ChunkDigests: digests}
	ref := Reference{Manifest: manifest, KeyHex: hex.EncodeToString(key), Metadata: metadata}
	if err := ValidateReference(ref); err != nil {
		return Reference{}, nil, err
	}
	return ref, chunks, nil
}

// Open verifies the manifest digest of every ordered chunk and every AEAD tag
// before returning any plaintext. It never decompresses, parses, or scans the
// result; consumers must apply sandbox/content policy after this function.
func Open(ref Reference, chunks []Chunk, policy Policy, now time.Time) ([]byte, error) {
	if err := ValidateReference(ref); err != nil {
		return nil, err
	}
	if err := policy.validate(ref, now); err != nil {
		return nil, err
	}
	if len(chunks) != len(ref.Manifest.ChunkDigests) {
		return nil, errors.New("attachment chunk set is incomplete")
	}
	key, _ := hex.DecodeString(ref.KeyHex)
	prefix, _ := hex.DecodeString(ref.Manifest.NoncePrefixHex)
	attachmentID, _ := hex.DecodeString(ref.Manifest.AttachmentIDHex)
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	plaintext := make([]byte, 0, int(ref.Manifest.PlaintextBytes))
	for index, chunk := range chunks {
		if chunk.Index != uint32(index) || chunk.Digest != ref.Manifest.ChunkDigests[index] || canon.Digest(chunk.Ciphertext) != chunk.Digest {
			return nil, errors.New("attachment chunk identity mismatch")
		}
		expectedPlain := expectedChunkPlaintext(ref.Manifest, index)
		if len(chunk.Ciphertext) != expectedPlain+aead.Overhead() {
			return nil, errors.New("attachment chunk has an invalid length")
		}
		nonce := chunkNonce(prefix, uint64(index))
		aad := chunkAAD(attachmentID, ref.Manifest.MetadataDigest, ref.Manifest.PlaintextBytes, ref.Manifest.ChunkBytes, uint32(len(chunks)), uint32(index))
		opened, err := aead.Open(nil, nonce, chunk.Ciphertext, aad)
		if err != nil {
			return nil, errors.New("attachment authentication failed")
		}
		plaintext = append(plaintext, opened...)
	}
	if uint64(len(plaintext)) != ref.Manifest.PlaintextBytes {
		return nil, errors.New("attachment plaintext length mismatch")
	}
	if ref.Metadata.PlaintextDigest != "" && canon.Digest(plaintext) != ref.Metadata.PlaintextDigest {
		return nil, errors.New("attachment plaintext digest mismatch")
	}
	return plaintext, nil
}

// MissingDigests supports interrupted-download recovery without decrypting or
// parsing partial content. held reports ciphertext objects already verified by
// their digest; the result preserves manifest order.
func MissingDigests(ref Reference, held map[string]bool) ([]string, error) {
	if err := ValidateReference(ref); err != nil {
		return nil, err
	}
	missing := make([]string, 0)
	for _, digest := range ref.Manifest.ChunkDigests {
		if !held[digest] {
			missing = append(missing, digest)
		}
	}
	return missing, nil
}

func ManifestDigest(manifest Manifest) (string, error) {
	raw, err := manifestCanonical(manifest)
	if err != nil {
		return "", err
	}
	return canon.Digest(raw), nil
}

// ManifestCanonicalBytes returns the exact ciphertext-manifest digest preimage.
func ManifestCanonicalBytes(manifest Manifest) ([]byte, error) { return manifestCanonical(manifest) }

func MetadataDigest(metadata Metadata) (string, error) {
	if err := validateMetadata(metadata); err != nil {
		return "", err
	}
	b := bytes.NewBufferString(canon.DomainAttachmentMetadata)
	canon.Text(b, Schema)
	canon.Text(b, metadata.Filename)
	canon.Text(b, metadata.MediaType)
	canon.Text(b, metadata.PlaintextDigest)
	canon.Uint64(b, metadata.ExpiresAtUnix)
	return canon.Digest(b.Bytes()), nil
}

func manifestCanonical(m Manifest) ([]byte, error) {
	if err := validateManifest(m); err != nil {
		return nil, err
	}
	b := bytes.NewBufferString(canon.DomainAttachmentManifest)
	canon.Text(b, m.Schema)
	canon.Text(b, m.Algorithm)
	canon.Text(b, m.AttachmentIDHex)
	canon.Text(b, m.NoncePrefixHex)
	canon.Uint64(b, m.PlaintextBytes)
	canon.Uint32(b, m.ChunkBytes)
	canon.Text(b, m.MetadataDigest)
	canon.Uint32(b, uint32(len(m.ChunkDigests)))
	for _, digest := range m.ChunkDigests {
		canon.Text(b, digest)
	}
	return b.Bytes(), nil
}

func ValidateReference(ref Reference) error {
	if err := validateManifest(ref.Manifest); err != nil {
		return err
	}
	key, err := hex.DecodeString(ref.KeyHex)
	if err != nil || len(key) != KeyBytes || canon.IsZero(key) {
		return errors.New("invalid attachment key")
	}
	if err := validateMetadata(ref.Metadata); err != nil {
		return err
	}
	digest, err := MetadataDigest(ref.Metadata)
	if err != nil || digest != ref.Manifest.MetadataDigest {
		return errors.New("attachment metadata does not match its commitment")
	}
	return nil
}

func EncodeReferenceJSON(ref Reference) ([]byte, error) {
	if err := ValidateReference(ref); err != nil {
		return nil, err
	}
	return json.Marshal(ref)
}

func DecodeReferenceJSON(raw []byte) (Reference, error) {
	if len(raw) == 0 || len(raw) > MaxReferenceBytes {
		return Reference{}, errors.New("invalid attachment reference size")
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	var ref Reference
	if err := decoder.Decode(&ref); err != nil {
		return Reference{}, err
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return Reference{}, errors.New("attachment reference has trailing JSON")
	}
	if err := ValidateReference(ref); err != nil {
		return Reference{}, err
	}
	return ref, nil
}

func validateManifest(m Manifest) error {
	if m.Schema != Schema || m.Algorithm != Algorithm {
		return errors.New("unsupported attachment profile")
	}
	id, err := hex.DecodeString(m.AttachmentIDHex)
	if err != nil || len(id) != AttachmentIDBytes || canon.IsZero(id) {
		return errors.New("invalid attachment identifier")
	}
	prefix, err := hex.DecodeString(m.NoncePrefixHex)
	if err != nil || len(prefix) != NoncePrefixBytes || canon.IsZero(prefix) {
		return errors.New("invalid attachment nonce prefix")
	}
	if m.PlaintextBytes == 0 || m.PlaintextBytes > MaxPlaintextBytes || m.ChunkBytes == 0 || m.ChunkBytes > MaxChunkBytes || !validContentDigest(m.MetadataDigest) {
		return errors.New("invalid attachment bounds")
	}
	expected := (m.PlaintextBytes + uint64(m.ChunkBytes) - 1) / uint64(m.ChunkBytes)
	if expected == 0 || expected > MaxChunks || uint64(len(m.ChunkDigests)) != expected {
		return errors.New("invalid attachment chunk count")
	}
	for _, digest := range m.ChunkDigests {
		if !validContentDigest(digest) {
			return errors.New("invalid attachment chunk digest")
		}
	}
	return nil
}

func validContentDigest(value string) bool {
	return strings.HasPrefix(value, "sha256:") && len(value) == len("sha256:")+64 && canon.ValidDigest(value)
}

func validateMetadata(m Metadata) error {
	if m.Filename == "" || len(m.Filename) > MaxFilenameBytes || !utf8.ValidString(m.Filename) || strings.TrimSpace(m.Filename) != m.Filename || filepath.Base(m.Filename) != m.Filename || strings.ContainsAny(m.Filename, "/\\\x00\r\n") {
		return errors.New("invalid attachment display filename")
	}
	if m.MediaType == "" || len(m.MediaType) > MaxMediaTypeBytes || strings.TrimSpace(m.MediaType) != m.MediaType {
		return errors.New("invalid attachment media type")
	}
	parsed, params, err := mime.ParseMediaType(m.MediaType)
	if err != nil || parsed != m.MediaType || len(params) != 0 {
		return errors.New("attachment media type must be a canonical type/subtype without parameters")
	}
	if m.PlaintextDigest != "" && !canon.ValidDigest(m.PlaintextDigest) {
		return errors.New("invalid optional plaintext digest")
	}
	if m.ExpiresAtUnix == 0 {
		return errors.New("attachment has no expiry")
	}
	return nil
}

func (p Policy) validate(ref Reference, now time.Time) error {
	if now.IsZero() || now.Unix() < 0 {
		return errors.New("invalid attachment open time")
	}
	limit := p.MaxPlaintextBytes
	if limit == 0 {
		limit = MaxPlaintextBytes
	}
	if limit > MaxPlaintextBytes || ref.Manifest.PlaintextBytes > limit {
		return errors.New("attachment exceeds local plaintext limit")
	}
	if uint64(now.Unix()) >= ref.Metadata.ExpiresAtUnix {
		return errors.New("attachment is expired")
	}
	if len(p.AllowedMediaTypes) > 0 {
		if _, ok := p.AllowedMediaTypes[ref.Metadata.MediaType]; !ok {
			return errors.New("attachment media type is not locally allowed")
		}
	}
	return nil
}

func chunkNonce(prefix []byte, index uint64) []byte {
	nonce := make([]byte, 12)
	copy(nonce, prefix)
	binary.BigEndian.PutUint64(nonce[4:], index)
	return nonce
}
func chunkAAD(id []byte, metadataDigest string, total uint64, chunkSize, count, index uint32) []byte {
	b := bytes.NewBufferString(canon.DomainAttachmentChunk)
	canon.Text(b, Schema)
	canon.Bytes(b, id)
	canon.Text(b, metadataDigest)
	canon.Uint64(b, total)
	canon.Uint32(b, chunkSize)
	canon.Uint32(b, count)
	canon.Uint32(b, index)
	return b.Bytes()
}
func expectedChunkPlaintext(m Manifest, index int) int {
	if index < len(m.ChunkDigests)-1 {
		return int(m.ChunkBytes)
	}
	prior := uint64(index) * uint64(m.ChunkBytes)
	return int(m.PlaintextBytes - prior)
}

// ChunkBase64 is a convenience for storage adapters with textual bodies.
func ChunkBase64(chunk Chunk) string { return base64.StdEncoding.EncodeToString(chunk.Ciphertext) }
