package attachments

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"io"

	"github.com/tosnetwork/tos-messenger/internal/canon"
)

// SealState is the daemon-owned, restartable state for one streaming
// attachment encryption. Plaintext chunks are authenticated and encrypted as
// they arrive and are never required to exist together in memory or on disk.
// Key, AttachmentID, and NoncePrefix are secret until Reference is carried
// inside application E2EE.
type SealState struct {
	Key            []byte   `json:"key_base64"`
	AttachmentID   []byte   `json:"attachment_id_base64"`
	NoncePrefix    []byte   `json:"nonce_prefix_base64"`
	Metadata       Metadata `json:"metadata"`
	PlaintextBytes uint64   `json:"plaintext_bytes"`
	ChunkBytes     uint32   `json:"chunk_bytes"`
	ChunkDigests   []string `json:"chunk_digests"`
}

// NewSealState draws a fresh AEAD key and nonce namespace for a bounded total
// size. A caller may persist this state before accepting the first plaintext
// chunk, making a crash retry use the original encryption identity.
func NewSealState(rng io.Reader, plaintextBytes uint64, metadata Metadata) (SealState, error) {
	return NewSealStateWithChunkBytes(rng, plaintextBytes, DefaultChunkBytes, metadata)
}

// NewSealStateWithChunkBytes selects a protocol-bounded chunk size. Outbound
// daemon streaming uses MaxChunkBytes so a maximum attachment's manifest and
// capability grant still fit the Event's bounded opaque fields.
func NewSealStateWithChunkBytes(rng io.Reader, plaintextBytes uint64, chunkBytes uint32, metadata Metadata) (SealState, error) {
	if plaintextBytes == 0 || plaintextBytes > MaxPlaintextBytes {
		return SealState{}, errors.New("invalid attachment size")
	}
	if chunkBytes == 0 || chunkBytes > MaxChunkBytes {
		return SealState{}, errors.New("invalid attachment chunk size")
	}
	if err := validateMetadata(metadata); err != nil {
		return SealState{}, err
	}
	if rng == nil {
		rng = rand.Reader
	}
	state := SealState{Key: make([]byte, KeyBytes), AttachmentID: make([]byte, AttachmentIDBytes),
		NoncePrefix: make([]byte, NoncePrefixBytes), Metadata: metadata, PlaintextBytes: plaintextBytes, ChunkBytes: chunkBytes}
	for _, target := range [][]byte{state.Key, state.AttachmentID, state.NoncePrefix} {
		if _, err := io.ReadFull(rng, target); err != nil {
			state.Clear()
			return SealState{}, errors.New("draw attachment sealing material")
		}
	}
	if canon.IsZero(state.Key) || canon.IsZero(state.AttachmentID) || canon.IsZero(state.NoncePrefix) {
		state.Clear()
		return SealState{}, errors.New("random attachment material is all zero")
	}
	return state, nil
}

// SealNext authenticates and encrypts exactly the next plaintext chunk. It
// advances only after a complete ciphertext and digest have been produced.
func (s *SealState) SealNext(plaintext []byte) (Chunk, error) {
	if err := s.validate(false); err != nil {
		return Chunk{}, err
	}
	index := len(s.ChunkDigests)
	count := s.chunkCount()
	if index >= count {
		return Chunk{}, errors.New("attachment already has every encrypted chunk")
	}
	want := int(s.ChunkBytes)
	if index == count-1 {
		want = int(s.PlaintextBytes - uint64(index)*uint64(s.ChunkBytes))
	}
	if len(plaintext) != want {
		return Chunk{}, errors.New("attachment plaintext chunk has an invalid length")
	}
	metadataDigest, err := MetadataDigest(s.Metadata)
	if err != nil {
		return Chunk{}, err
	}
	block, err := aes.NewCipher(s.Key)
	if err != nil {
		return Chunk{}, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return Chunk{}, err
	}
	nonce := chunkNonce(s.NoncePrefix, uint64(index))
	aad := chunkAAD(s.AttachmentID, metadataDigest, s.PlaintextBytes, s.ChunkBytes, uint32(count), uint32(index))
	ciphertext := aead.Seal(nil, nonce, plaintext, aad)
	digest := canon.Digest(ciphertext)
	for _, previous := range s.ChunkDigests {
		if previous == digest {
			clear(ciphertext)
			return Chunk{}, errors.New("attachment produced a duplicate ciphertext digest")
		}
	}
	s.ChunkDigests = append(s.ChunkDigests, digest)
	return Chunk{Index: uint32(index), Digest: digest, Ciphertext: ciphertext}, nil
}

// Reference returns the complete secret reference after every chunk has been
// sealed. Partial state is never a valid wire reference.
func (s SealState) Reference() (Reference, error) {
	if err := s.validate(true); err != nil {
		return Reference{}, err
	}
	metadataDigest, err := MetadataDigest(s.Metadata)
	if err != nil {
		return Reference{}, err
	}
	ref := Reference{Manifest: Manifest{Schema: Schema, Algorithm: Algorithm,
		AttachmentIDHex: hex.EncodeToString(s.AttachmentID), NoncePrefixHex: hex.EncodeToString(s.NoncePrefix),
		PlaintextBytes: s.PlaintextBytes, ChunkBytes: s.ChunkBytes, MetadataDigest: metadataDigest,
		ChunkDigests: append([]string(nil), s.ChunkDigests...)}, KeyHex: hex.EncodeToString(s.Key), Metadata: s.Metadata}
	if err := ValidateReference(ref); err != nil {
		return Reference{}, err
	}
	return ref, nil
}

// ValidateSealState validates persisted partial or complete streaming state.
func ValidateSealState(state SealState) error { return state.validate(false) }

// Clear overwrites in-memory secret material. Persisted records must also be
// removed after the Event is durably queued.
func (s *SealState) Clear() {
	if s == nil {
		return
	}
	clear(s.Key)
	clear(s.AttachmentID)
	clear(s.NoncePrefix)
	s.Key = nil
	s.AttachmentID = nil
	s.NoncePrefix = nil
}

func (s SealState) validate(complete bool) error {
	if len(s.Key) != KeyBytes || len(s.AttachmentID) != AttachmentIDBytes || len(s.NoncePrefix) != NoncePrefixBytes ||
		canon.IsZero(s.Key) || canon.IsZero(s.AttachmentID) || canon.IsZero(s.NoncePrefix) ||
		s.PlaintextBytes == 0 || s.PlaintextBytes > MaxPlaintextBytes {
		return errors.New("invalid attachment streaming seal state")
	}
	if s.ChunkBytes == 0 || s.ChunkBytes > MaxChunkBytes {
		return errors.New("invalid attachment streaming chunk size")
	}
	if err := validateMetadata(s.Metadata); err != nil {
		return err
	}
	count := s.chunkCount()
	if len(s.ChunkDigests) > count || complete && len(s.ChunkDigests) != count {
		return errors.New("invalid attachment streaming chunk count")
	}
	seen := make(map[string]struct{}, len(s.ChunkDigests))
	for _, digest := range s.ChunkDigests {
		if !validContentDigest(digest) {
			return errors.New("invalid attachment streaming chunk digest")
		}
		if _, duplicate := seen[digest]; duplicate {
			return errors.New("duplicate attachment streaming chunk digest")
		}
		seen[digest] = struct{}{}
	}
	return nil
}

func (s SealState) chunkCount() int {
	return int((s.PlaintextBytes + uint64(s.ChunkBytes) - 1) / uint64(s.ChunkBytes))
}
