package attachments

import (
	"bytes"
	"strings"
	"testing"
	"time"

	"github.com/tosnetwork/tos-messenger/internal/canon"
)

func attachmentMetadata(plaintext []byte) Metadata {
	return Metadata{Filename: "report.pdf", MediaType: "application/pdf", PlaintextDigest: canon.Digest(plaintext), ExpiresAtUnix: 2_000_000_000}
}

func deterministicRandom() *bytes.Reader {
	raw := make([]byte, KeyBytes+AttachmentIDBytes+NoncePrefixBytes)
	for index := range raw {
		raw[index] = byte(index + 1)
	}
	return bytes.NewReader(raw)
}

func TestAttachmentRoundTripAndResume(t *testing.T) {
	plaintext := bytes.Repeat([]byte("chunked-private-attachment"), DefaultChunkBytes/8)
	ref, chunks, err := Seal(deterministicRandom(), plaintext, attachmentMetadata(plaintext))
	if err != nil {
		t.Fatal(err)
	}
	if len(chunks) < 2 {
		t.Fatalf("fixture did not cross a chunk: %d", len(chunks))
	}
	digest, err := ManifestDigest(ref.Manifest)
	if err != nil || !canon.ValidDigest(digest) {
		t.Fatalf("manifest: %q %v", digest, err)
	}
	held := map[string]bool{chunks[0].Digest: true}
	missing, err := MissingDigests(ref, held)
	if err != nil || len(missing) != len(chunks)-1 {
		t.Fatalf("resume: %v %v", missing, err)
	}
	opened, err := Open(ref, chunks, Policy{MaxPlaintextBytes: uint64(len(plaintext)), AllowedMediaTypes: map[string]struct{}{"application/pdf": {}}}, time.Unix(1_900_000_000, 0))
	if err != nil || !bytes.Equal(opened, plaintext) {
		t.Fatalf("open: equal=%v err=%v", bytes.Equal(opened, plaintext), err)
	}
	raw, err := EncodeReferenceJSON(ref)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := DecodeReferenceJSON(raw)
	if err != nil {
		t.Fatal(err)
	}
	if decoded.KeyHex != ref.KeyHex {
		t.Fatal("reference round trip changed key")
	}
}

func TestAttachmentTamperingAndReorderingFailClosed(t *testing.T) {
	plaintext := bytes.Repeat([]byte("x"), DefaultChunkBytes+17)
	ref, chunks, err := Seal(deterministicRandom(), plaintext, attachmentMetadata(plaintext))
	if err != nil {
		t.Fatal(err)
	}
	cases := map[string]func(Reference, []Chunk) (Reference, []Chunk){
		"ciphertext": func(r Reference, c []Chunk) (Reference, []Chunk) { c[0].Ciphertext[0] ^= 1; return r, c },
		"digest": func(r Reference, c []Chunk) (Reference, []Chunk) {
			c[0].Digest = canon.Digest([]byte("lie"))
			return r, c
		},
		"order": func(r Reference, c []Chunk) (Reference, []Chunk) { c[0], c[1] = c[1], c[0]; return r, c },
		"key": func(r Reference, c []Chunk) (Reference, []Chunk) {
			r.KeyHex = strings.Repeat("ab", KeyBytes)
			return r, c
		},
		"metadata": func(r Reference, c []Chunk) (Reference, []Chunk) { r.Metadata.Filename = "other.pdf"; return r, c },
		"missing":  func(r Reference, c []Chunk) (Reference, []Chunk) { return r, c[:1] },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			copyChunks := make([]Chunk, len(chunks))
			for i, c := range chunks {
				copyChunks[i] = Chunk{Index: c.Index, Digest: c.Digest, Ciphertext: append([]byte(nil), c.Ciphertext...)}
			}
			changedRef, changedChunks := mutate(ref, copyChunks)
			if opened, err := Open(changedRef, changedChunks, DefaultPolicy(), time.Unix(1_900_000_000, 0)); err == nil || opened != nil {
				t.Fatalf("tampering returned plaintext: %x", opened)
			}
		})
	}
}

func TestAttachmentBoundsExpiryAndStrictReference(t *testing.T) {
	plaintext := []byte("private")
	ref, chunks, err := Seal(deterministicRandom(), plaintext, attachmentMetadata(plaintext))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Open(ref, chunks, Policy{MaxPlaintextBytes: 1}, time.Unix(1_900_000_000, 0)); err == nil {
		t.Fatal("local size cap ignored")
	}
	if _, err := Open(ref, chunks, DefaultPolicy(), time.Unix(2_000_000_000, 0)); err == nil {
		t.Fatal("expired attachment opened")
	}
	raw, _ := EncodeReferenceJSON(ref)
	unknown := append(raw[:len(raw)-1], []byte(`,"unknown":true}`)...)
	if _, err := DecodeReferenceJSON(unknown); err == nil {
		t.Fatal("unknown field accepted")
	}
	if _, err := DecodeReferenceJSON(append(raw, []byte(`{}`)...)); err == nil {
		t.Fatal("trailing JSON accepted")
	}
	oversized := ref
	oversized.Manifest.PlaintextBytes = MaxPlaintextBytes + 1
	if err := ValidateReference(oversized); err == nil {
		t.Fatal("oversized declared plaintext accepted")
	}
	badName := attachmentMetadata(plaintext)
	badName.Filename = "../secret"
	if _, _, err := Seal(deterministicRandom(), plaintext, badName); err == nil {
		t.Fatal("path-like filename accepted")
	}
	badDigest := attachmentMetadata(plaintext)
	badDigest.PlaintextDigest = canon.Digest([]byte("other"))
	if _, _, err := Seal(deterministicRandom(), plaintext, badDigest); err == nil {
		t.Fatal("false plaintext digest accepted")
	}
}

func TestChunkNoncesAndAADArePositionBound(t *testing.T) {
	prefix := []byte{1, 2, 3, 4}
	if bytes.Equal(chunkNonce(prefix, 0), chunkNonce(prefix, 1)) {
		t.Fatal("two chunks reused a nonce")
	}
	id := bytes.Repeat([]byte{9}, AttachmentIDBytes)
	digest := canon.Digest([]byte("metadata"))
	if bytes.Equal(chunkAAD(id, digest, 10, 5, 2, 0), chunkAAD(id, digest, 10, 5, 2, 1)) {
		t.Fatal("chunk position is absent from AAD")
	}
}
