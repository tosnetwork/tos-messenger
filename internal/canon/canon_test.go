package canon

import (
	"bytes"
	"strings"
	"testing"
)

func TestLengthPrefixSeparatesFields(t *testing.T) {
	// Without a length prefix these two field splits would produce identical
	// preimages, which is how one object gets to impersonate another.
	first := &bytes.Buffer{}
	Text(first, "ab")
	Text(first, "c")

	second := &bytes.Buffer{}
	Text(second, "a")
	Text(second, "bc")

	if bytes.Equal(first.Bytes(), second.Bytes()) {
		t.Fatal("different field splits produced the same preimage")
	}
}

func TestFixedWidthEncoding(t *testing.T) {
	buffer := &bytes.Buffer{}
	Uint32(buffer, 1)
	Uint64(buffer, 1)
	expected := []byte{0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 1}
	if !bytes.Equal(buffer.Bytes(), expected) {
		t.Fatalf("unexpected big-endian encoding: %v", buffer.Bytes())
	}
}

func TestBytesArePrefixed(t *testing.T) {
	buffer := &bytes.Buffer{}
	Bytes(buffer, []byte{0xaa, 0xbb})
	if !bytes.Equal(buffer.Bytes(), []byte{0, 0, 0, 2, 0xaa, 0xbb}) {
		t.Fatalf("unexpected byte encoding: %v", buffer.Bytes())
	}
}

func TestDigestShape(t *testing.T) {
	digest := Digest([]byte("preimage"))
	if !DigestPattern.MatchString(digest) {
		t.Fatalf("unexpected digest shape: %s", digest)
	}
	if Digest([]byte("preimage")) != digest {
		t.Fatal("digest is not deterministic")
	}
	if Digest([]byte("other")) == digest {
		t.Fatal("different preimages produced the same digest")
	}
}

func TestValidDigestFailsClosed(t *testing.T) {
	if !ValidDigest(Digest([]byte("preimage"))) {
		t.Fatal("expected a real digest to be valid")
	}
	for name, digest := range map[string]string{
		"empty":       "",
		"no prefix":   strings.Repeat("a", 64),
		"wrong algo":  "tvm-cell-sha256:" + strings.Repeat("a", 64),
		"short":       "sha256:" + strings.Repeat("a", 63),
		"uppercase":   "sha256:" + strings.Repeat("A", 64),
		"all zero":    "sha256:" + strings.Repeat("0", 64),
		"not hex":     "sha256:" + strings.Repeat("z", 64),
		"trailing ws": "sha256:" + strings.Repeat("a", 64) + " ",
	} {
		t.Run(name, func(t *testing.T) {
			if ValidDigest(digest) {
				t.Fatalf("expected %q to be refused", name)
			}
		})
	}
}

func TestIsZero(t *testing.T) {
	if !IsZero(make([]byte, 32)) || !IsZero(nil) {
		t.Fatal("expected zero values to be detected")
	}
	if IsZero([]byte{0, 0, 1}) {
		t.Fatal("expected a non-zero value to be detected")
	}
}
