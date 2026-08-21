// Package canon holds the shared canonical-encoding primitives used by every
// signed or digest-committed Messenger object.
//
// Canonical form is always a domain-separated, length-prefixed binary
// preimage. JSON is a transport encoding and is never hashed or signed, so a
// reordered or re-serialized JSON document can never change an object's
// identity.
package canon

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"regexp"
)

// DigestPattern matches the digest form committed by TOS objects.
var DigestPattern = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)

// HashPattern matches a bare 32-byte hash in lowercase hex.
var HashPattern = regexp.MustCompile(`^[0-9a-f]{64}$`)

// Text appends a length-prefixed string. The prefix is what stops two
// different field splits from producing the same preimage.
func Text(buffer *bytes.Buffer, value string) {
	Uint32(buffer, uint32(len(value)))
	buffer.WriteString(value)
}

// Bytes appends a length-prefixed byte slice.
func Bytes(buffer *bytes.Buffer, value []byte) {
	Uint32(buffer, uint32(len(value)))
	buffer.Write(value)
}

// Hash32 appends a strict lowercase bare-hex hash as its length-prefixed raw
// 32-byte value. JSON carries hashes as display hex, but a canonical preimage
// must never commit those 64 display characters. Callers propagate the error
// so malformed input cannot silently collapse to an empty or partial field.
func Hash32(buffer *bytes.Buffer, value string) error {
	if buffer == nil || !HashPattern.MatchString(value) {
		return errors.New("invalid canonical 32-byte hash")
	}
	raw, err := hex.DecodeString(value)
	if err != nil || len(raw) != sha256.Size {
		return errors.New("invalid canonical 32-byte hash")
	}
	Bytes(buffer, raw)
	return nil
}

// MustHash32 is for package-private encoders whose public entry point has
// already validated the complete object and whose interface cannot return an
// error. A panic here is an internal invariant failure, never peer-input error
// handling; exported canonical encoders use Hash32 and propagate errors.
func MustHash32(buffer *bytes.Buffer, value string) {
	if err := Hash32(buffer, value); err != nil {
		panic(err)
	}
}

// Uint32 appends a big-endian 32-bit value.
func Uint32(buffer *bytes.Buffer, value uint32) {
	var number [4]byte
	binary.BigEndian.PutUint32(number[:], value)
	buffer.Write(number[:])
}

// Bool appends one byte, 1 for true and 0 for false. A boolean is committed
// explicitly rather than omitted when false, because a preimage whose length
// depends on the value invites two objects to share one encoding.
func Bool(buffer *bytes.Buffer, value bool) {
	if value {
		buffer.WriteByte(1)
		return
	}
	buffer.WriteByte(0)
}

// Uint64 appends a big-endian 64-bit value.
func Uint64(buffer *bytes.Buffer, value uint64) {
	var number [8]byte
	binary.BigEndian.PutUint64(number[:], value)
	buffer.Write(number[:])
}

// Digest returns the TOS digest form of a preimage.
func Digest(preimage []byte) string {
	sum := sha256.Sum256(preimage)
	return "sha256:" + hex.EncodeToString(sum[:])
}

// ValidDigest reports whether a digest is well formed and not the all-zero
// value. An all-zero digest is almost always an uninitialized field rather
// than a real commitment, so it fails closed.
func ValidDigest(digest string) bool {
	if !DigestPattern.MatchString(digest) {
		return false
	}
	raw, err := hex.DecodeString(digest[len("sha256:"):])
	if err != nil {
		return false
	}
	return !bytes.Equal(raw, make([]byte, sha256.Size))
}

// IsZero reports whether a byte slice is entirely zero. A zero key, nonce, or
// identifier is never a legitimate value.
func IsZero(value []byte) bool {
	return bytes.Equal(value, make([]byte, len(value)))
}
