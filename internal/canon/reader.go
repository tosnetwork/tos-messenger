package canon

import (
	"encoding/binary"
	"errors"
	"unicode/utf8"
)

// Reader parses a canonical preimage back into its fields.
//
// It is deliberately strict and stateful. Every read is bounds-checked, a
// failed read latches so a caller that ignores one error cannot go on to read
// garbage from a shifted offset, and Done refuses trailing bytes. A decoder
// that accepted trailing bytes would let two different encodings mean the same
// object, and an object's identity is its bytes.
type Reader struct {
	buffer []byte
	offset int
	err    error
}

// NewReader reads a preimage that begins with the given domain separator.
func NewReader(domain string, preimage []byte) *Reader {
	reader := &Reader{buffer: preimage}
	if len(preimage) < len(domain) || string(preimage[:len(domain)]) != domain {
		reader.err = errors.New("preimage is not in the expected domain")
		return reader
	}
	reader.offset = len(domain)
	return reader
}

// Err returns the first error that occurred.
func (r *Reader) Err() error { return r.err }

func (r *Reader) fail(message string) {
	if r.err == nil {
		r.err = errors.New(message)
	}
}

func (r *Reader) take(count int) []byte {
	if r.err != nil {
		return nil
	}
	if count < 0 || r.offset+count > len(r.buffer) {
		r.fail("canonical value runs past the end of its preimage")
		return nil
	}
	value := r.buffer[r.offset : r.offset+count]
	r.offset += count
	return value
}

// Uint32 reads a big-endian 32-bit value.
func (r *Reader) Uint32() uint32 {
	raw := r.take(4)
	if raw == nil {
		return 0
	}
	return binary.BigEndian.Uint32(raw)
}

// Uint64 reads a big-endian 64-bit value.
func (r *Reader) Uint64() uint64 {
	raw := r.take(8)
	if raw == nil {
		return 0
	}
	return binary.BigEndian.Uint64(raw)
}

// Uint8 reads a single byte as an unsigned value.
func (r *Reader) Uint8() uint8 {
	raw := r.take(1)
	if raw == nil {
		return 0
	}
	return raw[0]
}

// Bytes reads a length-prefixed byte slice, refusing anything longer than the
// caller's bound. The bound is required: a length prefix a peer chooses is an
// allocation a peer chooses.
func (r *Reader) Bytes(maximum int) []byte {
	length := int(r.Uint32())
	if r.err != nil {
		return nil
	}
	if length > maximum {
		r.fail("canonical value exceeds its bound")
		return nil
	}
	raw := r.take(length)
	if raw == nil {
		return nil
	}
	value := make([]byte, length)
	copy(value, raw)
	return value
}

// Text reads a length-prefixed string and requires it to be valid UTF-8.
func (r *Reader) Text(maximum int) string {
	raw := r.Bytes(maximum)
	if raw == nil {
		return ""
	}
	if !utf8.Valid(raw) {
		r.fail("canonical text is not valid UTF-8")
		return ""
	}
	return string(raw)
}

// Count reads a length prefix for a repeated field, bounded by the caller.
func (r *Reader) Count(maximum int) int {
	count := int(r.Uint32())
	if r.err != nil {
		return 0
	}
	if count > maximum {
		r.fail("canonical repeated field exceeds its bound")
		return 0
	}
	return count
}

// Done reports the first error, or that trailing bytes were left unread.
func (r *Reader) Done() error {
	if r.err != nil {
		return r.err
	}
	if r.offset != len(r.buffer) {
		return errors.New("canonical preimage has trailing bytes")
	}
	return nil
}
