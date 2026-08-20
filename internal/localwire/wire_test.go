package localwire

import (
	"bytes"
	"encoding/binary"
	"io"
	"testing"
)

type shortWriter struct {
	buffer bytes.Buffer
	limit  int
	zero   bool
}

func (w *shortWriter) Write(value []byte) (int, error) {
	if w.zero {
		return 0, nil
	}
	if len(value) > w.limit {
		value = value[:w.limit]
	}
	return w.buffer.Write(value)
}

func TestBoundedFramesRoundTripAcrossShortWrites(t *testing.T) {
	writer := &shortWriter{limit: 2}
	if err := WriteFrame(writer, []byte("public contribution"), 64); err != nil {
		t.Fatal(err)
	}
	body, err := ReadFrame(bytes.NewReader(writer.buffer.Bytes()), 64)
	if err != nil || string(body) != "public contribution" {
		t.Fatalf("body=%q err=%v", body, err)
	}
}

func TestFramesRejectInvalidBoundsBeforeBodyAllocation(t *testing.T) {
	if _, err := Frame(nil, 64); err == nil {
		t.Fatal("empty frame was accepted")
	}
	if _, err := Frame(bytes.Repeat([]byte{1}, 65), 64); err == nil {
		t.Fatal("oversized frame was accepted")
	}
	var header [4]byte
	binary.BigEndian.PutUint32(header[:], 65)
	if _, err := ReadFrame(bytes.NewReader(header[:]), 64); err == nil {
		t.Fatal("oversized declared frame was accepted")
	}
	if err := WriteFrame(&shortWriter{zero: true}, []byte("body"), 64); err != io.ErrShortWrite {
		t.Fatalf("zero-progress write returned %v", err)
	}
}
