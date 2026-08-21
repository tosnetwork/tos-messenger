package attachments

import (
	"bytes"
	"testing"
	"time"
)

func TestStreamingSealRoundTripAndRestart(t *testing.T) {
	now := time.Unix(1_900_000_000, 0)
	body := bytes.Repeat([]byte("streaming attachment\n"), DefaultChunkBytes/21+3)
	metadata := Metadata{Filename: "evidence.txt", MediaType: "text/plain", ExpiresAtUnix: uint64(now.Add(time.Hour).Unix())}
	state, err := NewSealState(bytes.NewReader(bytes.Repeat([]byte{7}, KeyBytes+AttachmentIDBytes+NoncePrefixBytes)), uint64(len(body)), metadata)
	if err != nil {
		t.Fatal(err)
	}
	var chunks []Chunk
	for offset := 0; offset < len(body); {
		end := offset + DefaultChunkBytes
		if end > len(body) {
			end = len(body)
		}
		chunk, err := state.SealNext(body[offset:end])
		if err != nil {
			t.Fatal(err)
		}
		chunks = append(chunks, chunk)
		// Copying the state models strict JSON persistence and a daemon restart.
		state = SealState{Key: append([]byte(nil), state.Key...), AttachmentID: append([]byte(nil), state.AttachmentID...),
			NoncePrefix: append([]byte(nil), state.NoncePrefix...), Metadata: state.Metadata,
			PlaintextBytes: state.PlaintextBytes, ChunkBytes: state.ChunkBytes, ChunkDigests: append([]string(nil), state.ChunkDigests...)}
		offset = end
	}
	ref, err := state.Reference()
	if err != nil {
		t.Fatal(err)
	}
	opened, err := Open(ref, chunks, Policy{MaxPlaintextBytes: uint64(len(body)), AllowedMediaTypes: map[string]struct{}{"text/plain": {}}}, now)
	if err != nil || !bytes.Equal(opened, body) {
		t.Fatalf("opened=%d want=%d err=%v", len(opened), len(body), err)
	}
	clear(opened)
	state.Clear()
}

func TestStreamingSealRejectsWrongShape(t *testing.T) {
	state, err := NewSealState(bytes.NewReader(bytes.Repeat([]byte{9}, KeyBytes+AttachmentIDBytes+NoncePrefixBytes)), 2,
		Metadata{Filename: "x.txt", MediaType: "text/plain", ExpiresAtUnix: 2})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := state.SealNext([]byte("x")); err == nil {
		t.Fatal("accepted a short non-final chunk")
	}
	if _, err := state.Reference(); err == nil {
		t.Fatal("accepted an incomplete reference")
	}
}
