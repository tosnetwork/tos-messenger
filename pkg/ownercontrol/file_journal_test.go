package ownercontrol

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

type memoryJournalAuthority struct {
	installation []byte
	revision     uint64
	commitment   []byte
}

func (authority *memoryJournalAuthority) InstallationID(context.Context) ([]byte, error) {
	return append([]byte(nil), authority.installation...), nil
}
func (authority *memoryJournalAuthority) Read(context.Context, []byte) (uint64, []byte, error) {
	return authority.revision, append([]byte(nil), authority.commitment...), nil
}
func (authority *memoryJournalAuthority) Check(_ context.Context, _ []byte, revision uint64, commitment []byte) error {
	if authority.commitment == nil && revision == 0 {
		authority.commitment = append([]byte(nil), commitment...)
		return nil
	}
	if authority.revision != revision || !bytes.Equal(authority.commitment, commitment) {
		return errors.New("journal rollback detected")
	}
	return nil
}
func (authority *memoryJournalAuthority) CompareAndAdvance(_ context.Context, _ []byte, prior, next uint64, commitment []byte) error {
	if authority.revision != prior || next != prior+1 {
		return errors.New("journal high-water conflict")
	}
	authority.revision = next
	authority.commitment = append([]byte(nil), commitment...)
	return nil
}

func TestFileJournalRejectsRestoreAndConcurrentWriter(t *testing.T) {
	root := filepath.Join(t.TempDir(), "journal")
	authority := &memoryJournalAuthority{installation: bytes.Repeat([]byte{1}, 32)}
	journal, err := OpenFileJournal(root, authority)
	if err != nil {
		t.Fatal(err)
	}
	oldMetadata, err := os.ReadFile(filepath.Join(root, "journal-metadata.json"))
	if err != nil {
		t.Fatal(err)
	}
	if second, err := OpenFileJournal(root, authority); err == nil {
		_ = second.Close()
		t.Fatal("second journal writer was not fenced")
	}
	namespace, action := bytes.Repeat([]byte{2}, 32), bytes.Repeat([]byte{3}, 32)
	observation := TrustedTimeObservation{UnixSeconds: 100, Epoch: 1, EvidenceDigest: bytes.Repeat([]byte{4}, 32)}
	if _, _, inserted, err := journal.Begin(context.Background(), namespace, action, Record{}, observation); err != nil || !inserted {
		t.Fatalf("begin failed: inserted=%v err=%v", inserted, err)
	}
	if err := journal.Close(); err != nil {
		t.Fatal(err)
	}
	if _, _, _, err := journal.Begin(context.Background(), namespace, action, Record{}, observation); err == nil {
		t.Fatal("closed superseded journal retained command recovery authority")
	}
	if _, _, err := journal.Get(context.Background(), namespace, action); err == nil {
		t.Fatal("closed superseded journal remained queryable as an active sink")
	}
	if err := os.WriteFile(filepath.Join(root, "journal-metadata.json"), oldMetadata, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.RemoveAll(filepath.Join(root, "records")); err != nil {
		t.Fatal(err)
	}
	if restored, err := OpenFileJournal(root, authority); err == nil {
		_ = restored.Close()
		t.Fatal("restored journal erased a consequential Action")
	}
}

func TestFileJournalRejectsTrustedTimeRollback(t *testing.T) {
	root := filepath.Join(t.TempDir(), "journal")
	authority := &memoryJournalAuthority{installation: bytes.Repeat([]byte{5}, 32)}
	journal, err := OpenFileJournal(root, authority)
	if err != nil {
		t.Fatal(err)
	}
	defer journal.Close()
	namespace := bytes.Repeat([]byte{6}, 32)
	if _, _, _, err := journal.Begin(context.Background(), namespace, bytes.Repeat([]byte{7}, 32), Record{}, TrustedTimeObservation{UnixSeconds: 200, Epoch: 2, EvidenceDigest: bytes.Repeat([]byte{8}, 32)}); err != nil {
		t.Fatal(err)
	}
	if _, _, _, err := journal.Begin(context.Background(), namespace, bytes.Repeat([]byte{9}, 32), Record{}, TrustedTimeObservation{UnixSeconds: 100, Epoch: 1, EvidenceDigest: bytes.Repeat([]byte{8}, 32)}); err == nil {
		t.Fatal("trusted time rollback admitted a new command")
	}
}
