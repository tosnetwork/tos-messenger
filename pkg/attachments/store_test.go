package attachments

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/tosnetwork/tos-messenger/internal/dirlock"
)

func storedAttachment(t *testing.T, now time.Time) (Reference, []Chunk, []byte) {
	t.Helper()
	plaintext := bytes.Repeat([]byte("private attachment block"), DefaultChunkBytes/8)
	metadata := attachmentMetadata(plaintext)
	metadata.ExpiresAtUnix = uint64(now.Add(time.Hour).Unix())
	ref, chunks, err := Seal(deterministicRandom(), plaintext, metadata)
	if err != nil {
		t.Fatalf("seal: %v", err)
	}
	return ref, chunks, plaintext
}

func TestCiphertextStoreSurvivesRestartAndSupportsResume(t *testing.T) {
	now := time.Unix(1_900_000_000, 0)
	ref, chunks, plaintext := storedAttachment(t, now)
	root := filepath.Join(t.TempDir(), "attachments")
	store, err := OpenStore(root, DefaultStoreQuota())
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if _, err := OpenStore(root, DefaultStoreQuota()); !errors.Is(err, dirlock.ErrHeld) {
		t.Fatalf("second writer acquired the store: %v", err)
	}
	if fresh, err := store.Put(ref, chunks, now); err != nil || !fresh {
		t.Fatalf("put: fresh=%v err=%v", fresh, err)
	}
	if fresh, err := store.Put(ref, chunks, now); err != nil || fresh {
		t.Fatalf("retry: fresh=%v err=%v", fresh, err)
	}
	held, err := store.Held(ref)
	if err != nil {
		t.Fatalf("held: %v", err)
	}
	if missing, err := MissingDigests(ref, held); err != nil || len(missing) != 0 {
		t.Fatalf("stored chunks reported missing: %v %v", missing, err)
	}
	if err := store.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	store, err = OpenStore(root, DefaultStoreQuota())
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	defer store.Close()
	fetched, err := store.Fetch(ref)
	if err != nil {
		t.Fatalf("fetch: %v", err)
	}
	opened, err := Open(ref, fetched, DefaultPolicy(), now)
	if err != nil || !bytes.Equal(opened, plaintext) {
		t.Fatalf("decrypt fetched chunks: equal=%v err=%v", bytes.Equal(opened, plaintext), err)
	}
}

func TestCiphertextStoreDeleteAndGarbageCollection(t *testing.T) {
	now := time.Unix(1_900_000_000, 0)
	ref, chunks, _ := storedAttachment(t, now)
	store, err := OpenStore(filepath.Join(t.TempDir(), "attachments"), DefaultStoreQuota())
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	if _, err := store.Put(ref, chunks, now); err != nil {
		t.Fatal(err)
	}
	digest, _ := ManifestDigest(ref.Manifest)
	deleted, err := store.Delete(digest)
	if err != nil || !deleted {
		t.Fatalf("delete: deleted=%v err=%v", deleted, err)
	}
	if _, err := store.Fetch(ref); err == nil {
		t.Fatal("deleted lease still fetched")
	}
	report, err := store.GC(now)
	if err != nil || report.ObjectsRemoved != len(chunks) || report.ExpiredLeases != 0 {
		t.Fatalf("gc: %+v err=%v", report, err)
	}
	if deleted, err := store.Delete(digest); err != nil || deleted {
		t.Fatalf("repeated delete: deleted=%v err=%v", deleted, err)
	}
}

func TestCiphertextStoreExpiresLeasesAndFailsClosedOnDamage(t *testing.T) {
	now := time.Unix(1_900_000_000, 0)
	ref, chunks, _ := storedAttachment(t, now)
	root := filepath.Join(t.TempDir(), "attachments")
	store, err := OpenStore(root, DefaultStoreQuota())
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	if _, err := store.Put(ref, chunks, now); err != nil {
		t.Fatal(err)
	}
	path := store.objectPath(chunks[0].Digest)
	if err := os.WriteFile(path, []byte("tampered"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Fetch(ref); err == nil {
		t.Fatal("tampered ciphertext fetched")
	}
	if _, err := store.GC(now.Add(2 * time.Hour)); err == nil {
		t.Fatal("GC mutated a damaged store")
	}
	digest, _ := ManifestDigest(ref.Manifest)
	if _, err := os.Stat(store.leasePath(digest)); err != nil {
		t.Fatalf("fail-closed GC removed the lease: %v", err)
	}
}

func TestCiphertextStoreCollectsExpiredLease(t *testing.T) {
	now := time.Unix(1_900_000_000, 0)
	ref, chunks, _ := storedAttachment(t, now)
	store, err := OpenStore(filepath.Join(t.TempDir(), "attachments"), DefaultStoreQuota())
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	if _, err := store.Put(ref, chunks, now); err != nil {
		t.Fatal(err)
	}
	report, err := store.GC(time.Unix(int64(ref.Metadata.ExpiresAtUnix), 0))
	if err != nil || report.ExpiredLeases != 1 || report.ObjectsRemoved != len(chunks) {
		t.Fatalf("expired GC: %+v err=%v", report, err)
	}
}

func TestCiphertextStorePeriodicGCProtectsActiveMultiFrameUpload(t *testing.T) {
	now := time.Unix(1_900_000_000, 0)
	_, chunks, _ := storedAttachment(t, now)
	store, err := OpenStore(filepath.Join(t.TempDir(), "attachments"), DefaultStoreQuota())
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	if _, err := store.PutObjects(chunks[:1]); err != nil {
		t.Fatal(err)
	}
	stagedAt := time.Unix(1_800_000_000, 0)
	path := store.objectPath(chunks[0].Digest)
	if err := os.Chtimes(path, stagedAt, stagedAt); err != nil {
		t.Fatal(err)
	}
	report, err := store.GCWithStagingGrace(stagedAt.Add(DefaultStagingGrace/2), DefaultStagingGrace)
	if err != nil || report.ObjectsRemoved != 0 {
		t.Fatalf("active staging collection: %+v err=%v", report, err)
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("active staged chunk removed: %v", err)
	}
	report, err = store.GCWithStagingGrace(stagedAt.Add(DefaultStagingGrace+time.Second), DefaultStagingGrace)
	if err != nil || report.ObjectsRemoved != 1 {
		t.Fatalf("stale staging collection: %+v err=%v", report, err)
	}
	if _, err := store.GCWithStagingGrace(stagedAt, -time.Second); err == nil {
		t.Fatal("negative staging grace accepted")
	}
}

func TestCiphertextStoreEnforcesQuotaBeforeWriting(t *testing.T) {
	now := time.Unix(1_900_000_000, 0)
	ref, chunks, _ := storedAttachment(t, now)
	quota := DefaultStoreQuota()
	quota.MaxBytes = 1
	store, err := OpenStore(filepath.Join(t.TempDir(), "attachments"), quota)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	if _, err := store.Put(ref, chunks, now); err == nil {
		t.Fatal("over-quota attachment was stored")
	}
	entries, err := os.ReadDir(filepath.Join(store.root, objectsDir))
	if err != nil || len(entries) != 0 {
		t.Fatalf("quota failure left objects: count=%d err=%v", len(entries), err)
	}
}

func TestCiphertextStoreGenerationFailsClosed(t *testing.T) {
	t.Run("unmarked nonempty", func(t *testing.T) {
		root := filepath.Join(t.TempDir(), "attachments")
		if err := os.Mkdir(root, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(root, "legacy"), []byte("state"), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := OpenStore(root, DefaultStoreQuota()); err == nil {
			t.Fatal("unmarked nonempty attachment state opened")
		}
	})
	t.Run("public marker", func(t *testing.T) {
		root := filepath.Join(t.TempDir(), "attachments")
		store, err := OpenStore(root, DefaultStoreQuota())
		if err != nil {
			t.Fatal(err)
		}
		if err := store.Close(); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(filepath.Join(root, storeGenerationName), 0o644); err != nil {
			t.Fatal(err)
		}
		if _, err := OpenStore(root, DefaultStoreQuota()); err == nil {
			t.Fatal("public attachment generation marker accepted")
		}
	})
	t.Run("symlink marker", func(t *testing.T) {
		root := filepath.Join(t.TempDir(), "attachments")
		store, err := OpenStore(root, DefaultStoreQuota())
		if err != nil {
			t.Fatal(err)
		}
		if err := store.Close(); err != nil {
			t.Fatal(err)
		}
		marker := filepath.Join(root, storeGenerationName)
		target := filepath.Join(t.TempDir(), "marker")
		if err := os.WriteFile(target, []byte(storeGenerationValue), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.Remove(marker); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(target, marker); err != nil {
			t.Fatal(err)
		}
		if _, err := OpenStore(root, DefaultStoreQuota()); err == nil {
			t.Fatal("symlink attachment generation marker accepted")
		}
	})
}
