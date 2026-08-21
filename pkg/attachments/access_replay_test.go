package attachments

import (
	"errors"
	"strings"
	"testing"
	"time"
)

func TestAccessClockRefusesRollbackAcrossRestart(t *testing.T) {
	root := t.TempDir() + "/store"
	store, err := OpenStore(root, DefaultStoreQuota())
	if err != nil {
		t.Fatal(err)
	}
	now := time.Unix(1_800_000_000, 0)
	request := AccessRequest{Schema: AccessRequestSchema, GrantDigest: "sha256:" + strings.Repeat("a", 64),
		Operation: OperationFetch, BodyDigest: "sha256:" + strings.Repeat("b", 64), NonceHex: strings.Repeat("01", 32),
		IssuedAtUnix: uint64(now.Add(-time.Second).Unix()), ExpiresAtUnix: uint64(now.Add(time.Minute).Unix())}
	if err := store.claimAccess(request, now); err != nil {
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	store, err = OpenStore(root, DefaultStoreQuota())
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	request.NonceHex = strings.Repeat("02", 32)
	request.IssuedAtUnix = uint64(now.Add(-2 * time.Second).Unix())
	if err := store.claimAccess(request, now.Add(-time.Second)); !errors.Is(err, ErrClockRollback) {
		t.Fatalf("rollback error=%v", err)
	}
	if err := store.claimAccess(request, now.Add(time.Second)); err != nil {
		t.Fatalf("forward clock rejected: %v", err)
	}
}
