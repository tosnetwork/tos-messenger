package mailbox

import (
	"bytes"
	"crypto/ed25519"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/tosnetwork/tos-messenger/internal/canon"
	"github.com/tosnetwork/tos-messenger/internal/dirlock"
	"github.com/tosnetwork/tos-messenger/pkg/envelope"
)

const mailboxNow = int64(1_800_000_000)

func relayKey() ed25519.PrivateKey {
	return ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x31}, ed25519.SeedSize))
}

func relayEnvelope(messageByte byte) envelope.RelayEnvelope {
	return envelope.RelayEnvelope{
		OpaqueMailboxID: "mbx_" + strings.Repeat("a", 64),
		MessageID:       "msg_" + strings.Repeat(string([]byte{messageByte}), 64),
		Ciphertext:      bytes.Repeat([]byte{messageByte}, 64),
		ExpiresAtUnix:   uint64(mailboxNow + 3600),
		StorageToken:    "quota-token.1",
		AdmissionToken:  "invite_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
	}
}

func openStore(t *testing.T, quota Quota) *Store {
	t.Helper()
	store, err := Open(filepath.Join(t.TempDir(), "store"), quota, relayKey())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	return store
}

func TestStorePutIsDurableDeduplicatedAndSigned(t *testing.T) {
	root := filepath.Join(t.TempDir(), "store")
	store, err := Open(root, DefaultQuota(), relayKey())
	if err != nil {
		t.Fatal(err)
	}
	now := time.Unix(mailboxNow, 0)
	value := relayEnvelope('1')
	fresh, ack, err := store.Put(value, now)
	if err != nil || !fresh {
		t.Fatalf("put fresh=%v err=%v", fresh, err)
	}
	if err := VerifyAck(ack); err != nil {
		t.Fatalf("ack: %v", err)
	}
	if ack.CiphertextDigest != canon.Digest(value.Ciphertext) {
		t.Fatal("ack names another ciphertext")
	}
	if fresh, retry, err := store.Put(value, now.Add(time.Minute)); err != nil || fresh || retry.StoredAtUnix != ack.StoredAtUnix {
		t.Fatalf("retry fresh=%v ack=%+v err=%v", fresh, retry, err)
	}
	if _, err := Open(root, DefaultQuota(), relayKey()); !errors.Is(err, dirlock.ErrHeld) {
		t.Fatalf("second owner: %v", err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := Open(root, DefaultQuota(), relayKey())
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	listed, err := reopened.List(value.OpaqueMailboxID, now, 10)
	if err != nil || len(listed) != 1 || !bytes.Equal(listed[0].Ciphertext, value.Ciphertext) ||
		listed[0].AdmissionToken != value.AdmissionToken {
		t.Fatalf("listed=%v err=%v", listed, err)
	}
}

func TestStoreRefusesMessageIdentityConflict(t *testing.T) {
	store := openStore(t, DefaultQuota())
	now := time.Unix(mailboxNow, 0)
	value := relayEnvelope('2')
	if _, _, err := store.Put(value, now); err != nil {
		t.Fatal(err)
	}
	value.Ciphertext[0] ^= 0xff
	if _, _, err := store.Put(value, now); !errors.Is(err, ErrConflict) {
		t.Fatalf("conflict=%v", err)
	}
	value = relayEnvelope('2')
	value.ExpiresAtUnix++
	if _, _, err := store.Put(value, now); !errors.Is(err, ErrConflict) {
		t.Fatalf("expiry conflict=%v", err)
	}
	value = relayEnvelope('2')
	value.AdmissionToken = "invite_BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB"
	if _, _, err := store.Put(value, now); !errors.Is(err, ErrConflict) {
		t.Fatalf("admission-token conflict=%v", err)
	}
}

func TestStoreEnforcesQuotaBeforeCreatingARecord(t *testing.T) {
	quota := DefaultQuota()
	quota.MaxMessages = 1
	quota.MaxMessagesPerBox = 1
	store := openStore(t, quota)
	now := time.Unix(mailboxNow, 0)
	if _, _, err := store.Put(relayEnvelope('3'), now); err != nil {
		t.Fatal(err)
	}
	if _, _, err := store.Put(relayEnvelope('4'), now); !errors.Is(err, ErrQuota) {
		t.Fatalf("quota=%v", err)
	}
	listed, err := store.List(relayEnvelope('3').OpaqueMailboxID, now, 10)
	if err != nil || len(listed) != 1 {
		t.Fatalf("listed=%d err=%v", len(listed), err)
	}
}

func TestStoreDeleteAndExpiryAreExact(t *testing.T) {
	store := openStore(t, DefaultQuota())
	now := time.Unix(mailboxNow, 0)
	value := relayEnvelope('5')
	if _, _, err := store.Put(value, now); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Delete(value.OpaqueMailboxID, value.MessageID, "sha256:"+strings.Repeat("9", 64)); !errors.Is(err, ErrConflict) {
		t.Fatalf("blind delete=%v", err)
	}
	listed, err := store.List(value.OpaqueMailboxID, time.Unix(int64(value.ExpiresAtUnix), 0), 10)
	if err != nil || len(listed) != 0 {
		t.Fatalf("expired listed=%d err=%v", len(listed), err)
	}
	removed, err := store.Sweep(time.Unix(int64(value.ExpiresAtUnix), 0))
	if err != nil || removed != 1 {
		t.Fatalf("removed=%d err=%v", removed, err)
	}
	if deleted, err := store.Delete(value.OpaqueMailboxID, value.MessageID, canon.Digest(value.Ciphertext)); err != nil || deleted {
		t.Fatalf("deleted=%v err=%v", deleted, err)
	}
}

func TestStoredAckRefusesTampering(t *testing.T) {
	store := openStore(t, DefaultQuota())
	value := relayEnvelope('6')
	_, ack, err := store.Put(value, time.Unix(mailboxNow, 0))
	if err != nil {
		t.Fatal(err)
	}
	ack.ExpiresAtUnix++
	if err := VerifyAck(ack); err == nil {
		t.Fatal("tampered StoredAck verified")
	}
}

func TestStoredAckStrictWireRoundTrip(t *testing.T) {
	store := openStore(t, DefaultQuota())
	_, ack, err := store.Put(relayEnvelope('7'), time.Unix(mailboxNow, 0))
	if err != nil {
		t.Fatal(err)
	}
	raw, err := EncodeAckJSON(ack)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := DecodeAckJSON(raw)
	if err != nil || decoded.MessageID != ack.MessageID {
		t.Fatalf("decoded=%+v err=%v", decoded, err)
	}
	unknown := append(append([]byte{}, raw[:len(raw)-1]...), []byte(`,"extra":true}`)...)
	if _, err := DecodeAckJSON(unknown); err == nil {
		t.Fatal("unknown StoredAck field accepted")
	}
	if _, err := DecodeAckJSON(append(raw, raw...)); err == nil {
		t.Fatal("trailing StoredAck accepted")
	}
}

func TestOpenRefusesSymlinkedMailboxDirectory(t *testing.T) {
	root := filepath.Join(t.TempDir(), "store")
	target := t.TempDir()
	if err := os.Mkdir(root, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, filepath.Join(root, mailboxesDir)); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(root, DefaultQuota(), relayKey()); err == nil {
		t.Fatal("symlinked mailboxes accepted")
	}
}
