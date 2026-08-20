package mailbox

import (
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"errors"
	"testing"

	"github.com/tosnetwork/tos-messenger/internal/canon"
	"github.com/tosnetwork/tos-messenger/pkg/envelope"
)

type fakeRelay struct {
	key    ed25519.PrivateKey
	err    error
	mutate func(*StoredAck)
}

func (r *fakeRelay) PublicKeyHex() string {
	return hex.EncodeToString(r.key.Public().(ed25519.PublicKey))
}
func (r *fakeRelay) Store(_ context.Context, value envelope.RelayEnvelope) (StoredAck, error) {
	if r.err != nil {
		return StoredAck{}, r.err
	}
	ack, err := SignAck(StoredAck{MailboxID: value.OpaqueMailboxID, MessageID: value.MessageID,
		CiphertextDigest: canon.Digest(value.Ciphertext), StoredAtUnix: uint64(mailboxNow), ExpiresAtUnix: value.ExpiresAtUnix}, r.key)
	if r.mutate != nil {
		r.mutate(&ack)
	}
	return ack, err
}
func anotherRelayKey(seed byte) ed25519.PrivateKey {
	material := make([]byte, ed25519.SeedSize)
	for i := range material {
		material[i] = seed
	}
	return ed25519.NewKeyFromSeed(material)
}

func TestStoreRedundantRequiresIndependentValidAcks(t *testing.T) {
	goodA := &fakeRelay{key: anotherRelayKey(1)}
	goodB := &fakeRelay{key: anotherRelayKey(2)}
	bad := &fakeRelay{key: anotherRelayKey(3), mutate: func(a *StoredAck) { a.MessageID = "msg_" + string(make([]byte, 64)) }}
	result, err := StoreRedundant(context.Background(), []RelayClient{goodA, bad, goodB}, relayEnvelope('7'), 2)
	if err != nil || result.StoredCopies() != 2 {
		t.Fatalf("copies=%d err=%v", result.StoredCopies(), err)
	}
	if result.Attempts[1].Err == nil || result.Attempts[1].Ack != nil {
		t.Fatal("forged acknowledgement counted")
	}
}

func TestStoreRedundantReportsUnmetPolicy(t *testing.T) {
	good := &fakeRelay{key: anotherRelayKey(4)}
	failed := &fakeRelay{key: anotherRelayKey(5), err: errors.New("offline")}
	result, err := StoreRedundant(context.Background(), []RelayClient{good, failed}, relayEnvelope('8'), 2)
	if err == nil || result.StoredCopies() != 1 {
		t.Fatalf("copies=%d err=%v", result.StoredCopies(), err)
	}
}

func TestStoreRedundantRefusesDuplicateRelayIdentity(t *testing.T) {
	first := &fakeRelay{key: anotherRelayKey(6)}
	second := &fakeRelay{key: first.key}
	if _, err := StoreRedundant(context.Background(), []RelayClient{first, second}, relayEnvelope('9'), 2); err == nil {
		t.Fatal("one Relay counted twice")
	}
}
