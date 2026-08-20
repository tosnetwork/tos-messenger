package mlslab

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/tosnetwork/tos-messenger/pkg/envelope"
	"github.com/tosnetwork/tos-messenger/pkg/group"
	"github.com/tosnetwork/tos-messenger/pkg/mailbox"
)

type durableRelay struct {
	store *mailbox.Store
	key   string
	now   time.Time
}

func (r *durableRelay) PublicKeyHex() string { return r.key }
func (r *durableRelay) Store(_ context.Context, value envelope.RelayEnvelope) (mailbox.StoredAck, error) {
	_, ack, err := r.store.Put(value, r.now)
	if err == nil {
		r.now = r.now.Add(time.Second)
	}
	return ack, err
}

func TestOpenMLSPrivateMessagesCatchUpAcrossIndependentMailboxRelays(t *testing.T) {
	binary := os.Getenv("TOS_OPENMLS_DRIVER")
	if binary == "" {
		t.Skip("TOS_OPENMLS_DRIVER is set by make test-openmls")
	}
	driver := &group.OpenMLSSidecar{Command: []string{binary}, Timeout: 10 * time.Second}
	identities := make([]group.OpenMLSIdentity, 3)
	for i, name := range []string{"relay-alice", "relay-bob", "relay-carol"} {
		identity, err := driver.NewIdentity([]byte(name))
		if err != nil {
			t.Fatal(err)
		}
		identities[i] = identity
	}
	groupID := bytes.Repeat([]byte{0x4d}, group.MLSGroupIDBytes)
	states := make([][]byte, 3)
	var err error
	states[0], err = driver.CreateGroup(identities[0].State, identities[0].KeyPackage, groupID)
	if err != nil {
		t.Fatal(err)
	}
	for joining := 1; joining < 3; joining++ {
		ref := digestBytes(identities[joining].KeyPackage)
		next, commit, welcomes, err := driver.Commit(states[0], []group.LeafOperation{{Kind: group.LeafAdd, Next: &group.Leaf{
			CredentialIdentity:     []byte([]string{"relay-alice", "relay-bob", "relay-carol"}[joining]),
			LeafSignaturePublicKey: identities[joining].LeafSignaturePublicKey,
			KeyPackageRef:          ref, KeyPackage: identities[joining].KeyPackage,
		}}})
		if err != nil {
			t.Fatal(err)
		}
		states[0] = next
		for existing := 1; existing < joining; existing++ {
			states[existing], err = driver.Apply(states[existing], commit)
			if err != nil {
				t.Fatal(err)
			}
		}
		states[joining], err = driver.Join(identities[joining].State, welcomes[ref])
		if err != nil {
			t.Fatal(err)
		}
	}

	now := time.Unix(1_900_000_000, 0)
	relays := make([]*durableRelay, 2)
	roots := make([]string, 2)
	for i := range relays {
		root := filepath.Join(t.TempDir(), "relay")
		if err := os.Mkdir(root, 0o700); err != nil {
			t.Fatal(err)
		}
		key := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{byte(i + 1)}, ed25519.SeedSize))
		store, err := mailbox.Open(root, mailbox.DefaultQuota(), key)
		if err != nil {
			t.Fatal(err)
		}
		defer store.Close()
		relays[i] = &durableRelay{store: store, key: hex.EncodeToString(key.Public().(ed25519.PublicKey)), now: now}
		roots[i] = root
	}
	clients := []mailbox.RelayClient{relays[0], relays[1]}
	mailboxID := "mbx_" + strings.Repeat("5", 64)
	aad := []byte("multi-relay MLS acceptance")
	storeBoth := func(raw []byte) {
		t.Helper()
		value := envelope.RelayEnvelope{OpaqueMailboxID: mailboxID, MessageID: relayMessageID(raw), Ciphertext: raw, ExpiresAtUnix: uint64(now.Add(time.Hour).Unix())}
		result, err := mailbox.StoreRedundant(context.Background(), clients, value, 2)
		if err != nil || result.StoredCopies() != 2 {
			t.Fatalf("redundant store: copies=%d err=%v", result.StoredCopies(), err)
		}
	}

	opening := []byte("encrypted once and stored by two Relays")
	var ciphertext []byte
	states[0], ciphertext, err = driver.Seal(states[0], aad, opening)
	if err != nil {
		t.Fatal(err)
	}
	storeBoth(ciphertext)
	for i := 1; i < 3; i++ {
		var plaintext []byte
		states[i], plaintext, err = driver.Open(states[i], aad, ciphertext)
		if err != nil || !bytes.Equal(plaintext, opening) {
			t.Fatalf("member %d opening: %q %v", i, plaintext, err)
		}
	}

	// Carol now goes offline. Alice performs two PCS epochs; Bob applies them
	// live while both independent Relays retain the exact commits for catch-up.
	for epoch := 0; epoch < 2; epoch++ {
		var commit []byte
		states[0], commit, _, err = driver.Commit(states[0], nil)
		if err != nil {
			t.Fatal(err)
		}
		storeBoth(commit)
		states[1], err = driver.Apply(states[1], commit)
		if err != nil {
			t.Fatal(err)
		}
	}
	listedA, err := relays[0].store.List(mailboxID, now.Add(10*time.Second), 16)
	if err != nil || len(listedA) != 3 {
		t.Fatalf("offline Relay A catch-up: %d %v", len(listedA), err)
	}
	listedB, err := relays[1].store.List(mailboxID, now.Add(10*time.Second), 16)
	if err != nil || len(listedB) != len(listedA) {
		t.Fatalf("offline Relay B catch-up: %d %v", len(listedB), err)
	}
	for i := range listedA {
		if listedA[i].MessageID != listedB[i].MessageID || !bytes.Equal(listedA[i].Ciphertext, listedB[i].Ciphertext) {
			t.Fatal("Relays returned different opaque history")
		}
	}
	for _, retainedCommit := range listedA[1:] {
		states[2], err = driver.Apply(states[2], retainedCommit.Ciphertext)
		if err != nil {
			t.Fatal(err)
		}
	}

	future := []byte("offline member caught up across two MLS epochs")
	states[0], ciphertext, err = driver.Seal(states[0], aad, future)
	if err != nil {
		t.Fatal(err)
	}
	storeBoth(ciphertext)
	for i := 1; i < 3; i++ {
		var plaintext []byte
		states[i], plaintext, err = driver.Open(states[i], aad, ciphertext)
		if err != nil || !bytes.Equal(plaintext, future) {
			t.Fatalf("member %d future: %q %v", i, plaintext, err)
		}
	}
	for _, root := range roots {
		assertRelayExcludesSecrets(t, root, [][]byte{opening, future, states[0], states[1], states[2]})
	}
}

func relayMessageID(raw []byte) string {
	sum := sha256.Sum256(raw)
	return "msg_" + hex.EncodeToString(sum[:])
}

func digestBytes(raw []byte) string {
	return "sha256:" + strings.TrimPrefix(relayMessageID(raw), "msg_")
}

func assertRelayExcludesSecrets(t *testing.T, root string, secrets [][]byte) {
	t.Helper()
	err := filepath.WalkDir(root, func(path string, entry os.DirEntry, err error) error {
		if err != nil || entry.IsDir() {
			return err
		}
		raw, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		for _, secret := range secrets {
			if bytes.Contains(raw, secret) || bytes.Contains(raw, []byte(base64.StdEncoding.EncodeToString(secret))) {
				t.Fatalf("Relay file %s contained plaintext or an MLS private snapshot", path)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}
