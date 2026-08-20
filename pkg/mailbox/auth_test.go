package mailbox

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/tosnetwork/tos-messenger/internal/canon"
)

type fixedEndpointAuthority struct {
	key ed25519.PublicKey
	err error
}

func (a fixedEndpointAuthority) ResolveMailboxEndpoint(context.Context, CapabilityGrant, time.Time) (ed25519.PublicKey, error) {
	return append(ed25519.PublicKey(nil), a.key...), a.err
}

func mailboxEndpointKey() ed25519.PrivateKey {
	return ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x41}, ed25519.SeedSize))
}

func mailboxCapabilityKey() ed25519.PrivateKey {
	return ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x42}, ed25519.SeedSize))
}

func signedMailboxGrant(t *testing.T, operations []Operation) CapabilityGrant {
	t.Helper()
	grant, err := SignGrant(CapabilityGrant{
		NetworkID:              "tos-local",
		GenesisRootHash:        strings.Repeat("a", 64),
		GenesisFileHash:        strings.Repeat("b", 64),
		AgentID:                "agent_" + strings.Repeat("1", 64),
		EndpointID:             "mep_" + strings.Repeat("2", 64),
		RelayPublicKeyHex:      hex.EncodeToString(relayKey().Public().(ed25519.PublicKey)),
		MailboxID:              "mbx_" + strings.Repeat("a", 64),
		CapabilityPublicKeyHex: hex.EncodeToString(mailboxCapabilityKey().Public().(ed25519.PublicKey)),
		Operations:             operations,
		IssuedAtUnix:           uint64(mailboxNow - 60),
		ExpiresAtUnix:          uint64(mailboxNow + 3600),
	}, mailboxEndpointKey())
	if err != nil {
		t.Fatal(err)
	}
	return grant
}

func signedMailboxRequest(t *testing.T, grant CapabilityGrant, operation Operation, bodyDigest string, nonce byte) AccessRequest {
	t.Helper()
	digest, err := GrantDigest(grant)
	if err != nil {
		t.Fatal(err)
	}
	request, err := SignAccessRequest(AccessRequest{
		GrantDigest:   digest,
		Operation:     operation,
		MailboxID:     grant.MailboxID,
		BodyDigest:    bodyDigest,
		NonceHex:      strings.Repeat(hex.EncodeToString([]byte{nonce}), 32),
		IssuedAtUnix:  uint64(mailboxNow - 1),
		ExpiresAtUnix: uint64(mailboxNow + 60),
	}, mailboxCapabilityKey())
	if err != nil {
		t.Fatal(err)
	}
	return request
}

func authenticatedStore(t *testing.T, root string) (*Store, *AuthenticatedStore) {
	t.Helper()
	store, err := Open(root, DefaultQuota(), relayKey())
	if err != nil {
		t.Fatal(err)
	}
	authenticated, err := NewAuthenticatedStore(store, fixedEndpointAuthority{key: mailboxEndpointKey().Public().(ed25519.PublicKey)})
	if err != nil {
		_ = store.Close()
		t.Fatal(err)
	}
	return store, authenticated
}

func TestAuthenticatedStoreSeparatesOperationsAndPersistsReplayClaims(t *testing.T) {
	root := filepath.Join(t.TempDir(), "store")
	store, authenticated := authenticatedStore(t, root)
	now := time.Unix(mailboxNow, 0)
	grant := signedMailboxGrant(t, []Operation{OperationDelete, OperationDeposit, OperationRead})
	value := relayEnvelope('8')
	depositDigest, err := DepositBodyDigest(value)
	if err != nil {
		t.Fatal(err)
	}
	deposit := signedMailboxRequest(t, grant, OperationDeposit, depositDigest, 1)
	if fresh, _, err := authenticated.Put(context.Background(), grant, deposit, value, now); err != nil || !fresh {
		t.Fatalf("deposit fresh=%v err=%v", fresh, err)
	}
	if _, _, err := authenticated.Put(context.Background(), grant, deposit, value, now); !errors.Is(err, ErrAccessReplay) {
		t.Fatalf("same-process replay=%v", err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	store, authenticated = authenticatedStore(t, root)
	defer store.Close()
	if _, _, err := authenticated.Put(context.Background(), grant, deposit, value, now); !errors.Is(err, ErrAccessReplay) {
		t.Fatalf("restart replay=%v", err)
	}

	readDigest, err := ReadBodyDigest(grant.MailboxID, 10)
	if err != nil {
		t.Fatal(err)
	}
	read := signedMailboxRequest(t, grant, OperationRead, readDigest, 2)
	listed, err := authenticated.List(context.Background(), grant, read, now, 10)
	if err != nil || len(listed) != 1 || !bytes.Equal(listed[0].Ciphertext, value.Ciphertext) {
		t.Fatalf("list=%v err=%v", listed, err)
	}

	ciphertextDigest := canon.Digest(value.Ciphertext)
	deleteDigest, err := DeleteBodyDigest(grant.MailboxID, value.MessageID, ciphertextDigest)
	if err != nil {
		t.Fatal(err)
	}
	deletion := signedMailboxRequest(t, grant, OperationDelete, deleteDigest, 3)
	if deleted, err := authenticated.Delete(context.Background(), grant, deletion, value.MessageID, ciphertextDigest, now); err != nil || !deleted {
		t.Fatalf("delete=%v err=%v", deleted, err)
	}
}

func TestAuthenticatedStoreRefusesPermissionBodyRelayAndAuthoritySubstitution(t *testing.T) {
	store := openStore(t, DefaultQuota())
	now := time.Unix(mailboxNow, 0)
	value := relayEnvelope('9')
	body, err := DepositBodyDigest(value)
	if err != nil {
		t.Fatal(err)
	}
	readOnly := signedMailboxGrant(t, []Operation{OperationRead})
	request := signedMailboxRequest(t, readOnly, OperationDeposit, body, 4)
	authenticated, err := NewAuthenticatedStore(store, fixedEndpointAuthority{key: mailboxEndpointKey().Public().(ed25519.PublicKey)})
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := authenticated.Put(context.Background(), readOnly, request, value, now); err == nil {
		t.Fatal("read-only grant deposited ciphertext")
	}

	all := signedMailboxGrant(t, []Operation{OperationDelete, OperationDeposit, OperationRead})
	request = signedMailboxRequest(t, all, OperationDeposit, body, 5)
	other := value
	other.Ciphertext = append([]byte(nil), value.Ciphertext...)
	other.Ciphertext[0] ^= 0xff
	if _, _, err := authenticated.Put(context.Background(), all, request, other, now); err == nil {
		t.Fatal("request authorized substituted ciphertext")
	}

	other = value
	other.AdmissionToken = "invite_BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB"
	if _, _, err := authenticated.Put(context.Background(), all, request, other, now); err == nil {
		t.Fatal("request authorized a substituted admission token")
	}

	wrongRelay := all
	wrongRelay.RelayPublicKeyHex = hex.EncodeToString(mailboxCapabilityKey().Public().(ed25519.PublicKey))
	wrongRelay, err = SignGrant(wrongRelay, mailboxEndpointKey())
	if err != nil {
		t.Fatal(err)
	}
	wrongRequest := signedMailboxRequest(t, wrongRelay, OperationDeposit, body, 6)
	if _, _, err := authenticated.Put(context.Background(), wrongRelay, wrongRequest, value, now); err == nil {
		t.Fatal("grant for another Relay was accepted")
	}

	wrongAuthority, err := NewAuthenticatedStore(store, fixedEndpointAuthority{key: mailboxCapabilityKey().Public().(ed25519.PublicKey)})
	if err != nil {
		t.Fatal(err)
	}
	request = signedMailboxRequest(t, all, OperationDeposit, body, 7)
	if _, _, err := wrongAuthority.Put(context.Background(), all, request, value, now); err == nil {
		t.Fatal("grant under an unfinalized Endpoint key was accepted")
	}
}

func TestMailboxAuthenticationStrictWireAndCanonicalNetworkHashes(t *testing.T) {
	grant := signedMailboxGrant(t, []Operation{OperationDelete, OperationDeposit, OperationRead})
	raw, err := EncodeGrantJSON(grant)
	if err != nil {
		t.Fatal(err)
	}
	if decoded, err := DecodeGrantJSON(raw); err != nil || decoded.MailboxID != grant.MailboxID {
		t.Fatalf("grant decoded=%+v err=%v", decoded, err)
	}
	unknown := append(append([]byte{}, raw[:len(raw)-1]...), []byte(`,"extra":true}`)...)
	if _, err := DecodeGrantJSON(unknown); err == nil {
		t.Fatal("unknown grant field accepted")
	}
	prefixed := grant
	prefixed.GenesisRootHash = "sha256:" + prefixed.GenesisRootHash
	if _, err := GrantCanonicalBytes(prefixed); err == nil {
		t.Fatal("SDK-prefixed genesis hash entered a canonical grant")
	}

	body, err := ReadBodyDigest(grant.MailboxID, 10)
	if err != nil {
		t.Fatal(err)
	}
	request := signedMailboxRequest(t, grant, OperationRead, body, 8)
	requestRaw, err := EncodeAccessRequestJSON(request)
	if err != nil {
		t.Fatal(err)
	}
	if decoded, err := DecodeAccessRequestJSON(requestRaw); err != nil || decoded.NonceHex != request.NonceHex {
		t.Fatalf("request decoded=%+v err=%v", decoded, err)
	}
	if _, err := DecodeAccessRequestJSON(append(requestRaw, requestRaw...)); err == nil {
		t.Fatal("trailing request JSON accepted")
	}
}

func TestMailboxAccessValidityAndDamagedClaimFailClosed(t *testing.T) {
	root := filepath.Join(t.TempDir(), "store")
	store, authenticated := authenticatedStore(t, root)
	defer store.Close()
	grant := signedMailboxGrant(t, []Operation{OperationDeposit})
	value := relayEnvelope('a')
	body, err := DepositBodyDigest(value)
	if err != nil {
		t.Fatal(err)
	}
	request := signedMailboxRequest(t, grant, OperationDeposit, body, 9)
	if _, _, err := authenticated.Put(context.Background(), grant, request, value, time.Unix(mailboxNow+61, 0)); err == nil {
		t.Fatal("expired request was accepted")
	}
	if err := os.WriteFile(filepath.Join(root, accessClaimsDir, "damage.json"), []byte("{"), 0o600); err != nil {
		t.Fatal(err)
	}
	request = signedMailboxRequest(t, grant, OperationDeposit, body, 10)
	if _, _, err := authenticated.Put(context.Background(), grant, request, value, time.Unix(mailboxNow, 0)); err == nil {
		t.Fatal("damaged replay state failed open")
	}
}
