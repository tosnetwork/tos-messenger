package mailboxapi

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/tosnetwork/tos-messenger/internal/canon"
	"github.com/tosnetwork/tos-messenger/pkg/envelope"
	"github.com/tosnetwork/tos-messenger/pkg/mailbox"
)

type fixedAuthority struct{ key ed25519.PublicKey }

func (a fixedAuthority) ResolveMailboxEndpoint(context.Context, mailbox.CapabilityGrant, time.Time) (ed25519.PublicKey, error) {
	return a.key, nil
}

type serviceFixture struct {
	now           time.Time
	relayKey      ed25519.PrivateKey
	endpointKey   ed25519.PrivateKey
	capabilityKey ed25519.PrivateKey
	grant         mailbox.CapabilityGrant
	value         envelope.RelayEnvelope
}

func newServiceFixture(t *testing.T) serviceFixture {
	t.Helper()
	now := time.Unix(1_800_000_000, 0)
	relayKey := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x31}, ed25519.SeedSize))
	endpointKey := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x32}, ed25519.SeedSize))
	capabilityKey := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x33}, ed25519.SeedSize))
	grant, err := mailbox.SignGrant(mailbox.CapabilityGrant{
		NetworkID: "tos-local", GenesisRootHash: strings.Repeat("a", 64), GenesisFileHash: strings.Repeat("b", 64),
		AgentID: "agent_" + strings.Repeat("c", 64), EndpointID: "mep_" + strings.Repeat("d", 64),
		RelayPublicKeyHex: hex.EncodeToString(relayKey.Public().(ed25519.PublicKey)), MailboxID: "mbx_" + strings.Repeat("e", 64),
		CapabilityPublicKeyHex: hex.EncodeToString(capabilityKey.Public().(ed25519.PublicKey)),
		Operations:             []mailbox.Operation{mailbox.OperationDelete, mailbox.OperationDeposit, mailbox.OperationRead},
		IssuedAtUnix:           uint64(now.Unix() - 10), ExpiresAtUnix: uint64(now.Unix() + 3600),
	}, endpointKey)
	if err != nil {
		t.Fatal(err)
	}
	value := envelope.RelayEnvelope{OpaqueMailboxID: grant.MailboxID, MessageID: "msg_" + strings.Repeat("f", 64),
		Ciphertext: bytes.Repeat([]byte{0x42}, 64), ExpiresAtUnix: uint64(now.Unix() + 600)}
	return serviceFixture{now: now, relayKey: relayKey, endpointKey: endpointKey, capabilityKey: capabilityKey, grant: grant, value: value}
}

func (f serviceFixture) request(t *testing.T, op Operation, nonce byte, limit int) Request {
	t.Helper()
	var digest string
	switch op {
	case OpDeposit:
		digest, _ = mailbox.DepositBodyDigest(f.value)
	case OpRead:
		digest, _ = mailbox.ReadBodyDigest(f.grant.MailboxID, limit)
	case OpDelete:
		digest, _ = mailbox.DeleteBodyDigest(f.grant.MailboxID, f.value.MessageID, canon.Digest(f.value.Ciphertext))
	}
	access, err := mailbox.SignAccessRequest(mailbox.AccessRequest{GrantDigest: mustGrantDigest(t, f.grant), Operation: mailbox.Operation(op),
		MailboxID: f.grant.MailboxID, BodyDigest: digest, NonceHex: hex.EncodeToString(bytes.Repeat([]byte{nonce}, 32)),
		IssuedAtUnix: uint64(f.now.Unix() - 1), ExpiresAtUnix: uint64(f.now.Unix() + 30)}, f.capabilityKey)
	if err != nil {
		t.Fatal(err)
	}
	grantRaw, _ := mailbox.EncodeGrantJSON(f.grant)
	accessRaw, _ := mailbox.EncodeAccessRequestJSON(access)
	request := Request{Op: op, Grant: grantRaw, Access: accessRaw, Limit: limit}
	if op == OpDeposit {
		request.Envelope, _ = envelope.EncodeRelayJSON(f.value)
	}
	if op == OpDelete {
		request.MessageID = f.value.MessageID
		request.CiphertextDigest = canon.Digest(f.value.Ciphertext)
	}
	return request
}

func mustGrantDigest(t *testing.T, grant mailbox.CapabilityGrant) string {
	t.Helper()
	digest, err := mailbox.GrantDigest(grant)
	if err != nil {
		t.Fatal(err)
	}
	return digest
}

func TestUnixServiceDepositReadDeleteAndRestartReplayRefusal(t *testing.T) {
	f := newServiceFixture(t)
	root := t.TempDir() + "/relay"
	socketDir := t.TempDir() + "/private"
	if err := os.Mkdir(socketDir, 0o700); err != nil {
		t.Fatal(err)
	}
	socket := socketDir + "/mailbox.sock"
	store, err := mailbox.Open(root, mailbox.DefaultQuota(), f.relayKey)
	if err != nil {
		t.Fatal(err)
	}
	authenticated, err := mailbox.NewAuthenticatedStore(store, fixedAuthority{f.endpointKey.Public().(ed25519.PublicKey)})
	if err != nil {
		t.Fatal(err)
	}
	server, err := NewServer(authenticated, func() time.Time { return f.now }, 0)
	if err != nil {
		t.Fatal(err)
	}
	listener, err := ListenUnix(socket)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- server.Serve(ctx, listener) }()
	client, err := NewUnixClient(socket, 0)
	if err != nil {
		t.Fatal(err)
	}
	deposit := f.request(t, OpDeposit, 1, 0)
	response, err := client.Call(context.Background(), deposit)
	if err != nil || !response.Fresh {
		t.Fatalf("deposit: fresh=%v err=%v", response.Fresh, err)
	}
	ack, err := mailbox.DecodeAckJSON(response.Ack)
	if err != nil || ack.MessageID != f.value.MessageID {
		t.Fatalf("ack: %+v %v", ack, err)
	}
	read := f.request(t, OpRead, 2, 8)
	response, err = client.Call(context.Background(), read)
	if err != nil || response.Envelopes == nil || len(*response.Envelopes) != 1 {
		t.Fatalf("read: %+v %v", response, err)
	}
	cancel()
	<-done
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}

	store, err = mailbox.Open(root, mailbox.DefaultQuota(), f.relayKey)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	authenticated, _ = mailbox.NewAuthenticatedStore(store, fixedAuthority{f.endpointKey.Public().(ed25519.PublicKey)})
	server, _ = NewServer(authenticated, func() time.Time { return f.now }, 0)
	listener, err = ListenUnix(socket)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel = context.WithCancel(context.Background())
	defer cancel()
	go server.Serve(ctx, listener)
	if replay, err := client.Call(context.Background(), read); err == nil || replay.Code != CodeDenied {
		t.Fatalf("replay: %+v %v", replay, err)
	}
	response, err = client.Call(context.Background(), f.request(t, OpRead, 3, 8))
	if err != nil || response.Envelopes == nil || len(*response.Envelopes) != 1 {
		t.Fatalf("read after restart: %+v %v", response, err)
	}
	deleted, err := client.Call(context.Background(), f.request(t, OpDelete, 4, 0))
	if err != nil || deleted.Deleted == nil || !*deleted.Deleted {
		t.Fatalf("delete: %+v %v", deleted, err)
	}
}

func TestServiceStrictBoundsAndDamagedResponse(t *testing.T) {
	f := newServiceFixture(t)
	request := f.request(t, OpRead, 5, 8)
	framed, err := EncodeRequest(request)
	if err != nil || len(framed) == 0 {
		t.Fatal(err)
	}
	request.Limit = MaxServiceListResults + 1
	if _, err := EncodeRequest(request); err == nil {
		t.Fatal("oversized amplification request accepted")
	}
	valid := f.request(t, OpRead, 6, 8)
	raw, _ := json.Marshal(valid)
	var object map[string]any
	_ = json.Unmarshal(raw, &object)
	object["unexpected"] = true
	unknown, _ := json.Marshal(object)
	if _, err := DecodeRequest(unknown); err == nil {
		t.Fatal("unknown request field accepted")
	}
	bad := Response{Schema: ResponseSchema, OK: true, Ack: json.RawMessage(`{"schema":"tos.messaging.stored-ack.v1"}`)}
	raw, _ = json.Marshal(bad)
	if _, err := DecodeResponse(raw); err == nil {
		t.Fatal("damaged StoredAck accepted")
	}
	if _, err := DecodeRequest(bytes.Repeat([]byte("x"), int(MaxRequestBytes)+1)); err == nil {
		t.Fatal("oversized request accepted")
	}
}

func TestDepositClientsMeetThresholdAndSurviveOneRelayFailure(t *testing.T) {
	f := newServiceFixture(t)
	f2 := f
	f2.relayKey = ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x41}, ed25519.SeedSize))
	f2.grant.RelayPublicKeyHex = hex.EncodeToString(f2.relayKey.Public().(ed25519.PublicKey))
	f2.grant.EndpointSignatureHex = ""
	var err error
	f2.grant, err = mailbox.SignGrant(f2.grant, f.endpointKey)
	if err != nil {
		t.Fatal(err)
	}

	start := func(t *testing.T, fixture serviceFixture, name string) (*Client, context.CancelFunc, <-chan error, *mailbox.Store) {
		t.Helper()
		root := t.TempDir() + "/" + name
		socketDir := t.TempDir() + "/private"
		if err := os.Mkdir(socketDir, 0o700); err != nil {
			t.Fatal(err)
		}
		store, err := mailbox.Open(root, mailbox.DefaultQuota(), fixture.relayKey)
		if err != nil {
			t.Fatal(err)
		}
		authenticated, err := mailbox.NewAuthenticatedStore(store, fixedAuthority{f.endpointKey.Public().(ed25519.PublicKey)})
		if err != nil {
			t.Fatal(err)
		}
		server, err := NewServer(authenticated, func() time.Time { return f.now }, 0)
		if err != nil {
			t.Fatal(err)
		}
		listener, err := ListenUnix(socketDir + "/mailbox.sock")
		if err != nil {
			t.Fatal(err)
		}
		ctx, cancel := context.WithCancel(context.Background())
		done := make(chan error, 1)
		go func() { done <- server.Serve(ctx, listener) }()
		client, err := NewUnixClient(socketDir+"/mailbox.sock", time.Second)
		if err != nil {
			t.Fatal(err)
		}
		return client, cancel, done, store
	}

	client1, cancel1, done1, store1 := start(t, f, "relay1")
	client2, cancel2, done2, store2 := start(t, f2, "relay2")
	defer func() { cancel2(); <-done2; _ = store2.Close() }()
	deposit1, err := NewDepositClient(client1, f.grant, f.capabilityKey, func() time.Time { return f.now })
	if err != nil {
		t.Fatal(err)
	}
	deposit2, err := NewDepositClient(client2, f2.grant, f.capabilityKey, func() time.Time { return f.now })
	if err != nil {
		t.Fatal(err)
	}
	clients := []mailbox.RelayClient{deposit1, deposit2}
	result, err := mailbox.StoreRedundant(context.Background(), clients, f.value, 2)
	if err != nil || result.StoredCopies() != 2 {
		t.Fatalf("2-of-2: copies=%d err=%v", result.StoredCopies(), err)
	}

	cancel1()
	<-done1
	if err := store1.Close(); err != nil {
		t.Fatal(err)
	}
	next := f.value
	next.MessageID = "msg_" + strings.Repeat("7", 64)
	result, err = mailbox.StoreRedundant(context.Background(), clients, next, 1)
	if err != nil || result.StoredCopies() != 1 {
		t.Fatalf("one-Relay failover: copies=%d err=%v", result.StoredCopies(), err)
	}
	if result, err = mailbox.StoreRedundant(context.Background(), clients, next, 2); err == nil || result.StoredCopies() != 1 {
		t.Fatalf("unmet 2-of-2 was not reported: copies=%d err=%v", result.StoredCopies(), err)
	}
}
