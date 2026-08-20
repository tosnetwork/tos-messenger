package signerapi

import (
	"bufio"
	"bytes"
	"crypto"
	"crypto/ed25519"
	"encoding/json"
	"net"
	"path/filepath"
	"testing"
	"time"

	"github.com/tosnetwork/tos-messenger/internal/localwire"
)

func serveSignerOnce(t *testing.T, key ed25519.PrivateKey, mutate func(*response)) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "endpoint-signer.sock")
	listener, err := net.Listen("unix", path)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	go func() {
		defer listener.Close()
		connection, err := listener.Accept()
		if err != nil {
			return
		}
		defer connection.Close()
		raw, err := localwire.ReadFrame(bufio.NewReader(connection), MaxFrameBytes)
		if err != nil {
			return
		}
		var value request
		if json.Unmarshal(raw, &value) != nil || value.Schema != RequestSchema {
			return
		}
		answer := response{Schema: ResponseSchema, OK: true, Signature: ed25519.Sign(key, value.Message)}
		if mutate != nil {
			mutate(&answer)
		}
		encoded, _ := json.Marshal(answer)
		_ = localwire.WriteFrame(connection, encoded, MaxFrameBytes)
	}()
	return path
}

func TestClientVerifiesRemoteEndpointSignature(t *testing.T) {
	key := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x61}, ed25519.SeedSize))
	path := serveSignerOnce(t, key, nil)
	client, err := NewClient(path, key.Public().(ed25519.PublicKey), time.Second)
	if err != nil {
		t.Fatalf("client: %v", err)
	}
	message := []byte("domain-separated Endpoint signing preimage")
	signature, err := client.Sign(nil, message, crypto.Hash(0))
	if err != nil || !ed25519.Verify(key.Public().(ed25519.PublicKey), message, signature) {
		t.Fatalf("signature: bytes=%d err=%v", len(signature), err)
	}
	signature[0] ^= 0xff
	secondPublic := client.Public().(ed25519.PublicKey)
	secondPublic[0] ^= 0xff
	if !bytes.Equal(client.Public().(ed25519.PublicKey), key.Public().(ed25519.PublicKey)) {
		t.Fatal("Public returned aliased key bytes")
	}
}

func TestClientRefusesCorruptOrWrongPurposeSignerOutput(t *testing.T) {
	key := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x62}, ed25519.SeedSize))
	path := serveSignerOnce(t, key, func(answer *response) { answer.Signature[0] ^= 0xff })
	client, err := NewClient(path, key.Public().(ed25519.PublicKey), time.Second)
	if err != nil {
		t.Fatalf("client: %v", err)
	}
	if _, err := client.Sign(nil, []byte("message"), crypto.Hash(0)); err == nil {
		t.Fatal("corrupt remote signature was accepted")
	}
	if _, err := client.Sign(nil, []byte("message"), crypto.SHA256); err == nil {
		t.Fatal("pre-hashed signing request was accepted")
	}
}

func TestClientConfigurationAndResponseAreStrict(t *testing.T) {
	key := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x63}, ed25519.SeedSize))
	if _, err := NewClient("relative.sock", key.Public().(ed25519.PublicKey), time.Second); err == nil {
		t.Fatal("relative signer socket was accepted")
	}
	valid, _ := json.Marshal(response{Schema: ResponseSchema, OK: true, Signature: make([]byte, ed25519.SignatureSize)})
	cases := [][]byte{
		append(append([]byte(nil), valid...), []byte("{}")...),
		bytes.Replace(valid, []byte(ResponseSchema), []byte("tos.messaging.endpoint-sign-response.v2"), 1),
		[]byte(`{"schema":"tos.messaging.endpoint-sign-response.v1","ok":true,"signature_base64":"","unknown":1}`),
	}
	for index, raw := range cases {
		if _, err := decodeResponse(raw); err == nil {
			t.Fatalf("invalid response %d was accepted", index)
		}
	}
}
