package main

import (
	"bytes"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/tosnetwork/tos-messenger/pkg/localapi"
)

func TestOfflineSignProducesBoundDecision(t *testing.T) {
	key := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{7}, ed25519.SeedSize))
	request := localapi.Request{
		Schema: localapi.RequestSchema, Op: localapi.OpGrantAction,
		ActionID: "act_" + strings.Repeat("a", 64), Challenge: strings.Repeat("b", 64),
	}
	preimage, err := localapi.DecisionBytes(request, request.Challenge)
	if err != nil {
		t.Fatal(err)
	}
	envelope := decisionEnvelope{Schema: decisionSchema, Request: request, SigningBytesHex: hex.EncodeToString(preimage)}
	directory := t.TempDir()
	decisionPath := filepath.Join(directory, "decision.json")
	keyPath := filepath.Join(directory, "owner.key")
	raw, _ := json.Marshal(envelope)
	if err := os.WriteFile(decisionPath, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyPath, []byte(hex.EncodeToString(key)+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	var output bytes.Buffer
	if err := run([]string{"sign", "-key", keyPath, "-decision", decisionPath}, &output); err != nil {
		t.Fatal(err)
	}
	var signed decisionEnvelope
	if err := json.Unmarshal(output.Bytes(), &signed); err != nil {
		t.Fatal(err)
	}
	signature, err := hex.DecodeString(signed.Request.OwnerSignature)
	if err != nil || !ed25519.Verify(key.Public().(ed25519.PublicKey), preimage, signature) {
		t.Fatal("offline signature does not authorize the exact decision")
	}
}

func TestOfflineSignRejectsLooseKeyAndTamperedDecision(t *testing.T) {
	directory := t.TempDir()
	key := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{9}, ed25519.SeedSize))
	keyPath := filepath.Join(directory, "owner.key")
	if err := os.WriteFile(keyPath, []byte(hex.EncodeToString(key)), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := readPrivateKey(keyPath); err == nil {
		t.Fatal("world-readable owner key accepted")
	}
	envelope := decisionEnvelope{
		Schema:          decisionSchema,
		Request:         localapi.Request{Op: localapi.OpDenyAction, ActionID: "act_" + strings.Repeat("c", 64), Challenge: strings.Repeat("d", 64), Reason: "no"},
		SigningBytesHex: "00",
	}
	if err := validateEnvelope(envelope, false); err == nil {
		t.Fatal("tampered signing preimage accepted")
	}
}
