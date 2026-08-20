package e2ee

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"os"
	"path/filepath"
	"testing"
)

var updateSuiteVectors = flag.Bool("update-suite-vectors", false, "rewrite the default suite interoperability vectors")

type suiteVectorFile struct {
	Schema              string                   `json:"schema"`
	AlgorithmID         string                   `json:"algorithm_id"`
	EntropyHex          string                   `json:"entropy_hex"`
	BindingHex          string                   `json:"binding_hex"`
	InitiatorPublicHex  string                   `json:"initiator_prekey_public_hex"`
	InitiatorPrivateHex string                   `json:"initiator_prekey_private_hex"`
	AcceptorPublicHex   string                   `json:"acceptor_prekey_public_hex"`
	AcceptorPrivateHex  string                   `json:"acceptor_prekey_private_hex"`
	InitialHex          string                   `json:"initial_message_hex"`
	Messages            []suiteVectorMessage     `json:"messages"`
	Adversarial         []suiteAdversarialVector `json:"adversarial"`
	ReplayTarget        int                      `json:"replay_target"`
}

type suiteVectorMessage struct {
	Direction     string `json:"direction"`
	PlaintextHex  string `json:"plaintext_hex"`
	CiphertextHex string `json:"ciphertext_hex"`
}

type suiteAdversarialVector struct {
	Name          string `json:"name"`
	CiphertextHex string `json:"ciphertext_hex"`
	Error         string `json:"error"`
}

func TestDefaultSuiteInteroperabilityVectors(t *testing.T) {
	want := buildSuiteVector(t)
	path := filepath.Join("testdata", "default-suite-vectors.json")
	if *updateSuiteVectors {
		encoded, err := json.MarshalIndent(want, "", "  ")
		if err != nil {
			t.Fatal(err)
		}
		encoded = append(encoded, '\n')
		if err := os.WriteFile(path, encoded, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var got suiteVectorFile
	if err := json.Unmarshal(raw, &got); err != nil {
		t.Fatal(err)
	}
	wantJSON, err := json.Marshal(want)
	if err != nil {
		t.Fatal(err)
	}
	gotJSON, err := json.Marshal(got)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(gotJSON, wantJSON) {
		t.Fatal("default suite vectors changed; inspect the wire-format change and regenerate with -update-suite-vectors")
	}
	consumeSuiteVector(t, got)
}

func buildSuiteVector(t *testing.T) suiteVectorFile {
	t.Helper()
	entropy := make([]byte, 32*7)
	for block := 0; block < 7; block++ {
		for index := 0; index < 32; index++ {
			entropy[block*32+index] = byte(block*32 + index + 1)
		}
	}
	binding := []byte("tos-messenger default suite interoperability vector")
	suite := &doubleRatchetSuite{random: bytes.NewReader(entropy)}
	initiatorPublic, initiatorPrivate, err := suite.NewPrekeyMaterial()
	if err != nil {
		t.Fatal(err)
	}
	acceptorPublic, acceptorPrivate, err := suite.NewPrekeyMaterial()
	if err != nil {
		t.Fatal(err)
	}
	initiator, initial, err := suite.Initiate(initiatorPrivate, acceptorPublic, binding)
	if err != nil {
		t.Fatal(err)
	}
	acceptor, err := suite.Accept(acceptorPrivate, initiatorPublic, initial, binding)
	if err != nil {
		t.Fatal(err)
	}

	messages := []suiteVectorMessage{}
	firstPlaintext := []byte("offline first contact")
	first, initiator, err := suite.Seal(initiator, firstPlaintext, binding)
	if err != nil {
		t.Fatal(err)
	}
	opened, acceptorAfterFirst, err := suite.Open(acceptor, first, binding)
	if err != nil || !bytes.Equal(opened, firstPlaintext) {
		t.Fatalf("open first vector: plaintext=%x err=%v", opened, err)
	}
	messages = append(messages, vectorMessage("initiator-to-acceptor", firstPlaintext, first))

	replyPlaintext := []byte("ratchet reply")
	reply, acceptor, err := suite.Seal(acceptorAfterFirst, replyPlaintext, binding)
	if err != nil {
		t.Fatal(err)
	}
	opened, initiator, err = suite.Open(initiator, reply, binding)
	if err != nil || !bytes.Equal(opened, replyPlaintext) {
		t.Fatalf("open reply vector: plaintext=%x err=%v", opened, err)
	}
	messages = append(messages, vectorMessage("acceptor-to-initiator", replyPlaintext, reply))

	recoveredPlaintext := []byte("post-ratchet forward")
	recovered, initiator, err := suite.Seal(initiator, recoveredPlaintext, binding)
	if err != nil {
		t.Fatal(err)
	}
	opened, acceptor, err = suite.Open(acceptor, recovered, binding)
	if err != nil || !bytes.Equal(opened, recoveredPlaintext) {
		t.Fatalf("open recovered vector: plaintext=%x err=%v", opened, err)
	}
	messages = append(messages, vectorMessage("initiator-to-acceptor", recoveredPlaintext, recovered))

	truncated := append([]byte(nil), first[:len(first)-1]...)
	badVersion := append([]byte(nil), first...)
	badVersion[0] = 0xff
	badTag := append([]byte(nil), first...)
	badTag[len(badTag)-1] ^= 1
	badGap := append([]byte(nil), first...)
	badGap[37], badGap[38], badGap[39], badGap[40] = 0, 0, 4, 1

	return suiteVectorFile{
		Schema:              "tos.messaging.e2ee-suite-vectors.v1",
		AlgorithmID:         DefaultCandidateAlgorithmID,
		EntropyHex:          hex.EncodeToString(entropy),
		BindingHex:          hex.EncodeToString(binding),
		InitiatorPublicHex:  hex.EncodeToString(initiatorPublic),
		InitiatorPrivateHex: hex.EncodeToString(initiatorPrivate),
		AcceptorPublicHex:   hex.EncodeToString(acceptorPublic),
		AcceptorPrivateHex:  hex.EncodeToString(acceptorPrivate),
		InitialHex:          hex.EncodeToString(initial),
		Messages:            messages,
		Adversarial: []suiteAdversarialVector{
			{Name: "truncated-aead", CiphertextHex: hex.EncodeToString(truncated), Error: "not-authentic"},
			{Name: "unknown-header-version", CiphertextHex: hex.EncodeToString(badVersion), Error: "not-authentic"},
			{Name: "altered-authentication-tag", CiphertextHex: hex.EncodeToString(badTag), Error: "not-authentic"},
			{Name: "skipped-key-gap-over-limit", CiphertextHex: hex.EncodeToString(badGap), Error: "skipped-key-bound"},
		},
		ReplayTarget: 0,
	}
}

func consumeSuiteVector(t *testing.T, vector suiteVectorFile) {
	t.Helper()
	entropy := decodeVectorHex(t, vector.EntropyHex)
	binding := decodeVectorHex(t, vector.BindingHex)
	suite := &doubleRatchetSuite{random: bytes.NewReader(entropy)}
	initiatorPublic, initiatorPrivate, err := suite.NewPrekeyMaterial()
	if err != nil {
		t.Fatal(err)
	}
	acceptorPublic, acceptorPrivate, err := suite.NewPrekeyMaterial()
	if err != nil {
		t.Fatal(err)
	}
	if hex.EncodeToString(initiatorPublic) != vector.InitiatorPublicHex ||
		hex.EncodeToString(initiatorPrivate) != vector.InitiatorPrivateHex ||
		hex.EncodeToString(acceptorPublic) != vector.AcceptorPublicHex ||
		hex.EncodeToString(acceptorPrivate) != vector.AcceptorPrivateHex {
		t.Fatal("prekey materials do not match the committed vector")
	}
	initiator, initial, err := suite.Initiate(initiatorPrivate, acceptorPublic, binding)
	if err != nil {
		t.Fatal(err)
	}
	if hex.EncodeToString(initial) != vector.InitialHex {
		t.Fatal("initial message does not match the committed vector")
	}
	acceptor, err := suite.Accept(acceptorPrivate, initiatorPublic, initial, binding)
	if err != nil {
		t.Fatal(err)
	}
	acceptorBeforeFirst := append(State(nil), acceptor...)
	var acceptorAfterFirst State
	for index, message := range vector.Messages {
		plaintext := decodeVectorHex(t, message.PlaintextHex)
		wantCiphertext := message.CiphertextHex
		switch message.Direction {
		case "initiator-to-acceptor":
			ciphertext, next, err := suite.Seal(initiator, plaintext, binding)
			if err != nil {
				t.Fatal(err)
			}
			if hex.EncodeToString(ciphertext) != wantCiphertext {
				t.Fatalf("message %d ciphertext does not match", index)
			}
			initiator = next
			opened, next, err := suite.Open(acceptor, ciphertext, binding)
			if err != nil || !bytes.Equal(opened, plaintext) {
				t.Fatalf("message %d open: plaintext=%x err=%v", index, opened, err)
			}
			acceptor = next
			if index == 0 {
				acceptorAfterFirst = append(State(nil), acceptor...)
			}
		case "acceptor-to-initiator":
			ciphertext, next, err := suite.Seal(acceptor, plaintext, binding)
			if err != nil {
				t.Fatal(err)
			}
			if hex.EncodeToString(ciphertext) != wantCiphertext {
				t.Fatalf("message %d ciphertext does not match", index)
			}
			acceptor = next
			opened, next, err := suite.Open(initiator, ciphertext, binding)
			if err != nil || !bytes.Equal(opened, plaintext) {
				t.Fatalf("message %d open: plaintext=%x err=%v", index, opened, err)
			}
			initiator = next
		default:
			t.Fatalf("message %d has unknown direction %q", index, message.Direction)
		}
	}
	for _, adversarial := range vector.Adversarial {
		ciphertext := decodeVectorHex(t, adversarial.CiphertextHex)
		_, _, err := suite.Open(acceptorBeforeFirst, ciphertext, binding)
		switch adversarial.Error {
		case "not-authentic":
			if !errors.Is(err, ErrNotAuthentic) {
				t.Fatalf("%s: got %v, want ErrNotAuthentic", adversarial.Name, err)
			}
		case "skipped-key-bound":
			if err == nil || err.Error() != "message is beyond the skipped-key bound" {
				t.Fatalf("%s: got %v, want skipped-key bound", adversarial.Name, err)
			}
		default:
			t.Fatalf("%s has unknown expected error %q", adversarial.Name, adversarial.Error)
		}
	}
	replay := decodeVectorHex(t, vector.Messages[vector.ReplayTarget].CiphertextHex)
	if _, _, err := suite.Open(acceptorAfterFirst, replay, binding); !errors.Is(err, ErrReplayed) {
		t.Fatalf("replay vector: got %v, want ErrReplayed", err)
	}
}

func vectorMessage(direction string, plaintext, ciphertext []byte) suiteVectorMessage {
	return suiteVectorMessage{
		Direction:     direction,
		PlaintextHex:  hex.EncodeToString(plaintext),
		CiphertextHex: hex.EncodeToString(ciphertext),
	}
}

func decodeVectorHex(t *testing.T, value string) []byte {
	t.Helper()
	decoded, err := hex.DecodeString(value)
	if err != nil {
		t.Fatal(err)
	}
	return decoded
}
