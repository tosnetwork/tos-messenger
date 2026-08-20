package e2ee

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/hkdf"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"strings"
	"testing"
)

func TestCandidateRejectsMalformedInputsWithoutStateAdvance(t *testing.T) {
	suite := &doubleRatchetSuite{random: bytes.NewReader(bytes.Repeat([]byte{0x42}, 32*8))}
	localPublic, localPrivate, err := suite.NewPrekeyMaterial()
	if err != nil {
		t.Fatal(err)
	}
	peerPublic, peerPrivate, err := suite.NewPrekeyMaterial()
	if err != nil {
		t.Fatal(err)
	}
	binding := []byte("fixed associated data")
	sender, initial, err := suite.Initiate(localPrivate, peerPublic, binding)
	if err != nil {
		t.Fatal(err)
	}
	receiver, err := suite.Accept(peerPrivate, localPublic, initial, binding)
	if err != nil {
		t.Fatal(err)
	}
	ciphertext, senderNext, err := suite.Seal(sender, []byte("message"), binding)
	if err != nil {
		t.Fatal(err)
	}

	for name, altered := range map[string][]byte{
		"truncated":     ciphertext[:len(ciphertext)-1],
		"wrong version": append([]byte{0xff}, ciphertext[1:]...),
		"wrong binding": ciphertext,
	} {
		t.Run(name, func(t *testing.T) {
			openBinding := binding
			if name == "wrong binding" {
				openBinding = []byte("another binding")
			}
			if _, _, err := suite.Open(receiver, altered, openBinding); !errors.Is(err, ErrNotAuthentic) {
				t.Fatalf("got %v, want ErrNotAuthentic", err)
			}
		})
	}
	plaintext, receiverNext, err := suite.Open(receiver, ciphertext, binding)
	if err != nil || string(plaintext) != "message" {
		t.Fatalf("valid open after refusals: plaintext=%q err=%v", plaintext, err)
	}
	if _, _, err := suite.Open(receiverNext, ciphertext, binding); !errors.Is(err, ErrReplayed) {
		t.Fatalf("replay after persisted transition: %v", err)
	}
	if bytes.Equal(sender, senderNext) {
		t.Fatal("seal did not advance sender state")
	}
}

func TestCandidateRefusesExcessiveSkippedKeyGap(t *testing.T) {
	suite := &doubleRatchetSuite{random: bytes.NewReader(bytes.Repeat([]byte{0x24}, 32*8))}
	localPublic, localPrivate, err := suite.NewPrekeyMaterial()
	if err != nil {
		t.Fatal(err)
	}
	peerPublic, peerPrivate, err := suite.NewPrekeyMaterial()
	if err != nil {
		t.Fatal(err)
	}
	binding := []byte("binding")
	sender, initial, err := suite.Initiate(localPrivate, peerPublic, binding)
	if err != nil {
		t.Fatal(err)
	}
	receiver, err := suite.Accept(peerPrivate, localPublic, initial, binding)
	if err != nil {
		t.Fatal(err)
	}
	ciphertext, _, err := suite.Seal(sender, nil, binding)
	if err != nil {
		t.Fatal(err)
	}
	binaryHeader := append([]byte(nil), ciphertext...)
	binaryHeader[37], binaryHeader[38], binaryHeader[39], binaryHeader[40] = 0, 0, 4, 1
	if _, _, err := suite.Open(receiver, binaryHeader, binding); err == nil || !strings.Contains(err.Error(), "skipped-key bound") {
		t.Fatalf("excessive gap was not refused distinctly: %v", err)
	}
}

// These published known-answer vectors cross-check the three primitive
// implementations beneath the suite. They are independent of this protocol's
// own generated vectors: X25519 and HKDF come from their RFCs, and AES-GCM
// comes from NIST's zero-length plaintext example.
func TestCandidatePrimitiveKnownAnswers(t *testing.T) {
	t.Run("X25519 RFC 7748", func(t *testing.T) {
		privateBytes := mustHex(t, "77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a")
		peerBytes := mustHex(t, "de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f")
		private, err := ecdh.X25519().NewPrivateKey(privateBytes)
		if err != nil {
			t.Fatal(err)
		}
		peer, err := ecdh.X25519().NewPublicKey(peerBytes)
		if err != nil {
			t.Fatal(err)
		}
		shared, err := private.ECDH(peer)
		if err != nil {
			t.Fatal(err)
		}
		want := "4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742"
		if hex.EncodeToString(shared) != want {
			t.Fatalf("shared secret = %x, want %s", shared, want)
		}
	})
	t.Run("HKDF RFC 5869 case 1", func(t *testing.T) {
		ikm := bytes.Repeat([]byte{0x0b}, 22)
		salt := mustHex(t, "000102030405060708090a0b0c")
		info := mustHex(t, "f0f1f2f3f4f5f6f7f8f9")
		key, err := hkdf.Key(sha256.New, ikm, salt, string(info), 42)
		if err != nil {
			t.Fatal(err)
		}
		want := "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865"
		if hex.EncodeToString(key) != want {
			t.Fatalf("derived key = %x, want %s", key, want)
		}
	})
	t.Run("AES-256-GCM NIST zero plaintext", func(t *testing.T) {
		block, err := aes.NewCipher(make([]byte, 32))
		if err != nil {
			t.Fatal(err)
		}
		aead, err := cipher.NewGCM(block)
		if err != nil {
			t.Fatal(err)
		}
		tag := aead.Seal(nil, make([]byte, 12), nil, nil)
		want := "530f8afbc74536b9a963b4f1c4cb738b"
		if hex.EncodeToString(tag) != want {
			t.Fatalf("tag = %x, want %s", tag, want)
		}
	})
}

func mustHex(t *testing.T, value string) []byte {
	t.Helper()
	decoded, err := hex.DecodeString(value)
	if err != nil {
		t.Fatal(err)
	}
	return decoded
}
