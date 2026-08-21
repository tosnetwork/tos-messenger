package attachments

import (
	"bytes"
	"crypto"
	"crypto/ed25519"
	"encoding/hex"
	"errors"
	"io"
	"strings"
	"testing"
	"time"
)

type refusingAttachmentSigner struct {
	public    crypto.PublicKey
	signature []byte
	err       error
}

func (s refusingAttachmentSigner) Public() crypto.PublicKey { return s.public }

func (s refusingAttachmentSigner) Sign(io.Reader, []byte, crypto.SignerOpts) ([]byte, error) {
	return append([]byte(nil), s.signature...), s.err
}

func unsignedSignerGrant() CapabilityGrant {
	storage := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x52}, ed25519.SeedSize))
	capability := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x53}, ed25519.SeedSize))
	digest := "sha256:" + strings.Repeat("ab", 32)
	return CapabilityGrant{NetworkID: "tos-local", GenesisRootHash: strings.Repeat("a", 64),
		GenesisFileHash: strings.Repeat("b", 64), AgentID: "agent_" + strings.Repeat("c", 64),
		EndpointID: "mep_" + strings.Repeat("d", 64), StoragePublicKeyHex: hex.EncodeToString(storage.Public().(ed25519.PublicKey)),
		CapabilityPublicKeyHex: hex.EncodeToString(capability.Public().(ed25519.PublicKey)), ManifestDigest: digest,
		ChunkDigests: []string{digest}, CiphertextBytes: 17, RetainUntilUnix: 1_800_000_100,
		Operations: []Operation{OperationUpload}, IssuedAtUnix: 1_800_000_000, ExpiresAtUnix: 1_800_000_100}
}

func TestSignGrantWithSignerVerifiesExternalResult(t *testing.T) {
	endpoint := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x51}, ed25519.SeedSize))
	grant := unsignedSignerGrant()
	signed, err := SignGrantWithSigner(grant, endpoint, bytes.NewReader(nil))
	if err != nil || VerifyGrant(signed, endpoint.Public().(ed25519.PublicKey),
		mustDecodePublicKey(t, grant.StoragePublicKeyHex), time.Unix(1_800_000_001, 0)) != nil {
		t.Fatalf("external signer result was not usable: %v", err)
	}

	cases := map[string]crypto.Signer{
		"non Ed25519 public key": refusingAttachmentSigner{public: []byte("not-ed25519")},
		"signing failure":        refusingAttachmentSigner{public: endpoint.Public(), err: errors.New("custody offline")},
		"invalid signature":      refusingAttachmentSigner{public: endpoint.Public(), signature: bytes.Repeat([]byte{1}, ed25519.SignatureSize)},
	}
	for name, signer := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := SignGrantWithSigner(grant, signer, nil); err == nil {
				t.Fatal("accepted an unusable external signer result")
			}
		})
	}
}

func mustDecodePublicKey(t *testing.T, value string) ed25519.PublicKey {
	t.Helper()
	raw, err := hex.DecodeString(value)
	if err != nil {
		t.Fatal(err)
	}
	return ed25519.PublicKey(raw)
}
