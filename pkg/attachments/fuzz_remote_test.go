package attachments

import (
	"bytes"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"
)

func fuzzGrant(f *testing.F) (CapabilityGrant, ed25519.PrivateKey) {
	f.Helper()
	endpoint := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x41}, ed25519.SeedSize))
	storage := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x42}, ed25519.SeedSize))
	capability := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x43}, ed25519.SeedSize))
	digest := "sha256:" + strings.Repeat("ab", 32)
	grant, err := SignGrant(CapabilityGrant{NetworkID: "tos-local", GenesisRootHash: strings.Repeat("a", 64),
		GenesisFileHash: strings.Repeat("b", 64), AgentID: "agent_" + strings.Repeat("c", 64),
		EndpointID: "mep_" + strings.Repeat("d", 64), StoragePublicKeyHex: hex.EncodeToString(storage.Public().(ed25519.PublicKey)),
		CapabilityPublicKeyHex: hex.EncodeToString(capability.Public().(ed25519.PublicKey)), ManifestDigest: digest,
		ChunkDigests: []string{digest}, CiphertextBytes: 17, RetainUntilUnix: 1_800_000_100,
		Operations: []Operation{OperationDelete, OperationFetch, OperationUpload}, IssuedAtUnix: 1_800_000_000,
		ExpiresAtUnix: 1_800_000_200}, endpoint)
	if err != nil {
		f.Fatal(err)
	}
	return grant, capability
}

func FuzzDecodeAttachmentGrant(f *testing.F) {
	grant, _ := fuzzGrant(f)
	raw, err := EncodeGrantJSON(grant)
	if err != nil {
		f.Fatal(err)
	}
	f.Add(raw)
	f.Add([]byte(`{}`))
	f.Fuzz(func(t *testing.T, value []byte) {
		decoded, err := DecodeGrantJSON(value)
		if err != nil {
			return
		}
		reencoded, err := EncodeGrantJSON(decoded)
		if err != nil {
			t.Fatalf("accepted grant did not re-encode: %v", err)
		}
		if _, err := DecodeGrantJSON(reencoded); err != nil {
			t.Fatalf("grant round trip: %v", err)
		}
	})
}

func FuzzDecodeAttachmentAccessRequest(f *testing.F) {
	grant, capability := fuzzGrant(f)
	grantDigest, _ := GrantDigest(grant)
	request, err := SignAccessRequest(AccessRequest{GrantDigest: grantDigest, Operation: OperationDelete,
		BodyDigest: "sha256:" + strings.Repeat("ef", 32), NonceHex: strings.Repeat("12", 32),
		IssuedAtUnix: 1_800_000_001, ExpiresAtUnix: 1_800_000_061}, capability)
	if err != nil {
		f.Fatal(err)
	}
	raw, err := EncodeAccessRequestJSON(request)
	if err != nil {
		f.Fatal(err)
	}
	f.Add(raw)
	f.Add([]byte(`{}`))
	f.Fuzz(func(t *testing.T, value []byte) {
		decoded, err := DecodeAccessRequestJSON(value)
		if err != nil {
			return
		}
		reencoded, err := EncodeAccessRequestJSON(decoded)
		if err != nil {
			t.Fatalf("accepted access request did not re-encode: %v", err)
		}
		if _, err := DecodeAccessRequestJSON(reencoded); err != nil {
			t.Fatalf("access request round trip: %v", err)
		}
	})
}

func FuzzDecodeScanVerdict(f *testing.F) {
	f.Add([]byte(`{"schema":"tos.messaging.attachment-scan-verdict.v1","scanner_id":"reference-text","scanner_digest":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","plaintext_digest":"sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","size_bytes":4,"declared_media_type":"text/plain","detected_media_type":"text/plain","decision":"allow","reason_code":"utf8_text"}`))
	f.Add([]byte(`{}`))
	f.Add([]byte(`null`))
	f.Fuzz(func(t *testing.T, value []byte) {
		verdict, err := decodeScanVerdict(value)
		if err != nil {
			return
		}
		raw, err := json.Marshal(verdict)
		if err != nil {
			t.Fatalf("accepted verdict did not re-encode: %v", err)
		}
		if _, err := decodeScanVerdict(raw); err != nil {
			t.Fatalf("scan verdict round trip: %v", err)
		}
	})
}
