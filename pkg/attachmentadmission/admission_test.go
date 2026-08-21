package attachmentadmission

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/tosnetwork/tos-messenger/internal/canon"
	"github.com/tosnetwork/tos-messenger/pkg/attachmentapi"
	"github.com/tosnetwork/tos-messenger/pkg/attachments"
	"github.com/tosnetwork/tos-messenger/pkg/envelope"
	"github.com/tosnetwork/tos-messenger/pkg/payload"
	nativev1 "github.com/tosnetwork/tos-service-protocol/gen/tos/service/v1"
)

type chunkCaller struct {
	chunks []attachments.Chunk
	tamper bool
}

func (c chunkCaller) Call(_ context.Context, request attachmentapi.Request) (attachmentapi.Response, error) {
	if request.Op != attachmentapi.OpFetch || len(request.Digests) != len(c.chunks) {
		return attachmentapi.Response{}, errors.New("unexpected attachment test request")
	}
	chunks := append([]attachments.Chunk(nil), c.chunks...)
	if c.tamper {
		chunks[0].Ciphertext = append([]byte(nil), chunks[0].Ciphertext...)
		chunks[0].Ciphertext[0] ^= 1
	}
	wire, err := attachmentapi.EncodeChunks(chunks)
	if err != nil {
		return attachmentapi.Response{}, err
	}
	return attachmentapi.Response{Schema: attachmentapi.ResponseSchema, OK: true, Chunks: &wire}, nil
}

func TestAdmitFetchesAuthenticatesAndScansBeforeReturningText(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("attachment admission sandbox is Linux-only")
	}
	for _, path := range []string{"/usr/bin/bwrap", "/usr/bin/prlimit"} {
		if _, err := os.Stat(path); err != nil {
			t.Skipf("sandbox executable unavailable: %s", path)
		}
	}
	event, chunks, now := admissionFixture(t)
	admitter := testAdmitter(t, chunks, now, false)
	result, err := admitter.Admit(context.Background(), event)
	if err != nil {
		t.Fatalf("admit: %v", err)
	}
	if result.Body != "authenticated attachment text\n" || result.Metadata.Filename != "note.txt" ||
		result.Report.PlaintextDigest != canon.Digest([]byte(result.Body)) || len(result.Report.Scans) != 1 ||
		result.Report.Scans[0].Decision != attachments.ScanAllow {
		t.Fatalf("wrong admission result: %+v", result)
	}

	tampered := testAdmitter(t, chunks, now, true)
	if released, err := tampered.Admit(context.Background(), event); err == nil || released.Body != "" {
		t.Fatalf("tampered ciphertext reached Agent boundary: %+v err=%v", released, err)
	}
}

func testAdmitter(t *testing.T, chunks []attachments.Chunk, now time.Time, tamper bool) *Admitter {
	t.Helper()
	executable, err := filepath.Abs(os.Args[0])
	if err != nil {
		t.Fatal(err)
	}
	binary, err := os.ReadFile(executable)
	if err != nil {
		t.Fatal(err)
	}
	executable = filepath.Join(t.TempDir(), "admission-scanner")
	if err := os.WriteFile(executable, binary, 0o500); err != nil {
		t.Fatal(err)
	}
	scannerDigest, err := attachments.ExecutableDigest(executable)
	if err != nil {
		t.Fatal(err)
	}
	bwrapDigest, err := attachments.ExecutableDigest("/usr/bin/bwrap")
	if err != nil {
		t.Fatal(err)
	}
	prlimitDigest, err := attachments.ExecutableDigest("/usr/bin/prlimit")
	if err != nil {
		t.Fatal(err)
	}
	allowed := map[string]struct{}{"text/plain": {}}
	admitter, err := New(Config{OpenPolicy: attachments.Policy{MaxPlaintextBytes: envelope.MaxContentBytes, AllowedMediaTypes: allowed},
		ContentPolicy: attachments.AgentContentPolicy{MaxPlaintextBytes: envelope.MaxContentBytes, AllowedMediaTypes: allowed,
			Scanners: []attachments.ScannerSpec{{ID: "reference-text", Executable: executable,
				ExecutableDigest: scannerDigest, Args: []string{"-test.run=^TestAdmissionScannerHelper$", "--", "--admission-scanner"}}},
			BubblewrapDigest: bwrapDigest, PrlimitDigest: prlimitDigest, ScannerTimeout: 5 * time.Second,
			AddressSpaceBytes: 8 << 30, CPUSeconds: 5, MaxProcesses: 4096},
		CallerFactory: func(string, string) (attachmentapi.Caller, func(), error) {
			return chunkCaller{chunks: chunks, tamper: tamper}, nil, nil
		}, Now: func() time.Time { return now }, RNG: bytes.NewReader(bytes.Repeat([]byte{0x61}, 64))})
	if err != nil {
		t.Fatal(err)
	}
	return admitter
}

func admissionFixture(t *testing.T) (envelope.Event, []attachments.Chunk, time.Time) {
	t.Helper()
	now := time.Unix(1_800_000_000, 0)
	plaintext := []byte("authenticated attachment text\n")
	ref, chunks, err := attachments.Seal(bytes.NewReader(bytes.Repeat([]byte{0x41},
		attachments.KeyBytes+attachments.AttachmentIDBytes+attachments.NoncePrefixBytes)), plaintext,
		attachments.Metadata{Filename: "note.txt", MediaType: "text/plain", PlaintextDigest: canon.Digest(plaintext),
			ExpiresAtUnix: uint64(now.Add(time.Hour).Unix())})
	if err != nil {
		t.Fatal(err)
	}
	referenceJSON, _ := attachments.EncodeReferenceJSON(ref)
	manifestDigest, _ := attachments.ManifestDigest(ref.Manifest)
	endpointKey := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x42}, ed25519.SeedSize))
	storageKey := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x43}, ed25519.SeedSize))
	capabilityKey := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x44}, ed25519.SeedSize))
	var ciphertextBytes uint64
	for _, chunk := range chunks {
		ciphertextBytes += uint64(len(chunk.Ciphertext))
	}
	grant, err := attachments.SignGrant(attachments.CapabilityGrant{NetworkID: "tos-local",
		GenesisRootHash: strings.Repeat("a", 64), GenesisFileHash: strings.Repeat("b", 64),
		AgentID: "agent_" + strings.Repeat("c", 64), EndpointID: "mep_" + strings.Repeat("d", 64),
		StoragePublicKeyHex:    hex.EncodeToString(storageKey.Public().(ed25519.PublicKey)),
		CapabilityPublicKeyHex: hex.EncodeToString(capabilityKey.Public().(ed25519.PublicKey)),
		ManifestDigest:         manifestDigest, ChunkDigests: append([]string(nil), ref.Manifest.ChunkDigests...),
		CiphertextBytes: ciphertextBytes, RetainUntilUnix: ref.Metadata.ExpiresAtUnix,
		Operations: []attachments.Operation{attachments.OperationFetch}, IssuedAtUnix: uint64(now.Add(-time.Minute).Unix()),
		ExpiresAtUnix: ref.Metadata.ExpiresAtUnix}, endpointKey)
	if err != nil {
		t.Fatal(err)
	}
	grantJSON, _ := attachments.EncodeGrantJSON(grant)
	locator, _ := attachments.HTTPSLocator("https://attachments.example", manifestDigest)
	content, err := payload.Encode(payload.EncryptedAttachment{ManifestDigest: manifestDigest, ReferenceJSON: referenceJSON,
		Locator: locator, FetchGrantJSON: grantJSON, FetchCapabilityPrivateKeyHex: hex.EncodeToString(capabilityKey)})
	if err != nil {
		t.Fatal(err)
	}
	event, err := envelope.NewEvent(envelope.Event{Network: &nativev1.NetworkDomain{NetworkId: "tos-local",
		GenesisRootHash: strings.Repeat("a", 64), GenesisFileHash: strings.Repeat("b", 64)},
		ConversationID: "conv_" + strings.Repeat("e", 64), SenderAgentID: grant.AgentID,
		SenderEndpointID: grant.EndpointID, SenderDeviceID: "dev_" + strings.Repeat("f", 64),
		CreatedAtUnix: uint64(now.Unix()), ExpiresAtUnix: uint64(now.Add(time.Hour).Unix()),
		Kind: "artifact.encrypted", Content: content, AttachmentReferences: []string{manifestDigest}})
	if err != nil {
		t.Fatal(err)
	}
	return event, chunks, now
}

// TestAdmissionScannerHelper is re-executed inside bubblewrap. Only the one
// exact verdict is written to stdout.
func TestAdmissionScannerHelper(t *testing.T) {
	if argument(os.Args, "--admission-scanner") == "" {
		return
	}
	input := argument(os.Args, "--tos-input")
	mediaType := argument(os.Args, "--tos-declared-media-type")
	scannerID := argument(os.Args, "--tos-scanner-id")
	raw, err := os.ReadFile(input)
	if err != nil {
		os.Exit(91)
	}
	executable, err := os.Executable()
	if err != nil {
		os.Exit(92)
	}
	binary, err := os.Open(executable)
	if err != nil {
		os.Exit(93)
	}
	hash := sha256.New()
	_, err = io.Copy(hash, binary)
	_ = binary.Close()
	if err != nil {
		os.Exit(94)
	}
	verdict := attachments.ScanVerdict{Schema: attachments.ScanVerdictSchema, ScannerID: scannerID,
		ScannerDigest: "sha256:" + hex.EncodeToString(hash.Sum(nil)), PlaintextDigest: canon.Digest(raw),
		SizeBytes: uint64(len(raw)), DeclaredMediaType: mediaType, DetectedMediaType: mediaType,
		Decision: attachments.ScanAllow, ReasonCode: "utf8_text"}
	if json.NewEncoder(os.Stdout).Encode(verdict) != nil {
		os.Exit(95)
	}
	os.Exit(0)
}

func argument(arguments []string, name string) string {
	for index, value := range arguments {
		if value == name {
			if name == "--admission-scanner" {
				return "yes"
			}
			if index+1 < len(arguments) {
				return arguments[index+1]
			}
		}
	}
	return ""
}
