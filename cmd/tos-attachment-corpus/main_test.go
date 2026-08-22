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
	"time"

	"github.com/tosnetwork/tos-messenger/pkg/attachmentcorpus"
	"github.com/tosnetwork/tos-messenger/pkg/attachments"
)

func TestEvaluateSampleDoesNotCountInfrastructureFailureAsDeny(t *testing.T) {
	root := t.TempDir()
	body := []byte("private hostile control bytes")
	path := filepath.Join(root, "hostile.bin")
	if err := os.WriteFile(path, body, 0o400); err != nil {
		t.Fatal(err)
	}
	sample := attachmentcorpus.Sample{Name: "hostile.bin", SHA256: attachmentcorpus.SHA256Hex(body),
		SizeBytes: uint64(len(body)), Category: "malware-control", MediaType: "text/plain",
		ExpectedDecision: attachmentcorpus.DecisionDeny}
	policy := attachments.AgentContentPolicy{MaxPlaintextBytes: 128 << 10,
		AllowedMediaTypes: map[string]struct{}{"text/plain": {}},
		Scanners: []attachments.ScannerSpec{{ID: "clamav-official", Executable: "/bin/false",
			ExecutableDigest: "sha256:" + strings.Repeat("1", 64)}},
		BubblewrapDigest: "sha256:" + strings.Repeat("2", 64),
		PrlimitDigest:    "sha256:" + strings.Repeat("3", 64),
		ScannerTimeout:   time.Second, AddressSpaceBytes: 1 << 30, CPUSeconds: 1, MaxProcesses: 64}
	if _, err := evaluateSample(t.Context(), root, sample, policy, time.Unix(1_900_000_000, 0)); err == nil || !strings.Contains(err.Error(), "infrastructure failed instead of returning deny") {
		t.Fatalf("infrastructure failure counted as corpus result: %v", err)
	}
	if err := os.Chmod(path, 0o422); err != nil {
		t.Fatal(err)
	}
	if _, err := evaluateSample(t.Context(), root, sample, policy, time.Unix(1_900_000_000, 0)); err == nil || !strings.Contains(err.Error(), "unsafe ownership") {
		t.Fatalf("writable corpus sample accepted: %v", err)
	}
}

func TestPrivateKeyAndReportFileBoundaries(t *testing.T) {
	directory := t.TempDir()
	key := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{7}, ed25519.SeedSize))
	keyPath := filepath.Join(directory, "runner.key")
	if err := os.WriteFile(keyPath, append([]byte(hex.EncodeToString(key)), '\n'), 0o600); err != nil {
		t.Fatal(err)
	}
	restored, err := readPrivateKey(keyPath)
	if err != nil || !bytes.Equal(restored, key) {
		t.Fatalf("read private runner key: %v", err)
	}
	clear(restored)
	if err := os.Chmod(keyPath, 0o640); err != nil {
		t.Fatal(err)
	}
	if _, err := readPrivateKey(keyPath); err == nil {
		t.Fatal("group-readable runner key accepted")
	}

	reportPath := filepath.Join(directory, "report.json")
	if err := writeNewPrivate(reportPath, []byte("{}\n")); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(reportPath)
	if err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("report was not private: info=%v err=%v", info, err)
	}
	if err := writeNewPrivate(reportPath, []byte("replacement\n")); err == nil {
		t.Fatal("existing report was overwritten")
	}
}

func TestCommandRequiresExplicitModeAndAuthority(t *testing.T) {
	for _, arguments := range [][]string{nil, {"unknown"}, {"sign"}, {"run"}, {"verify"}} {
		var output, errorOutput bytes.Buffer
		code := run(arguments, &output, &errorOutput)
		if code != 2 && (len(arguments) == 0 || arguments[0] == "unknown") {
			t.Fatalf("arguments %v returned %d", arguments, code)
		}
		if len(arguments) > 0 && (arguments[0] == "sign" || arguments[0] == "run" || arguments[0] == "verify") && code != 1 {
			t.Fatalf("incomplete %s returned %d", arguments[0], code)
		}
	}
}

func TestSignManifestUsesCustodiedKeyAndRefusesOverwrite(t *testing.T) {
	directory := t.TempDir()
	key := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{8}, ed25519.SeedSize))
	keyPath := filepath.Join(directory, "approver.key")
	if err := os.WriteFile(keyPath, []byte(hex.EncodeToString(key)), 0o600); err != nil {
		t.Fatal(err)
	}
	draft := attachmentcorpus.Manifest{Schema: attachmentcorpus.ManifestSchema, CorpusID: "external-2026",
		Revision: "r1", ApprovedAtUnix: 1_900_000_000, Scope: "Externally selected private release controls.",
		Samples: []attachmentcorpus.Sample{
			{Name: "clean.txt", SHA256: strings.Repeat("1", 64), SizeBytes: 1, Category: "clean-control", MediaType: "text/plain", ExpectedDecision: attachmentcorpus.DecisionAllow},
			{Name: "hostile.bin", SHA256: strings.Repeat("2", 64), SizeBytes: 1, Category: "malware-control", MediaType: "text/plain", ExpectedDecision: attachmentcorpus.DecisionDeny},
		}}
	draftRaw, err := json.Marshal(draft)
	if err != nil {
		t.Fatal(err)
	}
	draftPath := filepath.Join(directory, "draft.json")
	if err := os.WriteFile(draftPath, draftRaw, 0o400); err != nil {
		t.Fatal(err)
	}
	manifestPath := filepath.Join(directory, "manifest.json")
	var output, errorOutput bytes.Buffer
	arguments := []string{"sign", "-draft", draftPath, "-approver-key", keyPath, "-output", manifestPath}
	if code := run(arguments, &output, &errorOutput); code != 0 {
		t.Fatalf("sign failed: code=%d stderr=%s", code, errorOutput.String())
	}
	raw, err := os.ReadFile(manifestPath)
	if err != nil {
		t.Fatal(err)
	}
	manifest, err := attachmentcorpus.DecodeManifestJSON(raw)
	if err != nil || attachmentcorpus.VerifyManifest(manifest, key.Public().(ed25519.PublicKey)) != nil {
		t.Fatalf("signed manifest did not verify: %v", err)
	}
	if code := run(arguments, &output, &errorOutput); code == 0 {
		t.Fatal("sign overwrote an existing manifest")
	}
}
