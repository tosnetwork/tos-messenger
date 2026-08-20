package evidence

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/tosnetwork/tos-messenger/pkg/reachability"
)

func evidenceTree(t *testing.T) string {
	t.Helper()
	root := filepath.Join(t.TempDir(), "input")
	collectorBinary := "collector-binary"
	collectorHash := sha256.Sum256([]byte(collectorBinary))
	manifest, err := reachability.EncodeManifestJSON(reachability.CollectorManifest{OrchestratorRepository: "github.com/tosnetwork/tos-messenger", OrchestratorCommit: strings.Repeat("a", 40), ADNLImplementation: "tosutils-go", ADNLImplementationCommit: "v1.18.1", DependencyVersion: "v1.18.1", BinarySHA256: hex.EncodeToString(collectorHash[:]), Target: "linux/amd64", Toolchain: "go1.26.5", WireProfile: "tos-adnl"})
	if err != nil {
		t.Fatal(err)
	}
	files := map[string]string{
		"verify.log": "verify passed\n", "build/linux-amd64.log": "amd64 passed\n", "build/linux-arm64.log": "arm64 passed\n",
		"bin/linux-amd64/tos-messengerd": "amd64-binary", "bin/linux-arm64/tos-messengerd": "arm64-binary",
		"collectors/lab-a.json": string(manifest), "vectors/objects.json": "[]\n", "vectors/adversarial.json": "[]\n", "vectors/e2ee.json": "{}\n",
		"collectors/lab-a.binary": collectorBinary,
	}
	for name, body := range files {
		path := filepath.Join(root, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return root
}

func TestPackAndVerifyDeterministicEvidence(t *testing.T) {
	root := evidenceTree(t)
	first := filepath.Join(t.TempDir(), "first.zip")
	second := filepath.Join(t.TempDir(), "second.zip")
	commit := strings.Repeat("a", 40)
	manifest, err := Pack(root, first, commit, "go1.26.5 linux/amd64")
	if err != nil {
		t.Fatal(err)
	}
	verified, err := Verify(first)
	if err != nil {
		t.Fatal(err)
	}
	if verified.Commit != commit || len(verified.Artifacts) != len(manifest.Artifacts) {
		t.Fatalf("verified=%+v", verified)
	}
	if _, err := Pack(root, second, commit, "go1.26.5 linux/amd64"); err != nil {
		t.Fatal(err)
	}
	left, _ := os.ReadFile(first)
	right, _ := os.ReadFile(second)
	if !bytes.Equal(left, right) {
		t.Fatal("same evidence produced different bundles")
	}
}

func TestPackRequiresEveryEvidenceClass(t *testing.T) {
	root := evidenceTree(t)
	if err := os.Remove(filepath.Join(root, "vectors", "e2ee.json")); err != nil {
		t.Fatal(err)
	}
	if _, err := Pack(root, filepath.Join(t.TempDir(), "bundle.zip"), strings.Repeat("b", 40), "go1.26.5"); err == nil {
		t.Fatal("incomplete evidence packed")
	}
}

func TestPackRefusesOutputInsideInputTree(t *testing.T) {
	root := evidenceTree(t)
	if _, err := Pack(root, filepath.Join(root, "bundle.zip"), strings.Repeat("e", 40), "go1.26.5"); err == nil {
		t.Fatal("output inside evidence input accepted")
	}
}

func TestPackRefusesSymlinkedArtifact(t *testing.T) {
	root := evidenceTree(t)
	if err := os.Symlink(filepath.Join(root, "verify.log"), filepath.Join(root, "collectors", "alias.json")); err != nil {
		t.Fatal(err)
	}
	if _, err := Pack(root, filepath.Join(t.TempDir(), "bundle.zip"), strings.Repeat("c", 40), "go1.26.5"); err == nil {
		t.Fatal("symlinked artifact packed")
	}
}

func TestPackRefusesCollectorBinaryMismatch(t *testing.T) {
	root := evidenceTree(t)
	if err := os.WriteFile(filepath.Join(root, "collectors", "lab-a.binary"), []byte("another binary"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Pack(root, filepath.Join(t.TempDir(), "bundle.zip"), strings.Repeat("f", 40), "go1.26.5"); err == nil {
		t.Fatal("collector manifest accepted another binary")
	}
}

func TestVerifyRefusesModifiedArchive(t *testing.T) {
	root := evidenceTree(t)
	output := filepath.Join(t.TempDir(), "bundle.zip")
	if _, err := Pack(root, output, strings.Repeat("d", 40), "go1.26.5"); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(output)
	if err != nil {
		t.Fatal(err)
	}
	raw = raw[:len(raw)-1]
	if err := os.WriteFile(output, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Verify(output); err == nil {
		t.Fatal("modified evidence verified")
	}
}
