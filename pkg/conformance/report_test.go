package conformance

import (
	"bytes"
	"crypto/ed25519"
	"os"
	"path/filepath"
	"testing"
)

func artifacts(t *testing.T) []Artifact {
	t.Helper()
	root := t.TempDir()
	paths := make([]string, 3)
	for index, name := range []string{"objects", "adversarial", "e2ee"} {
		paths[index] = filepath.Join(root, name+".json")
		if err := os.WriteFile(paths[index], []byte(name), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	expected, err := Expected(paths[0], paths[1], paths[2])
	if err != nil {
		t.Fatal(err)
	}
	return expected
}
func consumerKey() ed25519.PrivateKey {
	return ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x42}, ed25519.SeedSize))
}

func signedReport(t *testing.T, expected []Artifact) Report {
	t.Helper()
	report, err := Sign(Report{Implementation: "example.org/independent-messenger", ImplementationCommit: "release-1", Toolchain: "rustc-1.90", RunAtUnix: 1_800_000_000, Artifacts: expected, PositiveChecks: 12, AdversarialChecks: 44}, consumerKey())
	if err != nil {
		t.Fatal(err)
	}
	return report
}

func TestReportProvesExactArtifactConsumption(t *testing.T) {
	expected := artifacts(t)
	report := signedReport(t, expected)
	if err := VerifyAgainst(report, expected); err != nil {
		t.Fatal(err)
	}
	raw, err := EncodeJSON(report)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := DecodeJSON(raw)
	if err != nil || VerifyAgainst(decoded, expected) != nil {
		t.Fatalf("decode=%+v err=%v", decoded, err)
	}
}
func TestReportRefusesDifferentArtifactAndTampering(t *testing.T) {
	expected := artifacts(t)
	report := signedReport(t, expected)
	report.PositiveChecks++
	if err := VerifyAgainst(report, expected); err == nil {
		t.Fatal("tampered report verified")
	}
	report = signedReport(t, expected)
	other := append([]Artifact(nil), expected...)
	other[0].SHA256 = other[1].SHA256
	if err := VerifyAgainst(report, other); err == nil {
		t.Fatal("report accepted for another artifact set")
	}
}
func TestReportStrictDecoder(t *testing.T) {
	report := signedReport(t, artifacts(t))
	raw, _ := EncodeJSON(report)
	unknown := append(append([]byte{}, raw[:len(raw)-1]...), []byte(`,"extra":true}`)...)
	if _, err := DecodeJSON(unknown); err == nil {
		t.Fatal("unknown report field accepted")
	}
	if _, err := DecodeJSON(append(raw, raw...)); err == nil {
		t.Fatal("trailing report accepted")
	}
}
