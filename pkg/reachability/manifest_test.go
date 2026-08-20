package reachability

import (
	"strings"
	"testing"
)

// A manifest identifies a build, so every field has to move the digest: two
// manifests that differ anywhere are two builds, and a field the digest
// ignored would be a field an operator could lie in for free.
func TestCollectorManifestDigestCommitsEveryField(t *testing.T) {
	base := testManifest("digest-fields")
	baseDigest, err := base.Digest()
	if err != nil {
		t.Fatalf("digest: %v", err)
	}
	mutations := map[string]func(*CollectorManifest){
		"repository":     func(m *CollectorManifest) { m.OrchestratorRepository = "github.com/tosnetwork/other" },
		"commit":         func(m *CollectorManifest) { m.OrchestratorCommit = commitB },
		"implementation": func(m *CollectorManifest) { m.ADNLImplementation = "native-sidecar" },
		"implementation commit": func(m *CollectorManifest) {
			m.ADNLImplementationCommit = "v2.0.0"
		},
		"dependency version": func(m *CollectorManifest) { m.DependencyVersion = "v2.0.0" },
		"binary hash":        func(m *CollectorManifest) { m.BinarySHA256 = strings.Repeat("cd", 32) },
		"target":             func(m *CollectorManifest) { m.Target = "linux/arm64" },
		"toolchain":          func(m *CollectorManifest) { m.Toolchain = "go1.27.0" },
		"wire profile":       func(m *CollectorManifest) { m.WireProfile = "tos-adnl" },
	}
	for name, mutate := range mutations {
		t.Run(name, func(t *testing.T) {
			mutated := base
			mutate(&mutated)
			digest, err := mutated.Digest()
			if err != nil {
				t.Fatalf("digest: %v", err)
			}
			if digest == baseDigest {
				t.Fatalf("changing %q did not change the manifest identity", name)
			}
		})
	}
}

// Every field is validated fail-closed: a manifest with a hole in it is not a
// build description, and a digest over one would look checkable while
// committing to nothing.
func TestCollectorManifestValidatesFailClosed(t *testing.T) {
	cases := map[string]func(*CollectorManifest){
		"empty repository":         func(m *CollectorManifest) { m.OrchestratorRepository = "" },
		"padded repository":        func(m *CollectorManifest) { m.OrchestratorRepository = " padded" },
		"short commit":             func(m *CollectorManifest) { m.OrchestratorCommit = "abc" },
		"empty implementation":     func(m *CollectorManifest) { m.ADNLImplementation = "" },
		"empty implementation pin": func(m *CollectorManifest) { m.ADNLImplementationCommit = "" },
		"pin with whitespace":      func(m *CollectorManifest) { m.ADNLImplementationCommit = "v1 .0" },
		"empty dependency version": func(m *CollectorManifest) { m.DependencyVersion = "" },
		"bad binary hash":          func(m *CollectorManifest) { m.BinarySHA256 = "not-hex" },
		"short binary hash":        func(m *CollectorManifest) { m.BinarySHA256 = "abcd" },
		"empty target":             func(m *CollectorManifest) { m.Target = "" },
		"empty toolchain":          func(m *CollectorManifest) { m.Toolchain = "" },
		"empty wire profile":       func(m *CollectorManifest) { m.WireProfile = "" },
		"oversized field": func(m *CollectorManifest) {
			m.DependencyVersion = strings.Repeat("v", 257)
		},
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			manifest := testManifest("validate")
			mutate(&manifest)
			if err := manifest.Validate(); err == nil {
				t.Fatalf("expected %q to be refused", name)
			}
			if _, err := manifest.Digest(); err == nil {
				t.Fatalf("expected %q to have no digest", name)
			}
			if _, err := EncodeManifestJSON(manifest); err == nil {
				t.Fatalf("expected %q to be unencodable", name)
			}
		})
	}
	if err := testManifest("validate").Validate(); err != nil {
		t.Fatalf("the reference manifest was refused: %v", err)
	}
}

// The manifest travels as a document as well as a digest, because the evidence
// bundle has to be readable and not only checkable. Transport must not change
// identity, and the strict decoding rules the other wire objects obey apply.
func TestCollectorManifestJSONRoundTrip(t *testing.T) {
	manifest := testManifest("round-trip")
	encoded, err := EncodeManifestJSON(manifest)
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	decoded, err := DecodeManifestJSON(encoded)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	first, err := manifest.Digest()
	if err != nil {
		t.Fatalf("digest: %v", err)
	}
	second, err := decoded.Digest()
	if err != nil {
		t.Fatalf("digest: %v", err)
	}
	if first != second {
		t.Fatal("manifest identity changed across transport")
	}
	line := string(encoded)
	if _, err := DecodeManifestJSON([]byte(line + `{"x":1}`)); err == nil {
		t.Fatal("trailing JSON was accepted")
	}
	if _, err := DecodeManifestJSON([]byte(strings.Replace(line, CollectorManifestSchema, "other", 1))); err == nil {
		t.Fatal("an unknown schema was accepted")
	}
	brace := strings.IndexByte(line, '{')
	unknown := line[:brace+1] + `"unknown_field":1,` + line[brace+1:]
	if _, err := DecodeManifestJSON([]byte(unknown)); err == nil {
		t.Fatal("an unknown field was accepted")
	}
}
