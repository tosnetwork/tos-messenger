package canon

import (
	"bytes"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

func TestLengthPrefixSeparatesFields(t *testing.T) {
	// Without a length prefix these two field splits would produce identical
	// preimages, which is how one object gets to impersonate another.
	first := &bytes.Buffer{}
	Text(first, "ab")
	Text(first, "c")

	second := &bytes.Buffer{}
	Text(second, "a")
	Text(second, "bc")

	if bytes.Equal(first.Bytes(), second.Bytes()) {
		t.Fatal("different field splits produced the same preimage")
	}
}

func TestFixedWidthEncoding(t *testing.T) {
	buffer := &bytes.Buffer{}
	Uint32(buffer, 1)
	Uint64(buffer, 1)
	expected := []byte{0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 1}
	if !bytes.Equal(buffer.Bytes(), expected) {
		t.Fatalf("unexpected big-endian encoding: %v", buffer.Bytes())
	}
}

func TestBytesArePrefixed(t *testing.T) {
	buffer := &bytes.Buffer{}
	Bytes(buffer, []byte{0xaa, 0xbb})
	if !bytes.Equal(buffer.Bytes(), []byte{0, 0, 0, 2, 0xaa, 0xbb}) {
		t.Fatalf("unexpected byte encoding: %v", buffer.Bytes())
	}
}

func TestDigestShape(t *testing.T) {
	digest := Digest([]byte("preimage"))
	if !DigestPattern.MatchString(digest) {
		t.Fatalf("unexpected digest shape: %s", digest)
	}
	if Digest([]byte("preimage")) != digest {
		t.Fatal("digest is not deterministic")
	}
	if Digest([]byte("other")) == digest {
		t.Fatal("different preimages produced the same digest")
	}
}

func TestValidDigestFailsClosed(t *testing.T) {
	if !ValidDigest(Digest([]byte("preimage"))) {
		t.Fatal("expected a real digest to be valid")
	}
	for name, digest := range map[string]string{
		"empty":       "",
		"no prefix":   strings.Repeat("a", 64),
		"wrong algo":  "tvm-cell-sha256:" + strings.Repeat("a", 64),
		"short":       "sha256:" + strings.Repeat("a", 63),
		"uppercase":   "sha256:" + strings.Repeat("A", 64),
		"all zero":    "sha256:" + strings.Repeat("0", 64),
		"not hex":     "sha256:" + strings.Repeat("z", 64),
		"trailing ws": "sha256:" + strings.Repeat("a", 64) + " ",
	} {
		t.Run(name, func(t *testing.T) {
			if ValidDigest(digest) {
				t.Fatalf("expected %q to be refused", name)
			}
		})
	}
}

func TestIsZero(t *testing.T) {
	if !IsZero(make([]byte, 32)) || !IsZero(nil) {
		t.Fatal("expected zero values to be detected")
	}
	if IsZero([]byte{0, 0, 1}) {
		t.Fatal("expected a non-zero value to be detected")
	}
}

func TestDomainSeparatorsAreUnique(t *testing.T) {
	if len(Domains) == 0 {
		t.Fatal("no domain separators are registered")
	}
	seen := make(map[string]struct{}, len(Domains))
	for _, domain := range Domains {
		if _, duplicate := seen[domain]; duplicate {
			t.Fatalf("domain separator %q is used twice", domain)
		}
		seen[domain] = struct{}{}
	}
}

func TestDomainSeparatorsAreWellFormed(t *testing.T) {
	for _, domain := range Domains {
		if !strings.HasPrefix(domain, "tos.messaging.") {
			t.Fatalf("domain separator %q is outside the namespace", domain)
		}
		if !strings.HasSuffix(domain, "\x00") {
			t.Fatalf("domain separator %q does not terminate", domain)
		}
		body := strings.TrimSuffix(domain, "\x00")
		if !strings.Contains(body, ".v") {
			t.Fatalf("domain separator %q carries no version", domain)
		}
		if strings.Count(domain, "\x00") != 1 {
			t.Fatalf("domain separator %q has more than one terminator", domain)
		}
	}
}

// Every separator this repository actually uses must be registered. A package
// that inlines its own string is invisible to the uniqueness check, which is
// the whole reason the list exists.
func TestEveryUsedSeparatorIsRegistered(t *testing.T) {
	registered := make(map[string]struct{}, len(Domains))
	for _, domain := range Domains {
		registered[strings.TrimSuffix(domain, "\x00")] = struct{}{}
	}
	root := filepath.Join("..", "..")
	pattern := regexp.MustCompile(`"(tos\.messaging\.[a-z0-9.-]+)\\x00"`)
	err := filepath.WalkDir(root, func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.IsDir() {
			if entry.Name() == ".git" {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") {
			return nil
		}
		// domains.go is where the constants live, and it is checked separately
		// against the registry rather than skipped: a constant defined there
		// and left out of the list was invisible to this walk, which is
		// exactly the case that happened.
		if strings.HasSuffix(path, "domains.go") {
			return nil
		}
		content, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		for _, match := range pattern.FindAllStringSubmatch(string(content), -1) {
			if _, known := registered[match[1]]; !known {
				t.Errorf("%s uses unregistered domain separator %q", path, match[1])
			}
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walk: %v", err)
	}
}

// Every separator declared in domains.go must be in the registry.
//
// The walk above deliberately skips that file, because the constants there are
// declarations rather than uses. That left a gap: a constant could be declared,
// referenced everywhere by name, and never registered, and nothing would
// notice. This closes it by reading the declarations themselves.
func TestEveryDeclaredSeparatorIsRegistered(t *testing.T) {
	source, err := os.ReadFile("domains.go")
	if err != nil {
		t.Fatalf("read domains.go: %v", err)
	}
	declaration := regexp.MustCompile(`(?m)^\s*(Domain[A-Za-z0-9]+)\s*=\s*"(tos\.messaging\.[a-z0-9.-]+)\\x00"`)
	matches := declaration.FindAllStringSubmatch(string(source), -1)
	if len(matches) == 0 {
		t.Fatal("no domain separator declarations were found")
	}

	registered := make(map[string]struct{}, len(Domains))
	for _, domain := range Domains {
		registered[strings.TrimSuffix(domain, "\x00")] = struct{}{}
	}
	listing := string(source[strings.Index(string(source), "var Domains"):])
	for _, match := range matches {
		name, value := match[1], match[2]
		if _, found := registered[value]; !found {
			t.Fatalf("domain separator %s (%q) is declared but not registered", name, value)
		}
		if !strings.Contains(listing, name) {
			t.Fatalf("domain separator %s is not listed in the registry by name", name)
		}
	}
	if len(matches) != len(Domains) {
		t.Fatalf("%d separators are declared and %d are registered", len(matches), len(Domains))
	}
}
