package main

import (
	"crypto/ed25519"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/tosnetwork/tos-messenger/pkg/probe"
)

func keyPath(t *testing.T) string {
	t.Helper()
	return filepath.Join(t.TempDir(), "coordinator.key")
}

// A coordinator that generated a fresh key on every start would fall out of
// every policy that predeclared it, so the identity is written down once.
func TestCoordinatorIdentityIsStable(t *testing.T) {
	path := keyPath(t)
	first, err := loadOrCreateKey(path)
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	second, err := loadOrCreateKey(path)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if !first.Equal(second) {
		t.Fatal("the coordinator identity changed between restarts")
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("a signing key was written world-readable: %v", info.Mode().Perm())
	}
	if _, err := loadOrCreateKey(""); err == nil {
		t.Fatal("a missing key path was accepted")
	}
	if err := os.WriteFile(path, []byte("not a key"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	if _, err := loadOrCreateKey(path); err == nil {
		t.Fatal("a malformed key file was accepted")
	}
	if err := os.WriteFile(path, []byte(strings.Repeat("00", ed25519.PrivateKeySize)), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	restored, err := loadOrCreateKey(path)
	if err != nil {
		t.Fatalf("load zero key: %v", err)
	}
	if hex.EncodeToString(restored) != strings.Repeat("00", ed25519.PrivateKeySize) {
		t.Fatal("a key file was not read back verbatim")
	}
}

// run listens before it serves, so an unusable configuration has to fail
// before anything blocks.
func TestRunRefusesUnusableConfiguration(t *testing.T) {
	cases := map[string]struct {
		listen          string
		key             string
		ttl             time.Duration
		maxSessions     int
		perWindow       int
		window          time.Duration
		filterListen    string
		filterSecondary string
	}{
		"no key file":     {"127.0.0.1:0", "", probe.DefaultSessionTTL, 1, 1, time.Minute, "", ""},
		"negative ttl":    {"127.0.0.1:0", keyPath(t), -time.Second, 1, 1, time.Minute, "", ""},
		"negative window": {"127.0.0.1:0", keyPath(t), probe.DefaultSessionTTL, 1, 1, -time.Minute, "", ""},
		"bad listener":    {"not an address", keyPath(t), probe.DefaultSessionTTL, 1, 1, time.Minute, "", ""},
		"bad filter source": {"127.0.0.1:0", keyPath(t), probe.DefaultSessionTTL, 1, 1, time.Minute,
			"not an address", ""},
		"bad secondary filter source": {"127.0.0.1:0", keyPath(t), probe.DefaultSessionTTL, 1, 1, time.Minute,
			"127.0.0.1:0", "not an address"},
	}
	for name, testCase := range cases {
		t.Run(name, func(t *testing.T) {
			err := run(testCase.listen, testCase.key, testCase.ttl,
				testCase.maxSessions, testCase.perWindow, testCase.window,
				testCase.filterListen, testCase.filterSecondary)
			if err == nil {
				t.Fatalf("expected %q to be refused", name)
			}
		})
	}
}
