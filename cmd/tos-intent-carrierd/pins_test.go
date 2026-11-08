package main

import (
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	commerce "github.com/tosnetwork/tos-service-protocol/pkg/agentcommerce"
	"github.com/tosnetwork/tos-service-protocol/pkg/mldsa44/mldsa44test"
)

func TestCarrierPinsNeedTheVerifyOnlyHelperAndMLDSA44Keys(t *testing.T) {
	fake := &mldsa44test.Fake{}
	path := filepath.Join(t.TempDir(), "authority.hex")
	if err := os.WriteFile(path, []byte(hex.EncodeToString(fake.PublicKey("authority"))+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	pin := pinsFlag{"authority:test=" + fake.KeyID("authority") + "@" + path}
	if _, _, err := pinnedAuthorities(pin, helperFlags{}); err == nil || !strings.Contains(err.Error(), "--tosctl") {
		t.Fatalf("pins without the helper: error = %v", err)
	}
	if _, _, err := pinnedAuthorities(pin, helperFlags{binary: os.Getenv(mldsa44test.BinaryEnvironment)}); err == nil {
		t.Fatal("a helper without its SHA-256 pin was accepted")
	}
	if _, _, err := pinnedAuthorities(pin, helperFlags{binary: "/nonexistent/tosctl", sha256: strings.Repeat("a", 64)}); err == nil {
		t.Fatal("an unpinnable helper was accepted")
	}
	ed25519Pin := pinsFlag{"authority:test=ed25519:" + strings.Repeat("ab", 32)}
	if _, _, err := pinnedAuthorities(ed25519Pin, helperFlags{binary: "/nonexistent/tosctl", sha256: strings.Repeat("a", 64)}); !errors.Is(err, commerce.ErrEd25519ActionAuthority) {
		t.Fatalf("an Ed25519 pin was not refused with the Ed25519 diagnostic: %v", err)
	}
	mldsa44test.RequireTosctl(t)
	pins, verifier, err := pinnedAuthorities(pin, helperFlags{binary: os.Getenv(mldsa44test.BinaryEnvironment),
		sha256: os.Getenv(mldsa44test.SHA256Environment)})
	if err != nil || verifier == nil || describePins(pins) != "authority:test="+fake.KeyID("authority") {
		t.Fatalf("pins=%s err=%v", describePins(pins), err)
	}
}
