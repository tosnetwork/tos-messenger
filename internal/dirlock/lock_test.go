package dirlock

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func privateDir(t *testing.T) string {
	t.Helper()
	root := filepath.Join(t.TempDir(), "state")
	if err := os.MkdirAll(root, 0o700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	return root
}

func TestExclusiveOwnership(t *testing.T) {
	root := privateDir(t)
	first, err := Acquire(root, ".lock")
	if err != nil {
		t.Fatalf("acquire: %v", err)
	}
	if !first.Held() {
		t.Fatal("expected the lock to be held")
	}
	if _, err := Acquire(root, ".lock"); !errors.Is(err, ErrHeld) {
		t.Fatalf("expected a second acquisition to be refused, got %v", err)
	}
	if err := first.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	if first.Held() {
		t.Fatal("expected the lock to be released")
	}
	second, err := Acquire(root, ".lock")
	if err != nil {
		t.Fatalf("expected ownership to be reacquirable: %v", err)
	}
	if err := second.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	if err := second.Close(); err != nil {
		t.Fatalf("expected a repeated close to be safe: %v", err)
	}
}

func TestUnsafeConfigurationIsRefused(t *testing.T) {
	root := privateDir(t)
	cases := map[string][2]string{
		"relative directory": {"state", ".lock"},
		"empty directory":    {"", ".lock"},
		"empty name":         {root, ""},
		"nested name":        {root, "sub/.lock"},
		"dot name":           {root, "."},
		"parent name":        {root, ".."},
		"long name":          {root, string(make([]byte, MaxNameBytes+1))},
	}
	for name, arguments := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := Acquire(arguments[0], arguments[1]); err == nil {
				t.Fatalf("expected %q to be refused", name)
			}
		})
	}
}

func TestSharedDirectoryIsRefused(t *testing.T) {
	shared := filepath.Join(t.TempDir(), "shared")
	if err := os.MkdirAll(shared, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if _, err := Acquire(shared, ".lock"); err == nil {
		t.Fatal("expected a world-readable directory to be refused")
	}
}

func TestNilLockIsSafe(t *testing.T) {
	var lock *Lock
	if lock.Held() {
		t.Fatal("a nil lock is not held")
	}
	if err := lock.Close(); err != nil {
		t.Fatalf("closing a nil lock must be safe: %v", err)
	}
}
