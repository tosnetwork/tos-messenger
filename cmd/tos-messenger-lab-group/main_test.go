package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestRunDoesNotRemoveARegularFileAtSocketPath(t *testing.T) {
	root := t.TempDir()
	socket := filepath.Join(root, "must-survive")
	if err := os.WriteFile(socket, []byte("owner data"), 0o600); err != nil {
		t.Fatal(err)
	}
	err := run(socket, filepath.Join(root, "state.json"), []string{
		"agent_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa=alice-token-0001",
		"agent_bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb=bob-token-0000002",
	})
	if err == nil {
		t.Fatal("regular socket-path file was not refused")
	}
	raw, readErr := os.ReadFile(socket)
	if readErr != nil || string(raw) != "owner data" {
		t.Fatalf("regular file was changed: %q, %v", raw, readErr)
	}
}
