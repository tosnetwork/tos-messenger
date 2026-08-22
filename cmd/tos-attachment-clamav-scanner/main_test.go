package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/tosnetwork/tos-messenger/pkg/attachments"
)

func TestRunBindsPinnedEngineDatabasesAndVerdict(t *testing.T) {
	for _, test := range []struct {
		name     string
		exitCode string
		decision attachments.ScanDecision
		reason   string
	}{
		{name: "clean", exitCode: "0", decision: attachments.ScanAllow, reason: "clamav_clean"},
		{name: "infected", exitCode: "1", decision: attachments.ScanDeny, reason: "malware_detected"},
	} {
		t.Run(test.name, func(t *testing.T) {
			root, input, adapter, engineLog := clamavFixture(t, test.exitCode)
			var output bytes.Buffer
			arguments := []string{"--engine-resource", "clamscan", "--database-resource", "daily.cvd",
				"--database-resource", "main.cvd", "--tos-scanner-id", "clamav-official",
				"--tos-declared-media-type", "text/plain", "--tos-input", input}
			if err := run(arguments, &output, root, input, adapter); err != nil {
				t.Fatal(err)
			}
			var verdict attachments.ScanVerdict
			if err := json.Unmarshal(output.Bytes(), &verdict); err != nil {
				t.Fatal(err)
			}
			if verdict.Decision != test.decision || verdict.ReasonCode != test.reason || len(verdict.Resources) != 3 ||
				verdict.Resources[0].Name != "clamscan" || verdict.Resources[1].Name != "daily.cvd" ||
				verdict.Resources[2].Name != "main.cvd" {
				t.Fatalf("wrong ClamAV verdict: %+v", verdict)
			}
			for _, resource := range verdict.Resources {
				if !strings.HasPrefix(resource.Digest, "sha256:") {
					t.Fatalf("resource not bound by digest: %+v", resource)
				}
			}
			engineArguments, err := os.ReadFile(engineLog)
			if err != nil {
				t.Fatal(err)
			}
			for _, required := range []string{"--official-db-only=yes", "--alert-encrypted=yes", "--alert-broken=yes",
				"--alert-exceeds-max=yes",
				"--max-filesize=19", "--max-scansize=19", "--database=" + filepath.Join(root, "daily.cvd"),
				"--database=" + filepath.Join(root, "main.cvd"), input} {
				if !strings.Contains(string(engineArguments), required) {
					t.Fatalf("ClamAV invocation omitted %q: %s", required, engineArguments)
				}
			}
		})
	}
}

func TestRunFailsClosedForEngineAndDatabaseErrors(t *testing.T) {
	root, input, adapter, _ := clamavFixture(t, "2")
	base := []string{"--engine-resource", "clamscan", "--database-resource", "daily.cvd",
		"--database-resource", "main.cvd", "--tos-scanner-id", "clamav-official",
		"--tos-declared-media-type", "text/plain", "--tos-input", input}
	if err := run(base, &bytes.Buffer{}, root, input, adapter); err == nil {
		t.Fatal("ClamAV engine error was accepted")
	}
	for _, arguments := range [][]string{
		{"--engine-resource", "clamscan", "--database-resource", "daily.cvd", "--tos-scanner-id", "clamav-official",
			"--tos-declared-media-type", "text/plain", "--tos-input", input},
		{"--engine-resource", "clamscan", "--database-resource", "main.cvd", "--database-resource", "daily.cvd",
			"--tos-scanner-id", "clamav-official", "--tos-declared-media-type", "text/plain", "--tos-input", input},
		{"--engine-resource", "../clamscan", "--database-resource", "daily.cvd", "--database-resource", "main.cvd",
			"--tos-scanner-id", "clamav-official", "--tos-declared-media-type", "text/plain", "--tos-input", input},
		{"--engine-resource", "daily.cvd", "--database-resource", "daily.cvd", "--database-resource", "main.cvd",
			"--tos-scanner-id", "clamav-official", "--tos-declared-media-type", "text/plain", "--tos-input", input},
	} {
		if err := run(arguments, &bytes.Buffer{}, root, input, adapter); err == nil {
			t.Fatalf("unsafe database/engine invocation accepted: %v", arguments)
		}
	}
}

func clamavFixture(t *testing.T, exitCode string) (string, string, string, string) {
	t.Helper()
	root := t.TempDir()
	engine := filepath.Join(root, "clamscan")
	engineLog := filepath.Join(root, "engine-arguments")
	if err := os.WriteFile(engine, []byte("#!/bin/sh\nprintf '%s\\n' \"$@\" > "+engineLog+"\nexit "+exitCode+"\n"), 0o500); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"daily.cvd", "main.cvd"} {
		if err := os.WriteFile(filepath.Join(root, name), []byte("official-fixture-"+name), 0o400); err != nil {
			t.Fatal(err)
		}
	}
	input := filepath.Join(t.TempDir(), "input")
	if err := os.WriteFile(input, []byte("inert test content\n"), 0o400); err != nil {
		t.Fatal(err)
	}
	adapter := filepath.Join(t.TempDir(), "adapter")
	if err := os.WriteFile(adapter, []byte("scanner adapter fixture"), 0o500); err != nil {
		t.Fatal(err)
	}
	return root, input, adapter, engineLog
}
