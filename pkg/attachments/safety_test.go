package attachments

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/tosnetwork/tos-messenger/internal/canon"
)

func TestOpenForAgentRequiresPinnedSandboxedScanner(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("reference scanner sandbox is Linux-only")
	}
	for _, path := range []string{bubblewrapPath, prlimitPath} {
		if _, err := os.Stat(path); err != nil {
			t.Skipf("sandbox executable unavailable: %s", path)
		}
	}
	plaintext := []byte("inert attachment content\n")
	ref, chunks, err := Seal(bytes.NewReader(bytes.Repeat([]byte{0x73}, KeyBytes+AttachmentIDBytes+NoncePrefixBytes)), plaintext,
		Metadata{Filename: "note.txt", MediaType: "text/plain", PlaintextDigest: canon.Digest(plaintext), ExpiresAtUnix: 1_900_003_600})
	if err != nil {
		t.Fatal(err)
	}
	policy := scannerTestPolicy(t, "allow")
	admitted, err := OpenForAgent(context.Background(), ref, chunks,
		Policy{MaxPlaintextBytes: 1 << 20, AllowedMediaTypes: map[string]struct{}{"text/plain": {}}},
		policy, time.Unix(1_900_000_000, 0))
	if err != nil {
		t.Fatalf("admit: %v", err)
	}
	if !bytes.Equal(admitted.Plaintext, plaintext) || admitted.Metadata.MediaType != "text/plain" ||
		admitted.Report.Schema != AdmissionReportSchema || admitted.Report.PlaintextDigest != canon.Digest(plaintext) ||
		len(admitted.Report.Scans) != 1 || admitted.Report.Scans[0].Decision != ScanAllow {
		t.Fatalf("wrong admitted attachment: %+v", admitted)
	}
	multiple := scannerTestPolicy(t, "allow")
	first := multiple.Scanners[0]
	first.ID = "fixture-a"
	second := first
	second.ID = "fixture-b"
	second.Args = scannerHelperArgs("deny")
	multiple.Scanners = []ScannerSpec{first, second}
	if released, err := OpenForAgent(context.Background(), ref, chunks, Policy{MaxPlaintextBytes: 1 << 20},
		multiple, time.Unix(1_900_000_000, 0)); err == nil || released.Plaintext != nil {
		t.Fatalf("one allow bypassed a second scanner denial: %+v err=%v", released, err)
	}

	cases := map[string]func(*AgentContentPolicy){
		"deny": func(value *AgentContentPolicy) { value.Scanners[0].Args = scannerHelperArgs("deny") },
		"wrong digest verdict": func(value *AgentContentPolicy) {
			value.Scanners[0].Args = scannerHelperArgs("wrong-digest")
		},
		"wrong detected media": func(value *AgentContentPolicy) {
			value.Scanners[0].Args = scannerHelperArgs("wrong-media")
		},
		"wrong size verdict": func(value *AgentContentPolicy) {
			value.Scanners[0].Args = scannerHelperArgs("wrong-size")
		},
		"wrong scanner digest verdict": func(value *AgentContentPolicy) {
			value.Scanners[0].Args = scannerHelperArgs("wrong-scanner-digest")
		},
		"malformed verdict": func(value *AgentContentPolicy) {
			value.Scanners[0].Args = scannerHelperArgs("malformed-verdict")
		},
		"trailing verdict": func(value *AgentContentPolicy) {
			value.Scanners[0].Args = scannerHelperArgs("trailing-verdict")
		},
		"oversized output": func(value *AgentContentPolicy) {
			value.Scanners[0].Args = scannerHelperArgs("output-bomb")
		},
		"oversized stderr": func(value *AgentContentPolicy) {
			value.Scanners[0].Args = scannerHelperArgs("stderr-bomb")
		},
		"timeout": func(value *AgentContentPolicy) {
			value.ScannerTimeout = 100 * time.Millisecond
			value.Scanners[0].Args = scannerHelperArgs("timeout")
		},
		"scanner substitution": func(value *AgentContentPolicy) {
			value.Scanners[0].ExecutableDigest = "sha256:" + strings.Repeat("9", 64)
		},
		"sandbox substitution": func(value *AgentContentPolicy) {
			value.BubblewrapDigest = "sha256:" + strings.Repeat("8", 64)
		},
		"resource limiter substitution": func(value *AgentContentPolicy) {
			value.PrlimitDigest = "sha256:" + strings.Repeat("6", 64)
		},
		"cgroup launcher substitution": func(value *AgentContentPolicy) {
			value.Cgroup = &ScannerCgroupPolicy{SystemdRunDigest: "sha256:" + strings.Repeat("5", 64),
				MemoryMaxBytes: 256 << 20, TasksMax: 32}
		},
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			changed := scannerTestPolicy(t, "allow")
			mutate(&changed)
			result, err := OpenForAgent(context.Background(), ref, chunks, Policy{MaxPlaintextBytes: 1 << 20}, changed,
				time.Unix(1_900_000_000, 0))
			if err == nil || result.Plaintext != nil {
				t.Fatalf("unsafe content released: %+v err=%v", result, err)
			}
		})
	}
}

func TestScannerCgroupCommandIsFailClosed(t *testing.T) {
	runtimeDirectory := t.TempDir()
	if err := os.Chmod(runtimeDirectory, 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("XDG_RUNTIME_DIR", runtimeDirectory)
	policy := &ScannerCgroupPolicy{SystemdRunDigest: "sha256:" + strings.Repeat("1", 64),
		MemoryMaxBytes: 256 << 20, TasksMax: 32}
	command, err := scannerCommand(context.Background(), "/pinned/systemd-run", "/pinned/bwrap",
		[]string{"--sandbox-argument"}, 5*time.Second, policy)
	if err != nil {
		t.Fatal(err)
	}
	if command.Path != "/pinned/systemd-run" || len(command.Env) != 1 ||
		command.Env[0] != "XDG_RUNTIME_DIR="+runtimeDirectory {
		t.Fatalf("wrong cgroup command boundary: path=%q env=%v", command.Path, command.Env)
	}
	joined := strings.Join(command.Args, "\n")
	for _, required := range []string{
		"--user", "--wait", "--pipe", "--collect", "--quiet", "--service-type=exec",
		"--property=MemoryAccounting=yes", "--property=MemoryMax=268435456",
		"--property=MemorySwapMax=0", "--property=TasksAccounting=yes", "--property=TasksMax=32",
		"--property=LimitCORE=0", "--property=NoNewPrivileges=yes", "--property=KillMode=control-group",
		"--property=OOMPolicy=stop", "--property=RuntimeMaxSec=5s", "--property=TimeoutStopSec=1s",
		"/pinned/bwrap", "--sandbox-argument",
	} {
		if !strings.Contains(joined, required) {
			t.Fatalf("cgroup command omitted %q: %v", required, command.Args)
		}
	}
	if matched, _ := regexp.MatchString(`--unit=tos-attachment-scan-[0-9a-f]{32}\.service`, joined); !matched {
		t.Fatalf("cgroup command has no unpredictable bounded unit: %v", command.Args)
	}

	if err := os.Chmod(runtimeDirectory, 0o755); err != nil {
		t.Fatal(err)
	}
	if _, err := scannerCommand(context.Background(), "/pinned/systemd-run", "/pinned/bwrap", nil,
		5*time.Second, policy); err == nil {
		t.Fatal("unsafe user runtime directory accepted")
	}
}

func TestScannerCgroupHardLimitsLive(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("scanner cgroup is Linux-only")
	}
	for _, path := range []string{bubblewrapPath, prlimitPath, systemdRunPath} {
		if _, err := os.Stat(path); err != nil {
			t.Skipf("hard-isolation executable unavailable: %s", path)
		}
	}
	if os.Getenv("XDG_RUNTIME_DIR") == "" {
		t.Skip("user systemd runtime is unavailable")
	}
	probe := exec.Command(systemdRunPath, "--user", "--wait", "--pipe", "--collect", "--quiet",
		"--service-type=exec", "/bin/true")
	probe.Env = []string{"XDG_RUNTIME_DIR=" + os.Getenv("XDG_RUNTIME_DIR")}
	if err := probe.Run(); err != nil {
		t.Skipf("user systemd manager is unavailable: %v", err)
	}
	plaintext := []byte("cgroup isolated attachment\n")
	ref, chunks, err := Seal(bytes.NewReader(bytes.Repeat([]byte{0x76}, KeyBytes+AttachmentIDBytes+NoncePrefixBytes)), plaintext,
		Metadata{Filename: "cgroup.txt", MediaType: "text/plain", PlaintextDigest: canon.Digest(plaintext), ExpiresAtUnix: 1_900_003_600})
	if err != nil {
		t.Fatal(err)
	}
	policy := scannerTestPolicy(t, "cgroup-proof")
	digest, err := ExecutableDigest(systemdRunPath)
	if err != nil {
		t.Fatal(err)
	}
	policy.Cgroup = &ScannerCgroupPolicy{SystemdRunDigest: digest, MemoryMaxBytes: 256 << 20, TasksMax: 32}
	admitted, err := OpenForAgent(context.Background(), ref, chunks, Policy{MaxPlaintextBytes: 1 << 20}, policy,
		time.Unix(1_900_000_000, 0))
	if err != nil {
		t.Fatalf("cgroup admission: %v", err)
	}
	if len(admitted.Report.Scans) != 1 || admitted.Report.Scans[0].ReasonCode != "cgroup_hard_limits" {
		t.Fatalf("scanner did not observe its hard boundary: %+v", admitted.Report)
	}
	policy.Scanners[0].Args = scannerHelperArgs("oom")
	if released, err := OpenForAgent(context.Background(), ref, chunks, Policy{MaxPlaintextBytes: 1 << 20}, policy,
		time.Unix(1_900_000_000, 0)); err == nil || released.Plaintext != nil {
		t.Fatalf("memory-exhausting scanner released plaintext: %+v err=%v", released, err)
	}
}

func TestScanInputIsSealedAgainstMutation(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("sealed memfd is Linux-only")
	}
	file, err := newSealedScanInput([]byte("immutable"))
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	if _, err := file.WriteAt([]byte("x"), 0); err == nil {
		t.Fatal("sealed scan input was writable")
	}
	if err := file.Truncate(1); err == nil {
		t.Fatal("sealed scan input was shrinkable")
	}
	if err := file.Truncate(64); err == nil {
		t.Fatal("sealed scan input was growable")
	}
}

func TestScannerSandboxCannotReadUnboundHostFile(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("reference scanner sandbox is Linux-only")
	}
	if _, err := os.Stat(bubblewrapPath); err != nil {
		t.Skip("bubblewrap unavailable")
	}
	secret := filepath.Join(t.TempDir(), "host-secret")
	if err := os.WriteFile(secret, []byte("must not enter scanner"), 0o600); err != nil {
		t.Fatal(err)
	}
	plaintext := []byte("safe")
	ref, chunks, err := Seal(bytes.NewReader(bytes.Repeat([]byte{0x74}, KeyBytes+AttachmentIDBytes+NoncePrefixBytes)), plaintext,
		Metadata{Filename: "safe.txt", MediaType: "text/plain", ExpiresAtUnix: 1_900_003_600})
	if err != nil {
		t.Fatal(err)
	}
	policy := scannerTestPolicy(t, "isolation", secret)
	if _, err := OpenForAgent(context.Background(), ref, chunks, Policy{MaxPlaintextBytes: 1 << 20}, policy,
		time.Unix(1_900_000_000, 0)); err != nil {
		t.Fatalf("sandbox isolation check: %v", err)
	}
}

func TestReferenceTextScannerLive(t *testing.T) {
	path := os.Getenv("TOS_ATTACHMENT_TEXT_SCANNER")
	if path == "" {
		t.Skip("set TOS_ATTACHMENT_TEXT_SCANNER to the built reference scanner")
	}
	if runtime.GOOS != "linux" {
		t.Skip("reference scanner sandbox is Linux-only")
	}
	plaintext := []byte("# verified text\n\nscanner-safe input\n")
	ref, chunks, err := Seal(bytes.NewReader(bytes.Repeat([]byte{0x75}, KeyBytes+AttachmentIDBytes+NoncePrefixBytes)), plaintext,
		Metadata{Filename: "note.md", MediaType: "text/markdown", PlaintextDigest: canon.Digest(plaintext), ExpiresAtUnix: 1_900_003_600})
	if err != nil {
		t.Fatal(err)
	}
	scannerDigest, err := ExecutableDigest(path)
	if err != nil {
		t.Fatal(err)
	}
	bubblewrapDigest, err := ExecutableDigest(bubblewrapPath)
	if err != nil {
		t.Fatal(err)
	}
	prlimitDigest, err := ExecutableDigest(prlimitPath)
	if err != nil {
		t.Fatal(err)
	}
	policy := AgentContentPolicy{MaxPlaintextBytes: 1 << 20,
		AllowedMediaTypes: map[string]struct{}{"text/markdown": {}},
		Scanners:          []ScannerSpec{{ID: "reference-text", Executable: path, ExecutableDigest: scannerDigest}},
		BubblewrapDigest:  bubblewrapDigest, PrlimitDigest: prlimitDigest, ScannerTimeout: 5 * time.Second,
		AddressSpaceBytes: 8 << 30, CPUSeconds: 5, MaxProcesses: 4096}
	admitted, err := OpenForAgent(context.Background(), ref, chunks, Policy{MaxPlaintextBytes: 1 << 20}, policy,
		time.Unix(1_900_000_000, 0))
	if err != nil {
		t.Fatalf("reference scanner: %v", err)
	}
	if !bytes.Equal(admitted.Plaintext, plaintext) || len(admitted.Report.Scans) != 1 ||
		admitted.Report.Scans[0].ReasonCode != "utf8_text" {
		t.Fatalf("wrong reference scanner result: %+v", admitted)
	}
}

func TestAgentContentPolicyFailsClosed(t *testing.T) {
	metadata := Metadata{MediaType: "text/plain"}
	valid := scannerTestPolicyWithoutHost(t)
	cases := map[string]func(*AgentContentPolicy){
		"no media allow-list": func(value *AgentContentPolicy) { value.AllowedMediaTypes = nil },
		"declared type denied": func(value *AgentContentPolicy) {
			value.AllowedMediaTypes = map[string]struct{}{"application/pdf": {}}
		},
		"noncanonical media": func(value *AgentContentPolicy) {
			value.AllowedMediaTypes = map[string]struct{}{"text/plain; charset=utf-8": {}}
		},
		"no scanner": func(value *AgentContentPolicy) { value.Scanners = nil },
		"duplicate scanner": func(value *AgentContentPolicy) {
			value.Scanners = append(value.Scanners, value.Scanners[0])
		},
		"unbounded plaintext": func(value *AgentContentPolicy) { value.MaxPlaintextBytes = 0 },
		"unbounded timeout":   func(value *AgentContentPolicy) { value.ScannerTimeout = 3 * time.Minute },
		"cgroup launcher unpinned": func(value *AgentContentPolicy) {
			value.Cgroup = &ScannerCgroupPolicy{MemoryMaxBytes: 256 << 20, TasksMax: 32}
		},
		"cgroup memory too small": func(value *AgentContentPolicy) {
			value.Cgroup = &ScannerCgroupPolicy{SystemdRunDigest: "sha256:" + strings.Repeat("3", 64),
				MemoryMaxBytes: 32 << 20, TasksMax: 32}
		},
		"cgroup tasks exceed process ceiling": func(value *AgentContentPolicy) {
			value.Cgroup = &ScannerCgroupPolicy{SystemdRunDigest: "sha256:" + strings.Repeat("3", 64),
				MemoryMaxBytes: 256 << 20, TasksMax: 4097}
		},
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			changed := valid
			changed.Scanners = append([]ScannerSpec(nil), valid.Scanners...)
			mutate(&changed)
			if err := validateContentPolicy(changed, metadata, 4); err == nil {
				t.Fatal("invalid Agent content policy accepted")
			}
		})
	}
}

func TestExecutableDigestRefusesUnsafePaths(t *testing.T) {
	directory := t.TempDir()
	executable := filepath.Join(directory, "scanner")
	if err := os.WriteFile(executable, []byte("scanner"), 0o500); err != nil {
		t.Fatal(err)
	}
	if digest, err := ExecutableDigest(executable); err != nil || !canon.ValidDigest(digest) {
		t.Fatalf("safe executable digest: %q %v", digest, err)
	}
	symlink := filepath.Join(directory, "scanner-link")
	if err := os.Symlink(executable, symlink); err != nil {
		t.Fatal(err)
	}
	if _, err := ExecutableDigest(symlink); err == nil {
		t.Fatal("symlinked scanner executable accepted")
	}
	if err := os.Chmod(executable, 0o520); err != nil {
		t.Fatal(err)
	}
	if _, err := ExecutableDigest(executable); err == nil {
		t.Fatal("group-writable scanner executable accepted")
	}
	if _, err := ExecutableDigest("relative/scanner"); err == nil {
		t.Fatal("relative scanner executable accepted")
	}
}

func TestStagedExecutableKeepsVerifiedInodeAfterPathReplacement(t *testing.T) {
	directory := t.TempDir()
	source := filepath.Join(directory, "source")
	verified := []byte("reviewed executable")
	if err := os.WriteFile(source, verified, 0o500); err != nil {
		t.Fatal(err)
	}
	digest, err := ExecutableDigest(source)
	if err != nil {
		t.Fatal(err)
	}
	staging := filepath.Join(t.TempDir(), "private")
	if err := os.Mkdir(staging, 0o700); err != nil {
		t.Fatal(err)
	}
	staged, err := stagePinnedExecutable(staging, "launcher", source, digest)
	if err != nil {
		t.Fatal(err)
	}
	replacement := filepath.Join(directory, "replacement")
	if err := os.WriteFile(replacement, []byte("unreviewed replacement"), 0o500); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(replacement, source); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(staged)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, verified) {
		t.Fatalf("staged launcher changed after source replacement: %q", got)
	}
}

// TestSandboxScannerHelperProcess is re-executed as the pinned scanner inside
// bubblewrap. It exits directly so the Go test harness adds no stdout around
// the one strict verdict object.
func TestSandboxScannerHelperProcess(t *testing.T) {
	marker := argumentIndex(os.Args, "--scanner-helper")
	if marker < 0 {
		return
	}
	mode := os.Args[marker+1]
	input := argumentValue(os.Args, "--tos-input")
	declared := argumentValue(os.Args, "--tos-declared-media-type")
	scannerID := argumentValue(os.Args, "--tos-scanner-id")
	if mode == "timeout" {
		time.Sleep(5 * time.Second)
	}
	if mode == "oom" {
		allocation := make([]byte, 512<<20)
		for index := 0; index < len(allocation); index += os.Getpagesize() {
			allocation[index] = byte(index)
		}
		runtime.KeepAlive(allocation)
	}
	if mode == "output-bomb" {
		_, _ = os.Stdout.Write(bytes.Repeat([]byte("x"), MaxScanVerdictBytes+1))
		os.Exit(0)
	}
	if mode == "malformed-verdict" {
		_, _ = os.Stdout.Write([]byte("{}"))
		os.Exit(0)
	}
	if mode == "stderr-bomb" {
		_, _ = os.Stderr.Write(bytes.Repeat([]byte("x"), MaxScanVerdictBytes+1))
	}
	decision := ScanAllow
	if mode == "deny" {
		decision = ScanDeny
	}
	if mode == "isolation" {
		if _, err := os.ReadFile(os.Args[marker+2]); err == nil {
			decision = ScanDeny
		}
	}
	reason := ""
	if mode == "cgroup-proof" {
		membership, err := os.ReadFile("/proc/self/cgroup")
		var core syscall.Rlimit
		coreErr := syscall.Getrlimit(syscall.RLIMIT_CORE, &core)
		if err != nil || coreErr != nil || !bytes.Contains(membership, []byte("/tos-attachment-scan-")) || core.Cur != 0 {
			decision = ScanDeny
		} else {
			reason = "cgroup_hard_limits"
		}
	}
	raw, err := os.ReadFile(input)
	if err != nil {
		os.Exit(91)
	}
	executable, err := os.Executable()
	if err != nil {
		os.Exit(92)
	}
	executableDigest, err := ExecutableDigest(executable)
	if err != nil {
		os.Exit(93)
	}
	plaintextDigest := canon.Digest(raw)
	if mode == "wrong-scanner-digest" {
		executableDigest = "sha256:" + strings.Repeat("6", 64)
	}
	if mode == "wrong-digest" {
		plaintextDigest = "sha256:" + strings.Repeat("7", 64)
	}
	detected := declared
	if mode == "wrong-media" {
		detected = "application/octet-stream"
	}
	sizeBytes := uint64(len(raw))
	if mode == "wrong-size" {
		sizeBytes++
	}
	verdict := ScanVerdict{Schema: ScanVerdictSchema, ScannerID: scannerID, ScannerDigest: executableDigest,
		PlaintextDigest: plaintextDigest, SizeBytes: sizeBytes, DeclaredMediaType: declared,
		DetectedMediaType: detected, Decision: decision, ReasonCode: reason}
	if err := json.NewEncoder(os.Stdout).Encode(verdict); err != nil {
		os.Exit(94)
	}
	if mode == "trailing-verdict" {
		_, _ = os.Stdout.Write([]byte("{}"))
	}
	os.Exit(0)
}

func scannerTestPolicy(t *testing.T, mode string, extra ...string) AgentContentPolicy {
	t.Helper()
	policy := scannerTestPolicyWithoutHost(t)
	var err error
	policy.BubblewrapDigest, err = ExecutableDigest(bubblewrapPath)
	if err != nil {
		t.Fatal(err)
	}
	policy.PrlimitDigest, err = ExecutableDigest(prlimitPath)
	if err != nil {
		t.Fatal(err)
	}
	policy.Scanners[0].Args = scannerHelperArgs(mode, extra...)
	return policy
}

func scannerTestPolicyWithoutHost(t *testing.T) AgentContentPolicy {
	t.Helper()
	source, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	executable := filepath.Join(t.TempDir(), "scanner")
	input, err := os.Open(source)
	if err != nil {
		t.Fatal(err)
	}
	output, err := os.OpenFile(executable, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o500)
	if err != nil {
		_ = input.Close()
		t.Fatal(err)
	}
	if _, err := io.Copy(output, input); err != nil {
		_ = input.Close()
		_ = output.Close()
		t.Fatal(err)
	}
	if err := input.Close(); err != nil {
		_ = output.Close()
		t.Fatal(err)
	}
	if err := output.Sync(); err != nil {
		_ = output.Close()
		t.Fatal(err)
	}
	if err := output.Close(); err != nil {
		t.Fatal(err)
	}
	scannerDigest, err := ExecutableDigest(executable)
	if err != nil {
		t.Fatal(err)
	}
	return AgentContentPolicy{MaxPlaintextBytes: 1 << 20, AllowedMediaTypes: map[string]struct{}{"text/plain": {}},
		Scanners: []ScannerSpec{{ID: "fixture", Executable: executable, ExecutableDigest: scannerDigest,
			Args: scannerHelperArgs("allow")}},
		BubblewrapDigest: "sha256:" + strings.Repeat("1", 64), PrlimitDigest: "sha256:" + strings.Repeat("2", 64),
		ScannerTimeout: 5 * time.Second, AddressSpaceBytes: 8 << 30, CPUSeconds: 5, MaxProcesses: 4096}
}

func scannerHelperArgs(mode string, extra ...string) []string {
	arguments := []string{"-test.run=^TestSandboxScannerHelperProcess$", "--", "--scanner-helper", mode}
	return append(arguments, extra...)
}

func argumentIndex(arguments []string, name string) int {
	for index, value := range arguments {
		if value == name && index+1 < len(arguments) {
			return index
		}
	}
	return -1
}

func argumentValue(arguments []string, name string) string {
	index := argumentIndex(arguments, name)
	if index < 0 {
		fmt.Fprintln(os.Stderr, "missing scanner argument", name)
		os.Exit(90)
	}
	return arguments[index+1]
}
