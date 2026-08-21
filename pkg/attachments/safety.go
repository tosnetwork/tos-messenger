package attachments

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/tosnetwork/tos-messenger/internal/canon"
)

const (
	ScanVerdictSchema     = "tos.messaging.attachment-scan-verdict.v1"
	AdmissionReportSchema = "tos.messaging.attachment-admission-report.v1"
	MaxAdmissionScanners  = 4
	MaxScannerBinaryBytes = 128 << 20
	MaxScanVerdictBytes   = 16 << 10
	DefaultScannerTimeout = 30 * time.Second
	defaultAddressSpace   = 8 << 30
	defaultCPUSeconds     = 30
	defaultMaxProcesses   = 4096
	bubblewrapPath        = "/usr/bin/bwrap"
	prlimitPath           = "/usr/bin/prlimit"
)

var scannerIDPattern = regexp.MustCompile(`^[a-z][a-z0-9.-]{0,63}$`)
var scanReasonPattern = regexp.MustCompile(`^[a-z][a-z0-9_.-]{0,63}$`)

// ScannerSpec pins one scanner executable and its deterministic invocation.
// The executable is copied into a private staging directory after its SHA-256
// digest is verified, so a later path substitution cannot change what runs.
type ScannerSpec struct {
	ID               string
	Executable       string
	ExecutableDigest string
	Args             []string
}

// AgentContentPolicy is the fail-closed boundary between authenticated
// plaintext and Agent/model consumption. Bubblewrap and prlimit are pinned as
// part of the local policy because an untrusted launcher is not a sandbox.
type AgentContentPolicy struct {
	MaxPlaintextBytes uint64
	AllowedMediaTypes map[string]struct{}
	Scanners          []ScannerSpec
	BubblewrapDigest  string
	PrlimitDigest     string
	ScannerTimeout    time.Duration
	AddressSpaceBytes uint64
	CPUSeconds        uint64
	MaxProcesses      uint64
}

type ScanDecision string

const (
	ScanAllow ScanDecision = "allow"
	ScanDeny  ScanDecision = "deny"
)

// ScanVerdict is the only stdout shape accepted from a scanner. Binding the
// plaintext digest, size and both media types prevents a verdict for one byte
// string or declared format from being replayed for another.
type ScanVerdict struct {
	Schema            string       `json:"schema"`
	ScannerID         string       `json:"scanner_id"`
	ScannerDigest     string       `json:"scanner_digest"`
	PlaintextDigest   string       `json:"plaintext_digest"`
	SizeBytes         uint64       `json:"size_bytes"`
	DeclaredMediaType string       `json:"declared_media_type"`
	DetectedMediaType string       `json:"detected_media_type"`
	Decision          ScanDecision `json:"decision"`
	ReasonCode        string       `json:"reason_code,omitempty"`
}

type AdmissionReport struct {
	Schema          string        `json:"schema"`
	PlaintextDigest string        `json:"plaintext_digest"`
	SizeBytes       uint64        `json:"size_bytes"`
	MediaType       string        `json:"media_type"`
	Scans           []ScanVerdict `json:"scans"`
}

type AdmittedAttachment struct {
	Plaintext []byte
	Metadata  Metadata
	Report    AdmissionReport
}

// OpenForAgent authenticates and decrypts an attachment, then releases it only
// after every pinned scanner permits the exact plaintext inside a networkless,
// read-only bubblewrap namespace with prlimit resource ceilings.
func OpenForAgent(ctx context.Context, ref Reference, chunks []Chunk, openPolicy Policy,
	contentPolicy AgentContentPolicy, now time.Time) (AdmittedAttachment, error) {
	if ctx == nil {
		return AdmittedAttachment{}, errors.New("attachment admission needs a context")
	}
	plaintext, err := Open(ref, chunks, openPolicy, now)
	if err != nil {
		return AdmittedAttachment{}, err
	}
	report, err := admitPlaintext(ctx, plaintext, ref.Metadata, contentPolicy)
	if err != nil {
		clear(plaintext)
		return AdmittedAttachment{}, err
	}
	return AdmittedAttachment{Plaintext: plaintext, Metadata: ref.Metadata, Report: report}, nil
}

func admitPlaintext(ctx context.Context, plaintext []byte, metadata Metadata, policy AgentContentPolicy) (AdmissionReport, error) {
	if err := validateContentPolicy(policy, metadata, len(plaintext)); err != nil {
		return AdmissionReport{}, err
	}
	if runtime.GOOS != "linux" {
		return AdmissionReport{}, errors.New("attachment scanner sandbox requires Linux")
	}
	digest := canon.Digest(plaintext)
	directory, err := os.MkdirTemp("", ".tos-attachment-scan-")
	if err != nil {
		return AdmissionReport{}, errors.New("create private attachment scan directory")
	}
	defer os.RemoveAll(directory)
	if err := os.Chmod(directory, 0o700); err != nil {
		return AdmissionReport{}, errors.New("protect attachment scan directory")
	}
	sandboxPath, err := stagePinnedExecutable(directory, "bubblewrap", bubblewrapPath, policy.BubblewrapDigest)
	if err != nil {
		return AdmissionReport{}, fmt.Errorf("stage bubblewrap: %w", err)
	}
	resourceLimiterPath, err := stagePinnedExecutable(directory, "prlimit", prlimitPath, policy.PrlimitDigest)
	if err != nil {
		return AdmissionReport{}, fmt.Errorf("stage prlimit: %w", err)
	}
	input, err := newSealedScanInput(plaintext)
	if err != nil {
		return AdmissionReport{}, err
	}
	defer input.Close()
	report := AdmissionReport{Schema: AdmissionReportSchema, PlaintextDigest: digest,
		SizeBytes: uint64(len(plaintext)), MediaType: metadata.MediaType,
		Scans: make([]ScanVerdict, 0, len(policy.Scanners))}
	for index, scanner := range policy.Scanners {
		if err := ctx.Err(); err != nil {
			return AdmissionReport{}, err
		}
		scannerPath, err := copyPinnedScanner(directory, index, scanner)
		if err != nil {
			return AdmissionReport{}, err
		}
		verdict, err := runSandboxedScanner(ctx, input, sandboxPath, resourceLimiterPath, scannerPath, scanner, metadata,
			digest, uint64(len(plaintext)), policy)
		if err != nil {
			return AdmissionReport{}, err
		}
		if verdict.Decision != ScanAllow {
			return AdmissionReport{}, fmt.Errorf("attachment scanner %s denied content", scanner.ID)
		}
		report.Scans = append(report.Scans, verdict)
	}
	return report, nil
}

func validateContentPolicy(policy AgentContentPolicy, metadata Metadata, plaintextBytes int) error {
	if plaintextBytes < 1 || uint64(plaintextBytes) > MaxPlaintextBytes {
		return errors.New("invalid plaintext for attachment admission")
	}
	limit := policy.MaxPlaintextBytes
	if limit == 0 || limit > MaxPlaintextBytes || uint64(plaintextBytes) > limit {
		return errors.New("attachment exceeds Agent content limit")
	}
	if len(policy.AllowedMediaTypes) == 0 {
		return errors.New("Agent content policy needs an explicit media allow-list")
	}
	for mediaType := range policy.AllowedMediaTypes {
		if !canonicalMediaType(mediaType) {
			return errors.New("Agent content policy has a noncanonical media type")
		}
	}
	if _, allowed := policy.AllowedMediaTypes[metadata.MediaType]; !allowed {
		return errors.New("attachment media type is not allowed for Agent consumption")
	}
	if len(policy.Scanners) == 0 || len(policy.Scanners) > MaxAdmissionScanners {
		return errors.New("Agent content policy needs a bounded scanner set")
	}
	if !canon.ValidDigest(policy.BubblewrapDigest) || !canon.ValidDigest(policy.PrlimitDigest) {
		return errors.New("Agent content policy must pin sandbox executables")
	}
	timeout := policy.ScannerTimeout
	if timeout == 0 {
		timeout = DefaultScannerTimeout
	}
	if timeout < 100*time.Millisecond || timeout > 2*time.Minute {
		return errors.New("attachment scanner timeout is outside its bound")
	}
	addressSpace := policy.AddressSpaceBytes
	if addressSpace == 0 {
		addressSpace = defaultAddressSpace
	}
	if addressSpace < 512<<20 || addressSpace > 16<<30 {
		return errors.New("attachment scanner address-space limit is outside its bound")
	}
	cpuSeconds := policy.CPUSeconds
	if cpuSeconds == 0 {
		cpuSeconds = defaultCPUSeconds
	}
	if cpuSeconds < 1 || cpuSeconds > 120 {
		return errors.New("attachment scanner CPU limit is outside its bound")
	}
	maxProcesses := policy.MaxProcesses
	if maxProcesses == 0 {
		maxProcesses = defaultMaxProcesses
	}
	if maxProcesses < 64 || maxProcesses > 65535 {
		return errors.New("attachment scanner process limit is outside its bound")
	}
	previous := ""
	for _, scanner := range policy.Scanners {
		if !scannerIDPattern.MatchString(scanner.ID) || scanner.ID <= previous ||
			!filepath.IsAbs(scanner.Executable) || filepath.Clean(scanner.Executable) != scanner.Executable ||
			!canon.ValidDigest(scanner.ExecutableDigest) || len(scanner.Args) > 16 {
			return errors.New("invalid or noncanonical attachment scanner specification")
		}
		previous = scanner.ID
		for _, argument := range scanner.Args {
			if argument == "" || len(argument) > 256 || strings.ContainsAny(argument, "\x00\r\n") || !utf8.ValidString(argument) {
				return errors.New("invalid attachment scanner argument")
			}
		}
	}
	return nil
}

func runSandboxedScanner(parent context.Context, input *os.File, sandboxPath, resourceLimiterPath,
	scannerPath string, scanner ScannerSpec,
	metadata Metadata, plaintextDigest string, plaintextBytes uint64, policy AgentContentPolicy) (ScanVerdict, error) {
	if _, err := input.Seek(0, 0); err != nil {
		return ScanVerdict{}, errors.New("rewind attachment scanner input")
	}
	timeout := policy.ScannerTimeout
	if timeout == 0 {
		timeout = DefaultScannerTimeout
	}
	addressSpace := policy.AddressSpaceBytes
	if addressSpace == 0 {
		addressSpace = defaultAddressSpace
	}
	cpuSeconds := policy.CPUSeconds
	if cpuSeconds == 0 {
		cpuSeconds = defaultCPUSeconds
	}
	maxProcesses := policy.MaxProcesses
	if maxProcesses == 0 {
		maxProcesses = defaultMaxProcesses
	}
	ctx, cancel := context.WithTimeout(parent, timeout)
	defer cancel()
	arguments := []string{
		"--die-with-parent", "--new-session", "--unshare-all", "--cap-drop", "ALL", "--clearenv",
		"--setenv", "GOMEMLIMIT", "256MiB", "--setenv", "GOMAXPROCS", "2",
		"--ro-bind", "/usr", "/usr", "--ro-bind-try", "/lib", "/lib",
		"--ro-bind-try", "/lib64", "/lib64", "--proc", "/proc", "--dev", "/dev",
		"--tmpfs", "/tmp", "--dir", "/work", "--ro-bind-data", "0", "/work/input",
		"--ro-bind", scannerPath, "/scanner", "--ro-bind", resourceLimiterPath, "/prlimit",
		"--chdir", "/work", "--hostname", "tos-attachment-scan", "--",
		"/prlimit", fmt.Sprintf("--as=%d", addressSpace), fmt.Sprintf("--cpu=%d", cpuSeconds),
		fmt.Sprintf("--nproc=%d", maxProcesses), "--nofile=64", "--fsize=1048576", "--core=0", "--", "/scanner",
	}
	arguments = append(arguments, scanner.Args...)
	arguments = append(arguments, "--tos-scanner-id", scanner.ID, "--tos-declared-media-type", metadata.MediaType,
		"--tos-input", "/work/input")
	command := exec.CommandContext(ctx, sandboxPath, arguments...)
	command.Env = []string{}
	command.Dir = "/"
	command.Stdin = input
	command.WaitDelay = time.Second
	stdout := &boundedOutput{limit: MaxScanVerdictBytes}
	stderr := &boundedOutput{limit: MaxScanVerdictBytes}
	command.Stdout = stdout
	command.Stderr = stderr
	if err := command.Run(); err != nil {
		if ctx.Err() != nil {
			return ScanVerdict{}, fmt.Errorf("attachment scanner %s timed out or was canceled: %w", scanner.ID, ctx.Err())
		}
		return ScanVerdict{}, fmt.Errorf("attachment scanner %s failed", scanner.ID)
	}
	if stdout.overflow || stderr.overflow {
		return ScanVerdict{}, fmt.Errorf("attachment scanner %s exceeded its output bound", scanner.ID)
	}
	verdict, err := decodeScanVerdict(stdout.Bytes())
	if err != nil {
		return ScanVerdict{}, fmt.Errorf("attachment scanner %s returned an invalid verdict: %w", scanner.ID, err)
	}
	if verdict.ScannerID != scanner.ID || verdict.ScannerDigest != scanner.ExecutableDigest ||
		verdict.PlaintextDigest != plaintextDigest || verdict.SizeBytes != plaintextBytes ||
		verdict.DeclaredMediaType != metadata.MediaType || verdict.DetectedMediaType != metadata.MediaType {
		return ScanVerdict{}, fmt.Errorf("attachment scanner %s verdict does not bind the admitted content", scanner.ID)
	}
	return verdict, nil
}

func decodeScanVerdict(raw []byte) (ScanVerdict, error) {
	if len(raw) == 0 || len(raw) > MaxScanVerdictBytes {
		return ScanVerdict{}, errors.New("scan verdict is outside its bound")
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	var verdict ScanVerdict
	if err := decoder.Decode(&verdict); err != nil {
		return ScanVerdict{}, err
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return ScanVerdict{}, errors.New("scan verdict has trailing JSON")
	}
	if verdict.Schema != ScanVerdictSchema || !scannerIDPattern.MatchString(verdict.ScannerID) ||
		!canon.ValidDigest(verdict.ScannerDigest) || !canon.ValidDigest(verdict.PlaintextDigest) || verdict.SizeBytes == 0 ||
		!canonicalMediaType(verdict.DeclaredMediaType) || !canonicalMediaType(verdict.DetectedMediaType) ||
		(verdict.Decision != ScanAllow && verdict.Decision != ScanDeny) ||
		verdict.ReasonCode != "" && !scanReasonPattern.MatchString(verdict.ReasonCode) {
		return ScanVerdict{}, errors.New("invalid scan verdict")
	}
	return verdict, nil
}

func canonicalMediaType(value string) bool {
	parsed, parameters, err := mime.ParseMediaType(value)
	return err == nil && parsed == value && len(parameters) == 0
}

func copyPinnedScanner(directory string, index int, scanner ScannerSpec) (string, error) {
	path, err := stagePinnedExecutable(directory, fmt.Sprintf("scanner-%d", index), scanner.Executable, scanner.ExecutableDigest)
	if err != nil {
		return "", fmt.Errorf("stage attachment scanner %s: %w", scanner.ID, err)
	}
	return path, nil
}

// stagePinnedExecutable copies from the already validated open file, then
// verifies the copied bytes. Later pathname replacement cannot change the
// private inode used for this admission attempt.
func stagePinnedExecutable(directory, name, sourcePath, expectedDigest string) (string, error) {
	source, err := openPinnedExecutable(sourcePath)
	if err != nil {
		return "", err
	}
	defer source.Close()
	targetPath := filepath.Join(directory, name)
	target, err := os.OpenFile(targetPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o500)
	if err != nil {
		return "", errors.New("create private attachment scanner copy")
	}
	hash := sha256.New()
	written, copyErr := io.Copy(io.MultiWriter(target, hash), io.LimitReader(source, MaxScannerBinaryBytes+1))
	if copyErr != nil || written < 1 || written > MaxScannerBinaryBytes {
		_ = target.Close()
		return "", errors.New("copy attachment scanner executable")
	}
	if err := target.Sync(); err != nil {
		_ = target.Close()
		return "", errors.New("sync attachment scanner executable")
	}
	if err := target.Close(); err != nil {
		return "", errors.New("close attachment scanner executable")
	}
	actual := "sha256:" + hex.EncodeToString(hash.Sum(nil))
	if actual != expectedDigest {
		return "", errors.New("executable digest mismatch")
	}
	return targetPath, nil
}

// ExecutableDigest computes the SHA-256 identity of a bounded regular
// executable. It is intended for generating and checking local scanner policy.
func ExecutableDigest(path string) (string, error) {
	file, err := openPinnedExecutable(path)
	if err != nil {
		return "", err
	}
	defer file.Close()
	hash := sha256.New()
	written, err := io.Copy(hash, io.LimitReader(file, MaxScannerBinaryBytes+1))
	if err != nil || written < 1 || written > MaxScannerBinaryBytes {
		return "", errors.New("executable is outside its digest bound")
	}
	return "sha256:" + hex.EncodeToString(hash.Sum(nil)), nil
}

func openPinnedExecutable(path string) (*os.File, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return nil, errors.New("executable path must be absolute and canonical")
	}
	before, err := os.Lstat(path)
	if err != nil || !before.Mode().IsRegular() || before.Mode().Perm()&0o111 == 0 || before.Mode().Perm()&0o022 != 0 {
		return nil, errors.New("executable must be a non-writable regular file")
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, errors.New("open executable")
	}
	after, err := file.Stat()
	if err != nil || !os.SameFile(before, after) || !after.Mode().IsRegular() || after.Size() < 1 || after.Size() > MaxScannerBinaryBytes {
		_ = file.Close()
		return nil, errors.New("executable changed during validation")
	}
	return file, nil
}

type boundedOutput struct {
	buffer   bytes.Buffer
	limit    int
	overflow bool
}

func (w *boundedOutput) Write(value []byte) (int, error) {
	previous := w.buffer.Len()
	if w.buffer.Len() < w.limit {
		remaining := w.limit - w.buffer.Len()
		if remaining > len(value) {
			remaining = len(value)
		}
		_, _ = w.buffer.Write(value[:remaining])
	}
	if previous+len(value) > w.limit {
		w.overflow = true
	}
	return len(value), nil
}

func (w *boundedOutput) Bytes() []byte { return w.buffer.Bytes() }
