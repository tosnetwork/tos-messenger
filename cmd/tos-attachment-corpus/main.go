// Command tos-attachment-corpus runs and verifies externally approved private
// attachment scanner corpora. Corpus bytes remain outside the repository.
package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"runtime/debug"
	"strings"
	"syscall"
	"time"

	"github.com/tosnetwork/tos-messenger/internal/canon"
	"github.com/tosnetwork/tos-messenger/internal/securefile"
	"github.com/tosnetwork/tos-messenger/pkg/attachmentcorpus"
	"github.com/tosnetwork/tos-messenger/pkg/attachments"
	"github.com/tosnetwork/tos-messenger/pkg/daemon"
)

const maxPolicyBytes = 1 << 20

func main() { os.Exit(run(os.Args[1:], os.Stdout, os.Stderr)) }

func run(arguments []string, output, errorOutput io.Writer) int {
	if len(arguments) == 0 {
		fmt.Fprintln(errorOutput, "usage: tos-attachment-corpus keygen|sign|run|verify [flags]")
		return 2
	}
	switch arguments[0] {
	case "keygen":
		if err := generateKey(arguments[1:], output, errorOutput); err != nil {
			fmt.Fprintln(errorOutput, err)
			return 1
		}
		return 0
	case "sign":
		if err := signManifest(arguments[1:], output, errorOutput); err != nil {
			fmt.Fprintln(errorOutput, err)
			return 1
		}
		return 0
	case "run":
		if err := runCorpus(arguments[1:], output, errorOutput); err != nil {
			fmt.Fprintln(errorOutput, err)
			return 1
		}
		return 0
	case "verify":
		if err := verifyCorpus(arguments[1:], output, errorOutput); err != nil {
			fmt.Fprintln(errorOutput, err)
			return 1
		}
		return 0
	default:
		fmt.Fprintln(errorOutput, "usage: tos-attachment-corpus keygen|sign|run|verify [flags]")
		return 2
	}
}

func generateKey(arguments []string, output, errorOutput io.Writer) error {
	flags := flag.NewFlagSet("keygen", flag.ContinueOnError)
	flags.SetOutput(errorOutput)
	keyPath := flags.String("output", "", "new mode-0600 canonical Ed25519 key")
	if flags.Parse(arguments) != nil || flags.NArg() != 0 || *keyPath == "" {
		return errors.New("keygen requires output")
	}
	if !cleanAbsolute(*keyPath) {
		return errors.New("key output must be a clean absolute path")
	}
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return err
	}
	defer clear(private)
	if err := writeNewPrivate(*keyPath, []byte(hex.EncodeToString(private)+"\n")); err != nil {
		return err
	}
	fmt.Fprintf(output, "public_key=%s\n", hex.EncodeToString(public))
	return nil
}

func signManifest(arguments []string, output, errorOutput io.Writer) error {
	flags := flag.NewFlagSet("sign", flag.ContinueOnError)
	flags.SetOutput(errorOutput)
	draftPath := flags.String("draft", "", "strict unsigned corpus manifest draft")
	keyPath := flags.String("approver-key", "", "mode-0600 canonical Ed25519 approver key")
	manifestPath := flags.String("output", "", "new signed manifest path")
	if flags.Parse(arguments) != nil || flags.NArg() != 0 || *draftPath == "" || *keyPath == "" || *manifestPath == "" {
		return errors.New("sign requires draft, approver-key, and output")
	}
	if !cleanAbsolute(*manifestPath) {
		return errors.New("manifest output must be a clean absolute path")
	}
	raw, err := securefile.ReadBoundedRegular(*draftPath, attachmentcorpus.MaxManifestBytes)
	if err != nil {
		return err
	}
	draft, err := attachmentcorpus.DecodeManifestDraftJSON(raw)
	if err != nil {
		return err
	}
	key, err := readPrivateKey(*keyPath)
	if err != nil {
		return err
	}
	defer clear(key)
	manifest, err := attachmentcorpus.SignManifest(draft, key)
	if err != nil {
		return err
	}
	manifestRaw, err := attachmentcorpus.EncodeManifestJSON(manifest)
	if err != nil {
		return err
	}
	storedManifest := append(manifestRaw, '\n')
	if err := writeNewPrivate(*manifestPath, storedManifest); err != nil {
		return err
	}
	fmt.Fprintf(output, "corpus=%s revision=%s manifest_sha256=%s approver_public_key=%s\n",
		manifest.CorpusID, manifest.Revision, attachmentcorpus.SHA256Hex(storedManifest), manifest.ApproverPublicKeyHex)
	return nil
}

func runCorpus(arguments []string, output, errorOutput io.Writer) error {
	flags := flag.NewFlagSet("run", flag.ContinueOnError)
	flags.SetOutput(errorOutput)
	manifestPath := flags.String("manifest", "", "signed approved corpus manifest")
	samplesRoot := flags.String("samples", "", "private corpus sample directory")
	policyPath := flags.String("admission-policy", "", "strict attachment admission policy JSON")
	approverText := flags.String("approver-public-key", "", "pinned 64-hex Ed25519 approver key")
	runnerKeyPath := flags.String("runner-key", "", "mode-0600 canonical Ed25519 report key")
	reportPath := flags.String("output", "", "new signed report path")
	if flags.Parse(arguments) != nil || flags.NArg() != 0 || *manifestPath == "" || *samplesRoot == "" ||
		*policyPath == "" || *approverText == "" || *runnerKeyPath == "" || *reportPath == "" {
		return errors.New("run requires manifest, samples, admission-policy, approver-public-key, runner-key, and output")
	}
	if !cleanAbsolute(*samplesRoot) || !cleanAbsolute(*reportPath) {
		return errors.New("samples and output must be clean absolute paths")
	}
	manifestRaw, manifest, err := readManifest(*manifestPath, *approverText)
	if err != nil {
		return err
	}
	policyRaw, policy, err := readPolicy(*policyPath)
	if err != nil {
		return err
	}
	if len(policy.Scanners) != 1 || policy.Scanners[0].ID != "clamav-official" ||
		len(policy.Scanners[0].Resources) != attachments.MaxScannerResources {
		return errors.New("corpus acceptance requires exactly one clamav-official scanner with all eight resources")
	}
	key, err := readPrivateKey(*runnerKeyPath)
	if err != nil {
		return err
	}
	defer clear(key)
	commit, toolchain, err := buildIdentity()
	if err != nil {
		return err
	}
	now := time.Now().UTC()
	if manifest.ApprovedAtUnix > uint64(now.Unix()) {
		return errors.New("corpus approval time is in the future")
	}
	results := make([]attachmentcorpus.Result, 0, len(manifest.Samples))
	for _, sample := range manifest.Samples {
		result, err := evaluateSample(context.Background(), *samplesRoot, sample, policy, now)
		if err != nil {
			return fmt.Errorf("sample %s: %w", sample.Name, err)
		}
		results = append(results, result)
	}
	attachmentcorpus.SortResults(results)
	report, err := attachmentcorpus.SignReport(attachmentcorpus.Report{
		Schema: attachmentcorpus.ReportSchema, ManifestSHA256: attachmentcorpus.SHA256Hex(manifestRaw),
		AdmissionPolicySHA256: attachmentcorpus.SHA256Hex(policyRaw), RunnerCommit: commit,
		Toolchain: toolchain, RunAtUnix: uint64(now.Unix()), Results: results,
	}, key)
	if err != nil {
		return err
	}
	reportRaw, err := attachmentcorpus.EncodeReportJSON(report)
	if err != nil {
		return err
	}
	storedReport := append(reportRaw, '\n')
	if err := writeNewPrivate(*reportPath, storedReport); err != nil {
		return err
	}
	fmt.Fprintf(output, "corpus=%s revision=%s samples=%d report_sha256=%s\n",
		manifest.CorpusID, manifest.Revision, len(results), attachmentcorpus.SHA256Hex(storedReport))
	return nil
}

func verifyCorpus(arguments []string, output, errorOutput io.Writer) error {
	flags := flag.NewFlagSet("verify", flag.ContinueOnError)
	flags.SetOutput(errorOutput)
	manifestPath := flags.String("manifest", "", "signed approved corpus manifest")
	policyPath := flags.String("admission-policy", "", "strict attachment admission policy JSON")
	reportPath := flags.String("report", "", "signed corpus execution report")
	approverText := flags.String("approver-public-key", "", "pinned 64-hex Ed25519 approver key")
	runnerText := flags.String("runner-public-key", "", "pinned 64-hex Ed25519 runner key")
	if flags.Parse(arguments) != nil || flags.NArg() != 0 || *manifestPath == "" || *policyPath == "" ||
		*reportPath == "" || *approverText == "" || *runnerText == "" {
		return errors.New("verify requires manifest, admission-policy, report, approver-public-key, and runner-public-key")
	}
	manifestRaw, manifest, err := readManifest(*manifestPath, *approverText)
	if err != nil {
		return err
	}
	policyRaw, _, err := readPolicy(*policyPath)
	if err != nil {
		return err
	}
	reportRaw, err := securefile.ReadBoundedRegular(*reportPath, attachmentcorpus.MaxReportBytes)
	if err != nil {
		return err
	}
	report, err := attachmentcorpus.DecodeReportJSON(reportRaw)
	if err != nil {
		return err
	}
	runner, err := decodePublicKey(*runnerText)
	if err != nil {
		return err
	}
	if err := attachmentcorpus.VerifyReport(report, manifest, attachmentcorpus.SHA256Hex(manifestRaw),
		attachmentcorpus.SHA256Hex(policyRaw), runner); err != nil {
		return err
	}
	fmt.Fprintf(output, "corpus=%s revision=%s samples=%d runner_commit=%s\n",
		manifest.CorpusID, manifest.Revision, len(report.Results), report.RunnerCommit)
	return nil
}

func evaluateSample(ctx context.Context, root string, sample attachmentcorpus.Sample,
	policy attachments.AgentContentPolicy, now time.Time,
) (attachmentcorpus.Result, error) {
	path := filepath.Join(root, sample.Name)
	raw, err := readBoundedProtected(path, 128<<10, false)
	if err != nil {
		return attachmentcorpus.Result{}, err
	}
	if uint64(len(raw)) != sample.SizeBytes || attachmentcorpus.SHA256Hex(raw) != sample.SHA256 {
		return attachmentcorpus.Result{}, errors.New("corpus sample does not match its approved identity")
	}
	ref, chunks, err := attachments.Seal(rand.Reader, raw, attachments.Metadata{Filename: sample.Name,
		MediaType: sample.MediaType, PlaintextDigest: canon.Digest(raw), ExpiresAtUnix: uint64(now.Add(time.Hour).Unix())})
	if err != nil {
		return attachmentcorpus.Result{}, err
	}
	admitted, admissionErr := attachments.OpenForAgent(ctx, ref, chunks,
		attachments.Policy{MaxPlaintextBytes: policy.MaxPlaintextBytes, AllowedMediaTypes: policy.AllowedMediaTypes},
		policy, now)
	var verdict attachments.ScanVerdict
	observed := attachmentcorpus.DecisionAllow
	if admissionErr == nil {
		defer clear(admitted.Plaintext)
		if len(admitted.Report.Scans) != 1 {
			return attachmentcorpus.Result{}, errors.New("corpus admission returned an unexpected scanner count")
		}
		verdict = admitted.Report.Scans[0]
	} else {
		var denied *attachments.ScanDeniedError
		if !errors.As(admissionErr, &denied) {
			return attachmentcorpus.Result{}, fmt.Errorf("scanner infrastructure failed instead of returning deny: %w", admissionErr)
		}
		observed = attachmentcorpus.DecisionDeny
		verdict = denied.Verdict
	}
	if observed != sample.ExpectedDecision {
		return attachmentcorpus.Result{}, fmt.Errorf("observed %s, approved expectation is %s", observed, sample.ExpectedDecision)
	}
	expectedReason := "clamav_clean"
	if observed == attachmentcorpus.DecisionDeny {
		expectedReason = "malware_detected"
	}
	if verdict.ReasonCode != expectedReason || len(verdict.Resources) != attachments.MaxScannerResources {
		return attachmentcorpus.Result{}, errors.New("ClamAV corpus verdict omitted its exact decision or resource evidence")
	}
	resources := make([]attachmentcorpus.ResourceEvidence, len(verdict.Resources))
	for index, resource := range verdict.Resources {
		resources[index] = attachmentcorpus.ResourceEvidence{Name: resource.Name, Digest: resource.Digest}
	}
	return attachmentcorpus.Result{Name: sample.Name, SHA256: sample.SHA256,
		ExpectedDecision: sample.ExpectedDecision, ObservedDecision: observed,
		ScannerID: verdict.ScannerID, ScannerDigest: verdict.ScannerDigest,
		ReasonCode: verdict.ReasonCode, Resources: resources}, nil
}

func readManifest(path, approverText string) ([]byte, attachmentcorpus.Manifest, error) {
	raw, err := securefile.ReadBoundedRegular(path, attachmentcorpus.MaxManifestBytes)
	if err != nil {
		return nil, attachmentcorpus.Manifest{}, err
	}
	manifest, err := attachmentcorpus.DecodeManifestJSON(raw)
	if err != nil {
		return nil, attachmentcorpus.Manifest{}, err
	}
	approver, err := decodePublicKey(approverText)
	if err != nil {
		return nil, attachmentcorpus.Manifest{}, err
	}
	if err := attachmentcorpus.VerifyManifest(manifest, approver); err != nil {
		return nil, attachmentcorpus.Manifest{}, err
	}
	return raw, manifest, nil
}

func readPolicy(path string) ([]byte, attachments.AgentContentPolicy, error) {
	raw, err := securefile.ReadBoundedRegular(path, maxPolicyBytes)
	if err != nil {
		return nil, attachments.AgentContentPolicy{}, err
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	var config daemon.AttachmentAdmissionConfig
	if err := decoder.Decode(&config); err != nil {
		return nil, attachments.AgentContentPolicy{}, err
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return nil, attachments.AgentContentPolicy{}, errors.New("attachment admission policy has trailing JSON")
	}
	_, policy, _, err := config.Policies()
	if err != nil {
		return nil, attachments.AgentContentPolicy{}, err
	}
	return raw, policy, nil
}

func decodePublicKey(value string) (ed25519.PublicKey, error) {
	if len(value) != ed25519.PublicKeySize*2 || value != strings.ToLower(value) {
		return nil, errors.New("public key must be 64 lowercase hex digits")
	}
	decoded, err := hex.DecodeString(value)
	if err != nil || canon.IsZero(decoded) {
		return nil, errors.New("invalid Ed25519 public key")
	}
	return ed25519.PublicKey(decoded), nil
}

func readPrivateKey(path string) (ed25519.PrivateKey, error) {
	raw, err := readBoundedProtected(path, 130, true)
	if err != nil {
		return nil, err
	}
	text := strings.TrimSuffix(string(raw), "\n")
	decoded, err := hex.DecodeString(text)
	if err != nil || len(decoded) != ed25519.PrivateKeySize || text != strings.ToLower(text) {
		return nil, errors.New("signing key must contain 128 lowercase hex digits")
	}
	key := ed25519.PrivateKey(decoded)
	if !bytes.Equal(ed25519.NewKeyFromSeed(key[:ed25519.SeedSize]), key) {
		clear(key)
		return nil, errors.New("signing key public half does not reproduce its seed")
	}
	return key, nil
}

func buildIdentity() (string, string, error) {
	info, ok := debug.ReadBuildInfo()
	if !ok {
		return "", "", errors.New("corpus runner has no Go build identity")
	}
	settings := make(map[string]string, len(info.Settings))
	for _, setting := range info.Settings {
		settings[setting.Key] = setting.Value
	}
	commit := settings["vcs.revision"]
	if len(commit) != 40 || strings.ToLower(commit) != commit || settings["vcs.modified"] != "false" {
		return "", "", errors.New("corpus runner must be built from an exact unmodified commit")
	}
	return commit, runtime.Version() + " " + runtime.GOOS + "/" + runtime.GOARCH, nil
}

func writeNewPrivate(path string, raw []byte) error {
	if !cleanAbsolute(path) {
		return errors.New("report path must be clean and absolute")
	}
	if _, err := os.Lstat(path); err == nil {
		return errors.New("corpus report already exists")
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	file, err := os.CreateTemp(filepath.Dir(path), ".attachment-corpus-report-")
	if err != nil {
		return err
	}
	temporary := file.Name()
	defer os.Remove(temporary)
	if err := file.Chmod(0o600); err != nil {
		_ = file.Close()
		return err
	}
	if _, err := file.Write(raw); err != nil {
		_ = file.Close()
		return err
	}
	if err := file.Sync(); err != nil {
		_ = file.Close()
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	if err := os.Link(temporary, path); err != nil {
		return err
	}
	if err := os.Remove(temporary); err != nil {
		return err
	}
	directory, err := os.Open(filepath.Dir(path))
	if err != nil {
		return err
	}
	err = directory.Sync()
	_ = directory.Close()
	return err
}

func cleanAbsolute(path string) bool {
	return filepath.IsAbs(path) && filepath.Clean(path) == path
}

func readBoundedProtected(path string, limit int64, secret bool) ([]byte, error) {
	if path == "" || limit < 1 {
		return nil, errors.New("invalid protected file request")
	}
	pathInfo, err := os.Lstat(path)
	if err != nil || !protectedMode(pathInfo, secret) {
		return nil, errors.New("protected input has unsafe ownership, mode, or type")
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, errors.New("open protected input")
	}
	defer file.Close()
	openedInfo, err := file.Stat()
	if err != nil || !os.SameFile(pathInfo, openedInfo) || !protectedMode(openedInfo, secret) ||
		openedInfo.Size() < 1 || openedInfo.Size() > limit {
		return nil, errors.New("protected input changed or exceeds its bound")
	}
	raw, err := io.ReadAll(io.LimitReader(file, limit+1))
	if err != nil || len(raw) == 0 || int64(len(raw)) > limit {
		return nil, errors.New("read protected input")
	}
	return raw, nil
}

func protectedMode(info os.FileInfo, secret bool) bool {
	if info == nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		return false
	}
	stat, ok := infoSys(info)
	if !ok {
		return false
	}
	if secret {
		return stat.Uid == uint32(os.Geteuid()) && info.Mode().Perm() == 0o600
	}
	return info.Mode().Perm()&0o022 == 0
}

func infoSys(info os.FileInfo) (*syscall.Stat_t, bool) {
	if info == nil {
		return nil, false
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	return stat, ok
}

func clear(value []byte) {
	for index := range value {
		value[index] = 0
	}
}
