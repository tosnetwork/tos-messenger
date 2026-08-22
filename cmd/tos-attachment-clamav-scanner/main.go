// Command tos-attachment-clamav-scanner adapts one pinned ClamScan engine and
// pinned official CVD/CLD snapshots to the Messenger scan-verdict protocol.
// It is intended to run only inside attachments.OpenForAgent's sandbox.
package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"

	"github.com/tosnetwork/tos-messenger/pkg/attachments"
)

const scannerResourceRoot = "/scanner-resources"

type stringList []string

func (s *stringList) String() string { return strings.Join(*s, ",") }
func (s *stringList) Set(value string) error {
	*s = append(*s, value)
	return nil
}

func main() {
	executable, err := os.Executable()
	if err != nil {
		fmt.Fprintln(os.Stderr, "tos-attachment-clamav-scanner: resolve scanner adapter executable")
		os.Exit(1)
	}
	if err := run(os.Args[1:], os.Stdout, scannerResourceRoot, "/work/input", executable); err != nil {
		fmt.Fprintln(os.Stderr, "tos-attachment-clamav-scanner:", err)
		os.Exit(1)
	}
}

func run(arguments []string, output io.Writer, resourceRoot, requiredInput, adapterExecutable string) error {
	flags := flag.NewFlagSet("tos-attachment-clamav-scanner", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	scannerID := flags.String("tos-scanner-id", "", "bound scanner identifier")
	declared := flags.String("tos-declared-media-type", "", "declared attachment media type")
	input := flags.String("tos-input", "", "sandboxed read-only input path")
	engineName := flags.String("engine-resource", "", "pinned ClamScan resource name")
	var databases stringList
	flags.Var(&databases, "database-resource", "pinned official CVD/CLD resource name")
	if err := flags.Parse(arguments); err != nil || flags.NArg() != 0 || *scannerID == "" || *declared == "" ||
		*input != requiredInput || !validResourceName(*engineName) || !validDatabaseSet(databases) ||
		resourceNamePresent(databases, *engineName) {
		return errors.New("invalid ClamAV scanner invocation")
	}
	if !filepath.IsAbs(resourceRoot) || filepath.Clean(resourceRoot) != resourceRoot {
		return errors.New("invalid scanner resource root")
	}

	file, err := os.Open(*input)
	if err != nil {
		return errors.New("open scanner input")
	}
	hash := sha256.New()
	size, copyErr := io.Copy(hash, io.LimitReader(file, int64(attachments.MaxPlaintextBytes)+1))
	closeErr := file.Close()
	if copyErr != nil || closeErr != nil || size < 1 || uint64(size) > attachments.MaxPlaintextBytes {
		return errors.New("scanner input is outside its bound")
	}

	resources := append([]string{*engineName}, databases...)
	evidence := make([]attachments.ScanResourceEvidence, 0, len(resources))
	for _, name := range resources {
		path := filepath.Join(resourceRoot, name)
		digest, err := attachments.ScannerResourceDigest(path, name == *engineName)
		if err != nil {
			return fmt.Errorf("digest pinned scanner resource %s", name)
		}
		evidence = append(evidence, attachments.ScanResourceEvidence{Name: name, Digest: digest})
	}
	sort.Slice(evidence, func(i, j int) bool { return evidence[i].Name < evidence[j].Name })

	engine := filepath.Join(resourceRoot, *engineName)
	engineArguments := []string{"--no-summary", "--quiet", "--official-db-only=yes",
		"--alert-encrypted=yes", "--alert-broken=yes", "--alert-exceeds-max=yes", fmt.Sprintf("--max-filesize=%d", size),
		fmt.Sprintf("--max-scansize=%d", size)}
	for _, name := range databases {
		engineArguments = append(engineArguments, "--database="+filepath.Join(resourceRoot, name))
	}
	engineArguments = append(engineArguments, "--", *input)
	command := exec.Command(engine, engineArguments...)
	command.Env = []string{}
	command.Dir = "/"
	command.Stdout = io.Discard
	command.Stderr = io.Discard
	decision, reason := attachments.ScanAllow, "clamav_clean"
	if err := command.Run(); err != nil {
		var exit *exec.ExitError
		if !errors.As(err, &exit) || exit.ExitCode() != 1 {
			return errors.New("ClamAV engine failed closed")
		}
		decision, reason = attachments.ScanDeny, "malware_detected"
	}
	adapterDigest, err := attachments.ExecutableDigest(adapterExecutable)
	if err != nil {
		return errors.New("digest scanner adapter executable")
	}
	verdict := attachments.ScanVerdict{Schema: attachments.ScanVerdictSchema, ScannerID: *scannerID,
		ScannerDigest: adapterDigest, PlaintextDigest: "sha256:" + hex.EncodeToString(hash.Sum(nil)), SizeBytes: uint64(size),
		DeclaredMediaType: *declared, DetectedMediaType: *declared, Decision: decision, ReasonCode: reason,
		Resources: evidence}
	encoder := json.NewEncoder(output)
	encoder.SetEscapeHTML(false)
	return encoder.Encode(verdict)
}

func resourceNamePresent(resources []string, name string) bool {
	index := sort.SearchStrings(resources, name)
	return index < len(resources) && resources[index] == name
}

func validDatabaseSet(databases []string) bool {
	if len(databases) < 2 || len(databases) > 3 || !sort.StringsAreSorted(databases) {
		return false
	}
	hasMain, hasDaily := false, false
	previous := ""
	for _, name := range databases {
		if !validResourceName(name) || name == previous ||
			!(strings.HasSuffix(name, ".cvd") || strings.HasSuffix(name, ".cld")) {
			return false
		}
		base := strings.TrimSuffix(strings.TrimSuffix(name, ".cvd"), ".cld")
		switch base {
		case "main":
			hasMain = true
		case "daily":
			hasDaily = true
		case "bytecode":
		default:
			return false
		}
		previous = name
	}
	return hasMain && hasDaily
}

func validResourceName(value string) bool {
	if value == "" || len(value) > 64 || value[0] < 'a' || value[0] > 'z' {
		return false
	}
	for _, character := range value {
		if character != '.' && character != '-' && (character < 'a' || character > 'z') &&
			(character < '0' || character > '9') {
			return false
		}
	}
	return true
}
