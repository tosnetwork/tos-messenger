// Command tos-attachment-text-scanner is the minimal reference content
// inspector for inert UTF-8 text attachments. It is designed to run only
// through attachments.OpenForAgent's bubblewrap/prlimit boundary.
package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"unicode"
	"unicode/utf8"

	"github.com/tosnetwork/tos-messenger/internal/canon"
	"github.com/tosnetwork/tos-messenger/pkg/attachments"
)

const maxReferenceTextBytes = 8 << 20

func main() {
	if err := run(os.Args[1:], os.Stdout); err != nil {
		fmt.Fprintln(os.Stderr, "tos-attachment-text-scanner:", err)
		os.Exit(1)
	}
}

func run(arguments []string, output io.Writer) error {
	flags := flag.NewFlagSet("tos-attachment-text-scanner", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	scannerID := flags.String("tos-scanner-id", "", "bound scanner identifier")
	declared := flags.String("tos-declared-media-type", "", "declared attachment media type")
	input := flags.String("tos-input", "", "sandboxed read-only input path")
	if err := flags.Parse(arguments); err != nil || flags.NArg() != 0 || *scannerID == "" || *declared == "" || *input != "/work/input" {
		return errors.New("invalid scanner invocation")
	}
	file, err := os.Open(*input)
	if err != nil {
		return errors.New("open scanner input")
	}
	raw, err := io.ReadAll(io.LimitReader(file, maxReferenceTextBytes+1))
	closeErr := file.Close()
	if err != nil || closeErr != nil || len(raw) == 0 || len(raw) > maxReferenceTextBytes {
		return errors.New("scanner input is outside its bound")
	}
	executable, err := os.Executable()
	if err != nil {
		return errors.New("resolve scanner executable")
	}
	executableDigest, err := attachments.ExecutableDigest(executable)
	if err != nil {
		return errors.New("digest scanner executable")
	}
	decision, reason := inspectText(raw, *declared)
	verdict := attachments.ScanVerdict{Schema: attachments.ScanVerdictSchema, ScannerID: *scannerID,
		ScannerDigest: executableDigest, PlaintextDigest: canon.Digest(raw), SizeBytes: uint64(len(raw)),
		DeclaredMediaType: *declared, DetectedMediaType: *declared, Decision: decision, ReasonCode: reason}
	encoder := json.NewEncoder(output)
	encoder.SetEscapeHTML(false)
	return encoder.Encode(verdict)
}

func inspectText(raw []byte, declared string) (attachments.ScanDecision, string) {
	if declared != "text/plain" && declared != "text/markdown" {
		return attachments.ScanDeny, "unsupported_media_type"
	}
	if !utf8.Valid(raw) || bytes.IndexByte(raw, 0) >= 0 {
		return attachments.ScanDeny, "invalid_utf8_text"
	}
	for len(raw) > 0 {
		value, width := utf8.DecodeRune(raw)
		raw = raw[width:]
		if unicode.IsControl(value) && value != '\n' && value != '\t' {
			return attachments.ScanDeny, "unsafe_text_control"
		}
	}
	return attachments.ScanAllow, "utf8_text"
}
