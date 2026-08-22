// Package attachmentcorpus defines signed, private hostile-corpus manifests
// and signed execution reports for attachment scanner release acceptance. It
// commits evidence identities only: organizational independence, corpus
// representativeness, and approval authority remain external facts.
package attachmentcorpus

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"mime"
	"regexp"
	"sort"
	"strings"

	"github.com/tosnetwork/tos-messenger/internal/canon"
)

const (
	ManifestSchema   = "tos.messaging.attachment-corpus-manifest.v1"
	ReportSchema     = "tos.messaging.attachment-corpus-report.v1"
	MaxManifestBytes = 1 << 20
	MaxReportBytes   = 1 << 20
	MaxSamples       = 256
)

type Decision string

const (
	DecisionAllow Decision = "allow"
	DecisionDeny  Decision = "deny"
)

var (
	identifierPattern = regexp.MustCompile(`^[0-9A-Za-z][0-9A-Za-z._:@+-]{0,127}$`)
	sampleNamePattern = regexp.MustCompile(`^[0-9A-Za-z][0-9A-Za-z._-]{0,127}$`)
	categoryPattern   = regexp.MustCompile(`^[a-z][a-z0-9.-]{0,63}$`)
	reasonPattern     = regexp.MustCompile(`^[a-z][a-z0-9_.-]{0,63}$`)
	commitPattern     = regexp.MustCompile(`^[0-9a-f]{40}$`)
)

// Sample commits a private file without placing its bytes in the repository.
// Name is deliberately a single path component, preventing traversal and
// making an approver's manifest portable between isolated acceptance hosts.
type Sample struct {
	Name             string   `json:"name"`
	SHA256           string   `json:"sha256"`
	SizeBytes        uint64   `json:"size_bytes"`
	Category         string   `json:"category"`
	MediaType        string   `json:"media_type"`
	ExpectedDecision Decision `json:"expected_decision"`
}

type Manifest struct {
	Schema               string   `json:"schema"`
	CorpusID             string   `json:"corpus_id"`
	Revision             string   `json:"revision"`
	ApprovedAtUnix       uint64   `json:"approved_at_unix"`
	Scope                string   `json:"scope"`
	Samples              []Sample `json:"samples"`
	ApproverPublicKeyHex string   `json:"approver_public_key_hex"`
	SignatureHex         string   `json:"signature_hex"`
}

// ResourceEvidence is the exact engine/database/signature/certificate set
// repeated by the scanner verdict after private staging.
type ResourceEvidence struct {
	Name   string `json:"name"`
	Digest string `json:"digest"`
}

type Result struct {
	Name             string             `json:"name"`
	SHA256           string             `json:"sha256"`
	ExpectedDecision Decision           `json:"expected_decision"`
	ObservedDecision Decision           `json:"observed_decision"`
	ScannerID        string             `json:"scanner_id"`
	ScannerDigest    string             `json:"scanner_digest"`
	ReasonCode       string             `json:"reason_code"`
	Resources        []ResourceEvidence `json:"resources"`
}

type Report struct {
	Schema                string   `json:"schema"`
	ManifestSHA256        string   `json:"manifest_sha256"`
	AdmissionPolicySHA256 string   `json:"admission_policy_sha256"`
	RunnerCommit          string   `json:"runner_commit"`
	Toolchain             string   `json:"toolchain"`
	RunAtUnix             uint64   `json:"run_at_unix"`
	Results               []Result `json:"results"`
	RunnerPublicKeyHex    string   `json:"runner_public_key_hex"`
	SignatureHex          string   `json:"signature_hex"`
}

func CanonicalManifestBytes(manifest Manifest) ([]byte, error) {
	if err := validateManifest(manifest, false); err != nil {
		return nil, err
	}
	buffer := bytes.NewBufferString(canon.DomainAttachmentCorpusManifest)
	canon.Text(buffer, ManifestSchema)
	canon.Text(buffer, manifest.CorpusID)
	canon.Text(buffer, manifest.Revision)
	canon.Uint64(buffer, manifest.ApprovedAtUnix)
	canon.Text(buffer, manifest.Scope)
	canon.Uint32(buffer, uint32(len(manifest.Samples)))
	for _, sample := range manifest.Samples {
		canon.Text(buffer, sample.Name)
		canon.Text(buffer, sample.SHA256)
		canon.Uint64(buffer, sample.SizeBytes)
		canon.Text(buffer, sample.Category)
		canon.Text(buffer, sample.MediaType)
		canon.Text(buffer, string(sample.ExpectedDecision))
	}
	key, _ := hex.DecodeString(manifest.ApproverPublicKeyHex)
	canon.Bytes(buffer, key)
	return buffer.Bytes(), nil
}

func SignManifest(manifest Manifest, key ed25519.PrivateKey) (Manifest, error) {
	if len(key) != ed25519.PrivateKeySize {
		return Manifest{}, errors.New("invalid corpus approver key")
	}
	manifest.Schema = ManifestSchema
	manifest.ApproverPublicKeyHex = hex.EncodeToString(key.Public().(ed25519.PublicKey))
	manifest.SignatureHex = ""
	preimage, err := CanonicalManifestBytes(manifest)
	if err != nil {
		return Manifest{}, err
	}
	manifest.SignatureHex = hex.EncodeToString(ed25519.Sign(key, preimage))
	return manifest, nil
}

func VerifyManifest(manifest Manifest, expectedApprover ed25519.PublicKey) error {
	if len(expectedApprover) != ed25519.PublicKeySize || canon.IsZero(expectedApprover) {
		return errors.New("invalid expected corpus approver key")
	}
	if err := validateManifest(manifest, true); err != nil {
		return err
	}
	key, _ := hex.DecodeString(manifest.ApproverPublicKeyHex)
	if !bytes.Equal(key, expectedApprover) {
		return errors.New("corpus manifest has another approver")
	}
	preimage, err := CanonicalManifestBytes(manifest)
	if err != nil {
		return err
	}
	signature, _ := hex.DecodeString(manifest.SignatureHex)
	if !ed25519.Verify(expectedApprover, preimage, signature) {
		return errors.New("invalid corpus manifest signature")
	}
	return nil
}

func CanonicalReportBytes(report Report) ([]byte, error) {
	if err := validateReport(report, false); err != nil {
		return nil, err
	}
	buffer := bytes.NewBufferString(canon.DomainAttachmentCorpusReport)
	canon.Text(buffer, ReportSchema)
	canon.Text(buffer, report.ManifestSHA256)
	canon.Text(buffer, report.AdmissionPolicySHA256)
	canon.Text(buffer, report.RunnerCommit)
	canon.Text(buffer, report.Toolchain)
	canon.Uint64(buffer, report.RunAtUnix)
	canon.Uint32(buffer, uint32(len(report.Results)))
	for _, result := range report.Results {
		canon.Text(buffer, result.Name)
		canon.Text(buffer, result.SHA256)
		canon.Text(buffer, string(result.ExpectedDecision))
		canon.Text(buffer, string(result.ObservedDecision))
		canon.Text(buffer, result.ScannerID)
		canon.Text(buffer, result.ScannerDigest)
		canon.Text(buffer, result.ReasonCode)
		canon.Uint32(buffer, uint32(len(result.Resources)))
		for _, resource := range result.Resources {
			canon.Text(buffer, resource.Name)
			canon.Text(buffer, resource.Digest)
		}
	}
	key, _ := hex.DecodeString(report.RunnerPublicKeyHex)
	canon.Bytes(buffer, key)
	return buffer.Bytes(), nil
}

func SignReport(report Report, key ed25519.PrivateKey) (Report, error) {
	if len(key) != ed25519.PrivateKeySize {
		return Report{}, errors.New("invalid corpus report key")
	}
	report.Schema = ReportSchema
	report.RunnerPublicKeyHex = hex.EncodeToString(key.Public().(ed25519.PublicKey))
	report.SignatureHex = ""
	preimage, err := CanonicalReportBytes(report)
	if err != nil {
		return Report{}, err
	}
	report.SignatureHex = hex.EncodeToString(ed25519.Sign(key, preimage))
	return report, nil
}

func VerifyReport(report Report, manifest Manifest, manifestSHA256, policySHA256 string, expectedRunner ed25519.PublicKey) error {
	if len(expectedRunner) != ed25519.PublicKeySize || canon.IsZero(expectedRunner) {
		return errors.New("invalid expected corpus runner key")
	}
	if err := validateReport(report, true); err != nil {
		return err
	}
	if report.ManifestSHA256 != manifestSHA256 || report.AdmissionPolicySHA256 != policySHA256 {
		return errors.New("corpus report names another manifest or policy")
	}
	if len(report.Results) != len(manifest.Samples) {
		return errors.New("corpus report omits approved samples")
	}
	for index, sample := range manifest.Samples {
		result := report.Results[index]
		if result.Name != sample.Name || result.SHA256 != sample.SHA256 ||
			result.ExpectedDecision != sample.ExpectedDecision {
			return errors.New("corpus report substitutes an approved sample")
		}
	}
	key, _ := hex.DecodeString(report.RunnerPublicKeyHex)
	if !bytes.Equal(key, expectedRunner) {
		return errors.New("corpus report has another runner")
	}
	preimage, err := CanonicalReportBytes(report)
	if err != nil {
		return err
	}
	signature, _ := hex.DecodeString(report.SignatureHex)
	if !ed25519.Verify(expectedRunner, preimage, signature) {
		return errors.New("invalid corpus report signature")
	}
	return nil
}

func EncodeManifestJSON(manifest Manifest) ([]byte, error) {
	if err := validateManifest(manifest, true); err != nil {
		return nil, err
	}
	return json.Marshal(manifest)
}

func DecodeManifestJSON(raw []byte) (Manifest, error) {
	var manifest Manifest
	if err := decodeStrict(raw, MaxManifestBytes, &manifest); err != nil {
		return Manifest{}, err
	}
	if err := validateManifest(manifest, true); err != nil {
		return Manifest{}, err
	}
	return manifest, nil
}

// DecodeManifestDraftJSON accepts the exact unsigned shape used by an external
// approver. The authority fields must be empty; SignManifest derives them from
// the separately custodied key instead of trusting draft-supplied identity.
func DecodeManifestDraftJSON(raw []byte) (Manifest, error) {
	var manifest Manifest
	if err := decodeStrict(raw, MaxManifestBytes, &manifest); err != nil {
		return Manifest{}, err
	}
	if manifest.ApproverPublicKeyHex != "" || manifest.SignatureHex != "" {
		return Manifest{}, errors.New("attachment corpus draft already contains authority")
	}
	validation := manifest
	validation.ApproverPublicKeyHex = strings.Repeat("01", ed25519.PublicKeySize)
	if err := validateManifest(validation, false); err != nil {
		return Manifest{}, err
	}
	return manifest, nil
}

func EncodeReportJSON(report Report) ([]byte, error) {
	if err := validateReport(report, true); err != nil {
		return nil, err
	}
	return json.Marshal(report)
}

func DecodeReportJSON(raw []byte) (Report, error) {
	var report Report
	if err := decodeStrict(raw, MaxReportBytes, &report); err != nil {
		return Report{}, err
	}
	if err := validateReport(report, true); err != nil {
		return Report{}, err
	}
	return report, nil
}

func SHA256Hex(raw []byte) string {
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}

func validateManifest(manifest Manifest, signed bool) error {
	if manifest.Schema != ManifestSchema || !identifierPattern.MatchString(manifest.CorpusID) ||
		!identifierPattern.MatchString(manifest.Revision) || manifest.ApprovedAtUnix == 0 ||
		manifest.Scope == "" || len(manifest.Scope) > 512 || strings.TrimSpace(manifest.Scope) != manifest.Scope ||
		len(manifest.Samples) < 2 || len(manifest.Samples) > MaxSamples {
		return errors.New("invalid attachment corpus manifest")
	}
	allows, denies := 0, 0
	for index, sample := range manifest.Samples {
		if !sampleNamePattern.MatchString(sample.Name) || !validDigest(sample.SHA256) || sample.SizeBytes == 0 ||
			sample.SizeBytes > 128<<10 || !categoryPattern.MatchString(sample.Category) ||
			!canonicalMediaType(sample.MediaType) ||
			(sample.ExpectedDecision != DecisionAllow && sample.ExpectedDecision != DecisionDeny) {
			return errors.New("invalid attachment corpus sample")
		}
		if index > 0 && manifest.Samples[index-1].Name >= sample.Name {
			return errors.New("attachment corpus samples must be sorted and unique")
		}
		if sample.ExpectedDecision == DecisionAllow {
			allows++
		} else {
			denies++
		}
	}
	if allows == 0 || denies == 0 {
		return errors.New("attachment corpus needs allow and deny controls")
	}
	key, err := hex.DecodeString(manifest.ApproverPublicKeyHex)
	if err != nil || len(key) != ed25519.PublicKeySize || canon.IsZero(key) {
		return errors.New("invalid attachment corpus approver key")
	}
	if signed {
		signature, err := hex.DecodeString(manifest.SignatureHex)
		if err != nil || len(signature) != ed25519.SignatureSize {
			return errors.New("invalid attachment corpus signature")
		}
	}
	return nil
}

func validateReport(report Report, signed bool) error {
	if report.Schema != ReportSchema || !validDigest(report.ManifestSHA256) ||
		!validDigest(report.AdmissionPolicySHA256) || !commitPattern.MatchString(report.RunnerCommit) ||
		report.Toolchain == "" || len(report.Toolchain) > 256 || strings.TrimSpace(report.Toolchain) != report.Toolchain ||
		report.RunAtUnix == 0 || len(report.Results) < 2 || len(report.Results) > MaxSamples {
		return errors.New("invalid attachment corpus report")
	}
	for index, result := range report.Results {
		if !sampleNamePattern.MatchString(result.Name) || !validDigest(result.SHA256) ||
			(result.ExpectedDecision != DecisionAllow && result.ExpectedDecision != DecisionDeny) ||
			result.ObservedDecision != result.ExpectedDecision || !identifierPattern.MatchString(result.ScannerID) ||
			!validDigest(strings.TrimPrefix(result.ScannerDigest, "sha256:")) || !reasonPattern.MatchString(result.ReasonCode) ||
			len(result.Resources) == 0 || len(result.Resources) > 8 {
			return errors.New("invalid attachment corpus result")
		}
		if index > 0 && report.Results[index-1].Name >= result.Name {
			return errors.New("attachment corpus results must be sorted and unique")
		}
		for resourceIndex, resource := range result.Resources {
			if !sampleNamePattern.MatchString(resource.Name) || !validDigest(strings.TrimPrefix(resource.Digest, "sha256:")) {
				return errors.New("invalid attachment corpus resource evidence")
			}
			if resourceIndex > 0 && result.Resources[resourceIndex-1].Name >= resource.Name {
				return errors.New("attachment corpus resources must be sorted and unique")
			}
		}
	}
	key, err := hex.DecodeString(report.RunnerPublicKeyHex)
	if err != nil || len(key) != ed25519.PublicKeySize || canon.IsZero(key) {
		return errors.New("invalid attachment corpus runner key")
	}
	if signed {
		signature, err := hex.DecodeString(report.SignatureHex)
		if err != nil || len(signature) != ed25519.SignatureSize {
			return errors.New("invalid attachment corpus report signature")
		}
	}
	return nil
}

func decodeStrict(raw []byte, limit int, target any) error {
	if len(raw) == 0 || len(raw) > limit {
		return errors.New("attachment corpus JSON is outside its bound")
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return err
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return errors.New("attachment corpus JSON has trailing data")
	}
	return nil
}

func validDigest(value string) bool {
	if len(value) != 64 || strings.ToLower(value) != value {
		return false
	}
	decoded, err := hex.DecodeString(value)
	return err == nil && !canon.IsZero(decoded)
}

func canonicalMediaType(value string) bool {
	parsed, parameters, err := mime.ParseMediaType(value)
	return err == nil && len(parameters) == 0 && parsed == value && strings.ToLower(value) == value
}

// SortResults is provided for runners that execute samples concurrently but
// must sign one deterministic report.
func SortResults(results []Result) {
	sort.Slice(results, func(i, j int) bool { return results[i].Name < results[j].Name })
}
