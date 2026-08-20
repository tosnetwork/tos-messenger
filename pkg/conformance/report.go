// Package conformance verifies signed reports produced by independent vector
// consumers. It verifies artifact identity and accountability, not the social
// fact that an implementation is organizationally independent.
package conformance

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"regexp"
	"sort"
	"strings"

	"github.com/tosnetwork/tos-messenger/internal/canon"
)

const Schema = "tos.messaging.conformance-report.v1"
const MaxReportBytes = 16 << 10

var labelPattern = regexp.MustCompile(`^[0-9A-Za-z][0-9A-Za-z._+/@:-]{0,127}$`)

type Artifact struct {
	Name   string `json:"name"`
	SHA256 string `json:"sha256"`
}
type Report struct {
	Schema               string     `json:"schema"`
	Implementation       string     `json:"implementation"`
	ImplementationCommit string     `json:"implementation_commit"`
	Toolchain            string     `json:"toolchain"`
	RunAtUnix            uint64     `json:"run_at_unix"`
	Artifacts            []Artifact `json:"artifacts"`
	PositiveChecks       uint32     `json:"positive_checks"`
	AdversarialChecks    uint32     `json:"adversarial_checks"`
	ConsumerPublicKeyHex string     `json:"consumer_public_key_hex"`
	SignatureHex         string     `json:"signature_hex"`
}

func Expected(objects, adversarial, e2ee string) ([]Artifact, error) {
	paths := map[string]string{"adversarial": adversarial, "e2ee": e2ee, "objects": objects}
	result := make([]Artifact, 0, len(paths))
	for name, path := range paths {
		info, err := os.Lstat(path)
		if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Size() > 64<<20 {
			return nil, errors.New("invalid conformance artifact")
		}
		raw, err := os.ReadFile(path)
		if err != nil {
			return nil, err
		}
		sum := sha256.Sum256(raw)
		result = append(result, Artifact{Name: name, SHA256: hex.EncodeToString(sum[:])})
	}
	sort.Slice(result, func(i, j int) bool { return result[i].Name < result[j].Name })
	return result, nil
}

func CanonicalBytes(report Report) ([]byte, error) {
	if err := validate(report, false); err != nil {
		return nil, err
	}
	buffer := bytes.NewBufferString(canon.DomainConformanceReport)
	canon.Text(buffer, Schema)
	canon.Text(buffer, report.Implementation)
	canon.Text(buffer, report.ImplementationCommit)
	canon.Text(buffer, report.Toolchain)
	canon.Uint64(buffer, report.RunAtUnix)
	canon.Uint32(buffer, report.PositiveChecks)
	canon.Uint32(buffer, report.AdversarialChecks)
	canon.Uint32(buffer, uint32(len(report.Artifacts)))
	for _, artifact := range report.Artifacts {
		canon.Text(buffer, artifact.Name)
		canon.Text(buffer, artifact.SHA256)
	}
	key, _ := hex.DecodeString(report.ConsumerPublicKeyHex)
	canon.Bytes(buffer, key)
	return buffer.Bytes(), nil
}

func Sign(report Report, key ed25519.PrivateKey) (Report, error) {
	if len(key) != ed25519.PrivateKeySize {
		return Report{}, errors.New("invalid conformance signing key")
	}
	report.Schema = Schema
	report.ConsumerPublicKeyHex = hex.EncodeToString(key.Public().(ed25519.PublicKey))
	report.SignatureHex = ""
	preimage, err := CanonicalBytes(report)
	if err != nil {
		return Report{}, err
	}
	report.SignatureHex = hex.EncodeToString(ed25519.Sign(key, preimage))
	return report, nil
}

func VerifyAgainst(report Report, expected []Artifact) error {
	if err := validate(report, true); err != nil {
		return err
	}
	if len(report.Artifacts) != len(expected) {
		return errors.New("conformance report consumed another artifact set")
	}
	for index := range expected {
		if report.Artifacts[index] != expected[index] {
			return errors.New("conformance report consumed another artifact set")
		}
	}
	preimage, err := CanonicalBytes(report)
	if err != nil {
		return err
	}
	key, _ := hex.DecodeString(report.ConsumerPublicKeyHex)
	signature, _ := hex.DecodeString(report.SignatureHex)
	if !ed25519.Verify(ed25519.PublicKey(key), preimage, signature) {
		return errors.New("invalid conformance report signature")
	}
	return nil
}

func EncodeJSON(report Report) ([]byte, error) {
	if err := validate(report, true); err != nil {
		return nil, err
	}
	return json.Marshal(report)
}
func DecodeJSON(raw []byte) (Report, error) {
	if len(raw) == 0 || len(raw) > MaxReportBytes {
		return Report{}, errors.New("conformance report is outside its bound")
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	var report Report
	if err := decoder.Decode(&report); err != nil {
		return Report{}, err
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return Report{}, errors.New("conformance report has trailing JSON")
	}
	if err := validate(report, true); err != nil {
		return Report{}, err
	}
	return report, nil
}

func validate(report Report, signed bool) error {
	if report.Schema != Schema || !labelPattern.MatchString(report.Implementation) || !labelPattern.MatchString(report.ImplementationCommit) || report.Toolchain == "" || len(report.Toolchain) > 256 || strings.TrimSpace(report.Toolchain) != report.Toolchain || report.RunAtUnix == 0 || report.PositiveChecks == 0 || report.AdversarialChecks == 0 || len(report.Artifacts) != 3 {
		return errors.New("invalid conformance report")
	}
	for index, artifact := range report.Artifacts {
		if !labelPattern.MatchString(artifact.Name) || len(artifact.SHA256) != 64 {
			return errors.New("invalid conformance artifact digest")
		}
		if _, err := hex.DecodeString(artifact.SHA256); err != nil {
			return errors.New("invalid conformance artifact digest")
		}
		if index > 0 && report.Artifacts[index-1].Name >= artifact.Name {
			return errors.New("conformance artifacts must be sorted and unique")
		}
	}
	key, err := hex.DecodeString(report.ConsumerPublicKeyHex)
	if err != nil || len(key) != ed25519.PublicKeySize || canon.IsZero(key) {
		return errors.New("invalid conformance consumer key")
	}
	if signed {
		signature, err := hex.DecodeString(report.SignatureHex)
		if err != nil || len(signature) != ed25519.SignatureSize {
			return errors.New("invalid conformance report signature")
		}
	}
	return nil
}
