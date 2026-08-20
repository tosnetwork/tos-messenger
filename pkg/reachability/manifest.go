package reachability

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"strings"

	"github.com/tosnetwork/tos-messenger/internal/canon"
)

const (
	// CollectorManifestSchema is the strict schema of a collector manifest.
	CollectorManifestSchema = "tos.messaging.reachability-collector-manifest.v1"

	// maxManifestField bounds every free-text manifest field. A manifest is a
	// build description, not a document, and an unbounded field is a preimage a
	// reporter chooses the size of.
	maxManifestField = 256
)

// CollectorManifest is the content-addressed description of one collector
// build.
//
// A trial's commits name two repository revisions, which was enough provenance
// while every collector was this repository's pure-Go binary and nothing else.
// With a native probe sidecar in another repository, one endpoint is really an
// orchestrator at some commit driving an ADNL implementation at some commit,
// through a dependency at some version, compiled by some toolchain for some
// target, speaking some wire profile -- and two endpoints at identical
// orchestrator commits can still be running different ADNL code. The manifest
// writes all of that down, and its digest is what the trial commits and what
// the two halves of a pair cross-check about each other, exactly as they
// cross-check commits.
type CollectorManifest struct {
	// OrchestratorRepository names the repository of the process that ran the
	// measurement and signed the trial.
	OrchestratorRepository string `json:"orchestrator_repository"`
	// OrchestratorCommit is the exact revision of that repository, the same
	// value the trial carries as its local commit.
	OrchestratorCommit string `json:"orchestrator_commit"`
	// ADNLImplementation names the code that actually spoke ADNL on the wire:
	// a dependency of the orchestrator, or a sidecar in its own repository.
	ADNLImplementation string `json:"adnl_implementation"`
	// ADNLImplementationCommit pins that implementation's revision. For a
	// dependency consumed as a Go module this is the module version rather
	// than a repository commit, because the module version is the identity the
	// build actually resolved; a sidecar built from source pins its commit.
	ADNLImplementationCommit string `json:"adnl_implementation_commit"`
	// DependencyVersion is the version of the implementation as the build
	// system named it. It equals ADNLImplementationCommit for a Go module and
	// differs where an implementation is vendored or built out of tree.
	DependencyVersion string `json:"dependency_version"`
	// BinarySHA256 is the lowercase hex SHA-256 of the collector binary that
	// ran, so a rebuilt binary at the same commits is still a different
	// manifest.
	BinarySHA256 string `json:"binary_sha256"`
	// Target is the platform the binary was built for, as GOOS/GOARCH.
	Target string `json:"target"`
	// Toolchain names the compiler that produced the binary.
	Toolchain string `json:"toolchain"`
	// WireProfile names the ADNL lineage spoken on the wire, so evidence from
	// two protocol dialects cannot be silently pooled.
	WireProfile string `json:"wire_profile"`
}

type wireCollectorManifest struct {
	Schema string `json:"schema"`
	CollectorManifest
}

// Validate fails closed on anything a manifest cannot honestly leave open.
func (m CollectorManifest) Validate() error {
	if err := manifestToken(m.OrchestratorRepository); err != nil {
		return errors.New("invalid manifest orchestrator repository")
	}
	// The orchestrator commit is a repository revision by definition, so it is
	// held to the commit pattern the trial's own commits are held to.
	if !commitPattern.MatchString(m.OrchestratorCommit) {
		return errors.New("manifest must name the exact orchestrator commit")
	}
	if err := manifestToken(m.ADNLImplementation); err != nil {
		return errors.New("invalid manifest adnl implementation")
	}
	// The implementation pin is a commit for a sidecar and a module version for
	// a dependency, so it cannot be held to the commit pattern; it is held to
	// being one unpadded token.
	if err := manifestToken(m.ADNLImplementationCommit); err != nil {
		return errors.New("invalid manifest adnl implementation commit")
	}
	if err := manifestToken(m.DependencyVersion); err != nil {
		return errors.New("invalid manifest dependency version")
	}
	if !canon.HashPattern.MatchString(m.BinarySHA256) {
		return errors.New("manifest must carry the binary hash as lowercase hex sha-256")
	}
	if err := manifestToken(m.Target); err != nil {
		return errors.New("invalid manifest target")
	}
	if err := manifestToken(m.Toolchain); err != nil {
		return errors.New("invalid manifest toolchain")
	}
	if err := manifestToken(m.WireProfile); err != nil {
		return errors.New("invalid manifest wire profile")
	}
	return nil
}

// manifestToken enforces the shape every free-text manifest field shares: one
// non-empty, bounded token with no whitespace, because a field that can carry
// padding or line breaks can carry two spellings of one build.
func manifestToken(value string) error {
	if value == "" || len(value) > maxManifestField {
		return errors.New("invalid manifest field")
	}
	if strings.ContainsAny(value, " \t\r\n") {
		return errors.New("invalid manifest field")
	}
	return nil
}

// CanonicalBytes returns the digest preimage of a manifest.
func (m CollectorManifest) CanonicalBytes() ([]byte, error) {
	if err := m.Validate(); err != nil {
		return nil, err
	}
	buffer := bytes.NewBufferString(canon.DomainReachabilityCollectorManifest)
	canon.Text(buffer, CollectorManifestSchema)
	canon.Text(buffer, m.OrchestratorRepository)
	canon.Text(buffer, m.OrchestratorCommit)
	canon.Text(buffer, m.ADNLImplementation)
	canon.Text(buffer, m.ADNLImplementationCommit)
	canon.Text(buffer, m.DependencyVersion)
	canon.Text(buffer, m.BinarySHA256)
	canon.Text(buffer, m.Target)
	canon.Text(buffer, m.Toolchain)
	canon.Text(buffer, m.WireProfile)
	return buffer.Bytes(), nil
}

// Digest identifies one collector build.
func (m CollectorManifest) Digest() (string, error) {
	preimage, err := m.CanonicalBytes()
	if err != nil {
		return "", err
	}
	return canon.Digest(preimage), nil
}

// EncodeManifestJSON returns the publishable manifest document. The evidence
// bundle needs the document and not only its digest, because a digest can be
// checked but not read.
func EncodeManifestJSON(manifest CollectorManifest) ([]byte, error) {
	if err := manifest.Validate(); err != nil {
		return nil, err
	}
	return json.MarshalIndent(wireCollectorManifest{
		Schema: CollectorManifestSchema, CollectorManifest: manifest,
	}, "", "  ")
}

// DecodeManifestJSON rejects unknown fields, trailing data, and inconsistent
// documents.
func DecodeManifestJSON(raw []byte) (CollectorManifest, error) {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	var value wireCollectorManifest
	if err := decoder.Decode(&value); err != nil {
		return CollectorManifest{}, err
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return CollectorManifest{}, errors.New("manifest has trailing JSON")
	}
	if value.Schema != CollectorManifestSchema {
		return CollectorManifest{}, errors.New("unsupported manifest schema")
	}
	if err := value.CollectorManifest.Validate(); err != nil {
		return CollectorManifest{}, err
	}
	return value.CollectorManifest, nil
}
