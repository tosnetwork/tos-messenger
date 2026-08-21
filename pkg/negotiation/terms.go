package negotiation

import (
	"bytes"
	"errors"
	"regexp"

	"github.com/tosnetwork/tos-messenger/internal/canon"
	"github.com/tosnetwork/tos-messenger/internal/ids"
)

var (
	capabilityClassPattern = regexp.MustCompile(`^[a-z][a-z0-9]*(\.[a-z0-9]+)*$`)
	digestPattern          = regexp.MustCompile(`^(?:sha256|tvm-cell-sha256):[0-9a-f]{64}$`)
)

// Terms are the exact conditions two parties say they intend to commit to.
//
// Every field a canonical Quote Proposal carries appears here, and that is the
// point rather than completeness for its own sake. Terms that named only the
// capability and the price would let the canonical form differ from what was
// agreed in every other field: a different provider, a different manifest to
// execute, different escrow conditions, a different dispute policy, a
// different transport binding. Each of those changes what was bought while the
// number stays the same, so each has to be in what was agreed and in what is
// checked afterwards.
type Terms struct {
	CapabilityID      string
	CapabilityVersion string
	// CapabilityClass is what the owner's mandate restricts. It describes the
	// capability rather than the quote, and is not part of the canonical quote
	// for that reason.
	CapabilityClass string
	// ProviderAgentID is who will do the work. A quote that changed hands
	// silently would be a different purchase at the same price.
	ProviderAgentID string
	// ManifestDigest commits what will be executed.
	ManifestDigest string
	// TransportBindingDigest commits how it will be reached.
	TransportBindingDigest string
	// Price is the maximum that may be charged.
	Price Money
	// EscrowTermsDigest commits the conditions funds are held under.
	EscrowTermsDigest string
	// DisputePolicyDigest commits what happens when the parties disagree.
	DisputePolicyDigest string
	NotAfterUnix        uint64
}

// Validate enforces that terms are complete.
func (t Terms) Validate() error {
	if !ids.Capability.MatchString(t.CapabilityID) {
		return errors.New("terms name no capability")
	}
	if t.CapabilityVersion == "" || len(t.CapabilityVersion) > 64 {
		return errors.New("terms name no capability version")
	}
	if !capabilityClassPattern.MatchString(t.CapabilityClass) {
		return errors.New("terms name no capability class")
	}
	if !ids.Agent.MatchString(t.ProviderAgentID) {
		return errors.New("terms name no provider")
	}
	for name, digest := range map[string]string{
		"manifest":          t.ManifestDigest,
		"transport binding": t.TransportBindingDigest,
		"escrow terms":      t.EscrowTermsDigest,
		"dispute policy":    t.DisputePolicyDigest,
	} {
		if !digestPattern.MatchString(digest) || !canon.ValidDigest(normalizeDigest(digest)) {
			return errors.New("terms carry no " + name + " commitment")
		}
	}
	if err := t.Price.Validate(); err != nil {
		return err
	}
	if t.NotAfterUnix == 0 {
		return errors.New("terms must expire")
	}
	return nil
}

// normalizeDigest lets a TVM cell digest be checked for the all-zero value the
// same way a sha256 digest is.
func normalizeDigest(digest string) string {
	if len(digest) > len("tvm-cell-sha256:") && digest[:len("tvm-cell-sha256:")] == "tvm-cell-sha256:" {
		return "sha256:" + digest[len("tvm-cell-sha256:"):]
	}
	return digest
}

// CanonicalBytes returns the preimage that identifies one set of terms.
func (t Terms) CanonicalBytes() ([]byte, error) {
	if err := t.Validate(); err != nil {
		return nil, err
	}
	buffer := bytes.NewBufferString(canon.DomainNegotiationTerms)
	canon.Text(buffer, t.CapabilityID)
	canon.Text(buffer, t.CapabilityVersion)
	canon.Text(buffer, t.CapabilityClass)
	canon.Text(buffer, t.ProviderAgentID)
	canon.Text(buffer, t.ManifestDigest)
	canon.Text(buffer, t.TransportBindingDigest)
	if err := t.Price.canonical(buffer); err != nil {
		return nil, err
	}
	canon.Text(buffer, t.EscrowTermsDigest)
	canon.Text(buffer, t.DisputePolicyDigest)
	canon.Uint64(buffer, t.NotAfterUnix)
	return buffer.Bytes(), nil
}

// Digest identifies one set of terms.
//
// It is what an owner's approval is bound to. An approval that named only a
// negotiation could be carried across a change of terms, and the change a
// counterparty makes after an approval is the one they have the most reason to
// make.
func (t Terms) Digest() (string, error) {
	preimage, err := t.CanonicalBytes()
	if err != nil {
		return "", err
	}
	return canon.Digest(preimage), nil
}

// Equal reports whether two sets of terms are the same in every field.
func (t Terms) Equal(other Terms) bool {
	return t.CapabilityID == other.CapabilityID &&
		t.CapabilityVersion == other.CapabilityVersion &&
		t.CapabilityClass == other.CapabilityClass &&
		t.ProviderAgentID == other.ProviderAgentID &&
		t.ManifestDigest == other.ManifestDigest &&
		t.TransportBindingDigest == other.TransportBindingDigest &&
		t.Price.Equal(other.Price) &&
		t.EscrowTermsDigest == other.EscrowTermsDigest &&
		t.DisputePolicyDigest == other.DisputePolicyDigest &&
		t.NotAfterUnix == other.NotAfterUnix
}
