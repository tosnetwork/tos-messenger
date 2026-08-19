package negotiation

import (
	"errors"
	"time"
)

// ErrRenderingConflict reports that the structured payload and the text a
// person would read do not agree.
//
// It is named so a caller can surface it as a conflict rather than an ordinary
// refusal. The remedy is to show both and stop, never to pick one: a client
// that let a model decide which representation to believe would have made the
// text authoritative through a side door.
var ErrRenderingConflict = errors.New("structured terms and their rendering disagree")

// Candidate is what a reasoning step produced. It is untrusted.
//
// The compiler may reject it, and may not repair it. Every field a commitment
// needs is required here, and none is inferred from context: an asset taken
// from the mandate because the sentence did not name one would turn "ten" into
// ten of whatever the budget happened to be in.
type Candidate struct {
	CapabilityID      string
	CapabilityVersion string
	CapabilityClass   string
	// ProviderAgentID, and the four digests below, are every remaining field a
	// canonical Quote Proposal carries. They are required rather than inferred
	// for the same reason the asset is: a field the compiler filled in from
	// context is a term nobody agreed to.
	ProviderAgentID        string
	ManifestDigest         string
	TransportBindingDigest string
	EscrowTermsDigest      string
	DisputePolicyDigest    string
	Price                  Money
	NotAfterUnix           uint64

	// RenderedPrice is the amount the natural-language text was understood to
	// say, where the caller extracted one. Supplying it is optional. Supplying
	// one that disagrees with the structured amount is fatal.
	RenderedPrice *Money
}

// Compile turns a candidate into terms, or refuses.
//
// It returns whether the owner must decide personally alongside the terms,
// because a caller that had to ask separately could act on the terms and
// forget to ask.
func Compile(candidate Candidate, mandate Mandate, now time.Time) (Terms, bool, error) {
	if err := candidate.Price.Validate(); err != nil {
		return Terms{}, false, err
	}
	if candidate.Price.Atomic == "0" {
		// A zero price is not a free service; it is a field nobody filled in.
		return Terms{}, false, errors.New("no amount was named")
	}
	if candidate.CapabilityID == "" || candidate.CapabilityVersion == "" || candidate.CapabilityClass == "" {
		return Terms{}, false, errors.New("no capability, version, or class was named")
	}
	if candidate.NotAfterUnix == 0 {
		return Terms{}, false, errors.New("no expiry was named")
	}
	terms := Terms{
		CapabilityID:           candidate.CapabilityID,
		CapabilityVersion:      candidate.CapabilityVersion,
		CapabilityClass:        candidate.CapabilityClass,
		ProviderAgentID:        candidate.ProviderAgentID,
		ManifestDigest:         candidate.ManifestDigest,
		TransportBindingDigest: candidate.TransportBindingDigest,
		Price:                  candidate.Price,
		EscrowTermsDigest:      candidate.EscrowTermsDigest,
		DisputePolicyDigest:    candidate.DisputePolicyDigest,
		NotAfterUnix:           candidate.NotAfterUnix,
	}
	if err := terms.Validate(); err != nil {
		return Terms{}, false, err
	}
	if candidate.RenderedPrice != nil {
		if err := candidate.RenderedPrice.Validate(); err != nil {
			return Terms{}, false, err
		}
		if !candidate.RenderedPrice.Equal(terms.Price) {
			return Terms{}, false, ErrRenderingConflict
		}
	}
	needsApproval, err := mandate.Permits(terms, now)
	if err != nil {
		return Terms{}, false, err
	}
	return terms, needsApproval, nil
}
