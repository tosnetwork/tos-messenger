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
	Asset             string
	Units             uint64
	Decimals          uint8
	NotAfterUnix      uint64

	// RenderedTotal is the amount the natural-language text was understood to
	// say, where the caller extracted one. Supplying it is optional. Supplying
	// one that disagrees with the structured amount is fatal.
	RenderedTotal *Amount
}

// Compile turns a candidate into terms, or refuses.
//
// It returns whether the owner must decide personally alongside the terms,
// because a caller that had to ask separately could act on the terms and
// forget to ask.
func Compile(candidate Candidate, mandate Mandate, now time.Time) (Terms, bool, error) {
	if candidate.Asset == "" {
		return Terms{}, false, errors.New("no asset was named")
	}
	if candidate.Units == 0 {
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
		CapabilityID:      candidate.CapabilityID,
		CapabilityVersion: candidate.CapabilityVersion,
		CapabilityClass:   candidate.CapabilityClass,
		Total: Amount{
			Asset:    candidate.Asset,
			Units:    candidate.Units,
			Decimals: candidate.Decimals,
		},
		NotAfterUnix: candidate.NotAfterUnix,
	}
	if err := terms.Validate(); err != nil {
		return Terms{}, false, err
	}
	if candidate.RenderedTotal != nil {
		if err := candidate.RenderedTotal.Validate(); err != nil {
			return Terms{}, false, err
		}
		if !candidate.RenderedTotal.Equal(terms.Total) {
			return Terms{}, false, ErrRenderingConflict
		}
	}
	needsApproval, err := mandate.Permits(terms, now)
	if err != nil {
		return Terms{}, false, err
	}
	return terms, needsApproval, nil
}
