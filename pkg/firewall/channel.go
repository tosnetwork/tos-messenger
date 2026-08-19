package firewall

import (
	"errors"
	"strings"
	"unicode/utf8"

	"github.com/tosnetwork/tos-messenger/internal/canon"
)

// MaxQuotationBytes bounds one quoted body.
const MaxQuotationBytes = 128 << 10

// Instruction is text this owner or operator gave the Agent.
//
// It is a distinct type from received content, and there is deliberately no
// conversion between them. Content that arrived cannot become an instruction
// by being assigned to the wrong variable, passed to the wrong parameter, or
// concatenated into the wrong string, because those are compile errors rather
// than judgement calls made under time pressure.
type Instruction struct{ text string }

// OwnerInstruction records text the owner gave.
func OwnerInstruction(text string) (Instruction, error) {
	if text == "" || len(text) > MaxQuotationBytes {
		return Instruction{}, errors.New("an instruction must say something")
	}
	if !utf8.ValidString(text) {
		return Instruction{}, errors.New("an instruction is not valid UTF-8")
	}
	return Instruction{text: text}, nil
}

// String returns the instruction text.
func (i Instruction) String() string { return i.text }

// Quotation is received content prepared to be read.
//
// It carries its origin with it and renders inside a frame whose delimiter is
// derived from the content itself. A sender cannot close the frame early and
// continue outside it, because doing so would mean composing a message that
// contains a fragment of its own digest.
//
// What this achieves is that the boundary is unambiguous in the text. What it
// does not achieve is that the boundary is honoured: the reader is a model,
// and a model may still act on what it reads inside the frame. That is why
// this package's other half exists, and why nothing here is described as
// preventing injection.
type Quotation struct {
	origin Origin
	body   string
}

// Quote prepares received content for reading.
func Quote(origin Origin, body string) (Quotation, error) {
	if err := origin.Validate(); err != nil {
		return Quotation{}, err
	}
	if body == "" || len(body) > MaxQuotationBytes {
		return Quotation{}, errors.New("a quotation must have a body")
	}
	if !utf8.ValidString(body) {
		return Quotation{}, errors.New("quoted content is not valid UTF-8")
	}
	return Quotation{origin: origin, body: body}, nil
}

// Origin returns where the quoted content came from.
func (q Quotation) Origin() Origin { return q.origin }

// Body returns the quoted content itself, unmodified. Reading is not the
// gated operation; acting is.
func (q Quotation) Body() string { return q.body }

// delimiter derives a frame marker the body cannot contain.
func (q Quotation) delimiter() string {
	digest := canon.Digest([]byte(q.body))
	return "tos-received-" + digest[len("sha256:"):len("sha256:")+16]
}

// String renders the quotation as attributed, framed text.
//
// The attribution is part of the frame rather than a comment beside it,
// because a reader that has to correlate two pieces of text to know who said
// something will eventually correlate them wrongly.
func (q Quotation) String() string {
	marker := q.delimiter()
	builder := &strings.Builder{}
	builder.WriteString("<<<" + marker + " received-content")
	builder.WriteString(" agent=" + q.origin.AgentID)
	builder.WriteString(" endpoint=" + q.origin.EndpointID)
	builder.WriteString(" event=" + q.origin.EventID)
	builder.WriteString(" kind=" + q.origin.Kind)
	builder.WriteString(">>>\n")
	builder.WriteString(q.body)
	builder.WriteString("\n<<<" + marker + " end-received-content>>>")
	return builder.String()
}

// Compose assembles what the Agent reads.
//
// The instruction channel comes first and is never interleaved with received
// content. Quotations follow, each in its own frame. There is no parameter
// that lets a caller place received content in the instruction position: the
// order is fixed here rather than left to every call site, because a call site
// that got it wrong would look exactly like one that got it right.
func Compose(instruction Instruction, quotations ...Quotation) (string, error) {
	if instruction.text == "" {
		return "", errors.New("nothing to compose without an instruction")
	}
	if len(quotations) > MaxProvenance {
		return "", errors.New("more quotations than an owner could review")
	}
	builder := &strings.Builder{}
	builder.WriteString(instruction.text)
	for _, quotation := range quotations {
		if quotation.body == "" {
			return "", errors.New("a quotation with no body cannot be composed")
		}
		builder.WriteString("\n\n")
		builder.WriteString(quotation.String())
	}
	return builder.String(), nil
}

// Origins returns the provenance of a set of quotations, ready to be cited by
// an action. An Agent that read something and then acted has to be able to say
// what it read, and building that list by hand is how it stops matching.
func Origins(quotations ...Quotation) []Origin {
	origins := make([]Origin, 0, len(quotations))
	seen := make(map[string]struct{}, len(quotations))
	for _, quotation := range quotations {
		if _, duplicate := seen[quotation.origin.EventID]; duplicate {
			continue
		}
		seen[quotation.origin.EventID] = struct{}{}
		origins = append(origins, quotation.origin)
	}
	return origins
}
