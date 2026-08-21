// Package payload gives every event kind a typed body.
//
// An event kind and a payload schema that only ever named a string left the
// body as arbitrary bytes: two implementations could agree on the kind, agree
// on the schema identifier, and still disagree about what the bytes meant.
// This package is where the kind stops being a label and becomes a contract.
//
// Bodies are canonical binary, not JSON. The Event identifier commits the
// content, so the content needs one encoding and exactly one: a body that
// could be re-serialized into different bytes with the same meaning would give
// one event two identities.
//
// What this package does not do is judge the body. A payload that parses is
// structurally what its kind says it is; whether the text in it should be
// obeyed, and whether the action it describes should be taken, belong to the
// runtime and to owner approval. Parsing is not trust.
package payload

import (
	"bytes"
	"errors"
	"sort"

	"github.com/tosnetwork/tos-messenger/internal/canon"
)

// Bounds on the parts a body is built from. They exist so that a decoder
// allocates what a bound allows rather than what a peer's length prefix asks
// for.
const (
	// MaxTextBytes bounds one free-text field. It matches the event content
	// bound rather than sitting below it: this constant exists to bound what a
	// decoder allocates, and the question of what an event may carry belongs
	// to the envelope, which enforces its own limit and the recipient's.
	MaxTextBytes = 128 << 10
	// MaxShortTextBytes bounds an identifier-like or single-line field.
	MaxShortTextBytes = 512
	// MaxDigestBytes bounds a digest string.
	MaxDigestBytes = 128
	// MaxOpaqueBytes bounds a body this protocol carries but does not define.
	MaxOpaqueBytes = 128 << 10
	// MaxRepeated bounds any repeated field.
	MaxRepeated = 32
)

// Payload is one typed event body.
type Payload interface {
	// Schema is the payload schema identifier this body answers to.
	Schema() string
	// Validate enforces the parts of the contract that structure alone cannot:
	// required fields, closed vocabularies, and bounds.
	Validate() error
	// encode writes the canonical preimage after its domain separator.
	encode(*bytes.Buffer)
}

// codec is how one kind's body is produced from bytes.
type codec struct {
	schema string
	decode func(*canon.Reader) Payload
	// legacy contains read-only decoders for schemas that this build emitted
	// previously. New events always use schema/decode above, but immutable
	// history must remain readable after a schema advance.
	legacy map[string]func(*canon.Reader) Payload
}

// domainFor namespaces a payload preimage by its schema, so bytes that parse
// under one schema cannot be replayed as a different one.
func domainFor(schema string) string {
	return canon.DomainPayload + schema + "\x00"
}

// Encode returns the canonical bytes of a body.
func Encode(value Payload) ([]byte, error) {
	if value == nil {
		return nil, errors.New("no payload to encode")
	}
	if err := value.Validate(); err != nil {
		return nil, err
	}
	buffer := bytes.NewBufferString(domainFor(value.Schema()))
	value.encode(buffer)
	return buffer.Bytes(), nil
}

// Decode parses the body of an event of the given kind.
//
// A kind with no codec is refused rather than passed through. A build that let
// an unrecognised kind carry an uninterpreted body would be admitting exactly
// the events it cannot reason about.
func Decode(kind string, content []byte) (Payload, error) {
	spec, known := codecs[kind]
	if !known {
		return nil, errors.New("no payload codec for event kind " + kind)
	}
	return decodeSchema(spec, spec.schema, content)
}

// DecodeSchema parses content using the exact schema declared by an immutable
// Event. It accepts the current schema and explicitly registered historical
// schemas; it never guesses a schema from the bytes.
func DecodeSchema(kind, schema string, content []byte) (Payload, error) {
	spec, known := codecs[kind]
	if !known {
		return nil, errors.New("no payload codec for event kind " + kind)
	}
	return decodeSchema(spec, schema, content)
}

func decodeSchema(spec codec, schema string, content []byte) (Payload, error) {
	decode := spec.decode
	if schema != spec.schema {
		decode = spec.legacy[schema]
		if decode == nil {
			return nil, errors.New("unsupported payload schema")
		}
	}
	reader := canon.NewReader(domainFor(schema), content)
	value := decode(reader)
	if err := reader.Done(); err != nil {
		return nil, err
	}
	if value == nil {
		return nil, errors.New("payload decoder produced nothing")
	}
	if err := value.Validate(); err != nil {
		return nil, err
	}
	return value, nil
}

// SupportsSchema reports whether kind may carry schema. The current schema is
// used for new Events; historical schemas are decoding compatibility only.
func SupportsSchema(kind, schema string) bool {
	spec, known := codecs[kind]
	if !known {
		return false
	}
	return schema == spec.schema || spec.legacy[schema] != nil
}

// Validate reports whether content is a well-formed body for its kind.
func Validate(kind string, content []byte) error {
	_, err := Decode(kind, content)
	return err
}

// SchemaFor returns the payload schema a kind carries.
func SchemaFor(kind string) (string, bool) {
	spec, known := codecs[kind]
	if !known {
		return "", false
	}
	return spec.schema, true
}

// Kinds lists every kind with a codec, in a stable order.
func Kinds() []string {
	kinds := make([]string, 0, len(codecs))
	for kind := range codecs {
		kinds = append(kinds, kind)
	}
	sort.Strings(kinds)
	return kinds
}
