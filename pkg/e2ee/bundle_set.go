package e2ee

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
)

const (
	// BundleSetSchema identifies the bounded JSON publication wrapper for all
	// device bundles committed by one descriptor. The wrapper is not itself
	// signed; SetCanonicalBytes is the descriptor-committed representation.
	BundleSetSchema = "tos.messaging.prekey-bundle-set.v2"

	// MaxBundleSetWireBytes bounds an object fetched before JSON decoding. It
	// leaves room for MaxDevicesPerSet bundles at their material bound without
	// permitting an unbounded discovery response.
	MaxBundleSetWireBytes = 128 << 10
)

type wireBundleSet struct {
	Schema  string            `json:"schema"`
	Bundles []json.RawMessage `json:"bundles"`
}

// EncodeBundleSetJSON returns the complete publishable device set. The input
// order is preserved on the wire; identity remains order independent because
// the descriptor commits SetCanonicalBytes, which sorts bundle digests.
func EncodeBundleSetJSON(bundles []Bundle) ([]byte, error) {
	if err := ValidateSet(bundles); err != nil {
		return nil, err
	}
	wire := wireBundleSet{Schema: BundleSetSchema, Bundles: make([]json.RawMessage, 0, len(bundles))}
	for _, bundle := range bundles {
		raw, err := EncodeBundleJSON(bundle)
		if err != nil {
			return nil, err
		}
		wire.Bundles = append(wire.Bundles, raw)
	}
	raw, err := json.Marshal(wire)
	if err != nil {
		return nil, err
	}
	if len(raw) > MaxBundleSetWireBytes {
		return nil, errors.New("prekey bundle set exceeds its wire size bound")
	}
	return raw, nil
}

// DecodeBundleSetJSON strictly decodes a bounded publication wrapper and
// enforces whole-set coherence. Individual bundles retain their own strict
// schema and signature-shape validation.
func DecodeBundleSetJSON(raw []byte) ([]Bundle, error) {
	if len(raw) == 0 || len(raw) > MaxBundleSetWireBytes {
		return nil, errors.New("invalid prekey bundle set wire size")
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	var value wireBundleSet
	if err := decoder.Decode(&value); err != nil {
		return nil, err
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return nil, errors.New("prekey bundle set has trailing JSON")
	}
	if value.Schema != BundleSetSchema {
		return nil, errors.New("unsupported prekey bundle set schema")
	}
	if len(value.Bundles) == 0 || len(value.Bundles) > MaxDevicesPerSet {
		return nil, errors.New("invalid prekey bundle set size")
	}
	bundles := make([]Bundle, 0, len(value.Bundles))
	for _, rawBundle := range value.Bundles {
		bundle, err := DecodeBundleJSON(rawBundle)
		if err != nil {
			return nil, err
		}
		bundles = append(bundles, bundle)
	}
	if err := ValidateSet(bundles); err != nil {
		return nil, err
	}
	return bundles, nil
}
