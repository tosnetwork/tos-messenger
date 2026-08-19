package vectors

import (
	"encoding/hex"
	"encoding/json"
	"flag"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/tosnetwork/tos-messenger/pkg/directory"
	"github.com/tosnetwork/tos-messenger/pkg/e2ee"
	"github.com/tosnetwork/tos-messenger/pkg/envelope"
	"github.com/tosnetwork/tos-messenger/pkg/identity"
	"github.com/tosnetwork/tos-messenger/pkg/negotiation"
	"github.com/tosnetwork/tos-messenger/pkg/payload"
)

var updateCorpus = flag.Bool("update-corpus", false, "rewrite the adversarial corpus")

// The adversarial corpus is the other half of interoperability. The positive
// vectors say which valid objects two implementations must agree to accept;
// this says which invalid ones they must agree to refuse. Interop breaks
// exactly where they disagree about that -- one implementation admitting what
// another rejects is a security gap, not a cosmetic one -- so the set a second
// implementation must refuse is a shared, versioned artifact, and every entry
// records why it must be refused.
//
// A generator, not a hand-written file: each entry is produced by mutating a
// valid baseline in a named way, and the generation asserts this
// implementation refuses it. That makes it impossible to commit an entry this
// implementation actually accepts -- a corpus that lied about what it refuses
// would be worse than none, because a second implementation would weaken
// itself to match.

// CorpusEntry is one input a conforming implementation must refuse.
type CorpusEntry struct {
	Name string `json:"name"`
	// Layer says where the refusal is owed: "decode" for an input a decoder
	// must reject on shape, "verify" for one that decodes cleanly and must be
	// rejected only when measured against the authority it claims. A second
	// implementation runs the matching check for the layer; refusing a verify
	// entry at decode, or the reverse, is refusing for the wrong reason.
	Layer  string `json:"layer"`
	Target string `json:"target"`
	// Wire is the transport bytes to feed the target: the JSON document for
	// JSON targets, lowercase hex for binary ones.
	Wire   string `json:"wire"`
	Binary bool   `json:"binary,omitempty"`
	// Reason is why refusal is mandatory, for a human reading the corpus.
	Reason string `json:"reason"`
}

const (
	layerDecode = "decode"
	layerVerify = "verify"
)

// decoders is the wire surface a second implementation has to match. Each
// returns an error for input it refuses; the corpus asserts every entry does.
var decoders = map[string]func([]byte) error{
	"endpoint-delegation":  func(b []byte) error { _, err := identity.DecodeJSON(b); return err },
	"contact-descriptor":   func(b []byte) error { _, err := directory.DecodeDescriptorJSON(b); return err },
	"dht-locator":          func(b []byte) error { _, err := directory.DecodeLocator(b); return err },
	"prekey-bundle":        func(b []byte) error { _, err := e2ee.DecodeBundleJSON(b); return err },
	"messaging-event":      func(b []byte) error { _, err := envelope.DecodeEventJSON(b); return err },
	"payload-text":         func(b []byte) error { _, err := payload.Decode("text", b); return err },
	"negotiation-snapshot": func(b []byte) error { _, err := negotiation.DecodeSnapshotJSON(b); return err },
}

func TestAdversarialCorpus(t *testing.T) {
	verifiers := buildVerifiers(t)
	decodeOnly := verifyDecoders()
	entries := generateCorpus(t, verifiers)

	// The generation itself proves the claim: this implementation refuses
	// every entry, or the corpus is not built. The layer decides which check
	// runs, so a verify entry is never satisfied by a decoder that happened to
	// reject it for an unrelated reason.
	for _, entry := range entries {
		var check func([]byte) error
		switch entry.Layer {
		case layerDecode:
			decode, known := decoders[entry.Target]
			if !known {
				t.Fatalf("%s targets an unknown decoder %q", entry.Name, entry.Target)
			}
			check = decode
		case layerVerify:
			verify, known := verifiers[entry.Target]
			if !known {
				t.Fatalf("%s targets an unknown verifier %q", entry.Name, entry.Target)
			}
			check = verify
		default:
			t.Fatalf("%s names an unknown layer %q", entry.Name, entry.Layer)
		}
		raw := []byte(entry.Wire)
		if entry.Binary {
			decoded, err := hex.DecodeString(entry.Wire)
			if err != nil {
				t.Fatalf("%s has invalid hex: %v", entry.Name, err)
			}
			raw = decoded
		}
		// A verify entry must decode cleanly first: the whole point is that it
		// is refused for what it means, not for how it is shaped.
		if entry.Layer == layerVerify {
			if decode, known := decodeOnly[entry.Target]; known {
				if err := decode(raw); err != nil {
					t.Fatalf("%s is a verify entry but was rejected at decode (%v); that makes it a decode case for the wrong reason",
						entry.Name, err)
				}
			}
		}
		if err := check(raw); err == nil {
			t.Fatalf("%s (%s/%s) was accepted, but the corpus says it must be refused: %s",
				entry.Name, entry.Layer, entry.Target, entry.Reason)
		}
	}

	encoded, err := json.MarshalIndent(entries, "", "  ")
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	encoded = append(encoded, '\n')
	path := filepath.Join("testdata", "adversarial-corpus.json")
	if *updateCorpus {
		if err := os.WriteFile(path, encoded, 0o644); err != nil {
			t.Fatalf("write: %v", err)
		}
		return
	}
	committed, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read committed corpus: %v (run with -update-corpus to create it)", err)
	}
	if string(committed) != string(encoded) {
		t.Fatal("the adversarial corpus changed.\nA second implementation checks itself against the " +
			"committed file; if the change is intended, re-run with -update-corpus and review the diff.")
	}
}

// generateCorpus builds every negative case from a valid baseline.
func generateCorpus(t *testing.T, verifiers map[string]func([]byte) error) []CorpusEntry {
	t.Helper()
	var corpus []CorpusEntry
	add := func(name, target, wire, reason string) {
		corpus = append(corpus, CorpusEntry{Name: name, Layer: layerDecode, Target: target, Wire: wire, Reason: reason})
	}
	addBinary := func(name, target, hexWire, reason string) {
		corpus = append(corpus, CorpusEntry{Name: name, Layer: layerDecode, Target: target, Wire: hexWire, Binary: true, Reason: reason})
	}
	addVerify := func(name, target, wire, reason string) {
		corpus = append(corpus, CorpusEntry{Name: name, Layer: layerVerify, Target: target, Wire: wire, Reason: reason})
	}

	// A single generic mutation set applies to every JSON decoder: reordering
	// or padding must not change identity, but unknown fields and trailing
	// data must be refused, because a decoder that accepted them would let two
	// documents mean one object.
	jsonBaselines := map[string][]byte{
		"endpoint-delegation":  validDelegationJSON(t),
		"contact-descriptor":   validDescriptorJSON(t),
		"prekey-bundle":        validBundleJSON(t),
		"messaging-event":      validEventJSON(t),
		"negotiation-snapshot": validSnapshotJSON(t),
	}
	baselineTargets := make([]string, 0, len(jsonBaselines))
	for target := range jsonBaselines {
		baselineTargets = append(baselineTargets, target)
	}
	sort.Strings(baselineTargets)
	for _, target := range baselineTargets {
		valid := jsonBaselines[target]
		// Sanity: the baseline must itself be accepted, or the mutations prove
		// nothing.
		if err := decoders[target](valid); err != nil {
			t.Fatalf("the %s baseline is not valid: %v", target, err)
		}
		add(target+"/unknown-field", target, injectUnknownField(string(valid)),
			"an unknown field means the sender and receiver disagree about the object's shape")
		add(target+"/trailing-json", target, string(valid)+`{"x":1}`,
			"trailing data lets two byte streams decode to one object")
		add(target+"/truncated", target, string(valid[:len(valid)-1]),
			"a truncated document is not the object it was cut from")
		add(target+"/empty", target, "",
			"an empty document is not an object")
	}

	// Delegation: an inverted validity window, and a zeroed policy digest.
	add("endpoint-delegation/window-inverted", "endpoint-delegation",
		flipUnix(string(validDelegationJSON(t)), "not_before_unix", "expires_at_unix"),
		"a delegation whose window ends before it starts is valid for no instant")
	add("endpoint-delegation/zero-inbox-digest", "endpoint-delegation",
		setField(string(validDelegationJSON(t)), "inbox_admission_policy_digest",
			"sha256:"+strings.Repeat("0", 64)),
		"an all-zero digest is an uninitialised field, not a commitment")

	// Payload (binary): trailing bytes, and a length prefix past the bound.
	validText := validTextPayload(t)
	addBinary("payload-text/trailing-bytes", "payload-text",
		hex.EncodeToString(append(validText, 0x00)),
		"trailing bytes give one body two encodings")
	addBinary("payload-text/oversized-length", "payload-text",
		hex.EncodeToString(oversizedLengthPrefix(validText)),
		"a length prefix a peer chooses is an allocation a peer chooses, and must be bounded before the read")

	// Locator (binary): a truncated buffer.
	locator := validLocatorBytes(t)
	addBinary("dht-locator/truncated", "dht-locator",
		hex.EncodeToString(locator[:len(locator)-2]),
		"a truncated locator is not the locator it was cut from")

	// Snapshot: an approval from a later generation than the negotiation.
	add("negotiation-snapshot/future-approval", "negotiation-snapshot",
		futureApprovalSnapshotJSON(t),
		"an approval from a later version of the negotiation than the snapshot is an approval for terms that do not exist")

	// Verify layer. Each baseline must itself pass its verifier, or the
	// mutations prove nothing -- the same discipline the decode baselines get.
	verifyBaselines := map[string][]byte{
		"prekey-bundle-binding":    boundBundleJSON(t),
		"reachability-observation": validObservationJSON(t),
	}
	for target, valid := range verifyBaselines {
		verify, known := verifiers[target]
		if !known {
			t.Fatalf("no verifier registered for %q", target)
		}
		if err := verify(valid); err != nil {
			t.Fatalf("the %s verify baseline does not pass: %v", target, err)
		}
	}

	// A prekey bundle can decode and even carry a valid signature and still be
	// refused when bound: a forged signature, a bundle outliving its
	// delegation, a bundle naming an Agent the delegation does not authorise.
	addVerify("prekey-bundle-binding/tampered-signature", "prekey-bundle-binding",
		tamperedBundleSignatureJSON(t),
		"a bundle whose signature is not the delegated endpoint's over this content is not published material the endpoint stands behind")
	addVerify("prekey-bundle-binding/outlives-delegation", "prekey-bundle-binding",
		bundleOutlivingDelegationJSON(t),
		"a bundle that outlives the delegation authorising its key claims authority past the point the delegation grants it")
	addVerify("prekey-bundle-binding/foreign-agent", "prekey-bundle-binding",
		bundleForeignAgentJSON(t),
		"a validly signed bundle for another Agent is not authorised by this delegation")

	// A local-only kind carries authority granted on the owner's own
	// interface; arriving over the network it is refused before evaluation.
	addVerify("messaging-event-network-route/local-only-from-network", "messaging-event-network-route",
		localOnlyEventFromNetworkJSON(t),
		"an owner-approval kind expresses local authority and cannot be spoken by a remote party")

	// A coordinator attestation with a broken signature decodes and is
	// well-shaped, but does not verify under the key it names.
	addVerify("reachability-observation/tampered-signature", "reachability-observation",
		tamperedObservationJSON(t),
		"an attestation whose signature does not verify under its named coordinator key attests nothing")

	sort.Slice(corpus, func(i, j int) bool { return corpus[i].Name < corpus[j].Name })
	return corpus
}
