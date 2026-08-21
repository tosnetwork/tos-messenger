package vectors

import (
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"flag"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/tosnetwork/tos-messenger/pkg/attachments"
	"github.com/tosnetwork/tos-messenger/pkg/conformance"
	"github.com/tosnetwork/tos-messenger/pkg/directory"
	"github.com/tosnetwork/tos-messenger/pkg/e2ee"
	"github.com/tosnetwork/tos-messenger/pkg/envelope"
	"github.com/tosnetwork/tos-messenger/pkg/group"
	"github.com/tosnetwork/tos-messenger/pkg/identity"
	"github.com/tosnetwork/tos-messenger/pkg/mailbox"
	"github.com/tosnetwork/tos-messenger/pkg/negotiation"
	"github.com/tosnetwork/tos-messenger/pkg/payload"
	"github.com/tosnetwork/tos-messenger/pkg/reachability"
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
	"descriptor-policy":    func(b []byte) error { _, err := directory.DecodeDescriptorPolicyJSON(b); return err },
	"dht-locator":          func(b []byte) error { _, err := directory.DecodeLocator(b); return err },
	"prekey-bundle":        func(b []byte) error { _, err := e2ee.DecodeBundleJSON(b); return err },
	"prekey-bundle-set":    func(b []byte) error { _, err := e2ee.DecodeBundleSetJSON(b); return err },
	"messaging-event":      func(b []byte) error { _, err := envelope.DecodeEventJSON(b); return err },
	"payload-text":         func(b []byte) error { _, err := payload.Decode("text", b); return err },
	"negotiation-snapshot": func(b []byte) error { _, err := negotiation.DecodeSnapshotJSON(b); return err },
	"reachability-trial":   func(b []byte) error { _, err := reachability.DecodeTrialJSON(b); return err },
	"stored-ack":           func(b []byte) error { _, err := mailbox.DecodeAckJSON(b); return err },
	"mailbox-capability-grant": func(b []byte) error {
		_, err := mailbox.DecodeGrantJSON(b)
		return err
	},
	"mailbox-access-request": func(b []byte) error {
		_, err := mailbox.DecodeAccessRequestJSON(b)
		return err
	},
	"conformance-report":    func(b []byte) error { _, err := conformance.DecodeJSON(b); return err },
	"mls-device-credential": func(b []byte) error { _, err := group.DecodeDeviceCredentialJSON(b); return err },
	"encrypted-attachment":  func(b []byte) error { _, err := attachments.DecodeReferenceJSON(b); return err },
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
		"endpoint-delegation":      validDelegationJSON(t),
		"contact-descriptor":       validDescriptorJSON(t),
		"descriptor-policy":        validDescriptorPolicyJSON(t),
		"prekey-bundle":            validBundleJSON(t),
		"prekey-bundle-set":        validBundleSetJSON(t),
		"messaging-event":          validEventJSON(t),
		"negotiation-snapshot":     validSnapshotJSON(t),
		"stored-ack":               validStoredAckJSON(t),
		"mailbox-capability-grant": validMailboxGrantJSON(t),
		"mailbox-access-request":   validMailboxRequestJSON(t),
		"conformance-report":       validConformanceReportJSON(t),
		"mls-device-credential":    validMLSCredentialJSON(t),
		"encrypted-attachment":     validEncryptedAttachmentJSON(t),
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

	// Snapshot: terms priced on a network other than the exchange's binding.
	// The terms digest commits the asset's network, so identical terms on two
	// networks are two digests, and a snapshot carrying the foreign one is
	// carrying a purchase no commitment this exchange accepts could answer to.
	add("negotiation-snapshot/terms-on-another-network", "negotiation-snapshot",
		crossNetworkTermsSnapshotJSON(t),
		"terms priced on another network digest to a different commitment, so they cannot ride a negotiation bound to this one")

	// Verify layer. Each baseline must itself pass its verifier, or the
	// mutations prove nothing -- the same discipline the decode baselines get.
	verifyBaselines := map[string][]byte{
		"descriptor-policy-binding":        validDescriptorPolicyJSON(t),
		"mailbox-capability-grant-binding": validMailboxGrantJSON(t),
		"mailbox-access-request-binding":   validMailboxRequestJSON(t),
		"prekey-bundle-binding":            boundBundleJSON(t),
		"mls-credential-binding":           boundMLSCredentialJSON(t),
		"reachability-observation":         validObservationJSON(t),
		"reachability-trial":               validTrialJSON(t),
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
	addVerify("descriptor-policy-binding/wrong-commitment", "descriptor-policy-binding",
		mismatchedDescriptorPolicyJSON(t),
		"a valid policy document is not this Agent's policy unless it reproduces the digest committed by the finalized delegation")

	addVerify("mailbox-capability-grant-binding/tampered-endpoint-signature", "mailbox-capability-grant-binding",
		tamperedMailboxGrantSignatureJSON(t),
		"a grant whose signature is not the finalized Endpoint's over this exact Relay, mailbox, capability key, and operation set grants no authority")
	addVerify("mailbox-access-request-binding/tampered-capability-signature", "mailbox-access-request-binding",
		tamperedMailboxRequestSignatureJSON(t),
		"an operation request whose signature is not the scoped capability key's over its exact body and nonce grants no mailbox access")

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
	addVerify("mls-credential-binding/tampered-signature", "mls-credential-binding",
		tamperedMLSCredentialJSON(t),
		"an MLS device credential must carry the delegated Endpoint's signature over the exact leaf key and KeyPackage")
	addVerify("mls-credential-binding/stale-device-set", "mls-credential-binding",
		staleMLSCredentialJSON(t),
		"an MLS credential bound to an old device set cannot authorise a leaf after device succession")

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

	// A trial is a complete, signed record and still not evidence unless the
	// coordinator that attested it was predeclared and the endpoint signature
	// holds. Both are what keep the policy's thresholds from being advisory.
	addVerify("reachability-trial/foreign-coordinator", "reachability-trial",
		trialForeignCoordinatorJSON(t),
		"a trial attested by a coordinator the policy did not predeclare can be minted by anyone and must not count")
	addVerify("reachability-trial/tampered-endpoint-signature", "reachability-trial",
		trialTamperedSignatureJSON(t),
		"a trial whose endpoint signature does not verify is rewritable after the fact and is not the measurement it claims")
	addVerify("reachability-trial/tampered-sized-echo", "reachability-trial",
		trialTamperedSizedEchoJSON(t),
		"a sized-echo result is route evidence only when the endpoint signature covers its exact payload, outcome, and latency")

	// A trial may declare its NAT mapping, but the class is derived from the
	// coordinator-signed bind reflections it carries. Declaring
	// endpoint-independent while two distinct coordinators reflected differing
	// addresses is the endpoint attesting to a mapping the signed evidence
	// refutes, and it must not count.
	addVerify("reachability-trial/mapping-contradicts-bind", "reachability-trial",
		trialMappingContradictsBindJSON(t),
		"a declared endpoint-independent mapping contradicted by reflections from two coordinators at differing addresses is refuted by the signed evidence")

	// Filtering receipts are held to the same standard as bind reflections: a
	// receipt is a coordinator's signed statement that a cold-source probe was
	// demonstrably received, and one that does not verify, or names a different
	// measurement, is an unchecked assertion wearing a coordinator's name.
	addVerify("reachability-trial/forged-filtering-signature", "reachability-trial",
		trialForgedFilteringSignatureJSON(t),
		"a filtering receipt whose coordinator signature does not verify attests no receipt at all")
	addVerify("reachability-trial/filtering-names-another-session", "reachability-trial",
		trialFilteringForeignSessionJSON(t),
		"a validly signed filtering receipt for a different session is somebody else's receipt and must not count for this trial")
	add("reachability-trial/duplicate-filtering-coordinator", "reachability-trial",
		trialDuplicateFilteringCoordinatorJSON(t),
		"one coordinator attesting the same cold source twice could pad the set or hide two conflicting receipts under one name")

	// The collector-manifest digests are required: a trial that cannot name
	// which collector build produced each half cannot be filed under a
	// per-implementation report, so the field is refused missing or malformed
	// rather than defaulted.
	add("reachability-trial/missing-manifest-digest", "reachability-trial",
		setField(string(validTrialJSON(t)), "local_collector_manifest_digest", ""),
		"a trial without its own collector manifest digest cannot say which build produced it")
	add("reachability-trial/short-manifest-digest", "reachability-trial",
		setField(string(validTrialJSON(t)), "peer_collector_manifest_digest", "sha256:abc"),
		"a truncated manifest digest is not a commitment to any build")

	// The phase-status booleans carry cross-rules, and a record that breaks
	// them is not weaker evidence about a phase -- it is a record whose meaning
	// the reader would have to choose.
	add("reachability-trial/reconnect-success-without-latency", "reachability-trial",
		phaseStatusTrialJSON(t, func(trial *reachability.Trial) {
			trial.ReconnectAttempted = true
			trial.ReconnectSucceeded = true
		}),
		"a reconnect success and its measured latency imply each other, so a success without one is a claim without its measurement")
	add("reachability-trial/hold-completed-without-attempt", "reachability-trial",
		phaseStatusTrialJSON(t, func(trial *reachability.Trial) {
			trial.HoldCompleted = true
			trial.SurvivalSeconds = 30
		}),
		"a phase cannot complete without having been attempted")
	add("reachability-trial/tunnel-hold-on-direct-outcome", "reachability-trial",
		phaseStatusTrialJSON(t, func(trial *reachability.Trial) {
			trial.TunnelHoldAttempted = true
		}),
		"a tunnel hold belongs to a proxy fallback; on a direct outcome there was no tunneled session to hold")
	add("reachability-trial/sized-echo-success-without-latency", "reachability-trial",
		echoShapeTrialJSON(t, func(trial *reachability.Trial) {
			trial.SizedEchoes[0].RoundTripMillis = 0
		}),
		"a successful sized echo without a measured round trip is an outcome without evidence")
	add("reachability-trial/duplicate-sized-echo-payload", "reachability-trial",
		echoShapeTrialJSON(t, func(trial *reachability.Trial) {
			trial.SizedEchoes[1].PayloadBytes = trial.SizedEchoes[0].PayloadBytes
		}),
		"one payload size may contribute at most one attempt per endpoint half")
	add("reachability-trial/unordered-sized-echo-payloads", "reachability-trial",
		echoShapeTrialJSON(t, func(trial *reachability.Trial) {
			trial.SizedEchoes[0], trial.SizedEchoes[1] = trial.SizedEchoes[1], trial.SizedEchoes[0]
		}),
		"sized echo measurements have one canonical ascending order so signatures cannot cover alternate representations")

	sort.Slice(corpus, func(i, j int) bool { return corpus[i].Name < corpus[j].Name })
	return corpus
}

func validStoredAckJSON(t *testing.T) []byte {
	t.Helper()
	ack, err := mailbox.SignAck(mailbox.StoredAck{
		MailboxID: "mbx_" + strings.Repeat("5a", 32), MessageID: "msg_" + strings.Repeat("6b", 32),
		CiphertextDigest: "sha256:" + strings.Repeat("7c", 32), StoredAtUnix: baseUnix + 1,
		ExpiresAtUnix: baseUnix + 3600,
	}, endpointKey())
	if err != nil {
		t.Fatal(err)
	}
	raw, err := mailbox.EncodeAckJSON(ack)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func validMailboxGrant(t *testing.T) mailbox.CapabilityGrant {
	t.Helper()
	del := delegation(t)
	grant, err := mailbox.SignGrant(mailbox.CapabilityGrant{
		NetworkID:              del.Network.NetworkId,
		GenesisRootHash:        del.Network.GenesisRootHash,
		GenesisFileHash:        del.Network.GenesisFileHash,
		AgentID:                del.AgentID,
		EndpointID:             del.EndpointID,
		RelayPublicKeyHex:      hex.EncodeToString(mailboxRelayKey().Public().(ed25519.PublicKey)),
		MailboxID:              "mbx_" + strings.Repeat("5a", 32),
		CapabilityPublicKeyHex: hex.EncodeToString(mailboxCapabilityKey().Public().(ed25519.PublicKey)),
		Operations:             []mailbox.Operation{mailbox.OperationDelete, mailbox.OperationDeposit, mailbox.OperationRead},
		IssuedAtUnix:           baseUnix,
		ExpiresAtUnix:          baseUnix + 3600,
	}, endpointKey())
	if err != nil {
		t.Fatal(err)
	}
	return grant
}

func validMailboxGrantJSON(t *testing.T) []byte {
	t.Helper()
	raw, err := mailbox.EncodeGrantJSON(validMailboxGrant(t))
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func validMailboxRequestJSON(t *testing.T) []byte {
	t.Helper()
	grant := validMailboxGrant(t)
	grantDigest, err := mailbox.GrantDigest(grant)
	if err != nil {
		t.Fatal(err)
	}
	bodyDigest, err := mailbox.ReadBodyDigest(grant.MailboxID, 25)
	if err != nil {
		t.Fatal(err)
	}
	request, err := mailbox.SignAccessRequest(mailbox.AccessRequest{
		GrantDigest:   grantDigest,
		Operation:     mailbox.OperationRead,
		MailboxID:     grant.MailboxID,
		BodyDigest:    bodyDigest,
		NonceHex:      strings.Repeat("66", 32),
		IssuedAtUnix:  baseUnix + 10,
		ExpiresAtUnix: baseUnix + 70,
	}, mailboxCapabilityKey())
	if err != nil {
		t.Fatal(err)
	}
	raw, err := mailbox.EncodeAccessRequestJSON(request)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func validConformanceReportJSON(t *testing.T) []byte {
	t.Helper()
	report, err := conformance.Sign(conformance.Report{
		Implementation: "example.org/independent-messenger", ImplementationCommit: "release-1",
		Toolchain: "rustc-1.90", RunAtUnix: baseUnix + 2,
		Artifacts:      []conformance.Artifact{{Name: "adversarial", SHA256: strings.Repeat("1", 64)}, {Name: "e2ee", SHA256: strings.Repeat("2", 64)}, {Name: "objects", SHA256: strings.Repeat("3", 64)}},
		PositiveChecks: 12, AdversarialChecks: 44,
	}, endpointKey())
	if err != nil {
		t.Fatal(err)
	}
	raw, err := conformance.EncodeJSON(report)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}
