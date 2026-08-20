package vectors

import (
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/tosnetwork/tos-messenger/pkg/e2ee"
	"github.com/tosnetwork/tos-messenger/pkg/envelope"
	"github.com/tosnetwork/tos-messenger/pkg/payload"
	"github.com/tosnetwork/tos-messenger/pkg/reachability"
)

// The verify layer is where an object is refused for what it means, not for how
// it is shaped. Every input below decodes cleanly -- a second implementation
// that only checked its decoders would accept all of them -- and must still be
// refused once the object is measured against the authority it claims: the
// delegation a prekey bundle is signed under, the route a local-only kind
// arrived on, the key a reachability attestation names.
//
// These are kept apart from the decode-layer corpus for the reason the three
// original attempts were removed from it: a semantic refusal filed under a
// decoder would let a second implementation pass by refusing at decode for the
// wrong reason. Here the check is the real verifier, so an entry that this
// implementation's verifier accepted could not be generated.

// verifyNow is an instant inside the baseline delegation's window, so a bound
// bundle is neither unissued nor expired when the binding is checked.
func verifyNow() time.Time { return time.Unix(int64(baseUnix)+10, 0) }

// inPolicyCoordinatorKey signs attestations a trial policy predeclares; the
// baseline trial uses it, so a foreign-coordinator mutation is refused for the
// coordinator alone and not for a broken attestation.
func inPolicyCoordinatorKey() ed25519.PrivateKey {
	return ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize))
}

// foreignCoordinatorKey signs a self-consistent attestation from a coordinator
// no policy predeclared.
func foreignCoordinatorKey() ed25519.PrivateKey {
	seed := make([]byte, ed25519.SeedSize)
	for i := range seed {
		seed[i] = 0x07
	}
	return ed25519.NewKeyFromSeed(seed)
}

// secondCoordinatorKey is a second predeclared coordinator, so a trial can
// carry bind reflections from two distinct coordinators -- the minimum the NAT
// mapping class can be derived from.
func secondCoordinatorKey() ed25519.PrivateKey {
	seed := make([]byte, ed25519.SeedSize)
	for i := range seed {
		seed[i] = 0x22
	}
	return ed25519.NewKeyFromSeed(seed)
}

func coordinatorID(t *testing.T, key ed25519.PrivateKey) string {
	t.Helper()
	public, ok := key.Public().(ed25519.PublicKey)
	if !ok {
		t.Fatal("unexpected public key type")
	}
	id, err := reachability.CoordinatorID(public)
	if err != nil {
		t.Fatalf("coordinator id: %v", err)
	}
	return id
}

// trialPolicy predeclares both test coordinators, which is all VerifyTrial
// reads from a policy.
func trialPolicy(t *testing.T) reachability.Policy {
	t.Helper()
	return reachability.Policy{Coordinators: []string{
		coordinatorID(t, inPolicyCoordinatorKey()),
		coordinatorID(t, secondCoordinatorKey()),
	}}
}

// buildVerifiers returns the verify-layer checks, each closing over the fixed
// context (a delegation, a trial policy, the current instant) a second
// implementation would supply from its own state.
func buildVerifiers(t *testing.T) map[string]func([]byte) error {
	t.Helper()
	del := delegation(t)
	now := verifyNow()
	policy := trialPolicy(t)
	return map[string]func([]byte) error{
		"prekey-bundle-binding": func(b []byte) error {
			bundle, err := e2ee.DecodeBundleJSON(b)
			if err != nil {
				return err
			}
			return e2ee.BindBundle(del, bundle, now)
		},
		"messaging-event-network-route": func(b []byte) error {
			event, err := envelope.DecodeEventJSON(b)
			if err != nil {
				return err
			}
			if err := envelope.ValidateEvent(event); err != nil {
				return err
			}
			// The exact predicate the dispatcher and the admission gate consult
			// on the network path. A local-only kind carries authority, so it is
			// refused outright rather than evaluated.
			if envelope.LocalOnly(event.Kind) {
				return errors.New("a local-only kind arrived over the network")
			}
			return nil
		},
		"reachability-observation": func(b []byte) error {
			var observation reachability.Observation
			if err := json.Unmarshal(b, &observation); err != nil {
				return err
			}
			return reachability.VerifyObservation(observation)
		},
		"reachability-trial": func(b []byte) error {
			trial, err := reachability.DecodeTrialJSON(b)
			if err != nil {
				return err
			}
			return reachability.VerifyTrial(policy, trial)
		},
	}
}

// verifyDecoders is the decode-only step for each verify target. A verify entry
// must pass this and fail its verifier: that is what proves the refusal is owed
// to the authority the object claims, not to its shape. Without it, a verify
// entry that a decoder happened to reject would masquerade as a verify-layer
// case, the exact confusion this split exists to prevent.
func verifyDecoders() map[string]func([]byte) error {
	return map[string]func([]byte) error{
		"prekey-bundle-binding":         func(b []byte) error { _, err := e2ee.DecodeBundleJSON(b); return err },
		"messaging-event-network-route": func(b []byte) error { _, err := envelope.DecodeEventJSON(b); return err },
		"reachability-observation": func(b []byte) error {
			var observation reachability.Observation
			return json.Unmarshal(b, &observation)
		},
		"reachability-trial": func(b []byte) error { _, err := reachability.DecodeTrialJSON(b); return err },
	}
}

// signedBundle builds a bundle signed by the delegated endpoint key, applying a
// mutation before signing so the signature covers the mutated content. That is
// what separates a semantic refusal (identity, expiry) from a signature
// refusal: the signature is valid, and the binding still says no.
func signedBundle(t *testing.T, mutate func(*e2ee.Bundle)) e2ee.Bundle {
	t.Helper()
	del := delegation(t)
	bundle := e2ee.Bundle{
		Network: del.Network, AgentID: del.AgentID, EndpointID: del.EndpointID,
		DeviceID: deviceOne, AlgorithmID: algorithm,
		Material:     []byte("published prekey material"),
		IssuedAtUnix: baseUnix, ExpiresAtUnix: baseUnix + 3600,
	}
	if mutate != nil {
		mutate(&bundle)
	}
	signed, err := e2ee.SignBundle(bundle, endpointKey())
	if err != nil {
		t.Fatalf("sign bundle: %v", err)
	}
	return signed
}

func encodeBundle(t *testing.T, bundle e2ee.Bundle) string {
	t.Helper()
	encoded, err := e2ee.EncodeBundleJSON(bundle)
	if err != nil {
		t.Fatalf("encode bundle: %v", err)
	}
	return string(encoded)
}

// boundBundleJSON is the verify-layer baseline: a bundle that binds, so the
// mutations below prove the refusal and not a broken baseline.
func boundBundleJSON(t *testing.T) []byte {
	t.Helper()
	return []byte(encodeBundle(t, signedBundle(t, nil)))
}

// tamperedBundleSignatureJSON keeps a valid-length signature that is not the
// endpoint's over this content.
func tamperedBundleSignatureJSON(t *testing.T) string {
	t.Helper()
	bundle := signedBundle(t, nil)
	bundle.EndpointSignature[0] ^= 0xff
	return encodeBundle(t, bundle)
}

// bundleOutlivingDelegationJSON is validly signed but claims to live one second
// past the delegation that authorised its key.
func bundleOutlivingDelegationJSON(t *testing.T) string {
	t.Helper()
	del := delegation(t)
	bundle := signedBundle(t, func(b *e2ee.Bundle) {
		b.ExpiresAtUnix = del.ExpiresAtUnix + 1
	})
	return encodeBundle(t, bundle)
}

// bundleForeignAgentJSON is validly signed over its own content, but names an
// Agent the delegation does not authorise.
func bundleForeignAgentJSON(t *testing.T) string {
	t.Helper()
	foreign := "agent_" + strings.Repeat("9", 64)
	bundle := signedBundle(t, func(b *e2ee.Bundle) { b.AgentID = foreign })
	return encodeBundle(t, bundle)
}

// localOnlyEventFromNetworkJSON is a well-formed owner-approval event. The kind
// exists only on the owner's own interface; arriving over the network, it must
// be refused before it is evaluated.
func localOnlyEventFromNetworkJSON(t *testing.T) string {
	t.Helper()
	del := delegation(t)
	body, err := payload.Encode(payload.OwnerApprovalGrant{
		ApprovalID:    "apr-verify-1",
		EventID:       "evt_" + strings.Repeat("a", 64),
		DecidedAtUnix: baseUnix,
	})
	if err != nil {
		t.Fatalf("approval payload: %v", err)
	}
	event, err := envelope.NewEvent(envelope.Event{
		Network: del.Network, ConversationID: convoID,
		SenderAgentID: del.AgentID, SenderEndpointID: del.EndpointID, SenderDeviceID: deviceOne,
		CreatedAtUnix: baseUnix + 10, Kind: "owner.approval.grant", Content: body, Rendering: "grant",
	})
	if err != nil {
		t.Fatalf("owner-approval event: %v", err)
	}
	encoded, err := envelope.EncodeEventJSON(event)
	if err != nil {
		t.Fatalf("event wire: %v", err)
	}
	return string(encoded)
}

// validObservationJSON is the verify-layer baseline for a coordinator
// attestation, so the tampering below is measured against a signature that
// otherwise verifies.
func validObservationJSON(t *testing.T) []byte {
	t.Helper()
	return []byte(observationJSON(t, false))
}

// tamperedObservationJSON keeps a valid-length coordinator signature that does
// not verify under the key the attestation names.
func tamperedObservationJSON(t *testing.T) string {
	t.Helper()
	return observationJSON(t, true)
}

func observationJSON(t *testing.T, tamper bool) string {
	t.Helper()
	public, ok := endpointKey().Public().(ed25519.PublicKey)
	if !ok {
		t.Fatal("unexpected public key type")
	}
	coordinatorKey := ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize))
	observation, err := reachability.SignObservation(reachability.Observation{
		SessionID:            "ses-verify-1",
		Role:                 "a",
		EndpointPublicKeyHex: hex.EncodeToString(public),
		Probe:                string(reachability.ProbeUDP),
		Observed:             "203.0.113.7:41234",
		PeerPublic:           "yes",
		AtUnix:               baseUnix,
	}, coordinatorKey)
	if err != nil {
		t.Fatalf("sign observation: %v", err)
	}
	if tamper {
		signature, err := hex.DecodeString(observation.SignatureHex)
		if err != nil || len(signature) == 0 {
			t.Fatalf("decode signature: %v", err)
		}
		signature[0] ^= 0xff
		observation.SignatureHex = hex.EncodeToString(signature)
	}
	encoded, err := json.Marshal(observation)
	if err != nil {
		t.Fatalf("encode observation: %v", err)
	}
	return string(encoded)
}

// corpusManifestDigest is the digest of a fixed collector manifest, varied by
// seed so the baseline trial's two halves name two different builds the way
// two real endpoints do.
func corpusManifestDigest(t *testing.T, seed string) string {
	t.Helper()
	digest, err := reachability.CollectorManifest{
		OrchestratorRepository:   "github.com/tosnetwork/tos-messenger",
		OrchestratorCommit:       strings.Repeat("a", 40),
		ADNLImplementation:       "tosutils-go",
		ADNLImplementationCommit: "v1.0.0-" + seed,
		DependencyVersion:        "v1.0.0-" + seed,
		BinarySHA256:             strings.Repeat("ab", 32),
		Target:                   "linux/amd64",
		Toolchain:                "go1.26.5",
		WireProfile:              "ton-adnl",
	}.Digest()
	if err != nil {
		t.Fatalf("manifest digest: %v", err)
	}
	return digest
}

// signedTrial builds a complete measurement half signed by the endpoint that
// produced it, with a coordinator attestation over the same session, role,
// endpoint key, and probe. The coordinator key is a parameter so a baseline can
// use one the policy predeclares and a mutation can use one it does not.
func signedTrial(t *testing.T, coordinatorKey ed25519.PrivateKey) reachability.Trial {
	t.Helper()
	public, ok := endpointKey().Public().(ed25519.PublicKey)
	if !ok {
		t.Fatal("unexpected public key type")
	}
	endpointHex := hex.EncodeToString(public)
	const session = "ses-trial-1"
	pairID, err := reachability.PairID(session)
	if err != nil {
		t.Fatalf("pair id: %v", err)
	}
	siteID, err := reachability.SiteID("site-verify-1")
	if err != nil {
		t.Fatalf("site id: %v", err)
	}
	operatorID, err := reachability.OperatorID("operator-verify-1")
	if err != nil {
		t.Fatalf("operator id: %v", err)
	}
	observation, err := reachability.SignObservation(reachability.Observation{
		SessionID:            session,
		Role:                 string(reachability.RoleA),
		EndpointPublicKeyHex: endpointHex,
		Probe:                string(reachability.ProbeUDP),
		Observed:             "203.0.113.7:41234",
		PeerPublic:           "no",
		AtUnix:               baseUnix,
	}, coordinatorKey)
	if err != nil {
		t.Fatalf("sign observation: %v", err)
	}
	trial := reachability.Trial{
		Local: reachability.EndpointStratum{
			Family: reachability.FamilyIPv4, Reachability: reachability.BehindNAT,
			NATBehavior: reachability.NATEndpointIndependent, Carrier: reachability.CarrierConsumerISP,
			UDPPolicy: reachability.UDPAllowed, Mobility: reachability.MobilityStationary,
			EndpointClass: reachability.ClassDesktop, Assistance: reachability.AssistanceNone,
		},
		PairID:              pairID,
		SiteID:              siteID,
		OperatorID:          operatorID,
		SessionID:           session,
		Role:                reachability.RoleA,
		Observation:         observation,
		Probe:               reachability.ProbeUDP,
		Outcome:             reachability.OutcomeDirect,
		Failure:             reachability.FailureNone,
		EstablishMillis:     42,
		StartedAtUnix:       baseUnix,
		LocalCommit:         strings.Repeat("a", 40),
		PeerCommit:          strings.Repeat("b", 40),
		LocalManifestDigest: corpusManifestDigest(t, "local"),
		PeerManifestDigest:  corpusManifestDigest(t, "peer"),
	}
	signed, err := reachability.SignTrial(trial, endpointKey())
	if err != nil {
		t.Fatalf("sign trial: %v", err)
	}
	return signed
}

func encodeTrial(t *testing.T, trial reachability.Trial) string {
	t.Helper()
	encoded, err := reachability.EncodeTrialJSON(trial)
	if err != nil {
		t.Fatalf("encode trial: %v", err)
	}
	return string(encoded)
}

// validTrialJSON is the verify-layer baseline for a measurement half: it is
// signed and its coordinator is predeclared, so the mutations below prove the
// refusal and not a broken baseline.
func validTrialJSON(t *testing.T) []byte {
	t.Helper()
	return []byte(encodeTrial(t, signedTrial(t, inPolicyCoordinatorKey())))
}

// trialForeignCoordinatorJSON is a fully valid, signed trial whose attestation
// comes from a coordinator no policy predeclared.
func trialForeignCoordinatorJSON(t *testing.T) string {
	t.Helper()
	return encodeTrial(t, signedTrial(t, foreignCoordinatorKey()))
}

// trialTamperedSignatureJSON keeps a valid-length endpoint signature that is
// not the endpoint's over this trial.
func trialTamperedSignatureJSON(t *testing.T) string {
	t.Helper()
	trial := signedTrial(t, inPolicyCoordinatorKey())
	signature, err := hex.DecodeString(trial.EndpointSignatureHex)
	if err != nil || len(signature) == 0 {
		t.Fatalf("decode endpoint signature: %v", err)
	}
	signature[0] ^= 0xff
	trial.EndpointSignatureHex = hex.EncodeToString(signature)
	return encodeTrial(t, trial)
}

// signBindReflection signs one coordinator's reflection of the baseline
// endpoint's external address, for the key the baseline trial signs with.
func signBindReflection(t *testing.T, coordinatorKey ed25519.PrivateKey, session, observed string) reachability.BindObservation {
	t.Helper()
	public, ok := endpointKey().Public().(ed25519.PublicKey)
	if !ok {
		t.Fatal("unexpected public key type")
	}
	observation, err := reachability.SignBindObservation(reachability.BindObservation{
		SessionID:            session,
		Role:                 string(reachability.RoleA),
		EndpointPublicKeyHex: hex.EncodeToString(public),
		Probe:                string(reachability.ProbeUDP),
		Observed:             observed,
		AtUnix:               baseUnix,
	}, coordinatorKey)
	if err != nil {
		t.Fatalf("sign bind observation: %v", err)
	}
	return observation
}

// signFilterReceipt signs one coordinator's receipt that the baseline endpoint
// demonstrably received a cold-source probe, for the key the baseline trial
// signs with.
func signFilterReceipt(t *testing.T, coordinatorKey ed25519.PrivateKey, session string,
	source reachability.FilterSourceKind) reachability.FilteringObservation {
	t.Helper()
	public, ok := endpointKey().Public().(ed25519.PublicKey)
	if !ok {
		t.Fatal("unexpected public key type")
	}
	observation, err := reachability.SignFilteringObservation(reachability.FilteringObservation{
		SessionID:            session,
		Role:                 string(reachability.RoleA),
		EndpointPublicKeyHex: hex.EncodeToString(public),
		Probe:                string(reachability.ProbeUDP),
		Observed:             "203.0.113.7:41234",
		Source:               source,
		AtUnix:               baseUnix,
	}, coordinatorKey)
	if err != nil {
		t.Fatalf("sign filtering observation: %v", err)
	}
	return observation
}

// trialWithFilteringJSON is a signed trial carrying the given filtering
// receipts, re-signed so the endpoint signature covers them and any refusal is
// owed to the receipts themselves.
func trialWithFilteringJSON(t *testing.T, receipts []reachability.FilteringObservation) string {
	t.Helper()
	trial := signedTrial(t, inPolicyCoordinatorKey())
	trial.FilteringObservations = receipts
	signed, err := reachability.SignTrial(trial, endpointKey())
	if err != nil {
		t.Fatalf("sign trial: %v", err)
	}
	return encodeTrial(t, signed)
}

// trialForgedFilteringSignatureJSON carries a filtering receipt whose
// coordinator signature is valid-length but not the coordinator's over this
// content: a receipt nobody issued.
func trialForgedFilteringSignatureJSON(t *testing.T) string {
	t.Helper()
	receipt := signFilterReceipt(t, inPolicyCoordinatorKey(), "ses-trial-1",
		reachability.FilterSourceOtherPort)
	signature, err := hex.DecodeString(receipt.SignatureHex)
	if err != nil || len(signature) == 0 {
		t.Fatalf("decode filtering signature: %v", err)
	}
	signature[0] ^= 0xff
	receipt.SignatureHex = hex.EncodeToString(signature)
	return trialWithFilteringJSON(t, []reachability.FilteringObservation{receipt})
}

// trialFilteringForeignSessionJSON carries a validly signed filtering receipt
// that names a different session than the trial it rides in: somebody else's
// receipt worn by this measurement.
func trialFilteringForeignSessionJSON(t *testing.T) string {
	t.Helper()
	receipt := signFilterReceipt(t, inPolicyCoordinatorKey(), "ses-trial-other",
		reachability.FilterSourceOtherPort)
	return trialWithFilteringJSON(t, []reachability.FilteringObservation{receipt})
}

// trialDuplicateFilteringCoordinatorJSON carries one coordinator attesting the
// same cold source twice. It is malformed on shape -- the duplicate could pad a
// count or hide two conflicting receipts under one name -- so it is refused at
// decode. The trial is deliberately left with its original signature: the
// signing path refuses the malformed set, so the wire had to be assembled by
// hand, exactly as an attacker would.
func trialDuplicateFilteringCoordinatorJSON(t *testing.T) string {
	t.Helper()
	trial := signedTrial(t, inPolicyCoordinatorKey())
	receipt := signFilterReceipt(t, inPolicyCoordinatorKey(), trial.SessionID,
		reachability.FilterSourceOtherPort)
	trial.FilteringObservations = []reachability.FilteringObservation{receipt, receipt}
	document, err := json.Marshal(struct {
		Schema string `json:"schema"`
		reachability.Trial
	}{Schema: reachability.TrialSchema, Trial: trial})
	if err != nil {
		t.Fatalf("encode trial: %v", err)
	}
	return string(document)
}

// phaseStatusTrialJSON is the baseline trial with its phase-status fields
// edited after signing and marshalled by hand: the signing path refuses every
// one of these combinations, so the wire had to be assembled the way an
// attacker would assemble it, and the decoder must refuse the result on shape.
func phaseStatusTrialJSON(t *testing.T, mutate func(*reachability.Trial)) string {
	t.Helper()
	trial := signedTrial(t, inPolicyCoordinatorKey())
	mutate(&trial)
	document, err := json.Marshal(struct {
		Schema string `json:"schema"`
		reachability.Trial
	}{Schema: reachability.TrialSchema, Trial: trial})
	if err != nil {
		t.Fatalf("encode trial: %v", err)
	}
	return string(document)
}

// trialMappingContradictsBindJSON is a fully valid, signed trial that declares
// an endpoint-independent mapping while carrying two predeclared coordinators'
// reflections of differing external addresses. The signed evidence shows a
// destination-dependent mapping, so the declaration is refused.
func trialMappingContradictsBindJSON(t *testing.T) string {
	t.Helper()
	trial := signedTrial(t, inPolicyCoordinatorKey())
	// The baseline already declares NATEndpointIndependent; attach reflections
	// that refute it, then re-sign so the endpoint signature covers them and the
	// refusal is owed to the mapping check, not a broken signature.
	trial.BindObservations = []reachability.BindObservation{
		signBindReflection(t, inPolicyCoordinatorKey(), trial.SessionID, "203.0.113.7:41234"),
		signBindReflection(t, secondCoordinatorKey(), trial.SessionID, "198.51.100.9:5000"),
	}
	signed, err := reachability.SignTrial(trial, endpointKey())
	if err != nil {
		t.Fatalf("sign trial: %v", err)
	}
	return encodeTrial(t, signed)
}
