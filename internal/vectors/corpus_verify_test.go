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

// buildVerifiers returns the verify-layer checks, each closing over the fixed
// context (a delegation, the current instant) a second implementation would
// supply from its own state.
func buildVerifiers(t *testing.T) map[string]func([]byte) error {
	t.Helper()
	del := delegation(t)
	now := verifyNow()
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
