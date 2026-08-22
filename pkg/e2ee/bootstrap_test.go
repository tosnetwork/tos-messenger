package e2ee

import (
	"bytes"
	"strings"
	"testing"
)

func validFirstContact(t *testing.T) FirstContact {
	t.Helper()
	key := endpointKey(t, 0x42)
	delegation := testDelegation(t, key)
	bundle := signedBundle(t, delegation, deviceOne, key)
	digest, err := BundleDigest(bundle)
	if err != nil {
		t.Fatalf("digest bundle: %v", err)
	}
	return FirstContact{Binding: Binding{
		Network: delegation.Network, AlgorithmID: algorithm,
		ConversationID: "conv_" + strings.Repeat("1", 64),
		SenderAgentID:  delegation.AgentID, SenderEndpointID: delegation.EndpointID,
		SenderDeviceID: deviceOne, RecipientAgentID: "agent_" + strings.Repeat("5", 64),
		RecipientEndpointID: "mep_" + strings.Repeat("6", 64), RecipientDeviceID: deviceTwo,
	}, SenderBundle: bundle, RecipientBundleDigest: digest, Initial: []byte("suite initial")}
}

func TestFirstContactRoundTripBindsPublicEvidence(t *testing.T) {
	value := validFirstContact(t)
	raw, err := EncodeFirstContactJSON(value)
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	decoded, err := DecodeFirstContactJSON(raw)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if decoded.Binding.SenderAgentID != value.Binding.SenderAgentID ||
		decoded.Binding.RecipientDeviceID != value.Binding.RecipientDeviceID ||
		!bytes.Equal(decoded.Initial, value.Initial) {
		t.Fatalf("round trip changed bootstrap: %+v", decoded)
	}
}

func TestFirstContactRejectsAuthoritySubstitution(t *testing.T) {
	tests := map[string]func(*FirstContact){
		"sender agent":  func(v *FirstContact) { v.Binding.SenderAgentID = "agent_" + strings.Repeat("9", 64) },
		"sender device": func(v *FirstContact) { v.Binding.SenderDeviceID = "dev_" + strings.Repeat("9", 64) },
		"network": func(v *FirstContact) {
			v.Binding.Network = testNetwork()
			v.Binding.Network.NetworkId = "another-network"
		},
		"recipient digest": func(v *FirstContact) { v.RecipientBundleDigest = "sha256:wrong" },
		"empty initial":    func(v *FirstContact) { v.Initial = nil },
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			value := validFirstContact(t)
			mutate(&value)
			if _, err := EncodeFirstContactJSON(value); err == nil {
				t.Fatal("authority substitution was accepted")
			}
		})
	}
}

func TestFirstContactWireRejectsMutationAndUnknownFields(t *testing.T) {
	raw, err := EncodeFirstContactJSON(validFirstContact(t))
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	mutated := bytes.Replace(raw, []byte(`"initial_digest":"sha256:`), []byte(`"initial_digest":"sha256:f`), 1)
	if _, err := DecodeFirstContactJSON(mutated); err == nil {
		t.Fatal("mutated initial digest was accepted")
	}
	unknown := append(append([]byte(nil), raw[:len(raw)-1]...), []byte(`,"route":"model-chosen"}`)...)
	if _, err := DecodeFirstContactJSON(unknown); err == nil {
		t.Fatal("unknown low-level routing field was accepted")
	}
}
