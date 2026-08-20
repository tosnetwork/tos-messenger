package directory

import (
	"bytes"
	"strings"
	"testing"
)

func TestDescriptorPolicyJSONRoundTripPreservesCommitment(t *testing.T) {
	policy := testPolicy()
	raw, err := EncodeDescriptorPolicyJSON(policy)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := DecodeDescriptorPolicyJSON(raw)
	if err != nil {
		t.Fatal(err)
	}
	want, err := policy.Digest()
	if err != nil {
		t.Fatal(err)
	}
	got, err := decoded.Digest()
	if err != nil || got != want {
		t.Fatalf("digest=%q err=%v, want %q", got, err, want)
	}
}

func TestDescriptorPolicyJSONStrictRefusal(t *testing.T) {
	valid, err := EncodeDescriptorPolicyJSON(testPolicy())
	if err != nil {
		t.Fatal(err)
	}
	cases := map[string][]byte{
		"empty":        nil,
		"unknown":      bytes.Replace(valid, []byte(`{"schema"`), []byte(`{"unknown":1,"schema"`), 1),
		"wrong schema": bytes.Replace(valid, []byte(DescriptorPolicySchema), []byte("tos.messaging.descriptor-policy.v2"), 1),
		"trailing":     append(append([]byte(nil), valid...), []byte(`{"x":1}`)...),
		"oversized":    []byte(strings.Repeat(" ", MaxDescriptorPolicyWireBytes+1)),
	}
	for name, raw := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := DecodeDescriptorPolicyJSON(raw); err == nil {
				t.Fatal("accepted invalid descriptor policy")
			}
		})
	}
}
