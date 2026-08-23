package payload

import (
	"bytes"
	"testing"
)

func TestAgentGiftPayloadsPreserveExactCanonicalBytes(t *testing.T) {
	tests := map[string]Payload{
		"agent.gift.address-request":  GiftAddressRequest{CanonicalRequest: []byte{1, 2, 3}},
		"agent.gift.address-response": GiftAddressResponse{CanonicalResponse: []byte{4, 5, 6}},
		"agent.gift.signed-boc-offer": GiftSignedBOCOffer{CanonicalOffer: []byte{7, 8, 9}},
	}
	for kind, value := range tests {
		encoded, err := Encode(value)
		if err != nil {
			t.Fatal(err)
		}
		decoded, err := Decode(kind, encoded)
		if err != nil {
			t.Fatal(err)
		}
		reencoded, err := Encode(decoded)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(encoded, reencoded) {
			t.Fatalf("%s changed exact bytes", kind)
		}
	}
}

func TestAgentGiftPayloadBounds(t *testing.T) {
	if _, err := Encode(GiftSignedBOCOffer{}); err == nil {
		t.Fatal("empty offer accepted")
	}
	if _, err := Encode(GiftSignedBOCOffer{CanonicalOffer: make([]byte, MaxGiftCanonicalBytes+1)}); err == nil {
		t.Fatal("oversized offer accepted")
	}
}
