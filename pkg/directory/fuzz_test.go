package directory

import "testing"

func FuzzDecodeDescriptorJSON(f *testing.F) {
	f.Add([]byte(`{"schema":"tos.messaging.contact-descriptor.v1"}`))
	f.Add([]byte("{}"))
	f.Fuzz(func(t *testing.T, raw []byte) {
		decoded, err := DecodeDescriptorJSON(raw)
		if err != nil {
			return
		}
		if _, err := EncodeDescriptorJSON(decoded); err != nil {
			t.Fatalf("a decoded descriptor could not be re-encoded: %v", err)
		}
	})
}

// The locator decoder parses a length-prefixed binary value straight off the
// DHT, which is the one place in this package where a malformed length could
// read past a buffer.
func FuzzDecodeLocator(f *testing.F) {
	f.Add(make([]byte, 147))
	f.Add([]byte{1})
	f.Add([]byte(""))
	f.Fuzz(func(t *testing.T, raw []byte) {
		decoded, err := DecodeLocator(raw)
		if err != nil {
			return
		}
		encoded, err := EncodeLocator(decoded)
		if err != nil {
			t.Fatalf("a decoded locator could not be re-encoded: %v", err)
		}
		if len(encoded) > MaxDHTValueBytes {
			t.Fatalf("a decoded locator re-encoded beyond the network limit: %d", len(encoded))
		}
	})
}
