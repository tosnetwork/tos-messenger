package fault

import "testing"

// A fault response is read from a peer, so a hidden code must never survive a
// round trip through it.
func FuzzDecodeResponseJSON(f *testing.F) {
	if encoded, err := EncodeResponseJSON(PeerCode(CodeRateLimited, 30)); err == nil {
		f.Add(encoded)
	}
	f.Add([]byte(`{"schema":"tos.messaging.fault-response.v1","code":"rejected"}`))
	f.Add([]byte(""))
	f.Fuzz(func(t *testing.T, raw []byte) {
		decoded, err := DecodeResponseJSON(raw)
		if err != nil {
			return
		}
		if !PeerVisible(decoded.Code) {
			t.Fatalf("a hidden code survived decoding: %q", decoded.Code)
		}
		if _, err := EncodeResponseJSON(decoded); err != nil {
			t.Fatalf("a decoded response could not be re-encoded: %v", err)
		}
	})
}
