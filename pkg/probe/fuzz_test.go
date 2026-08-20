package probe

import "testing"

// Probe datagrams arrive unauthenticated from anywhere.
func FuzzDecode(f *testing.F) {
	if encoded, err := EncodeRequest(Message{
		Kind: KindBind, SessionID: testSession, Role: RoleA, Nonce: testNonce,
	}); err == nil {
		f.Add(encoded)
	}
	if encoded, err := EncodeRequest(Message{
		Kind: KindFilterEcho, SessionID: testSession, Role: RoleA, Nonce: testNonce,
		Token: testNonce, EndpointKey: testEndpointKey(RoleA), Probe: "udp",
	}); err == nil {
		f.Add(encoded)
	}
	f.Add([]byte(`{"schema":"tos.messaging.reachability-probe.v1"}`))
	f.Add([]byte(""))
	f.Fuzz(func(t *testing.T, raw []byte) {
		decoded, err := Decode(raw)
		if err != nil {
			return
		}
		if _, err := Encode(decoded); err != nil {
			t.Fatalf("a decoded message could not be re-encoded: %v", err)
		}
	})
}
