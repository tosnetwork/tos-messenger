package envelope

import "testing"

// A relay envelope arrives from anyone who can reach the mailbox, so its
// decoder sees the most hostile bytes in the system.
func FuzzDecodeRelayJSON(f *testing.F) {
	if encoded, err := EncodeRelayJSON(RelayEnvelope{
		OpaqueMailboxID: "mbx_" + repeatHex("5a", 32),
		MessageID:       "msg_" + repeatHex("6b", 32),
		Ciphertext:      []byte("0123456789abcdef0123456789abcdef0123456789"),
		ExpiresAtUnix:   1_800_003_600,
	}); err == nil {
		f.Add(encoded)
	}
	f.Add([]byte(`{"schema":"tos.messaging.relay-envelope.v1"}`))
	f.Add([]byte(""))
	f.Fuzz(func(t *testing.T, raw []byte) {
		decoded, err := DecodeRelayJSON(raw)
		if err != nil {
			return
		}
		encoded, err := EncodeRelayJSON(decoded)
		if err != nil {
			t.Fatalf("a decoded envelope could not be re-encoded: %v", err)
		}
		if _, err := DecodeRelayJSON(encoded); err != nil {
			t.Fatalf("a re-encoded envelope could not be decoded: %v", err)
		}
	})
}

func FuzzDecodeEventJSON(f *testing.F) {
	f.Add([]byte(`{"schema":"tos.messaging.event.v2"}`))
	f.Add([]byte("{}"))
	f.Fuzz(func(t *testing.T, raw []byte) {
		decoded, err := DecodeEventJSON(raw)
		if err != nil {
			return
		}
		// Anything that decodes carries an identifier that matches its own
		// content, or the content addressing is not doing its job.
		if err := ValidateEvent(decoded); err != nil {
			t.Fatalf("a decoded event failed validation: %v", err)
		}
		if _, err := EncodeEventJSON(decoded); err != nil {
			t.Fatalf("a decoded event could not be re-encoded: %v", err)
		}
	})
}

func repeatHex(pair string, count int) string {
	out := make([]byte, 0, len(pair)*count)
	for index := 0; index < count; index++ {
		out = append(out, pair...)
	}
	return string(out)
}
