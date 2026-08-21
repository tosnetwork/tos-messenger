package attachmentops

import (
	"bytes"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"

	"github.com/tosnetwork/tos-messenger/pkg/identity"
)

func validConfig(t *testing.T) Config {
	t.Helper()
	return testConfig()
}

func testConfig() Config {
	storage := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{8}, ed25519.SeedSize))
	return Config{Schema: ConfigSchema, StorageOrigin: "https://storage.example",
		StoragePublicKeyHex:  hex.EncodeToString(storage.Public().(ed25519.PublicKey)),
		EndpointSignerSocket: "/run/tos/endpoint-signer.sock", SignerTimeoutSeconds: 10,
		RetentionSeconds: 3600, MaxPlaintextBytes: 8 << 20,
		AllowedMediaTypes:          []string{"application/octet-stream", "text/plain"},
		HTTPSRequestTimeoutSeconds: 30, HTTPSConnectTimeoutSeconds: 5}
}

func TestConfigStrictDecodeAndAuthoritySeparation(t *testing.T) {
	config := validConfig(t)
	raw, _ := json.Marshal(config)
	decoded, err := Decode(raw)
	if err != nil || decoded.StorageOrigin != config.StorageOrigin {
		t.Fatalf("decode=%+v err=%v", decoded, err)
	}
	mutations := map[string][]byte{
		"unknown":         bytes.Replace(raw, []byte(`"schema"`), []byte(`"unknown":1,"schema"`), 1),
		"relative signer": bytes.Replace(raw, []byte(config.EndpointSignerSocket), []byte("sign.sock"), 1),
		"port origin":     bytes.Replace(raw, []byte(config.StorageOrigin), []byte("https://storage.example:443"), 1),
		"unsorted media":  bytes.Replace(raw, []byte(`"application/octet-stream","text/plain"`), []byte(`"text/plain","application/octet-stream"`), 1),
		"trailing":        append(append([]byte(nil), raw...), []byte(`{}`)...),
	}
	for name, candidate := range mutations {
		t.Run(name, func(t *testing.T) {
			if _, err := Decode(candidate); err == nil {
				t.Fatal("accepted invalid operator configuration")
			}
		})
	}
	endpoint := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{9}, ed25519.SeedSize))
	delegation := identity.Delegation{IdentityPublicKey: endpoint.Public().(ed25519.PublicKey)}
	if _, err := Assemble(config, delegation); err != nil {
		t.Fatal(err)
	}
	config.StoragePublicKeyHex = hex.EncodeToString(endpoint.Public().(ed25519.PublicKey))
	if _, err := Assemble(config, delegation); err == nil || !strings.Contains(err.Error(), "distinct") {
		t.Fatalf("storage/Endpoint key reuse was not refused: %v", err)
	}
}

func FuzzDecodeAttachmentEmissionConfig(f *testing.F) {
	config := testConfig()
	seed, _ := json.Marshal(config)
	f.Add(seed)
	f.Add([]byte(`{}`))
	f.Add([]byte(`{"schema":"tos.messaging.attachment-emission-operator.v1"}`))
	f.Fuzz(func(t *testing.T, raw []byte) {
		decoded, err := Decode(raw)
		if err != nil {
			return
		}
		if err := decoded.Validate(); err != nil {
			t.Fatalf("Decode accepted a configuration that Validate rejects: %v", err)
		}
		canonical, err := json.Marshal(decoded)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := Decode(canonical); err != nil {
			t.Fatalf("accepted configuration did not round-trip: %v", err)
		}
	})
}
