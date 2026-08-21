package e2ee

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
)

func TestBundleSetJSONRoundTripAndCommitment(t *testing.T) {
	first, second := setTestBundles(t)
	raw, err := EncodeBundleSetJSON([]Bundle{first, second})
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := DecodeBundleSetJSON(raw)
	if err != nil {
		t.Fatal(err)
	}
	want, err := SetDigest([]Bundle{first, second})
	if err != nil {
		t.Fatal(err)
	}
	got, err := SetDigest(decoded)
	if err != nil || got != want {
		t.Fatalf("digest=%q err=%v, want %q", got, err, want)
	}
	reversed, err := SetCanonicalBytes([]Bundle{second, first})
	if err != nil {
		t.Fatal(err)
	}
	canonical, err := SetCanonicalBytes(decoded)
	if err != nil || !bytes.Equal(canonical, reversed) {
		t.Fatal("set commitment changed with publication order")
	}
}

func TestBundleSetJSONStrictRefusal(t *testing.T) {
	first, second := setTestBundles(t)
	valid, err := EncodeBundleSetJSON([]Bundle{first, second})
	if err != nil {
		t.Fatal(err)
	}
	var object map[string]any
	if err := json.Unmarshal(valid, &object); err != nil {
		t.Fatal(err)
	}
	object["unknown"] = true
	unknown, _ := json.Marshal(object)
	empty := []byte(`{"schema":"` + BundleSetSchema + `","bundles":[]}`)
	wrongSchema := bytes.Replace(valid, []byte(BundleSetSchema), []byte("tos.messaging.prekey-bundle-set.v999"), 1)
	badNested := bytes.Replace(valid, []byte(`"device_id"`), []byte(`"unknown_device_id"`), 1)
	cases := map[string][]byte{
		"empty": nil, "empty set": empty, "unknown": unknown,
		"wrong schema": wrongSchema, "nested unknown": badNested,
		"trailing":  append(append([]byte(nil), valid...), []byte(`{"x":1}`)...),
		"oversized": []byte(strings.Repeat(" ", MaxBundleSetWireBytes+1)),
	}
	for name, raw := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := DecodeBundleSetJSON(raw); err == nil {
				t.Fatal("accepted invalid bundle set")
			}
		})
	}
}

func setTestBundles(t *testing.T) (Bundle, Bundle) {
	t.Helper()
	key := endpointKey(t, 0x11)
	delegation := testDelegation(t, key)
	first := signedBundle(t, delegation, "dev_"+strings.Repeat("4", 64), key)
	second := first
	second.DeviceID = "dev_" + strings.Repeat("7", 64)
	signed, err := SignBundle(second, key)
	if err != nil {
		t.Fatal(err)
	}
	return first, signed
}
