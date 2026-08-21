package directory

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/tosnetwork/tos-messenger/pkg/e2ee"
)

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(request *http.Request) (*http.Response, error) { return f(request) }

func objectResponse(status int, contentType string, body []byte) *http.Response {
	return &http.Response{StatusCode: status, Header: http.Header{"Content-Type": []string{contentType}}, Body: io.NopCloser(bytes.NewReader(body)), ContentLength: int64(len(body))}
}

func TestHTTPSObjectsFetchesCommittedObjects(t *testing.T) {
	key := endpointKey(t, 0x11)
	delegation := testDelegation(t, key)
	bundle, err := e2ee.SignBundle(e2ee.Bundle{Network: delegation.Network, AgentID: delegation.AgentID,
		EndpointID: delegation.EndpointID, DeviceID: "dev_" + strings.Repeat("4", 64),
		AlgorithmID: "tos.messaging.e2ee.x3dh-aes256gcm-dr.v2", Material: []byte("published prekey"),
		IssuedAtUnix: baseUnix, ExpiresAtUnix: baseUnix + 3600}, key)
	if err != nil {
		t.Fatal(err)
	}
	bundleWire, err := e2ee.EncodeBundleSetJSON([]e2ee.Bundle{bundle})
	if err != nil {
		t.Fatal(err)
	}
	digest, err := e2ee.SetDigest([]e2ee.Bundle{bundle})
	if err != nil {
		t.Fatal(err)
	}
	descriptor := testDescriptor(t, delegation)
	descriptor.PrekeyBundleDigest = digest
	descriptor, err = SignDescriptor(descriptor, key)
	if err != nil {
		t.Fatal(err)
	}
	descriptorWire, err := EncodeDescriptorJSON(descriptor)
	if err != nil {
		t.Fatal(err)
	}
	locator := signedLocator(t, descriptor, key, "https://directory.example/objects/descriptor.json")
	wantPrekeys, err := PrekeyBundleSetURL(locator, digest)
	if err != nil {
		t.Fatal(err)
	}

	client := &http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
		if request.Header.Get("Accept") != "application/json" {
			t.Error("missing JSON accept header")
		}
		switch request.URL.String() {
		case locator.DescriptorLocator:
			return objectResponse(http.StatusOK, "application/json; charset=utf-8", descriptorWire), nil
		case wantPrekeys:
			return objectResponse(http.StatusOK, "application/json", bundleWire), nil
		default:
			t.Fatalf("unexpected URL %s", request.URL)
			return nil, nil
		}
	})}
	objects := &HTTPSObjects{client: client}
	raw, err := objects.Descriptor(context.Background(), locator.DescriptorLocator)
	if err != nil || !bytes.Equal(raw, descriptorWire) {
		t.Fatalf("descriptor err=%v", err)
	}
	bundles, err := objects.Prekeys(context.Background(), descriptor, locator)
	if err != nil || len(bundles) != 1 || bundles[0].DeviceID != bundle.DeviceID {
		t.Fatalf("prekeys=%v err=%v", len(bundles), err)
	}
}

func TestHTTPSObjectsRefusesUntrustedResponses(t *testing.T) {
	valid := []byte(`{"schema":"x"}`)
	cases := map[string]*http.Response{
		"status":             objectResponse(http.StatusNotFound, "application/json", valid),
		"content type":       objectResponse(http.StatusOK, "text/plain", valid),
		"declared oversized": {StatusCode: http.StatusOK, Header: http.Header{"Content-Type": []string{"application/json"}}, Body: io.NopCloser(bytes.NewReader(valid)), ContentLength: MaxDescriptorWireBytes + 1},
		"streamed oversized": objectResponse(http.StatusOK, "application/json", bytes.Repeat([]byte("x"), MaxDescriptorWireBytes+1)),
	}
	for name, response := range cases {
		t.Run(name, func(t *testing.T) {
			objects := &HTTPSObjects{client: &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) { return response, nil })}}
			if _, err := objects.Descriptor(context.Background(), "https://directory.example/descriptor"); err == nil {
				t.Fatal("accepted response")
			}
		})
	}
	objects := &HTTPSObjects{client: &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) { return nil, errors.New("should not dial") })}}
	for _, reference := range []string{"http://directory.example/x", "https://user@directory.example/x", "https://directory.example:8443/x", "https://directory.example/x?q=1", "https://directory.example/x#f"} {
		if _, err := objects.Descriptor(context.Background(), reference); err == nil {
			t.Fatalf("accepted %s", reference)
		}
	}
	if _, err := objects.Descriptor(nil, "https://directory.example/x"); err == nil {
		t.Fatal("accepted nil context")
	}
}

func TestHTTPSObjectsRefusesBundleSetSubstitution(t *testing.T) {
	_, descriptor, locator := httpsObjectFixture(t)
	descriptor.PrekeyBundleDigest = "sha256:" + strings.Repeat("7a", 32)
	objects := &HTTPSObjects{client: &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
		bundle, _, _ := httpsObjectFixture(t)
		raw, err := e2ee.EncodeBundleSetJSON([]e2ee.Bundle{bundle})
		if err != nil {
			t.Fatal(err)
		}
		return objectResponse(http.StatusOK, "application/json", raw), nil
	})}}
	if _, err := objects.Prekeys(context.Background(), descriptor, locator); err == nil {
		t.Fatal("accepted substituted bundle set")
	}
}

func TestPublicAddressValidationFailsClosed(t *testing.T) {
	public := netip.MustParseAddr("1.1.1.1")
	if got, err := validatePublicAnswers([]netip.Addr{netip.MustParseAddr("2606:4700:4700::1111"), public}); err != nil || got[0] != public {
		t.Fatalf("public answers=%v err=%v", got, err)
	}
	for _, answers := range [][]netip.Addr{
		nil,
		{netip.MustParseAddr("127.0.0.1")},
		{netip.MustParseAddr("10.0.0.1")},
		{netip.MustParseAddr("169.254.169.254")},
		{netip.MustParseAddr("100.64.0.1")},
		{public, netip.MustParseAddr("192.168.1.1")},
	} {
		if _, err := validatePublicAnswers(answers); err == nil {
			t.Fatalf("accepted %v", answers)
		}
	}
}

func TestNewHTTPSObjectsHasFiniteBudgets(t *testing.T) {
	objects, err := NewHTTPSObjects(HTTPSObjectConfig{})
	if err != nil {
		t.Fatal(err)
	}
	defer objects.CloseIdleConnections()
	if objects.client.Timeout != DefaultHTTPSObjectTimeout {
		t.Fatalf("timeout=%v", objects.client.Timeout)
	}
	if err := objects.client.CheckRedirect(&http.Request{}, nil); err == nil {
		t.Fatal("redirect policy accepted a redirect")
	}
	if _, err := NewHTTPSObjects(HTTPSObjectConfig{RequestTimeout: 31 * time.Second}); err == nil {
		t.Fatal("accepted excessive timeout")
	}
}

func httpsObjectFixture(t *testing.T) (e2ee.Bundle, Descriptor, Locator) {
	t.Helper()
	key := endpointKey(t, 0x11)
	delegation := testDelegation(t, key)
	bundle, err := e2ee.SignBundle(e2ee.Bundle{Network: delegation.Network, AgentID: delegation.AgentID, EndpointID: delegation.EndpointID,
		DeviceID: "dev_" + strings.Repeat("4", 64), AlgorithmID: "tos.messaging.e2ee.x3dh-aes256gcm-dr.v2", Material: []byte("prekey"), IssuedAtUnix: baseUnix, ExpiresAtUnix: baseUnix + 3600}, key)
	if err != nil {
		t.Fatal(err)
	}
	digest, err := e2ee.SetDigest([]e2ee.Bundle{bundle})
	if err != nil {
		t.Fatal(err)
	}
	descriptor := testDescriptor(t, delegation)
	descriptor.PrekeyBundleDigest = digest
	descriptor, err = SignDescriptor(descriptor, key)
	if err != nil {
		t.Fatal(err)
	}
	return bundle, descriptor, signedLocator(t, descriptor, key, "https://directory.example/descriptor")
}
