package safehttps

import (
	"crypto/tls"
	"net/http"
	"net/netip"
	"testing"
	"time"
)

func TestURLAndPublicAddressPolicyFailsClosed(t *testing.T) {
	for _, reference := range []string{
		"http://objects.example/x", "https://user@objects.example/x",
		"https://objects.example:8443/x", "https://objects.example/x?q=1",
		"https://objects.example/x#fragment",
	} {
		if _, err := ParseURL(reference); err == nil {
			t.Fatalf("accepted %s", reference)
		}
	}
	public := netip.MustParseAddr("1.1.1.1")
	if values, err := ValidatePublicAnswers([]netip.Addr{netip.MustParseAddr("2606:4700:4700::1111"), public, public}); err != nil || len(values) != 2 || values[0] != public {
		t.Fatalf("public answers=%v err=%v", values, err)
	}
	for _, answers := range [][]netip.Addr{
		nil,
		{netip.MustParseAddr("127.0.0.1")},
		{netip.MustParseAddr("10.0.0.1")},
		{netip.MustParseAddr("169.254.169.254")},
		{netip.MustParseAddr("100.64.0.1")},
		{netip.MustParseAddr("::1")},
		{public, netip.MustParseAddr("192.168.1.1")},
	} {
		if _, err := ValidatePublicAnswers(answers); err == nil {
			t.Fatalf("accepted %v", answers)
		}
	}
}

func TestClientHasFiniteProxyFreeRedirectPolicy(t *testing.T) {
	client, err := NewClient(Config{RequestTimeout: time.Second, ConnectTimeout: time.Second,
		MaxIdleConns: 4, MaxPerHost: 1, RedirectError: "no redirect"})
	if err != nil {
		t.Fatal(err)
	}
	defer client.CloseIdleConnections()
	transport, ok := client.Transport.(*http.Transport)
	if !ok || transport.Proxy != nil || client.Timeout != time.Second || transport.TLSClientConfig == nil || transport.TLSClientConfig.MinVersion != tls.VersionTLS12 {
		t.Fatalf("unsafe client: %+v", client)
	}
	if err := client.CheckRedirect(&http.Request{}, nil); err == nil {
		t.Fatal("redirect accepted")
	}
	if _, err := NewClient(Config{RequestTimeout: time.Hour, ConnectTimeout: time.Second, MaxIdleConns: 1, MaxPerHost: 1}); err == nil {
		t.Fatal("unbounded request timeout accepted")
	}
}
