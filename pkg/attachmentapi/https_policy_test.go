package attachmentapi

import (
	"context"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/tosnetwork/tos-messenger/pkg/attachments"
)

type fixedResolver []netip.Addr

func (r fixedResolver) LookupNetIP(context.Context, string, string) ([]netip.Addr, error) {
	return append([]netip.Addr(nil), r...), nil
}

func TestHTTPSClientPinsOnlyPublicAnswersAndRefusesRedirects(t *testing.T) {
	digest := "sha256:" + strings.Repeat("ab", 32)
	locator, err := attachments.HTTPSLocator("https://attachments.example", digest)
	if err != nil {
		t.Fatal(err)
	}
	client, err := NewHTTPSClient(locator, digest, HTTPSConfig{RequestTimeout: time.Second,
		ConnectTimeout: time.Second, Resolver: fixedResolver{netip.MustParseAddr("1.1.1.1"), netip.MustParseAddr("127.0.0.1")}})
	if err != nil {
		t.Fatal(err)
	}
	defer client.CloseIdleConnections()
	if err := client.client.CheckRedirect(&http.Request{}, nil); err == nil {
		t.Fatal("attachment redirect accepted")
	}
	transport := client.client.Transport.(*http.Transport)
	if transport.Proxy != nil {
		t.Fatal("ambient proxy enabled")
	}
	if _, err := transport.DialContext(context.Background(), "tcp", net.JoinHostPort("attachments.example", "443")); err == nil {
		t.Fatal("mixed public/private DNS answer set was dialed")
	}

	privateLocator, _ := attachments.HTTPSLocator("https://127.0.0.1", digest)
	privateClient, err := NewHTTPSClient(privateLocator, digest, HTTPSConfig{RequestTimeout: time.Second, ConnectTimeout: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	defer privateClient.CloseIdleConnections()
	privateTransport := privateClient.client.Transport.(*http.Transport)
	if _, err := privateTransport.DialContext(context.Background(), "tcp", "127.0.0.1:443"); err == nil {
		t.Fatal("loopback attachment locator was dialed")
	}
}
