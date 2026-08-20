package directory

import (
	"context"
	"errors"
	"fmt"
	"io"
	"mime"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"sort"
	"strings"
	"time"

	"github.com/tosnetwork/tos-messenger/internal/canon"
	"github.com/tosnetwork/tos-messenger/pkg/e2ee"
)

const (
	// MaxDescriptorWireBytes bounds an HTTPS discovery response before it is
	// decoded and matched against the signed DHT locator.
	MaxDescriptorWireBytes     = 32 << 10
	DefaultHTTPSObjectTimeout  = 10 * time.Second
	DefaultHTTPSConnectTimeout = 5 * time.Second
)

// IPResolver is the DNS surface used by the rebinding-resistant dialer.
type IPResolver interface {
	LookupNetIP(context.Context, string, string) ([]netip.Addr, error)
}

// HTTPSObjectConfig controls finite network budgets. Zero values select the
// conservative defaults; callers cannot disable the limits.
type HTTPSObjectConfig struct {
	RequestTimeout time.Duration
	ConnectTimeout time.Duration
	Resolver       IPResolver
}

// HTTPSObjects retrieves descriptor and prekey publication objects. It is a
// discovery source only: it neither selects nor opens a message route.
type HTTPSObjects struct {
	client *http.Client
}

// NewHTTPSObjects constructs a client that ignores environment proxies,
// refuses redirects, and pins each connection to a DNS answer checked before
// dialing. Refusing the entire answer set when any address is non-public
// prevents a hostname from alternating public and private answers.
func NewHTTPSObjects(config HTTPSObjectConfig) (*HTTPSObjects, error) {
	requestTimeout, err := boundedDuration(config.RequestTimeout, DefaultHTTPSObjectTimeout, 30*time.Second)
	if err != nil {
		return nil, fmt.Errorf("HTTPS object request timeout: %w", err)
	}
	connectTimeout, err := boundedDuration(config.ConnectTimeout, DefaultHTTPSConnectTimeout, 10*time.Second)
	if err != nil {
		return nil, fmt.Errorf("HTTPS object connect timeout: %w", err)
	}
	resolver := config.Resolver
	if resolver == nil {
		resolver = net.DefaultResolver
	}
	dialer := &publicDialer{resolver: resolver, dialer: &net.Dialer{Timeout: connectTimeout, KeepAlive: 30 * time.Second}}
	transport := &http.Transport{
		Proxy:                 nil,
		DialContext:           dialer.DialContext,
		ForceAttemptHTTP2:     true,
		DisableCompression:    true,
		MaxIdleConns:          16,
		MaxIdleConnsPerHost:   2,
		IdleConnTimeout:       30 * time.Second,
		TLSHandshakeTimeout:   connectTimeout,
		ResponseHeaderTimeout: requestTimeout,
	}
	return &HTTPSObjects{client: &http.Client{
		Transport: transport,
		Timeout:   requestTimeout,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return errors.New("HTTPS discovery redirects are refused")
		},
	}}, nil
}

// Descriptor retrieves exactly the reference committed by the DHT locator.
func (h *HTTPSObjects) Descriptor(ctx context.Context, reference string) ([]byte, error) {
	return h.getJSON(ctx, reference, MaxDescriptorWireBytes)
}

// Prekeys retrieves the descriptor-committed bundle set from a deterministic
// path on the descriptor locator's origin. The content digest is checked here
// and again by the durable admitter, so the server is availability rather than
// authority.
func (h *HTTPSObjects) Prekeys(ctx context.Context, descriptor Descriptor, locator Locator) ([]e2ee.Bundle, error) {
	reference, err := PrekeyBundleSetURL(locator, descriptor.PrekeyBundleDigest)
	if err != nil {
		return nil, err
	}
	raw, err := h.getJSON(ctx, reference, e2ee.MaxBundleSetWireBytes)
	if err != nil {
		return nil, err
	}
	bundles, err := e2ee.DecodeBundleSetJSON(raw)
	if err != nil {
		return nil, err
	}
	if err := e2ee.MatchesDescriptorDigest(descriptor.PrekeyBundleDigest, bundles); err != nil {
		return nil, err
	}
	return bundles, nil
}

// PrekeyBundleSetURL defines the same-origin publication convention. A digest
// is safe as a path component only after strict digest validation performed by
// the descriptor and by this helper.
func PrekeyBundleSetURL(locator Locator, digest string) (string, error) {
	if err := ValidateLocator(locator, true); err != nil {
		return "", err
	}
	if !canon.ValidDigest(digest) {
		return "", errors.New("invalid prekey bundle digest")
	}
	base, err := parseHTTPSObjectURL(locator.DescriptorLocator)
	if err != nil {
		return "", err
	}
	base.Path = "/.well-known/tos-messenger/prekeys/" + strings.TrimPrefix(digest, "sha256:") + ".json"
	base.RawPath = ""
	return base.String(), nil
}

func (h *HTTPSObjects) getJSON(ctx context.Context, reference string, limit int64) ([]byte, error) {
	if h == nil || h.client == nil {
		return nil, errors.New("no HTTPS object client")
	}
	if ctx == nil {
		return nil, errors.New("HTTPS object request needs a context")
	}
	parsed, err := parseHTTPSObjectURL(reference)
	if err != nil {
		return nil, err
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, parsed.String(), nil)
	if err != nil {
		return nil, err
	}
	request.Header.Set("Accept", "application/json")
	response, err := h.client.Do(request)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTPS object returned status %d", response.StatusCode)
	}
	mediaType, _, err := mime.ParseMediaType(response.Header.Get("Content-Type"))
	if err != nil || mediaType != "application/json" {
		return nil, errors.New("HTTPS object is not application/json")
	}
	if response.ContentLength > limit {
		return nil, errors.New("HTTPS object exceeds its wire size bound")
	}
	raw, err := io.ReadAll(io.LimitReader(response.Body, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(raw)) > limit {
		return nil, errors.New("HTTPS object exceeds its wire size bound")
	}
	return raw, nil
}

func parseHTTPSObjectURL(reference string) (*url.URL, error) {
	parsed, err := url.Parse(reference)
	if err != nil || parsed.Scheme != "https" || parsed.Host == "" || parsed.User != nil ||
		parsed.RawQuery != "" || parsed.ForceQuery || parsed.Fragment != "" {
		return nil, errors.New("invalid HTTPS object URL")
	}
	if port := parsed.Port(); port != "" && port != "443" {
		return nil, errors.New("HTTPS object URL must use port 443")
	}
	return parsed, nil
}

func boundedDuration(value, fallback, maximum time.Duration) (time.Duration, error) {
	if value == 0 {
		return fallback, nil
	}
	if value < time.Millisecond || value > maximum {
		return 0, errors.New("duration is outside its bound")
	}
	return value, nil
}

type publicDialer struct {
	resolver IPResolver
	dialer   *net.Dialer
}

func (d *publicDialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		return nil, errors.New("invalid HTTPS dial address")
	}
	addresses, err := d.resolve(ctx, host)
	if err != nil {
		return nil, err
	}
	var last error
	for _, address := range addresses {
		connection, err := d.dialer.DialContext(ctx, network, net.JoinHostPort(address.String(), port))
		if err == nil {
			return connection, nil
		}
		last = err
	}
	return nil, last
}

func (d *publicDialer) resolve(ctx context.Context, host string) ([]netip.Addr, error) {
	if literal, err := netip.ParseAddr(host); err == nil {
		return validatePublicAnswers([]netip.Addr{literal})
	}
	answers, err := d.resolver.LookupNetIP(ctx, "ip", host)
	if err != nil {
		return nil, err
	}
	return validatePublicAnswers(answers)
}

var sharedAddressSpace = netip.MustParsePrefix("100.64.0.0/10")

func validatePublicAnswers(answers []netip.Addr) ([]netip.Addr, error) {
	if len(answers) == 0 {
		return nil, errors.New("HTTPS object hostname has no addresses")
	}
	checked := make([]netip.Addr, 0, len(answers))
	for _, address := range answers {
		address = address.Unmap()
		if !address.IsValid() || !address.IsGlobalUnicast() || address.IsPrivate() ||
			address.IsLoopback() || address.IsLinkLocalUnicast() || address.IsLinkLocalMulticast() ||
			address.IsMulticast() || address.IsUnspecified() || sharedAddressSpace.Contains(address) {
			return nil, errors.New("HTTPS object hostname resolves outside public address space")
		}
		checked = append(checked, address)
	}
	sort.Slice(checked, func(i, j int) bool { return checked[i].Compare(checked[j]) < 0 })
	return checked, nil
}

// CloseIdleConnections releases pooled discovery connections.
func (h *HTTPSObjects) CloseIdleConnections() {
	if h != nil && h.client != nil {
		h.client.CloseIdleConnections()
	}
}

// DelegationSource is the out-of-band finalized delegation bootstrap. It is
// intentionally separate because the TOS DHT locator key cannot be derived
// until the delegated Endpoint key is already known.
type DelegationSource interface {
	Delegation(context.Context, string) ([]byte, error)
}

type LocatorSource interface {
	Locator(context.Context, DHTKey) ([]byte, error)
}

// NetworkRefreshSource composes the three production retrieval authorities
// without conflating them. TOSDHT is a LocatorSource and HTTPSObjects supplies
// the remaining network objects.
type NetworkRefreshSource struct {
	Delegations DelegationSource
	Locators    LocatorSource
	Objects     *HTTPSObjects
}

func (s NetworkRefreshSource) Delegation(ctx context.Context, agentID string) ([]byte, error) {
	if s.Delegations == nil {
		return nil, errors.New("no delegation source")
	}
	return s.Delegations.Delegation(ctx, agentID)
}
func (s NetworkRefreshSource) Locator(ctx context.Context, key DHTKey) ([]byte, error) {
	if s.Locators == nil {
		return nil, errors.New("no locator source")
	}
	return s.Locators.Locator(ctx, key)
}
func (s NetworkRefreshSource) Descriptor(ctx context.Context, reference string) ([]byte, error) {
	if s.Objects == nil {
		return nil, errors.New("no HTTPS object source")
	}
	return s.Objects.Descriptor(ctx, reference)
}
func (s NetworkRefreshSource) Prekeys(ctx context.Context, descriptor Descriptor, locator Locator) ([]e2ee.Bundle, error) {
	if s.Objects == nil {
		return nil, errors.New("no HTTPS object source")
	}
	return s.Objects.Prekeys(ctx, descriptor, locator)
}

var _ RefreshSource = NetworkRefreshSource{}
