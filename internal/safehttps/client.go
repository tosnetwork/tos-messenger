// Package safehttps constructs bounded HTTPS clients that refuse ambient
// proxies, redirects, DNS rebinding into non-public address space, and URL
// authority ambiguity. It supplies transport safety only; callers must still
// authenticate the bytes they retrieve.
package safehttps

import (
	"context"
	"crypto/tls"
	"errors"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"sort"
	"time"
)

// IPResolver is the DNS surface used by the rebinding-resistant dialer.
type IPResolver interface {
	LookupNetIP(context.Context, string, string) ([]netip.Addr, error)
}

type Config struct {
	RequestTimeout time.Duration
	ConnectTimeout time.Duration
	Resolver       IPResolver
	MaxIdleConns   int
	MaxPerHost     int
	RedirectError  string
}

// NewClient returns a client with finite budgets and no ambient proxy or
// redirect behavior. Every connection dials only the public DNS answers that
// were validated for that connection attempt.
func NewClient(config Config) (*http.Client, error) {
	if config.RequestTimeout < time.Millisecond || config.RequestTimeout > time.Minute ||
		config.ConnectTimeout < time.Millisecond || config.ConnectTimeout > 30*time.Second {
		return nil, errors.New("safe HTTPS timeout is outside its bound")
	}
	if config.MaxIdleConns <= 0 || config.MaxIdleConns > 256 || config.MaxPerHost <= 0 || config.MaxPerHost > 16 {
		return nil, errors.New("safe HTTPS connection budget is outside its bound")
	}
	resolver := config.Resolver
	if resolver == nil {
		resolver = net.DefaultResolver
	}
	dialer := &publicDialer{resolver: resolver, dialer: &net.Dialer{Timeout: config.ConnectTimeout, KeepAlive: 30 * time.Second}}
	transport := &http.Transport{
		Proxy:                 nil,
		DialContext:           dialer.DialContext,
		ForceAttemptHTTP2:     true,
		DisableCompression:    true,
		MaxIdleConns:          config.MaxIdleConns,
		MaxIdleConnsPerHost:   config.MaxPerHost,
		IdleConnTimeout:       30 * time.Second,
		TLSHandshakeTimeout:   config.ConnectTimeout,
		ResponseHeaderTimeout: config.RequestTimeout,
		TLSClientConfig:       &tls.Config{MinVersion: tls.VersionTLS12},
	}
	message := config.RedirectError
	if message == "" {
		message = "HTTPS redirects are refused"
	}
	return &http.Client{Transport: transport, Timeout: config.RequestTimeout,
		CheckRedirect: func(*http.Request, []*http.Request) error { return errors.New(message) }}, nil
}

// ParseURL admits one unambiguous HTTPS authority. Callers separately constrain
// the path for their object type.
func ParseURL(reference string) (*url.URL, error) {
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
	for _, candidate := range addresses {
		connection, dialErr := d.dialer.DialContext(ctx, network, net.JoinHostPort(candidate.String(), port))
		if dialErr == nil {
			return connection, nil
		}
		last = dialErr
	}
	if last == nil {
		last = errors.New("HTTPS hostname has no dialable public address")
	}
	return nil, last
}

func (d *publicDialer) resolve(ctx context.Context, host string) ([]netip.Addr, error) {
	if literal, err := netip.ParseAddr(host); err == nil {
		return ValidatePublicAnswers([]netip.Addr{literal})
	}
	answers, err := d.resolver.LookupNetIP(ctx, "ip", host)
	if err != nil {
		return nil, err
	}
	return ValidatePublicAnswers(answers)
}

var sharedAddressSpace = netip.MustParsePrefix("100.64.0.0/10")

// ValidatePublicAnswers rejects the complete answer set if any entry is not a
// public global-unicast address. This is intentionally stricter than merely
// skipping private answers: mixed answers are a rebinding signal.
func ValidatePublicAnswers(answers []netip.Addr) ([]netip.Addr, error) {
	if len(answers) == 0 {
		return nil, errors.New("HTTPS object hostname has no addresses")
	}
	checked := make([]netip.Addr, 0, len(answers))
	seen := make(map[netip.Addr]struct{}, len(answers))
	for _, address := range answers {
		address = address.Unmap()
		if !address.IsValid() || !address.IsGlobalUnicast() || address.IsPrivate() ||
			address.IsLoopback() || address.IsLinkLocalUnicast() || address.IsLinkLocalMulticast() ||
			address.IsMulticast() || address.IsUnspecified() || sharedAddressSpace.Contains(address) {
			return nil, errors.New("HTTPS object hostname resolves outside public address space")
		}
		if _, duplicate := seen[address]; duplicate {
			continue
		}
		seen[address] = struct{}{}
		checked = append(checked, address)
	}
	sort.Slice(checked, func(i, j int) bool { return checked[i].Compare(checked[j]) < 0 })
	return checked, nil
}
