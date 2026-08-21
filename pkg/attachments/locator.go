package attachments

import (
	"errors"
	"net/url"
	"strings"

	"github.com/tosnetwork/tos-messenger/internal/safehttps"
)

const locatorPathPrefix = "/.well-known/tos-messenger/attachments/"

// HTTPSLocator derives the only HTTPS path accepted for a manifest. A locator
// is an E2EE-authenticated retrieval hint, never storage authority or a bearer
// credential.
func HTTPSLocator(origin, manifestDigest string) (string, error) {
	if !validContentDigest(manifestDigest) {
		return "", errors.New("invalid attachment locator manifest digest")
	}
	base, err := safehttps.ParseURL(origin)
	if err != nil || base.Path != "" && base.Path != "/" || base.RawPath != "" {
		return "", errors.New("invalid attachment storage origin")
	}
	if err := validateCanonicalAuthority(base); err != nil {
		return "", err
	}
	base.Path = locatorPathPrefix + strings.TrimPrefix(manifestDigest, "sha256:")
	return base.String(), nil
}

// ParseHTTPSLocator requires a canonical public-HTTPS URL shape and an exact
// content-addressed path. The safe HTTPS client separately validates and pins
// public DNS answers at dial time.
func ParseHTTPSLocator(reference, manifestDigest string) (*url.URL, error) {
	if !validContentDigest(manifestDigest) {
		return nil, errors.New("invalid attachment locator manifest digest")
	}
	parsed, err := safehttps.ParseURL(reference)
	if err != nil || parsed.RawPath != "" || parsed.Opaque != "" || parsed.Path != locatorPathPrefix+strings.TrimPrefix(manifestDigest, "sha256:") {
		return nil, errors.New("invalid attachment HTTPS locator")
	}
	if err := validateCanonicalAuthority(parsed); err != nil {
		return nil, err
	}
	if parsed.String() != reference {
		return nil, errors.New("attachment HTTPS locator is not canonical")
	}
	return parsed, nil
}

func validateCanonicalAuthority(parsed *url.URL) error {
	host := parsed.Hostname()
	if host == "" || host != strings.ToLower(host) || strings.HasSuffix(host, ".") || strings.Contains(host, "%") {
		return errors.New("attachment HTTPS authority is not canonical")
	}
	want := host
	if strings.Contains(host, ":") {
		want = "[" + host + "]"
	}
	if parsed.Port() != "" || parsed.Host != want {
		return errors.New("attachment HTTPS authority is not canonical")
	}
	return nil
}
