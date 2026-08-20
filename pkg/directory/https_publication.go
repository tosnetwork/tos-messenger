package directory

import (
	"bytes"
	"context"
	"crypto"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/tosnetwork/tos-messenger/internal/canon"
	"github.com/tosnetwork/tos-messenger/pkg/e2ee"
	"github.com/tosnetwork/tos-messenger/pkg/identity"
)

const descriptorObjectDir = "descriptors"

// HTTPSPublicationSink is the ordered public-object boundary. Both operations
// are content-addressed and therefore safe to retry after a crash.
type HTTPSPublicationSink interface {
	PutPrekeySet(context.Context, string, []byte) error
	PutDescriptor(context.Context, string, []byte) error
}

// HTTPSPublisher writes immutable objects beneath an operator-served static
// origin. The root and all publication directories are non-symlinked and not
// writable by group or other users.
type HTTPSPublisher struct {
	prekeys     string
	descriptors string
}

// OpenHTTPSPublisher prepares the fixed same-origin object directories.
func OpenHTTPSPublisher(root string) (*HTTPSPublisher, error) {
	if !filepath.IsAbs(root) || filepath.Clean(root) != root {
		return nil, errors.New("HTTPS publication root must be absolute and clean")
	}
	if err := requirePublicationDirectory(root, false); err != nil {
		return nil, err
	}
	wellKnown := filepath.Join(root, ".well-known")
	messenger := filepath.Join(wellKnown, "tos-messenger")
	prekeys := filepath.Join(messenger, "prekeys")
	descriptors := filepath.Join(messenger, descriptorObjectDir)
	for _, path := range []string{wellKnown, messenger, prekeys, descriptors} {
		if err := requirePublicationDirectory(path, true); err != nil {
			return nil, err
		}
	}
	return &HTTPSPublisher{prekeys: prekeys, descriptors: descriptors}, nil
}

// PutPrekeySet validates and installs one immutable bundle-set object.
func (p *HTTPSPublisher) PutPrekeySet(ctx context.Context, digest string, raw []byte) error {
	if p == nil {
		return errors.New("no HTTPS publication store")
	}
	if ctx == nil {
		return errors.New("prekey object publication needs a context")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := requirePublicationDirectory(p.prekeys, false); err != nil {
		return err
	}
	bundles, canonical, err := canonicalPrekeyObject(raw)
	if err != nil {
		return err
	}
	if !bytes.Equal(raw, canonical) {
		return errors.New("prekey object is not in canonical publication order")
	}
	actual, err := e2ee.SetDigest(bundles)
	if err != nil || actual != digest {
		return errors.New("prekey object does not match its content address")
	}
	return putImmutable(filepath.Join(p.prekeys, strings.TrimPrefix(digest, "sha256:")+".json"), raw)
}

// PutDescriptor validates and installs one immutable signed descriptor.
func (p *HTTPSPublisher) PutDescriptor(ctx context.Context, digest string, raw []byte) error {
	if p == nil {
		return errors.New("no HTTPS publication store")
	}
	if ctx == nil {
		return errors.New("descriptor object publication needs a context")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := requirePublicationDirectory(p.descriptors, false); err != nil {
		return err
	}
	descriptor, err := DecodeDescriptorJSON(raw)
	if err != nil {
		return err
	}
	actual, err := DescriptorDigest(descriptor)
	if err != nil || actual != digest {
		return errors.New("descriptor object does not match its content address")
	}
	return putImmutable(filepath.Join(p.descriptors, strings.TrimPrefix(digest, "sha256:")+".json"), raw)
}

// DescriptorObjectURL returns the immutable same-origin descriptor URL a DHT
// locator names. The mutable endpoint path is never reused as the object path.
func DescriptorObjectURL(httpsEndpoint, digest string) (string, error) {
	if err := validateHTTPSEndpoint(httpsEndpoint); err != nil || httpsEndpoint == "" {
		return "", errors.New("descriptor publication needs a valid HTTPS endpoint")
	}
	if !canon.ValidDigest(digest) {
		return "", errors.New("invalid descriptor digest")
	}
	base, err := url.Parse(httpsEndpoint)
	if err != nil {
		return "", errors.New("invalid descriptor HTTPS endpoint")
	}
	base.Path = "/.well-known/tos-messenger/" + descriptorObjectDir + "/" + strings.TrimPrefix(digest, "sha256:") + ".json"
	base.RawPath, base.RawQuery, base.Fragment = "", "", ""
	return base.String(), nil
}

// HTTPSActivationPlan contains the unsigned descriptor template and the
// short-lived locator window that will expose it.
type HTTPSActivationPlan struct {
	Descriptor       Descriptor
	LocatorIssuedAt  uint64
	LocatorExpiresAt uint64
}

// HTTPSActivation is ready for native DHT publication only after both HTTPS
// objects are durable.
type HTTPSActivation struct {
	Descriptor       Descriptor
	DescriptorJSON   []byte
	DescriptorDigest string
	Locator          Locator
}

// ActivateHTTPSPublication verifies and signs everything before mutation,
// then publishes prekeys before the descriptor. The signed locator is returned
// last; publishing it is the authority-changing step and belongs to the DHT
// adapter after these immutable dependencies exist.
func ActivateHTTPSPublication(ctx context.Context, sink HTTPSPublicationSink, signer crypto.Signer,
	delegation identity.Delegation, policy DescriptorPolicy, plan HTTPSActivationPlan,
	prekeyDigest string, prekeyJSON []byte, now time.Time) (HTTPSActivation, error) {
	if ctx == nil || sink == nil {
		return HTTPSActivation{}, errors.New("HTTPS activation needs a context and sink")
	}
	if err := ctx.Err(); err != nil {
		return HTTPSActivation{}, err
	}
	bundles, canonicalPrekeys, err := canonicalPrekeyObject(prekeyJSON)
	if err != nil {
		return HTTPSActivation{}, err
	}
	if !bytes.Equal(prekeyJSON, canonicalPrekeys) {
		return HTTPSActivation{}, errors.New("prekey object is not in canonical publication order")
	}
	if err := e2ee.BindBundleSet(delegation, bundles, prekeyDigest, now); err != nil {
		return HTTPSActivation{}, err
	}
	descriptor := plan.Descriptor
	descriptor.PrekeyBundleDigest = prekeyDigest
	descriptor.EndpointSignature = nil
	signed, err := SignDescriptorWith(descriptor, signer)
	if err != nil {
		return HTTPSActivation{}, err
	}
	if err := Bind(delegation, signed, policy, now); err != nil {
		return HTTPSActivation{}, err
	}
	descriptorJSON, err := EncodeDescriptorJSON(signed)
	if err != nil {
		return HTTPSActivation{}, err
	}
	descriptorDigest, err := DescriptorDigest(signed)
	if err != nil {
		return HTTPSActivation{}, err
	}
	reference, err := DescriptorObjectURL(signed.HTTPSEndpoint, descriptorDigest)
	if err != nil {
		return HTTPSActivation{}, err
	}
	locator, err := NewLocator(signed, reference, plan.LocatorIssuedAt, plan.LocatorExpiresAt)
	if err != nil {
		return HTTPSActivation{}, err
	}
	locator, err = SignLocatorWith(locator, signer)
	if err != nil {
		return HTTPSActivation{}, err
	}
	if err := VerifyLocator(delegation, locator, now); err != nil {
		return HTTPSActivation{}, err
	}
	if err := sink.PutPrekeySet(ctx, prekeyDigest, append([]byte(nil), prekeyJSON...)); err != nil {
		return HTTPSActivation{}, err
	}
	if err := sink.PutDescriptor(ctx, descriptorDigest, descriptorJSON); err != nil {
		return HTTPSActivation{}, err
	}
	return HTTPSActivation{
		Descriptor: signed, DescriptorJSON: descriptorJSON, DescriptorDigest: descriptorDigest, Locator: locator,
	}, nil
}

func requirePublicationDirectory(path string, create bool) error {
	if create {
		if err := os.Mkdir(path, 0o755); err != nil && !errors.Is(err, os.ErrExist) {
			return errors.New("create HTTPS publication directory")
		}
	}
	info, err := os.Lstat(path)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0o022 != 0 {
		return fmt.Errorf("HTTPS publication path %q must be a non-symlinked protected directory", path)
	}
	return nil
}

func canonicalPrekeyObject(raw []byte) ([]e2ee.Bundle, []byte, error) {
	bundles, err := e2ee.DecodeBundleSetJSON(raw)
	if err != nil {
		return nil, nil, err
	}
	sort.Slice(bundles, func(i, j int) bool { return bundles[i].DeviceID < bundles[j].DeviceID })
	canonical, err := e2ee.EncodeBundleSetJSON(bundles)
	if err != nil {
		return nil, nil, err
	}
	return bundles, canonical, nil
}

func putImmutable(path string, raw []byte) error {
	if len(raw) == 0 {
		return errors.New("cannot publish an empty object")
	}
	if existing, err := readExistingPublication(path, int64(len(raw))); err == nil {
		if bytes.Equal(existing, raw) {
			return nil
		}
		return errors.New("content address already contains different bytes")
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	temporary, err := os.CreateTemp(filepath.Dir(path), ".publication-")
	if err != nil {
		return errors.New("create publication temporary file")
	}
	name := temporary.Name()
	defer os.Remove(name)
	if err := temporary.Chmod(0o644); err != nil {
		_ = temporary.Close()
		return errors.New("set publication permissions")
	}
	if _, err := temporary.Write(raw); err != nil {
		_ = temporary.Close()
		return errors.New("write publication object")
	}
	if err := temporary.Sync(); err != nil {
		_ = temporary.Close()
		return errors.New("sync publication object")
	}
	if err := temporary.Close(); err != nil {
		return errors.New("close publication object")
	}
	if err := os.Link(name, path); err != nil {
		if existing, readErr := readExistingPublication(path, int64(len(raw))); readErr == nil && bytes.Equal(existing, raw) {
			return nil
		}
		return errors.New("install immutable publication object")
	}
	directory, err := os.Open(filepath.Dir(path))
	if err != nil {
		return errors.New("open publication directory")
	}
	defer directory.Close()
	if err := directory.Sync(); err != nil {
		return errors.New("sync publication directory")
	}
	return nil
}

func readExistingPublication(path string, expected int64) ([]byte, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Size() != expected {
		return nil, errors.New("existing publication object is not the expected regular file")
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, errors.New("open existing publication object")
	}
	defer file.Close()
	opened, err := file.Stat()
	if err != nil || !os.SameFile(info, opened) {
		return nil, errors.New("publication object changed while opening")
	}
	raw, err := io.ReadAll(io.LimitReader(file, expected+1))
	if err != nil || int64(len(raw)) != expected {
		return nil, errors.New("read existing publication object")
	}
	return raw, nil
}
