package directory

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"net/url"
	"strings"
	"time"

	"github.com/tosnetwork/tos-messenger/internal/canon"
	"github.com/tosnetwork/tos-messenger/pkg/identity"
)

const (
	// LocatorVersion is the first byte of a published locator.
	LocatorVersion = 1

	// LocatorKeyName is the DHT key name every Messenger locator is published
	// under. It is well inside the 127-byte name bound TOS Core enforces.
	LocatorKeyName = "tos.messaging.locator"
	// LocatorKeyIndex is the index of the primary locator. TOS Core allows
	// indices up to 15, which is the room available for further record kinds
	// under one endpoint.
	LocatorKeyIndex = 0
	// MaxLocatorKeyIndex mirrors the bound TOS Core enforces on a DHT key.
	MaxLocatorKeyIndex = 15

	// MaxDHTValueBytes is the hard limit TOS Core places on a DHT value.
	// Anything larger is refused by the network, not by us.
	MaxDHTValueBytes = 768
	// MaxLocatorBytes is the bound this protocol places on itself, chosen
	// below the network limit so a later field does not have to be paid for by
	// a breaking change.
	MaxLocatorBytes = 640
	// MaxDescriptorLocatorBytes bounds the retrieval reference. It is what
	// keeps the encoded locator inside the bound above.
	MaxDescriptorLocatorBytes = 256
	// MaxLocatorLifetimeSeconds bounds issued_at..expires_at. A published
	// pointer is a cache entry, and a stale one costs reachability, so its
	// lifetime is short and now actually enforced.
	MaxLocatorLifetimeSeconds = 24 * 60 * 60

	// ed25519PublicKeyTL is the TL constructor identifier of pub.ed25519 in
	// TOS Core. The DHT key identifier is the SHA-256 of the boxed public key,
	// so this constant is part of the wire contract rather than a detail.
	ed25519PublicKeyTL = 0x4813B4C6
)

// DHTKey is the TOS DHT key a locator is published under.
//
// The identifier is not ours to choose. TOS Core refuses a key description
// whose identifier is not the short identifier of the publishing public key,
// so the endpoint key determines where its locator lives. That has a
// consequence worth stating: a resolver must already hold the endpoint's
// delegation, and therefore its key, before it can look anything up. Discovery
// follows authority rather than preceding it, and first contact is bootstrapped
// out of band.
type DHTKey struct {
	ID    [32]byte
	Name  string
	Index uint32
}

// EndpointKeyID computes the DHT key identifier of an endpoint key. It is the
// SHA-256 of the boxed TL representation of the public key, which is what TOS
// Core compares against.
func EndpointKeyID(key ed25519.PublicKey) ([32]byte, error) {
	if len(key) != ed25519.PublicKeySize || canon.IsZero(key) {
		return [32]byte{}, errors.New("invalid endpoint public key")
	}
	boxed := make([]byte, 4, 4+ed25519.PublicKeySize)
	binary.LittleEndian.PutUint32(boxed, ed25519PublicKeyTL)
	boxed = append(boxed, key...)
	return sha256.Sum256(boxed), nil
}

// LocatorKey returns the DHT key a delegation's locator is published under.
func LocatorKey(delegation identity.Delegation) (DHTKey, error) {
	identifier, err := EndpointKeyID(delegation.IdentityPublicKey)
	if err != nil {
		return DHTKey{}, err
	}
	return DHTKey{ID: identifier, Name: LocatorKeyName, Index: LocatorKeyIndex}, nil
}

// UpdateRule names the TOS DHT update rule this protocol publishes under.
//
// The signature rule makes the DHT itself refuse a write that is not signed by
// the key the record belongs to, so an unauthorized overwrite is rejected by
// the network rather than detected by us afterwards. It also replaces a stored
// value only when the new one has a strictly greater time to live, which is
// why Republish refuses a locator that does not extend the previous expiry.
const UpdateRule = "dht.updateRule.signature"

// Locator is the bounded, signed value published in the DHT.
//
// It carries the endpoint identifier rather than separate network and Agent
// digests, because that identifier is already derived from the network tuple,
// the Agent, and the endpoint key. Repeating them would spend bytes on a
// commitment that is already made.
type Locator struct {
	EndpointID        string
	DescriptorDigest  string
	DescriptorLocator string
	IssuedAtUnix      uint64
	ExpiresAtUnix     uint64
	EndpointSignature []byte
}

// LocatorSigningBytes returns the exact preimage the endpoint key signs.
//
// The canonical form is compact binary. JSON is available for debugging and
// file exchange and is never what is published or signed, so the two cannot
// diverge into different meanings of the same locator.
func LocatorSigningBytes(locator Locator) ([]byte, error) {
	if err := ValidateLocator(locator, false); err != nil {
		return nil, err
	}
	endpoint, err := hex.DecodeString(locator.EndpointID[len("mep_"):])
	if err != nil {
		return nil, errors.New("invalid locator endpoint identifier")
	}
	descriptor, err := hex.DecodeString(locator.DescriptorDigest[len("sha256:"):])
	if err != nil {
		return nil, errors.New("invalid locator descriptor digest")
	}
	buffer := bytes.NewBufferString(canon.DomainDHTLocator)
	buffer.WriteByte(LocatorVersion)
	buffer.Write(endpoint)
	buffer.Write(descriptor)
	canon.Uint64(buffer, locator.IssuedAtUnix)
	canon.Uint64(buffer, locator.ExpiresAtUnix)
	canon.Text(buffer, locator.DescriptorLocator)
	return buffer.Bytes(), nil
}

// EncodeLocator returns the published DHT value.
func EncodeLocator(locator Locator) ([]byte, error) {
	if err := ValidateLocator(locator, true); err != nil {
		return nil, err
	}
	endpoint, err := hex.DecodeString(locator.EndpointID[len("mep_"):])
	if err != nil {
		return nil, errors.New("invalid locator endpoint identifier")
	}
	descriptor, err := hex.DecodeString(locator.DescriptorDigest[len("sha256:"):])
	if err != nil {
		return nil, errors.New("invalid locator descriptor digest")
	}
	buffer := &bytes.Buffer{}
	buffer.WriteByte(LocatorVersion)
	buffer.Write(endpoint)
	buffer.Write(descriptor)
	canon.Uint64(buffer, locator.IssuedAtUnix)
	canon.Uint64(buffer, locator.ExpiresAtUnix)
	var length [2]byte
	binary.BigEndian.PutUint16(length[:], uint16(len(locator.DescriptorLocator)))
	buffer.Write(length[:])
	buffer.WriteString(locator.DescriptorLocator)
	buffer.Write(locator.EndpointSignature)
	if buffer.Len() > MaxLocatorBytes {
		return nil, errors.New("locator exceeds its published size bound")
	}
	return buffer.Bytes(), nil
}

// DecodeLocator parses a published DHT value.
func DecodeLocator(raw []byte) (Locator, error) {
	if len(raw) > MaxLocatorBytes {
		return Locator{}, errors.New("locator exceeds its published size bound")
	}
	const fixed = 1 + 32 + 32 + 8 + 8 + 2 + ed25519.SignatureSize
	if len(raw) < fixed {
		return Locator{}, errors.New("locator is truncated")
	}
	if raw[0] != LocatorVersion {
		return Locator{}, errors.New("unsupported locator version")
	}
	cursor := 1
	endpoint := raw[cursor : cursor+32]
	cursor += 32
	descriptor := raw[cursor : cursor+32]
	cursor += 32
	issued := binary.BigEndian.Uint64(raw[cursor : cursor+8])
	cursor += 8
	expires := binary.BigEndian.Uint64(raw[cursor : cursor+8])
	cursor += 8
	length := int(binary.BigEndian.Uint16(raw[cursor : cursor+2]))
	cursor += 2
	if len(raw) != cursor+length+ed25519.SignatureSize {
		return Locator{}, errors.New("locator length does not match its reference")
	}
	reference := string(raw[cursor : cursor+length])
	cursor += length
	locator := Locator{
		EndpointID:        "mep_" + hex.EncodeToString(endpoint),
		DescriptorDigest:  "sha256:" + hex.EncodeToString(descriptor),
		DescriptorLocator: reference,
		IssuedAtUnix:      issued,
		ExpiresAtUnix:     expires,
		EndpointSignature: append([]byte(nil), raw[cursor:]...),
	}
	if err := ValidateLocator(locator, true); err != nil {
		return Locator{}, err
	}
	return locator, nil
}

// NewLocator builds the locator for a descriptor.
func NewLocator(descriptor Descriptor, reference string, issuedAtUnix, expiresAtUnix uint64) (Locator, error) {
	descriptorDigest, err := DescriptorDigest(descriptor)
	if err != nil {
		return Locator{}, err
	}
	if expiresAtUnix > descriptor.ExpiresAtUnix {
		return Locator{}, errors.New("locator outlives its descriptor")
	}
	locator := Locator{
		EndpointID:        descriptor.EndpointID,
		DescriptorDigest:  descriptorDigest,
		DescriptorLocator: reference,
		IssuedAtUnix:      issuedAtUnix,
		ExpiresAtUnix:     expiresAtUnix,
	}
	if err := ValidateLocator(locator, false); err != nil {
		return Locator{}, err
	}
	return locator, nil
}

// SignLocator signs a locator with the delegated Messaging Endpoint key.
func SignLocator(locator Locator, endpointKey ed25519.PrivateKey) (Locator, error) {
	if len(endpointKey) != ed25519.PrivateKeySize {
		return Locator{}, errors.New("invalid locator signing key")
	}
	locator.EndpointSignature = nil
	preimage, err := LocatorSigningBytes(locator)
	if err != nil {
		return Locator{}, err
	}
	locator.EndpointSignature = ed25519.Sign(endpointKey, preimage)
	return locator, nil
}

// Republish checks that a replacement will actually take effect.
//
// The signature update rule keeps whichever stored value has the greater time
// to live, so a locator republished with an expiry that does not exceed the
// previous one is accepted by the network and then ignored. Refusing it here
// turns a silent no-op into an error.
func Republish(previous, next Locator) error {
	if err := ValidateLocator(next, true); err != nil {
		return err
	}
	if next.EndpointID != previous.EndpointID {
		return errors.New("a republished locator belongs to another endpoint")
	}
	if next.ExpiresAtUnix <= previous.ExpiresAtUnix {
		return errors.New("a republished locator must extend the stored expiry to replace it")
	}
	return nil
}

// VerifyLocator admits a published pointer only under a live delegation.
func VerifyLocator(delegation identity.Delegation, locator Locator, now time.Time) error {
	if now.IsZero() {
		return errors.New("invalid locator verification time")
	}
	if err := ValidateLocator(locator, true); err != nil {
		return err
	}
	if err := identity.CheckWindow(delegation, now); err != nil {
		return err
	}
	if locator.EndpointID != delegation.EndpointID {
		return errors.New("locator does not match its delegation")
	}
	if locator.ExpiresAtUnix > delegation.ExpiresAtUnix {
		return errors.New("locator outlives its delegation")
	}
	seconds := now.Unix()
	if seconds < 0 || uint64(seconds) >= locator.ExpiresAtUnix {
		return errors.New("locator is expired")
	}
	if uint64(seconds) < locator.IssuedAtUnix {
		return errors.New("locator is not yet issued")
	}
	preimage, err := LocatorSigningBytes(locator)
	if err != nil {
		return err
	}
	if !ed25519.Verify(delegation.IdentityPublicKey, preimage, locator.EndpointSignature) {
		return errors.New("locator signature is not from the delegated endpoint key")
	}
	return nil
}

// MatchesDescriptor reports whether a fetched descriptor is the one the
// locator committed to.
func MatchesDescriptor(locator Locator, descriptor Descriptor) error {
	digest, err := DescriptorDigest(descriptor)
	if err != nil {
		return err
	}
	if digest != locator.DescriptorDigest {
		return errors.New("retrieved descriptor does not match the locator commitment")
	}
	if descriptor.EndpointID != locator.EndpointID {
		return errors.New("retrieved descriptor belongs to another endpoint")
	}
	return nil
}

// ValidateLocator enforces every structural rule.
func ValidateLocator(locator Locator, signed bool) error {
	if !identity.EndpointPattern.MatchString(locator.EndpointID) {
		return errors.New("invalid locator endpoint identifier")
	}
	if !canon.ValidDigest(locator.DescriptorDigest) {
		return errors.New("invalid locator descriptor digest")
	}
	if err := validateDescriptorLocator(locator.DescriptorLocator); err != nil {
		return err
	}
	if locator.IssuedAtUnix == 0 || locator.ExpiresAtUnix <= locator.IssuedAtUnix ||
		locator.ExpiresAtUnix-locator.IssuedAtUnix > MaxLocatorLifetimeSeconds {
		return errors.New("invalid locator validity window")
	}
	if signed && len(locator.EndpointSignature) != ed25519.SignatureSize {
		return errors.New("invalid locator signature")
	}
	return nil
}

// validateDescriptorLocator bounds the retrieval reference.
//
// The reference is followed by a resolver and is published where anyone can
// read it, so it carries no credentials: user info, a query string, and a
// fragment are all refused. A token in a query string would sit in the DHT for
// the life of the record.
func validateDescriptorLocator(reference string) error {
	if reference == "" || len(reference) > MaxDescriptorLocatorBytes || strings.TrimSpace(reference) != reference {
		return errors.New("invalid descriptor locator reference")
	}
	parsed, err := url.Parse(reference)
	if err != nil || parsed.User != nil || parsed.RawQuery != "" || parsed.ForceQuery ||
		parsed.Fragment != "" || parsed.Host == "" {
		return errors.New("invalid descriptor locator reference")
	}
	switch parsed.Scheme {
	case "https", "adnl", "rldp":
		return nil
	case "http":
		if parsed.Hostname() == "127.0.0.1" || parsed.Hostname() == "localhost" || parsed.Hostname() == "::1" {
			return nil
		}
	}
	return errors.New("descriptor locator reference uses an unsupported scheme")
}
