package directory

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/url"
	"strings"
	"time"

	"github.com/tosnetwork/tos-messenger/internal/canon"
	"github.com/tosnetwork/tos-messenger/pkg/identity"
	nativev1 "github.com/tosnetwork/tos-service-protocol/gen/tos/service/v1"
)

const (
	// LocatorSchema is the strict wire schema identifier.
	LocatorSchema = "tos.messaging.dht-locator.v1"

	locatorDomain       = "tos.messaging.dht-locator.v1\x00"
	networkDigestDomain = "tos.messaging.network-domain.v1\x00"
	agentDigestDomain   = "tos.messaging.agent-locator.v1\x00"
	lookupKeyDomain     = "tos.messaging.dht-key.v1\x00"

	// MaxLocatorBytes bounds one published DHT value. The DHT carries a
	// pointer, never history, so the bound is deliberately small.
	MaxLocatorBytes = 1024
	// MaxDescriptorLocatorBytes bounds the retrieval reference itself.
	MaxDescriptorLocatorBytes = 512
	// MaxLocatorLifetimeSeconds bounds how long a published pointer stays
	// valid. Short lifetimes are what limit the damage a stale value can do.
	MaxLocatorLifetimeSeconds = 24 * 60 * 60
)

// Locator is the bounded, signed DHT value that points at a descriptor.
type Locator struct {
	NetworkDomainDigest string
	AgentIDDigest       string
	EndpointID          string
	DescriptorDigest    string
	DescriptorLocator   string
	ExpiresAtUnix       uint64
	EndpointSignature   []byte
}

type wireLocator struct {
	Schema              string `json:"schema"`
	NetworkDomainDigest string `json:"network_domain_digest"`
	AgentIDDigest       string `json:"agent_id_digest"`
	EndpointID          string `json:"messaging_endpoint_id"`
	DescriptorDigest    string `json:"descriptor_digest"`
	DescriptorLocator   string `json:"descriptor_locator"`
	ExpiresAtUnix       uint64 `json:"expires_at_unix"`
	SignatureHex        string `json:"endpoint_signature_hex"`
}

// NetworkDomainDigest commits the full network tuple in one bounded field.
func NetworkDomainDigest(network *nativev1.NetworkDomain) (string, error) {
	if network == nil || network.NetworkId == "" || len(network.NetworkId) > 128 ||
		!canon.HashPattern.MatchString(network.GenesisRootHash) ||
		!canon.HashPattern.MatchString(network.GenesisFileHash) {
		return "", errors.New("invalid locator network domain")
	}
	buffer := bytes.NewBufferString(networkDigestDomain)
	canon.Text(buffer, network.NetworkId)
	canon.Text(buffer, network.GenesisRootHash)
	canon.Text(buffer, network.GenesisFileHash)
	return canon.Digest(buffer.Bytes()), nil
}

// AgentIDDigest keeps the plain Agent identifier out of published DHT values
// and binds the result to one network, so the same Agent identifier in another
// domain never collides.
func AgentIDDigest(network *nativev1.NetworkDomain, agentID string) (string, error) {
	networkDigest, err := NetworkDomainDigest(network)
	if err != nil {
		return "", err
	}
	if !identity.AgentPattern.MatchString(agentID) {
		return "", errors.New("invalid locator Agent identifier")
	}
	buffer := bytes.NewBufferString(agentDigestDomain)
	canon.Text(buffer, networkDigest)
	canon.Text(buffer, agentID)
	return canon.Digest(buffer.Bytes()), nil
}

// LookupKey derives the DHT key a publisher writes and a resolver reads.
//
// The derivation is a proposal pending the M0 freeze; see docs/OPEN_DECISIONS.md.
func LookupKey(network *nativev1.NetworkDomain, agentID, endpointID string) ([sha256.Size]byte, error) {
	agentDigest, err := AgentIDDigest(network, agentID)
	if err != nil {
		return [sha256.Size]byte{}, err
	}
	if !identity.EndpointPattern.MatchString(endpointID) {
		return [sha256.Size]byte{}, errors.New("invalid locator endpoint identifier")
	}
	buffer := bytes.NewBufferString(lookupKeyDomain)
	canon.Text(buffer, agentDigest)
	canon.Text(buffer, endpointID)
	return sha256.Sum256(buffer.Bytes()), nil
}

// LocatorSigningBytes returns the exact preimage the endpoint key signs.
func LocatorSigningBytes(locator Locator) ([]byte, error) {
	if err := ValidateLocator(locator, false); err != nil {
		return nil, err
	}
	buffer := bytes.NewBufferString(locatorDomain)
	canon.Text(buffer, LocatorSchema)
	canon.Text(buffer, locator.NetworkDomainDigest)
	canon.Text(buffer, locator.AgentIDDigest)
	canon.Text(buffer, locator.EndpointID)
	canon.Text(buffer, locator.DescriptorDigest)
	canon.Text(buffer, locator.DescriptorLocator)
	canon.Uint64(buffer, locator.ExpiresAtUnix)
	return buffer.Bytes(), nil
}

// NewLocator builds the locator for a descriptor. Deriving the committed
// fields from the descriptor itself is what keeps a publisher from advertising
// one Agent's descriptor under another Agent's key.
func NewLocator(descriptor Descriptor, reference string, expiresAtUnix uint64) (Locator, error) {
	networkDigest, err := NetworkDomainDigest(descriptor.Network)
	if err != nil {
		return Locator{}, err
	}
	agentDigest, err := AgentIDDigest(descriptor.Network, descriptor.AgentID)
	if err != nil {
		return Locator{}, err
	}
	descriptorDigest, err := DescriptorDigest(descriptor)
	if err != nil {
		return Locator{}, err
	}
	if expiresAtUnix > descriptor.ExpiresAtUnix {
		return Locator{}, errors.New("locator outlives its descriptor")
	}
	locator := Locator{
		NetworkDomainDigest: networkDigest,
		AgentIDDigest:       agentDigest,
		EndpointID:          descriptor.EndpointID,
		DescriptorDigest:    descriptorDigest,
		DescriptorLocator:   reference,
		ExpiresAtUnix:       expiresAtUnix,
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

// EncodeLocatorJSON returns the published DHT value.
func EncodeLocatorJSON(locator Locator) ([]byte, error) {
	if err := ValidateLocator(locator, true); err != nil {
		return nil, err
	}
	encoded, err := json.Marshal(wireLocator{
		Schema:              LocatorSchema,
		NetworkDomainDigest: locator.NetworkDomainDigest,
		AgentIDDigest:       locator.AgentIDDigest,
		EndpointID:          locator.EndpointID,
		DescriptorDigest:    locator.DescriptorDigest,
		DescriptorLocator:   locator.DescriptorLocator,
		ExpiresAtUnix:       locator.ExpiresAtUnix,
		SignatureHex:        hex.EncodeToString(locator.EndpointSignature),
	})
	if err != nil {
		return nil, err
	}
	if len(encoded) > MaxLocatorBytes {
		return nil, errors.New("locator exceeds its published size bound")
	}
	return encoded, nil
}

// DecodeLocatorJSON rejects oversized values, unknown fields, and trailing
// data.
func DecodeLocatorJSON(raw []byte) (Locator, error) {
	if len(raw) > MaxLocatorBytes {
		return Locator{}, errors.New("locator exceeds its published size bound")
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	var value wireLocator
	if err := decoder.Decode(&value); err != nil {
		return Locator{}, err
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return Locator{}, errors.New("locator has trailing JSON")
	}
	if value.Schema != LocatorSchema {
		return Locator{}, errors.New("unsupported locator schema")
	}
	signature, err := hex.DecodeString(value.SignatureHex)
	if err != nil || len(signature) != ed25519.SignatureSize {
		return Locator{}, errors.New("invalid locator signature")
	}
	locator := Locator{
		NetworkDomainDigest: value.NetworkDomainDigest,
		AgentIDDigest:       value.AgentIDDigest,
		EndpointID:          value.EndpointID,
		DescriptorDigest:    value.DescriptorDigest,
		DescriptorLocator:   value.DescriptorLocator,
		ExpiresAtUnix:       value.ExpiresAtUnix,
		EndpointSignature:   signature,
	}
	if err := ValidateLocator(locator, true); err != nil {
		return Locator{}, err
	}
	return locator, nil
}

// VerifyLocator admits a published pointer only under a live delegation. The
// delegation is resolved from finalized state by the caller, so an expired or
// withdrawn delegation makes every locator that references it useless, no
// matter what the DHT still holds.
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
	networkDigest, err := NetworkDomainDigest(delegation.Network)
	if err != nil {
		return err
	}
	agentDigest, err := AgentIDDigest(delegation.Network, delegation.AgentID)
	if err != nil {
		return err
	}
	if locator.NetworkDomainDigest != networkDigest || locator.AgentIDDigest != agentDigest ||
		locator.EndpointID != delegation.EndpointID {
		return errors.New("locator does not match its delegation")
	}
	if locator.ExpiresAtUnix > delegation.ExpiresAtUnix {
		return errors.New("locator outlives its delegation")
	}
	seconds := now.Unix()
	if seconds < 0 || uint64(seconds) >= locator.ExpiresAtUnix {
		return errors.New("locator is expired")
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
// locator committed to. Any retrieval path is acceptable as long as it yields
// these exact digest-authenticated bytes.
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
	if !canon.ValidDigest(locator.NetworkDomainDigest) || !canon.ValidDigest(locator.AgentIDDigest) ||
		!canon.ValidDigest(locator.DescriptorDigest) {
		return errors.New("invalid locator digest")
	}
	if !identity.EndpointPattern.MatchString(locator.EndpointID) {
		return errors.New("invalid locator endpoint identifier")
	}
	if err := validateDescriptorLocator(locator.DescriptorLocator); err != nil {
		return err
	}
	if locator.ExpiresAtUnix == 0 {
		return errors.New("invalid locator expiry")
	}
	if signed && len(locator.EndpointSignature) != ed25519.SignatureSize {
		return errors.New("invalid locator signature")
	}
	return nil
}

// validateDescriptorLocator bounds the retrieval reference. The reference is
// followed by a resolver, so an unbounded or credential-bearing value is a
// request-forgery surface, not a convenience.
func validateDescriptorLocator(reference string) error {
	if reference == "" || len(reference) > MaxDescriptorLocatorBytes || strings.TrimSpace(reference) != reference {
		return errors.New("invalid descriptor locator reference")
	}
	parsed, err := url.Parse(reference)
	if err != nil || parsed.User != nil || parsed.Fragment != "" || parsed.Host == "" {
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
