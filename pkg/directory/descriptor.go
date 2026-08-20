// Package directory implements Messenger discovery: the signed Messaging
// Contact Descriptor and the bounded DHT locator that points at it.
//
// Neither object is canonical. A descriptor is a claim signed by a Messaging
// Endpoint key, and it means nothing until the delegation that authorized that
// key is resolved from finalized TOS state. A stale locator can cause a
// temporary failure to reach someone; it can never restore a revoked endpoint
// or change who an Agent is.
package directory

import (
	"bytes"
	"crypto"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/tosnetwork/tos-messenger/internal/canon"
	"github.com/tosnetwork/tos-messenger/pkg/identity"
	nativev1 "github.com/tosnetwork/tos-service-protocol/gen/tos/service/v1"
)

const (
	// DescriptorSchema is the strict wire schema identifier.
	DescriptorSchema = "tos.messaging.contact-descriptor.v1"

	// MaxDescriptorLifetimeSeconds bounds issued_at..expires_at. A descriptor
	// is a cache entry, so it expires far sooner than the delegation behind it.
	MaxDescriptorLifetimeSeconds = 7 * 24 * 60 * 60
	// MaxAdapterVersions bounds the advertised A2A and MCP versions.
	MaxAdapterVersions = 8
	// MaxAdapterVersionBytes bounds one advertised adapter version label.
	MaxAdapterVersionBytes = 32
	// MinEnvelopeBytes is the smallest envelope an endpoint may advertise.
	MinEnvelopeBytes = 4 << 10
	// MaxEnvelopeBytes is the largest envelope any endpoint may advertise.
	MaxEnvelopeBytes = 1 << 20
	// MaxHTTPSEndpointBytes bounds the optional bootstrap endpoint.
	MaxHTTPSEndpointBytes = 512
	// MaxCandidateRelays bounds a published Mailbox Relay set.
	MaxCandidateRelays = 8
)

var adapterVersionPattern = regexp.MustCompile(`^[0-9a-z][0-9a-z.\-]{0,31}$`)

// Descriptor is a signed, non-canonical Messaging Contact Descriptor.
type Descriptor struct {
	Network                    *nativev1.NetworkDomain
	AgentID                    string
	EndpointID                 string
	DelegationDigest           string
	SupportedMessagingVersions []uint32
	SupportedA2AVersions       []string
	SupportedMCPVersions       []string
	ADNLID                     string
	HTTPSEndpoint              string
	PrekeyBundleDigest         string
	MailboxRelaySetDigest      string
	InboxAdmissionPolicyDigest string
	AttachmentServiceDigest    string
	MaximumEnvelopeBytes       uint32
	IssuedAtUnix               uint64
	ExpiresAtUnix              uint64
	EndpointSignature          []byte
}

type wireDescriptor struct {
	Schema                     string   `json:"schema"`
	NetworkID                  string   `json:"network_id"`
	GenesisRootHash            string   `json:"genesis_root_hash"`
	GenesisFileHash            string   `json:"genesis_file_hash"`
	AgentID                    string   `json:"agent_id"`
	EndpointID                 string   `json:"messaging_endpoint_id"`
	DelegationDigest           string   `json:"delegation_digest"`
	SupportedMessagingVersions []uint32 `json:"supported_messaging_versions"`
	SupportedA2AVersions       []string `json:"supported_a2a_versions,omitempty"`
	SupportedMCPVersions       []string `json:"supported_mcp_versions,omitempty"`
	ADNLID                     string   `json:"adnl_id,omitempty"`
	HTTPSEndpoint              string   `json:"optional_https_endpoint,omitempty"`
	PrekeyBundleDigest         string   `json:"prekey_bundle_digest"`
	MailboxRelaySetDigest      string   `json:"mailbox_relay_set_digest,omitempty"`
	InboxAdmissionPolicyDigest string   `json:"inbox_admission_policy_digest"`
	AttachmentServiceDigest    string   `json:"attachment_service_digest,omitempty"`
	MaximumEnvelopeBytes       uint32   `json:"maximum_envelope_bytes"`
	IssuedAtUnix               uint64   `json:"issued_at_unix"`
	ExpiresAtUnix              uint64   `json:"expires_at_unix"`
	SignatureHex               string   `json:"endpoint_signature_hex"`
}

// SigningBytes returns the exact preimage the endpoint key signs.
func SigningBytes(descriptor Descriptor) ([]byte, error) {
	if err := ValidateDescriptor(descriptor, false); err != nil {
		return nil, err
	}
	buffer := bytes.NewBufferString(canon.DomainContactDescriptor)
	canon.Text(buffer, DescriptorSchema)
	canon.Text(buffer, descriptor.Network.NetworkId)
	canon.Text(buffer, descriptor.Network.GenesisRootHash)
	canon.Text(buffer, descriptor.Network.GenesisFileHash)
	canon.Text(buffer, descriptor.AgentID)
	canon.Text(buffer, descriptor.EndpointID)
	canon.Text(buffer, descriptor.DelegationDigest)
	canon.Uint32(buffer, uint32(len(descriptor.SupportedMessagingVersions)))
	for _, version := range descriptor.SupportedMessagingVersions {
		canon.Uint32(buffer, version)
	}
	canon.Uint32(buffer, uint32(len(descriptor.SupportedA2AVersions)))
	for _, version := range descriptor.SupportedA2AVersions {
		canon.Text(buffer, version)
	}
	canon.Uint32(buffer, uint32(len(descriptor.SupportedMCPVersions)))
	for _, version := range descriptor.SupportedMCPVersions {
		canon.Text(buffer, version)
	}
	canon.Text(buffer, descriptor.ADNLID)
	canon.Text(buffer, descriptor.HTTPSEndpoint)
	canon.Text(buffer, descriptor.PrekeyBundleDigest)
	canon.Text(buffer, descriptor.MailboxRelaySetDigest)
	canon.Text(buffer, descriptor.InboxAdmissionPolicyDigest)
	canon.Text(buffer, descriptor.AttachmentServiceDigest)
	canon.Uint32(buffer, descriptor.MaximumEnvelopeBytes)
	canon.Uint64(buffer, descriptor.IssuedAtUnix)
	canon.Uint64(buffer, descriptor.ExpiresAtUnix)
	return buffer.Bytes(), nil
}

// DescriptorDigest is the value a DHT locator commits to. It covers the signed
// preimage, so a locator cannot be pointed at a different descriptor without
// detection.
func DescriptorDigest(descriptor Descriptor) (string, error) {
	preimage, err := SigningBytes(descriptor)
	if err != nil {
		return "", err
	}
	return canon.Digest(preimage), nil
}

// SignDescriptor signs a descriptor with the delegated Messaging Endpoint key.
// The Agent controller key is never used here.
func SignDescriptor(descriptor Descriptor, endpointKey ed25519.PrivateKey) (Descriptor, error) {
	if len(endpointKey) != ed25519.PrivateKeySize {
		return Descriptor{}, errors.New("invalid descriptor signing key")
	}
	return SignDescriptorWith(descriptor, endpointKey)
}

// SignDescriptorWith signs through an Endpoint signer without requiring its
// private bytes to be exportable to the publication coordinator.
func SignDescriptorWith(descriptor Descriptor, signer crypto.Signer) (Descriptor, error) {
	descriptor.EndpointSignature = nil
	preimage, err := SigningBytes(descriptor)
	if err != nil {
		return Descriptor{}, err
	}
	signature, err := signEndpoint(signer, preimage)
	if err != nil {
		return Descriptor{}, errors.New("sign descriptor: " + err.Error())
	}
	descriptor.EndpointSignature = signature
	return descriptor, nil
}

// EncodeDescriptorJSON returns the transport representation.
func EncodeDescriptorJSON(descriptor Descriptor) ([]byte, error) {
	if err := ValidateDescriptor(descriptor, true); err != nil {
		return nil, err
	}
	return json.Marshal(wireDescriptor{
		Schema:                     DescriptorSchema,
		NetworkID:                  descriptor.Network.NetworkId,
		GenesisRootHash:            descriptor.Network.GenesisRootHash,
		GenesisFileHash:            descriptor.Network.GenesisFileHash,
		AgentID:                    descriptor.AgentID,
		EndpointID:                 descriptor.EndpointID,
		DelegationDigest:           descriptor.DelegationDigest,
		SupportedMessagingVersions: descriptor.SupportedMessagingVersions,
		SupportedA2AVersions:       descriptor.SupportedA2AVersions,
		SupportedMCPVersions:       descriptor.SupportedMCPVersions,
		ADNLID:                     descriptor.ADNLID,
		HTTPSEndpoint:              descriptor.HTTPSEndpoint,
		PrekeyBundleDigest:         descriptor.PrekeyBundleDigest,
		MailboxRelaySetDigest:      descriptor.MailboxRelaySetDigest,
		InboxAdmissionPolicyDigest: descriptor.InboxAdmissionPolicyDigest,
		AttachmentServiceDigest:    descriptor.AttachmentServiceDigest,
		MaximumEnvelopeBytes:       descriptor.MaximumEnvelopeBytes,
		IssuedAtUnix:               descriptor.IssuedAtUnix,
		ExpiresAtUnix:              descriptor.ExpiresAtUnix,
		SignatureHex:               hex.EncodeToString(descriptor.EndpointSignature),
	})
}

// DecodeDescriptorJSON rejects unknown and trailing fields. Decoding proves
// nothing about authority.
func DecodeDescriptorJSON(raw []byte) (Descriptor, error) {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	var value wireDescriptor
	if err := decoder.Decode(&value); err != nil {
		return Descriptor{}, err
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return Descriptor{}, errors.New("descriptor has trailing JSON")
	}
	if value.Schema != DescriptorSchema {
		return Descriptor{}, errors.New("unsupported descriptor schema")
	}
	signature, err := hex.DecodeString(value.SignatureHex)
	if err != nil || len(signature) != ed25519.SignatureSize {
		return Descriptor{}, errors.New("invalid descriptor signature")
	}
	descriptor := Descriptor{
		Network: &nativev1.NetworkDomain{
			NetworkId:       value.NetworkID,
			GenesisRootHash: value.GenesisRootHash,
			GenesisFileHash: value.GenesisFileHash,
		},
		AgentID:                    value.AgentID,
		EndpointID:                 value.EndpointID,
		DelegationDigest:           value.DelegationDigest,
		SupportedMessagingVersions: value.SupportedMessagingVersions,
		SupportedA2AVersions:       value.SupportedA2AVersions,
		SupportedMCPVersions:       value.SupportedMCPVersions,
		ADNLID:                     value.ADNLID,
		HTTPSEndpoint:              value.HTTPSEndpoint,
		PrekeyBundleDigest:         value.PrekeyBundleDigest,
		MailboxRelaySetDigest:      value.MailboxRelaySetDigest,
		InboxAdmissionPolicyDigest: value.InboxAdmissionPolicyDigest,
		AttachmentServiceDigest:    value.AttachmentServiceDigest,
		MaximumEnvelopeBytes:       value.MaximumEnvelopeBytes,
		IssuedAtUnix:               value.IssuedAtUnix,
		ExpiresAtUnix:              value.ExpiresAtUnix,
		EndpointSignature:          signature,
	}
	if err := ValidateDescriptor(descriptor, true); err != nil {
		return Descriptor{}, err
	}
	return descriptor, nil
}

// Bind checks a descriptor against the delegation that must authorize it: same
// network, same Agent, same endpoint, the delegation's own digest, a signature
// by the delegated key, and scope the delegation actually granted.
//
// A descriptor may never outlive its delegation. If it could, a revoked
// endpoint would keep a usable locator until the descriptor's own expiry.
func Bind(delegation identity.Delegation, descriptor Descriptor, policy DescriptorPolicy, now time.Time) error {
	if now.IsZero() {
		return errors.New("invalid descriptor verification time")
	}
	if err := ValidateDescriptor(descriptor, true); err != nil {
		return err
	}
	if err := identity.CheckWindow(delegation, now); err != nil {
		return err
	}
	digest, err := identity.Digest(delegation)
	if err != nil {
		return err
	}
	if descriptor.DelegationDigest != digest {
		return errors.New("descriptor does not commit its delegation")
	}
	if descriptor.AgentID != delegation.AgentID || descriptor.EndpointID != delegation.EndpointID {
		return errors.New("descriptor identity does not match its delegation")
	}
	if descriptor.Network.NetworkId != delegation.Network.NetworkId ||
		descriptor.Network.GenesisRootHash != delegation.Network.GenesisRootHash ||
		descriptor.Network.GenesisFileHash != delegation.Network.GenesisFileHash {
		return errors.New("descriptor network tuple does not match its delegation")
	}
	if descriptor.ADNLID != delegation.ADNLID {
		return errors.New("descriptor advertises an undelegated ADNL identity")
	}
	for _, version := range descriptor.SupportedMessagingVersions {
		if !identity.AllowsProtocolVersion(delegation, version) {
			return errors.New("descriptor advertises an undelegated protocol version")
		}
	}
	if descriptor.ExpiresAtUnix > delegation.ExpiresAtUnix {
		return errors.New("descriptor outlives its delegation")
	}
	// The policy the Agent committed to is checked against the descriptor the
	// endpoint signed. This is what bounds a delegated key: whoever holds it
	// can sign, but only inside limits fixed before the key existed anywhere.
	policyDigest, err := policy.Digest()
	if err != nil {
		return err
	}
	if policyDigest != delegation.ContactDescriptorPolicyDigest {
		return errors.New("descriptor policy is not the one the Agent committed")
	}
	if err := policy.Permits(descriptor); err != nil {
		return err
	}
	if descriptor.InboxAdmissionPolicyDigest != delegation.InboxAdmissionPolicyDigest {
		return errors.New("descriptor advertises an inbox policy its Agent did not commit")
	}
	seconds := now.Unix()
	if seconds < 0 || uint64(seconds) >= descriptor.ExpiresAtUnix {
		return errors.New("descriptor is expired")
	}
	if uint64(seconds) < descriptor.IssuedAtUnix {
		return errors.New("descriptor is not yet issued")
	}
	preimage, signErr := SigningBytes(descriptor)
	if signErr != nil {
		return signErr
	}
	if !ed25519.Verify(delegation.IdentityPublicKey, preimage, descriptor.EndpointSignature) {
		return errors.New("descriptor signature is not from the delegated endpoint key")
	}
	return nil
}

// Resolve performs the discovery half of the resolution algorithm: resolve the
// Agent and its live delegation from finalized state, then admit a candidate
// descriptor only if the delegation still authorizes it.
//
// Establishing a session is deliberately not part of this function. Route
// selection is frozen only after the reachability study, and a prekey bundle
// belongs to the encryption profile.
func Resolve(resolver identity.AgentResolver, network *nativev1.NetworkDomain, chain identity.ChainPolicy, delegationJSON, descriptorJSON []byte, policy DescriptorPolicy, now time.Time) (identity.Delegation, Descriptor, error) {
	delegation, err := identity.Verify(resolver, network, chain, delegationJSON, now)
	if err != nil {
		return identity.Delegation{}, Descriptor{}, err
	}
	descriptor, err := DecodeDescriptorJSON(descriptorJSON)
	if err != nil {
		return identity.Delegation{}, Descriptor{}, err
	}
	if err := Bind(delegation, descriptor, policy, now); err != nil {
		return identity.Delegation{}, Descriptor{}, err
	}
	return delegation, descriptor, nil
}

// ValidateDescriptor enforces every structural rule. When signed is false the
// signature field is not required, which is the state during signing.
func ValidateDescriptor(descriptor Descriptor, signed bool) error {
	if descriptor.Network == nil || descriptor.Network.NetworkId == "" || len(descriptor.Network.NetworkId) > 128 ||
		!canon.HashPattern.MatchString(descriptor.Network.GenesisRootHash) ||
		!canon.HashPattern.MatchString(descriptor.Network.GenesisFileHash) {
		return errors.New("invalid descriptor network domain")
	}
	if !identity.AgentPattern.MatchString(descriptor.AgentID) ||
		!identity.EndpointPattern.MatchString(descriptor.EndpointID) {
		return errors.New("invalid descriptor identity")
	}
	if !canon.ValidDigest(descriptor.DelegationDigest) || !canon.ValidDigest(descriptor.PrekeyBundleDigest) ||
		!canon.ValidDigest(descriptor.InboxAdmissionPolicyDigest) {
		return errors.New("invalid descriptor digest")
	}
	// A Relay set is optional. Every endpoint has none until offline delivery
	// exists, and requiring one would have made implementers invent a
	// placeholder rather than say so.
	if descriptor.MailboxRelaySetDigest != "" && !canon.ValidDigest(descriptor.MailboxRelaySetDigest) {
		return errors.New("invalid descriptor Relay set digest")
	}
	if descriptor.AttachmentServiceDigest != "" && !canon.ValidDigest(descriptor.AttachmentServiceDigest) {
		return errors.New("invalid descriptor attachment service digest")
	}
	if err := validateMessagingVersions(descriptor.SupportedMessagingVersions); err != nil {
		return err
	}
	if err := validateAdapterVersions(descriptor.SupportedA2AVersions); err != nil {
		return err
	}
	if err := validateAdapterVersions(descriptor.SupportedMCPVersions); err != nil {
		return err
	}
	if descriptor.ADNLID != "" && !identity.ADNLPattern.MatchString(descriptor.ADNLID) {
		return errors.New("invalid descriptor ADNL identifier")
	}
	if descriptor.ADNLID == "" && descriptor.HTTPSEndpoint == "" {
		return errors.New("descriptor advertises no reachable route")
	}
	if err := validateHTTPSEndpoint(descriptor.HTTPSEndpoint); err != nil {
		return err
	}
	if descriptor.MaximumEnvelopeBytes < MinEnvelopeBytes || descriptor.MaximumEnvelopeBytes > MaxEnvelopeBytes {
		return errors.New("invalid descriptor envelope bound")
	}
	if descriptor.IssuedAtUnix == 0 || descriptor.ExpiresAtUnix <= descriptor.IssuedAtUnix ||
		descriptor.ExpiresAtUnix-descriptor.IssuedAtUnix > MaxDescriptorLifetimeSeconds {
		return errors.New("invalid descriptor validity window")
	}
	if signed && len(descriptor.EndpointSignature) != ed25519.SignatureSize {
		return errors.New("invalid descriptor signature")
	}
	return nil
}

func validateMessagingVersions(versions []uint32) error {
	if len(versions) == 0 || len(versions) > identity.MaxProtocolVersions {
		return errors.New("invalid descriptor messaging versions")
	}
	for index, version := range versions {
		if version == 0 {
			return errors.New("invalid descriptor messaging versions")
		}
		if index > 0 && versions[index-1] >= version {
			return errors.New("descriptor messaging versions must be sorted and unique")
		}
	}
	return nil
}

func validateAdapterVersions(versions []string) error {
	if len(versions) > MaxAdapterVersions {
		return errors.New("too many descriptor adapter versions")
	}
	for index, version := range versions {
		if len(version) > MaxAdapterVersionBytes || !adapterVersionPattern.MatchString(version) {
			return errors.New("invalid descriptor adapter version")
		}
		if index > 0 && versions[index-1] >= version {
			return errors.New("descriptor adapter versions must be sorted and unique")
		}
	}
	return nil
}

func validateHTTPSEndpoint(endpoint string) error {
	if endpoint == "" {
		return nil
	}
	if len(endpoint) > MaxHTTPSEndpointBytes || strings.TrimSpace(endpoint) != endpoint {
		return errors.New("invalid descriptor HTTPS endpoint")
	}
	parsed, err := url.Parse(endpoint)
	if err != nil || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" || parsed.Host == "" {
		return errors.New("invalid descriptor HTTPS endpoint")
	}
	if parsed.Scheme == "https" {
		return nil
	}
	loopback := parsed.Hostname() == "127.0.0.1" || parsed.Hostname() == "localhost" || parsed.Hostname() == "::1"
	if parsed.Scheme == "http" && loopback {
		return nil
	}
	return errors.New("descriptor HTTPS endpoint must use HTTPS outside loopback")
}
