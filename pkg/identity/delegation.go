// Package identity implements the Messaging Endpoint delegation document.
//
// A Messaging Endpoint is an online service authorized by an Agent. It is not
// the Agent. Authority comes from one place only: the finalized Agent account
// commits the immutable digest of the exact delegation bytes. This package
// therefore defines no second signature scheme of its own - a delegation is
// authentic when its canonical digest appears in the live Agent state, and it
// stops being authentic the moment that commitment is gone.
//
// The canonical form is the length-prefixed binary preimage below. JSON is a
// transport encoding and never the digest input.
package identity

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"regexp"
	"time"

	"github.com/tosnetwork/tos-messenger/internal/canon"
	"github.com/tosnetwork/tos-messenger/internal/ids"
	nativev1 "github.com/tosnetwork/tos-service-protocol/gen/tos/service/v1"
)

const (
	// Schema is the strict wire schema identifier.
	Schema = "tos.messaging.endpoint-delegation.v1"

	// MaxProtocolVersions bounds the advertised messaging protocol versions.
	MaxProtocolVersions = 16
	// MaxEventClasses bounds the event classes one endpoint may accept.
	MaxEventClasses = 64
	// MaxEventClassBytes bounds one event class label.
	MaxEventClassBytes = 64

	// MaxDelegationLifetimeSeconds bounds not_before..expires_at. A delegation
	// that never expires cannot be retired by waiting; it can only be retired
	// by an on-chain action, so the window stays bounded.
	MaxDelegationLifetimeSeconds = 365 * 24 * 60 * 60
	// MinSessionLifetimeSeconds bounds the shortest useful session lifetime.
	MinSessionLifetimeSeconds = 60
	// MaxSessionLifetimeSeconds bounds the longest permitted session lifetime.
	MaxSessionLifetimeSeconds = 30 * 24 * 60 * 60
)

// Identifier patterns are re-exported from the single definition in
// internal/ids so discovery and event objects apply exactly the same rules.
var (
	// AgentPattern matches a finalized Agent identifier.
	AgentPattern = ids.Agent
	// EndpointPattern matches a Messaging Endpoint identifier.
	EndpointPattern = ids.Endpoint
	// ADNLPattern matches an ADNL identity commitment.
	ADNLPattern = ids.ADNL

	eventClassPattern = regexp.MustCompile(`^[a-z][a-z0-9]*(\.[a-z][a-z0-9]*)*$`)
)

// Delegation is a Messaging Endpoint delegation document. Every field is part
// of the canonical digest; none of them may be changed without a new on-chain
// commitment.
type Delegation struct {
	Network                       *nativev1.NetworkDomain
	AgentID                       string
	EndpointID                    string
	IdentityPublicKey             ed25519.PublicKey
	ADNLID                        string
	AllowedProtocolVersions       []uint32
	AllowedEventClasses           []string
	NotBeforeUnix                 uint64
	ExpiresAtUnix                 uint64
	MaximumSessionLifetimeSeconds uint64
	ContactDescriptorPolicyDigest string
	InboxAdmissionPolicyDigest    string
}

type wireDelegation struct {
	Schema                        string   `json:"schema"`
	NetworkID                     string   `json:"network_id"`
	GenesisRootHash               string   `json:"genesis_root_hash"`
	GenesisFileHash               string   `json:"genesis_file_hash"`
	AgentID                       string   `json:"agent_id"`
	EndpointID                    string   `json:"messaging_endpoint_id"`
	IdentityPublicKeyHex          string   `json:"messaging_identity_public_key_hex"`
	ADNLID                        string   `json:"adnl_id,omitempty"`
	AllowedProtocolVersions       []uint32 `json:"allowed_protocol_versions"`
	AllowedEventClasses           []string `json:"allowed_event_classes"`
	NotBeforeUnix                 uint64   `json:"not_before_unix"`
	ExpiresAtUnix                 uint64   `json:"expires_at_unix"`
	MaximumSessionLifetimeSeconds uint64   `json:"maximum_session_lifetime_seconds"`
	ContactDescriptorPolicyDigest string   `json:"contact_descriptor_policy_digest"`
	InboxAdmissionPolicyDigest    string   `json:"inbox_admission_policy_digest"`
}

// DeriveEndpointID binds the endpoint identifier to the network tuple, the
// owning Agent, and the endpoint key. A caller cannot present one endpoint's
// key under another endpoint's identifier.
//
// The derivation is a proposal pending the M0 freeze; see docs/OPEN_DECISIONS.md.
func DeriveEndpointID(network *nativev1.NetworkDomain, agentID string, key ed25519.PublicKey) (string, error) {
	if err := validateNetwork(network); err != nil {
		return "", err
	}
	if !AgentPattern.MatchString(agentID) {
		return "", errors.New("invalid delegation Agent identifier")
	}
	if err := validateKey(key); err != nil {
		return "", err
	}
	buffer := bytes.NewBufferString(canon.DomainEndpointID)
	canon.Text(buffer, network.NetworkId)
	canon.Text(buffer, network.GenesisRootHash)
	canon.Text(buffer, network.GenesisFileHash)
	canon.Text(buffer, agentID)
	buffer.Write(key)
	sum := sha256.Sum256(buffer.Bytes())
	return "mep_" + hex.EncodeToString(sum[:]), nil
}

// CanonicalBytes returns the exact digest preimage. It validates first, so an
// invalid delegation can never produce a digest that some other component
// might later accept.
func CanonicalBytes(delegation Delegation) ([]byte, error) {
	if err := Validate(delegation); err != nil {
		return nil, err
	}
	buffer := bytes.NewBufferString(canon.DomainEndpointDelegation)
	canon.Text(buffer, Schema)
	canon.Text(buffer, delegation.Network.NetworkId)
	canon.Text(buffer, delegation.Network.GenesisRootHash)
	canon.Text(buffer, delegation.Network.GenesisFileHash)
	canon.Text(buffer, delegation.AgentID)
	canon.Text(buffer, delegation.EndpointID)
	buffer.Write(delegation.IdentityPublicKey)
	canon.Text(buffer, delegation.ADNLID)
	canon.Uint32(buffer, uint32(len(delegation.AllowedProtocolVersions)))
	for _, version := range delegation.AllowedProtocolVersions {
		canon.Uint32(buffer, version)
	}
	canon.Uint32(buffer, uint32(len(delegation.AllowedEventClasses)))
	for _, class := range delegation.AllowedEventClasses {
		canon.Text(buffer, class)
	}
	canon.Uint64(buffer, delegation.NotBeforeUnix)
	canon.Uint64(buffer, delegation.ExpiresAtUnix)
	canon.Uint64(buffer, delegation.MaximumSessionLifetimeSeconds)
	canon.Text(buffer, delegation.ContactDescriptorPolicyDigest)
	canon.Text(buffer, delegation.InboxAdmissionPolicyDigest)
	return buffer.Bytes(), nil
}

// Digest returns the value the Agent account commits on chain.
func Digest(delegation Delegation) (string, error) {
	canonical, err := CanonicalBytes(delegation)
	if err != nil {
		return "", err
	}
	return canon.Digest(canonical), nil
}

// EncodeJSON returns the transport representation of a valid delegation.
func EncodeJSON(delegation Delegation) ([]byte, error) {
	if err := Validate(delegation); err != nil {
		return nil, err
	}
	value := wireDelegation{
		Schema:                        Schema,
		NetworkID:                     delegation.Network.NetworkId,
		GenesisRootHash:               delegation.Network.GenesisRootHash,
		GenesisFileHash:               delegation.Network.GenesisFileHash,
		AgentID:                       delegation.AgentID,
		EndpointID:                    delegation.EndpointID,
		IdentityPublicKeyHex:          hex.EncodeToString(delegation.IdentityPublicKey),
		ADNLID:                        delegation.ADNLID,
		AllowedProtocolVersions:       delegation.AllowedProtocolVersions,
		AllowedEventClasses:           delegation.AllowedEventClasses,
		NotBeforeUnix:                 delegation.NotBeforeUnix,
		ExpiresAtUnix:                 delegation.ExpiresAtUnix,
		MaximumSessionLifetimeSeconds: delegation.MaximumSessionLifetimeSeconds,
		ContactDescriptorPolicyDigest: delegation.ContactDescriptorPolicyDigest,
		InboxAdmissionPolicyDigest:    delegation.InboxAdmissionPolicyDigest,
	}
	return json.Marshal(value)
}

// DecodeJSON rejects unknown and trailing fields and reconstructs the exact
// delegation. Decoding proves nothing about authority; Verify must still run.
func DecodeJSON(raw []byte) (Delegation, error) {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	var value wireDelegation
	if err := decoder.Decode(&value); err != nil {
		return Delegation{}, err
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return Delegation{}, errors.New("delegation has trailing JSON")
	}
	if value.Schema != Schema {
		return Delegation{}, errors.New("unsupported delegation schema")
	}
	key, err := hex.DecodeString(value.IdentityPublicKeyHex)
	if err != nil || len(key) != ed25519.PublicKeySize {
		return Delegation{}, errors.New("invalid delegation identity key")
	}
	delegation := Delegation{
		Network: &nativev1.NetworkDomain{
			NetworkId:       value.NetworkID,
			GenesisRootHash: value.GenesisRootHash,
			GenesisFileHash: value.GenesisFileHash,
		},
		AgentID:                       value.AgentID,
		EndpointID:                    value.EndpointID,
		IdentityPublicKey:             ed25519.PublicKey(key),
		ADNLID:                        value.ADNLID,
		AllowedProtocolVersions:       value.AllowedProtocolVersions,
		AllowedEventClasses:           value.AllowedEventClasses,
		NotBeforeUnix:                 value.NotBeforeUnix,
		ExpiresAtUnix:                 value.ExpiresAtUnix,
		MaximumSessionLifetimeSeconds: value.MaximumSessionLifetimeSeconds,
		ContactDescriptorPolicyDigest: value.ContactDescriptorPolicyDigest,
		InboxAdmissionPolicyDigest:    value.InboxAdmissionPolicyDigest,
	}
	if err := Validate(delegation); err != nil {
		return Delegation{}, err
	}
	return delegation, nil
}

// Verify runs the full resolution required before a delegation may authorize
// anything: the Agent is finalized and live, the exact bytes reproduce a digest
// the Agent still commits, the network tuple matches the caller's configured
// domain, and the current time is inside the delegation window.
//
// Membership in the finalized delegation digest list is what proves the
// delegation was authorized under the live Agent policy: an Agent account only
// accumulates a digest through a delegation action signed for that purpose, and
// loses it when the commitment is withdrawn.
func Verify(resolver AgentResolver, network *nativev1.NetworkDomain, chain ChainPolicy, raw []byte, now time.Time) (Delegation, error) {
	if resolver == nil || now.IsZero() {
		return Delegation{}, errors.New("invalid delegation verification context")
	}
	if err := validateNetwork(network); err != nil {
		return Delegation{}, err
	}
	delegation, err := DecodeJSON(raw)
	if err != nil {
		return Delegation{}, err
	}
	if delegation.Network.NetworkId != network.NetworkId ||
		delegation.Network.GenesisRootHash != network.GenesisRootHash ||
		delegation.Network.GenesisFileHash != network.GenesisFileHash {
		return Delegation{}, errors.New("delegation network tuple mismatch")
	}
	state, found, err := resolver.ResolveAgent(delegation.AgentID)
	if err != nil {
		return Delegation{}, err
	}
	if !found {
		return Delegation{}, errors.New("delegation Agent is not finalized")
	}
	agent, err := CheckState(chain, network, delegation.AgentID, state)
	if err != nil {
		return Delegation{}, err
	}
	digest, err := Digest(delegation)
	if err != nil {
		return Delegation{}, err
	}
	committed := false
	for _, candidate := range agent.DelegationDigests {
		if candidate == digest {
			committed = true
			break
		}
	}
	if !committed {
		return Delegation{}, errors.New("delegation is not committed by the finalized Agent")
	}
	if err := CheckWindow(delegation, now); err != nil {
		return Delegation{}, err
	}
	return delegation, nil
}

// CheckWindow reports whether the delegation is inside its validity window.
// It is separated from Verify so a caller holding an already verified
// delegation can re-check expiry without another finalized read.
func CheckWindow(delegation Delegation, now time.Time) error {
	if now.IsZero() {
		return errors.New("invalid delegation time")
	}
	seconds := now.Unix()
	if seconds < 0 {
		return errors.New("invalid delegation time")
	}
	current := uint64(seconds)
	if current < delegation.NotBeforeUnix {
		return errors.New("delegation is not yet valid")
	}
	if current >= delegation.ExpiresAtUnix {
		return errors.New("delegation is expired")
	}
	return nil
}

// AllowsEventClass reports whether the delegation admits an event class. An
// endpoint that was never delegated a class must not receive it, so an unknown
// class fails closed.
func AllowsEventClass(delegation Delegation, class string) bool {
	if !eventClassPattern.MatchString(class) {
		return false
	}
	for _, allowed := range delegation.AllowedEventClasses {
		if allowed == class {
			return true
		}
	}
	return false
}

// AllowsProtocolVersion reports whether the delegation admits a protocol
// version.
func AllowsProtocolVersion(delegation Delegation, version uint32) bool {
	for _, allowed := range delegation.AllowedProtocolVersions {
		if allowed == version {
			return true
		}
	}
	return false
}

// Validate enforces every structural rule. It is called by every encoder,
// decoder, and verifier so no path can construct a delegation the others would
// reject.
func Validate(delegation Delegation) error {
	if err := validateNetwork(delegation.Network); err != nil {
		return err
	}
	if !AgentPattern.MatchString(delegation.AgentID) {
		return errors.New("invalid delegation Agent identifier")
	}
	if err := validateKey(delegation.IdentityPublicKey); err != nil {
		return err
	}
	derived, err := DeriveEndpointID(delegation.Network, delegation.AgentID, delegation.IdentityPublicKey)
	if err != nil {
		return err
	}
	if !EndpointPattern.MatchString(delegation.EndpointID) || delegation.EndpointID != derived {
		return errors.New("delegation endpoint identifier does not bind its key")
	}
	if delegation.ADNLID != "" {
		if !ADNLPattern.MatchString(delegation.ADNLID) {
			return errors.New("invalid delegation ADNL identifier")
		}
		raw, err := hex.DecodeString(delegation.ADNLID[len("adnl:"):])
		if err != nil || canon.IsZero(raw) {
			return errors.New("invalid delegation ADNL identifier")
		}
	}
	if err := validateVersions(delegation.AllowedProtocolVersions); err != nil {
		return err
	}
	if err := validateEventClasses(delegation.AllowedEventClasses); err != nil {
		return err
	}
	if err := validateWindowFields(delegation); err != nil {
		return err
	}
	if !canon.ValidDigest(delegation.ContactDescriptorPolicyDigest) ||
		!canon.ValidDigest(delegation.InboxAdmissionPolicyDigest) {
		return errors.New("invalid delegation policy digest")
	}
	return nil
}

func validateWindowFields(delegation Delegation) error {
	if delegation.NotBeforeUnix == 0 || delegation.ExpiresAtUnix == 0 ||
		delegation.ExpiresAtUnix <= delegation.NotBeforeUnix {
		return errors.New("invalid delegation validity window")
	}
	lifetime := delegation.ExpiresAtUnix - delegation.NotBeforeUnix
	if lifetime > MaxDelegationLifetimeSeconds {
		return errors.New("delegation lifetime exceeds its bound")
	}
	if delegation.MaximumSessionLifetimeSeconds < MinSessionLifetimeSeconds ||
		delegation.MaximumSessionLifetimeSeconds > MaxSessionLifetimeSeconds ||
		delegation.MaximumSessionLifetimeSeconds > lifetime {
		return errors.New("invalid delegation session lifetime")
	}
	return nil
}

func validateVersions(versions []uint32) error {
	if len(versions) == 0 || len(versions) > MaxProtocolVersions {
		return errors.New("invalid delegation protocol versions")
	}
	for index, version := range versions {
		if version == 0 {
			return errors.New("invalid delegation protocol versions")
		}
		if index > 0 && versions[index-1] >= version {
			return errors.New("delegation protocol versions must be sorted and unique")
		}
	}
	return nil
}

func validateEventClasses(classes []string) error {
	if len(classes) == 0 || len(classes) > MaxEventClasses {
		return errors.New("invalid delegation event classes")
	}
	for index, class := range classes {
		if len(class) > MaxEventClassBytes || !eventClassPattern.MatchString(class) {
			return errors.New("invalid delegation event classes")
		}
		if index > 0 && classes[index-1] >= class {
			return errors.New("delegation event classes must be sorted and unique")
		}
	}
	return nil
}

func validateNetwork(network *nativev1.NetworkDomain) error {
	if network == nil || network.NetworkId == "" || len(network.NetworkId) > 128 ||
		!canon.HashPattern.MatchString(network.GenesisRootHash) || !canon.HashPattern.MatchString(network.GenesisFileHash) {
		return errors.New("invalid delegation network domain")
	}
	return nil
}

func validateKey(key ed25519.PublicKey) error {
	if len(key) != ed25519.PublicKeySize || canon.IsZero(key) {
		return errors.New("invalid delegation identity key")
	}
	return nil
}
