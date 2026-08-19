package e2ee

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"sort"
	"time"

	"github.com/tosnetwork/tos-messenger/internal/canon"
	"github.com/tosnetwork/tos-messenger/internal/ids"
	"github.com/tosnetwork/tos-messenger/pkg/identity"
	nativev1 "github.com/tosnetwork/tos-service-protocol/gen/tos/service/v1"
)

const (
	// BundleSchema is the strict wire schema identifier.
	BundleSchema = "tos.messaging.prekey-bundle.v1"

	// MaxMaterialBytes bounds one published prekey bundle's material.
	MaxMaterialBytes = 4 << 10
	// MaxBundleLifetimeSeconds bounds how long published material stays valid.
	// Published prekeys are consumed by senders the owner never hears from, so
	// material that never expires is material that can never be retired.
	MaxBundleLifetimeSeconds = 30 * 24 * 60 * 60
	// MaxDevicesPerSet bounds the devices one endpoint publishes at once.
	MaxDevicesPerSet = 16
)

// Bundle is one device's published prekey material.
//
// It is signed by the delegated Messaging Endpoint key, never by the Agent
// controller key, and it means nothing until the delegation behind that key is
// resolved from finalized TOS state.
type Bundle struct {
	Network           *nativev1.NetworkDomain
	AgentID           string
	EndpointID        string
	DeviceID          string
	AlgorithmID       string
	Material          []byte
	IssuedAtUnix      uint64
	ExpiresAtUnix     uint64
	EndpointSignature []byte
}

type wireBundle struct {
	Schema          string `json:"schema"`
	NetworkID       string `json:"network_id"`
	GenesisRootHash string `json:"genesis_root_hash"`
	GenesisFileHash string `json:"genesis_file_hash"`
	AgentID         string `json:"agent_id"`
	EndpointID      string `json:"messaging_endpoint_id"`
	DeviceID        string `json:"device_id"`
	AlgorithmID     string `json:"algorithm_id"`
	MaterialBase64  string `json:"material_base64"`
	IssuedAtUnix    uint64 `json:"issued_at_unix"`
	ExpiresAtUnix   uint64 `json:"expires_at_unix"`
	SignatureHex    string `json:"endpoint_signature_hex"`
}

// BundleSigningBytes returns the exact preimage the endpoint key signs.
func BundleSigningBytes(bundle Bundle) ([]byte, error) {
	if err := ValidateBundle(bundle, false); err != nil {
		return nil, err
	}
	buffer := bytes.NewBufferString(canon.DomainPrekeyBundle)
	canon.Text(buffer, BundleSchema)
	canon.Text(buffer, bundle.Network.NetworkId)
	canon.Text(buffer, bundle.Network.GenesisRootHash)
	canon.Text(buffer, bundle.Network.GenesisFileHash)
	canon.Text(buffer, bundle.AgentID)
	canon.Text(buffer, bundle.EndpointID)
	canon.Text(buffer, bundle.DeviceID)
	canon.Text(buffer, bundle.AlgorithmID)
	canon.Bytes(buffer, bundle.Material)
	canon.Uint64(buffer, bundle.IssuedAtUnix)
	canon.Uint64(buffer, bundle.ExpiresAtUnix)
	return buffer.Bytes(), nil
}

// BundleDigest identifies one published bundle.
func BundleDigest(bundle Bundle) (string, error) {
	preimage, err := BundleSigningBytes(bundle)
	if err != nil {
		return "", err
	}
	return canon.Digest(preimage), nil
}

// SetDigest is the value a Messaging Contact Descriptor commits as its prekey
// bundle digest.
//
// It covers every device's bundle, so a descriptor cannot be paired with a
// device set the endpoint never published, and adding or removing a device
// changes the descriptor rather than happening silently underneath it. The
// order devices are listed in does not change the result.
func SetDigest(bundles []Bundle) (string, error) {
	if err := ValidateSet(bundles); err != nil {
		return "", err
	}
	digests := make([]string, 0, len(bundles))
	for _, bundle := range bundles {
		digest, err := BundleDigest(bundle)
		if err != nil {
			return "", err
		}
		digests = append(digests, digest)
	}
	sort.Strings(digests)
	buffer := bytes.NewBufferString(canon.DomainPrekeyBundleSet)
	canon.Uint32(buffer, uint32(len(digests)))
	for _, digest := range digests {
		canon.Text(buffer, digest)
	}
	return canon.Digest(buffer.Bytes()), nil
}

// ValidateSet enforces that a published set is one endpoint's devices and
// nothing else.
//
// A protocol core cannot rely on every caller remembering to check each bundle
// afterwards. A set that mixes Agents, networks, or suites would produce a
// digest a descriptor could commit, and the mixing would only be noticed by
// whoever happened to verify the bundles individually.
func ValidateSet(bundles []Bundle) error {
	if len(bundles) == 0 || len(bundles) > MaxDevicesPerSet {
		return errors.New("invalid prekey bundle set size")
	}
	first := bundles[0]
	devices := make(map[string]struct{}, len(bundles))
	for _, bundle := range bundles {
		if err := ValidateBundle(bundle, true); err != nil {
			return err
		}
		if bundle.EndpointID != first.EndpointID {
			return errors.New("a prekey bundle set belongs to one endpoint")
		}
		if bundle.AgentID != first.AgentID {
			return errors.New("a prekey bundle set belongs to one Agent")
		}
		if bundle.Network.NetworkId != first.Network.NetworkId ||
			bundle.Network.GenesisRootHash != first.Network.GenesisRootHash ||
			bundle.Network.GenesisFileHash != first.Network.GenesisFileHash {
			return errors.New("a prekey bundle set belongs to one network")
		}
		if bundle.AlgorithmID != first.AlgorithmID {
			// A sender picks one suite for the conversation, not one per
			// device, so a set spanning suites has no single answer.
			return errors.New("a prekey bundle set uses one suite")
		}
		if _, duplicate := devices[bundle.DeviceID]; duplicate {
			return errors.New("a prekey bundle set cannot list one device twice")
		}
		devices[bundle.DeviceID] = struct{}{}
	}
	return nil
}

// BindBundleSet admits a published device set under one delegation.
//
// It does in one call what a caller would otherwise have to remember to do for
// each device: the set is coherent, every bundle is signed by the delegated
// key, none outlives the delegation, and the whole set reproduces the digest
// the descriptor committed.
func BindBundleSet(delegation identity.Delegation, bundles []Bundle, committed string, now time.Time) error {
	if err := ValidateSet(bundles); err != nil {
		return err
	}
	for _, bundle := range bundles {
		if err := BindBundle(delegation, bundle, now); err != nil {
			return err
		}
	}
	return MatchesDescriptorDigest(committed, bundles)
}

// MatchesDescriptorDigest checks a published device set against the prekey
// bundle digest a Messaging Contact Descriptor committed.
//
// A sender resolves the descriptor from finalized identity and then fetches
// material from wherever it is served. This is what stops the two from
// disagreeing: material that does not reproduce the committed digest is not
// the material the endpoint published, whatever the server that returned it
// claims.
func MatchesDescriptorDigest(committed string, bundles []Bundle) error {
	if !canon.ValidDigest(committed) {
		return errors.New("invalid committed prekey bundle digest")
	}
	digest, err := SetDigest(bundles)
	if err != nil {
		return err
	}
	if digest != committed {
		return errors.New("published prekey material does not match the descriptor commitment")
	}
	return nil
}

// SignBundle signs published material with the delegated endpoint key.
func SignBundle(bundle Bundle, endpointKey ed25519.PrivateKey) (Bundle, error) {
	if len(endpointKey) != ed25519.PrivateKeySize {
		return Bundle{}, errors.New("invalid bundle signing key")
	}
	bundle.EndpointSignature = nil
	preimage, err := BundleSigningBytes(bundle)
	if err != nil {
		return Bundle{}, err
	}
	bundle.EndpointSignature = ed25519.Sign(endpointKey, preimage)
	return bundle, nil
}

// EncodeBundleJSON returns the publishable bundle.
func EncodeBundleJSON(bundle Bundle) ([]byte, error) {
	if err := ValidateBundle(bundle, true); err != nil {
		return nil, err
	}
	return json.Marshal(wireBundle{
		Schema:          BundleSchema,
		NetworkID:       bundle.Network.NetworkId,
		GenesisRootHash: bundle.Network.GenesisRootHash,
		GenesisFileHash: bundle.Network.GenesisFileHash,
		AgentID:         bundle.AgentID,
		EndpointID:      bundle.EndpointID,
		DeviceID:        bundle.DeviceID,
		AlgorithmID:     bundle.AlgorithmID,
		MaterialBase64:  base64.StdEncoding.EncodeToString(bundle.Material),
		IssuedAtUnix:    bundle.IssuedAtUnix,
		ExpiresAtUnix:   bundle.ExpiresAtUnix,
		SignatureHex:    hex.EncodeToString(bundle.EndpointSignature),
	})
}

// DecodeBundleJSON rejects unknown fields, trailing data, and malformed
// bundles.
func DecodeBundleJSON(raw []byte) (Bundle, error) {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	var value wireBundle
	if err := decoder.Decode(&value); err != nil {
		return Bundle{}, err
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return Bundle{}, errors.New("prekey bundle has trailing JSON")
	}
	if value.Schema != BundleSchema {
		return Bundle{}, errors.New("unsupported prekey bundle schema")
	}
	material, err := base64.StdEncoding.Strict().DecodeString(value.MaterialBase64)
	if err != nil {
		return Bundle{}, errors.New("invalid prekey bundle material")
	}
	signature, err := hex.DecodeString(value.SignatureHex)
	if err != nil || len(signature) != ed25519.SignatureSize {
		return Bundle{}, errors.New("invalid prekey bundle signature")
	}
	bundle := Bundle{
		Network: &nativev1.NetworkDomain{
			NetworkId:       value.NetworkID,
			GenesisRootHash: value.GenesisRootHash,
			GenesisFileHash: value.GenesisFileHash,
		},
		AgentID:           value.AgentID,
		EndpointID:        value.EndpointID,
		DeviceID:          value.DeviceID,
		AlgorithmID:       value.AlgorithmID,
		Material:          material,
		IssuedAtUnix:      value.IssuedAtUnix,
		ExpiresAtUnix:     value.ExpiresAtUnix,
		EndpointSignature: signature,
	}
	if err := ValidateBundle(bundle, true); err != nil {
		return Bundle{}, err
	}
	return bundle, nil
}

// BindBundle admits published material only under the delegation that
// authorized the key which signed it.
//
// A sender uses this material to start a session with someone who is offline
// and cannot object, so the check runs before the material is used, not after
// the first reply.
func BindBundle(delegation identity.Delegation, bundle Bundle, now time.Time) error {
	if now.IsZero() {
		return errors.New("invalid bundle verification time")
	}
	if err := ValidateBundle(bundle, true); err != nil {
		return err
	}
	if err := identity.CheckWindow(delegation, now); err != nil {
		return err
	}
	if bundle.AgentID != delegation.AgentID || bundle.EndpointID != delegation.EndpointID {
		return errors.New("bundle identity does not match its delegation")
	}
	if bundle.Network.NetworkId != delegation.Network.NetworkId ||
		bundle.Network.GenesisRootHash != delegation.Network.GenesisRootHash ||
		bundle.Network.GenesisFileHash != delegation.Network.GenesisFileHash {
		return errors.New("bundle network tuple does not match its delegation")
	}
	if bundle.ExpiresAtUnix > delegation.ExpiresAtUnix {
		return errors.New("bundle outlives its delegation")
	}
	seconds := now.Unix()
	if seconds < 0 || uint64(seconds) >= bundle.ExpiresAtUnix {
		return errors.New("bundle is expired")
	}
	if uint64(seconds) < bundle.IssuedAtUnix {
		return errors.New("bundle is not yet issued")
	}
	preimage, err := BundleSigningBytes(bundle)
	if err != nil {
		return err
	}
	if !ed25519.Verify(delegation.IdentityPublicKey, preimage, bundle.EndpointSignature) {
		return errors.New("bundle signature is not from the delegated endpoint key")
	}
	return nil
}

// ValidateBundle enforces every structural rule.
func ValidateBundle(bundle Bundle, signed bool) error {
	if bundle.Network == nil || bundle.Network.NetworkId == "" || len(bundle.Network.NetworkId) > 128 ||
		!canon.HashPattern.MatchString(bundle.Network.GenesisRootHash) ||
		!canon.HashPattern.MatchString(bundle.Network.GenesisFileHash) {
		return errors.New("invalid bundle network domain")
	}
	if !ids.Agent.MatchString(bundle.AgentID) || !ids.Endpoint.MatchString(bundle.EndpointID) ||
		!ids.Device.MatchString(bundle.DeviceID) {
		return errors.New("invalid bundle identity")
	}
	if err := ValidateAlgorithmID(bundle.AlgorithmID); err != nil {
		return err
	}
	if len(bundle.Material) == 0 || len(bundle.Material) > MaxMaterialBytes || canon.IsZero(bundle.Material) {
		return errors.New("invalid bundle material")
	}
	if bundle.IssuedAtUnix == 0 || bundle.ExpiresAtUnix <= bundle.IssuedAtUnix ||
		bundle.ExpiresAtUnix-bundle.IssuedAtUnix > MaxBundleLifetimeSeconds {
		return errors.New("invalid bundle validity window")
	}
	if signed && len(bundle.EndpointSignature) != ed25519.SignatureSize {
		return errors.New("invalid bundle signature")
	}
	return nil
}
