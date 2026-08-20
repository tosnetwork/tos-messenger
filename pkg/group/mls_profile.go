package group

// This file is the application-side boundary around an RFC 9420
// implementation. It deliberately contains no TreeKEM or MLS cryptography.
// Those operations belong to a reviewed MLS library; the types below enforce
// the TOS authority, two-clock, and persistence invariants around that library.

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
	"github.com/tosnetwork/tos-messenger/pkg/e2ee"
	"github.com/tosnetwork/tos-messenger/pkg/identity"
	"github.com/tosnetwork/tos-messenger/pkg/room"
	nativev1 "github.com/tosnetwork/tos-service-protocol/gen/tos/service/v1"
)

const (
	// MLSCipherSuite is the only suite admitted by the TOS-MLS v1 candidate.
	MLSCipherSuite uint16 = 0x0001
	// MLSDeviceCredentialSchema identifies the endpoint-signed authority object.
	// The profile remains a candidate until the freeze evidence in ROADMAP exists.
	MLSDeviceCredentialSchema    = "tos.messaging.mls-device-credential.v1"
	MaxKeyPackageBytes           = 64 << 10
	MaxCredentialLifetimeSeconds = 30 * 24 * 60 * 60
)

// Driver is the deliberately narrow boundary a reviewed RFC 9420 library
// adapter must satisfy. Opaque state and KeyPackage private state are secret
// serialized values owned by that library. Every operation may advance state;
// callers durably record the returned state before exposing its result.
//
// This interface is not an MLS implementation and does not bless one. A
// Driver is admissible only when its KeyPackage parser enforces suite 0x0001
// and matches the LeafNode signature key to DeviceCredential.
type Driver interface {
	CipherSuite() uint16
	ValidateKeyPackage(keyPackage []byte, expectedLeafSignatureKey ed25519.PublicKey) error
	Join(keyPackagePrivateState, welcome []byte) (opaqueState []byte, err error)
	Commit(opaqueState []byte, operations []LeafOperation) (nextState, commit []byte, welcomes map[string][]byte, err error)
	Apply(opaqueState, commit []byte) (nextState []byte, err error)
	Seal(opaqueState, authenticatedData, plaintext []byte) (nextState, privateMessage []byte, err error)
	Open(opaqueState, authenticatedData, privateMessage []byte) (nextState, plaintext []byte, err error)
}

// Clock separates logical Agent membership from MLS cryptographic evolution.
// RoomEpoch changes only with pkg/room; MLSEpoch changes on every accepted MLS
// commit, including device churn and PCS updates.
type Clock struct {
	RoomEpoch uint64
	MLSEpoch  uint64
}

// State is the public application binding of one opaque MLS library state.
type State struct {
	RoomID            string
	Clock             Clock
	MembershipDigest  string
	AcceptedCommitRef string
}

// Transition describes the application facts an MLS commit must be checked
// against before its opaque result can become durable.
type Transition struct {
	Prior      State
	Next       State
	Membership room.Membership
	CommitRef  string
}

// ValidateTransition rejects rollback, gaps, forks, and invented room epochs.
// A room change advances both clocks; an MLS-only update advances only MLS.
func ValidateTransition(t Transition) error {
	if !ids.Room.MatchString(t.Prior.RoomID) || t.Next.RoomID != t.Prior.RoomID {
		return errors.New("MLS transition changes or omits the room")
	}
	if !canon.ValidDigest(t.Prior.MembershipDigest) || !canon.ValidDigest(t.Next.MembershipDigest) ||
		(t.Prior.AcceptedCommitRef != "" && !canon.ValidDigest(t.Prior.AcceptedCommitRef)) {
		return errors.New("MLS transition has an invalid durable binding")
	}
	if t.Prior.Clock.RoomEpoch == 0 || t.Next.Clock.MLSEpoch != t.Prior.Clock.MLSEpoch+1 {
		return errors.New("MLS transition has an epoch gap or rollback")
	}
	if !canon.ValidDigest(t.CommitRef) || t.Next.AcceptedCommitRef != t.CommitRef {
		return errors.New("MLS transition has no exact accepted commit reference")
	}
	if t.Next.Clock.RoomEpoch == t.Prior.Clock.RoomEpoch {
		if t.Next.MembershipDigest != t.Prior.MembershipDigest {
			return errors.New("an MLS-only update changed Agent membership")
		}
		return nil
	}
	if t.Next.Clock.RoomEpoch != t.Prior.Clock.RoomEpoch+1 {
		return errors.New("MLS transition skipped a room epoch")
	}
	if t.Membership.RoomID != t.Prior.RoomID || t.Membership.Epoch != t.Next.Clock.RoomEpoch {
		return errors.New("MLS transition does not carry its successor membership")
	}
	announcement, err := t.Membership.Announce()
	if err != nil {
		return err
	}
	if announcement.MembershipDigest != t.Next.MembershipDigest || t.Next.MembershipDigest == t.Prior.MembershipDigest {
		return errors.New("MLS transition is not bound to the successor membership")
	}
	return nil
}

// DeviceCredential authorises one device's distinct MLS LeafNode signature
// key and exact one-time KeyPackage under the delegated Endpoint key.
type DeviceCredential struct {
	Network                *nativev1.NetworkDomain
	AgentID                string
	EndpointID             string
	DeviceID               string
	DeviceSetDigest        string
	LeafSignaturePublicKey ed25519.PublicKey
	KeyPackage             []byte
	IssuedAtUnix           uint64
	ExpiresAtUnix          uint64
	EndpointSignature      []byte
}

type wireDeviceCredential struct {
	Schema                    string `json:"schema"`
	NetworkID                 string `json:"network_id"`
	GenesisRootHash           string `json:"genesis_root_hash"`
	GenesisFileHash           string `json:"genesis_file_hash"`
	AgentID                   string `json:"agent_id"`
	EndpointID                string `json:"messaging_endpoint_id"`
	DeviceID                  string `json:"device_id"`
	DeviceSetDigest           string `json:"device_set_digest"`
	LeafSignaturePublicKeyHex string `json:"leaf_signature_public_key_hex"`
	CipherSuite               uint16 `json:"cipher_suite"`
	KeyPackageBase64          string `json:"key_package_base64"`
	IssuedAtUnix              uint64 `json:"issued_at_unix"`
	ExpiresAtUnix             uint64 `json:"expires_at_unix"`
	EndpointSignatureHex      string `json:"endpoint_signature_hex"`
}

// CredentialSigningBytes returns the strict endpoint-signature preimage.
func CredentialSigningBytes(c DeviceCredential) ([]byte, error) {
	if err := validateCredential(c, false); err != nil {
		return nil, err
	}
	b := bytes.NewBufferString(canon.DomainMLSDeviceCredential)
	canon.Text(b, MLSDeviceCredentialSchema)
	canon.Text(b, c.Network.NetworkId)
	canon.Text(b, c.Network.GenesisRootHash)
	canon.Text(b, c.Network.GenesisFileHash)
	canon.Text(b, c.AgentID)
	canon.Text(b, c.EndpointID)
	canon.Text(b, c.DeviceID)
	canon.Text(b, c.DeviceSetDigest)
	canon.Bytes(b, c.LeafSignaturePublicKey)
	canon.Uint32(b, uint32(MLSCipherSuite))
	canon.Bytes(b, c.KeyPackage)
	canon.Uint64(b, c.IssuedAtUnix)
	canon.Uint64(b, c.ExpiresAtUnix)
	return b.Bytes(), nil
}

// KeyPackageRef identifies the exact published MLS KeyPackage.
func KeyPackageRef(c DeviceCredential) (string, error) {
	preimage, err := CredentialSigningBytes(c)
	if err != nil {
		return "", err
	}
	return canon.Digest(preimage), nil
}

// SignDeviceCredential signs a publication with the delegated Endpoint key.
func SignDeviceCredential(c DeviceCredential, endpointKey ed25519.PrivateKey) (DeviceCredential, error) {
	if len(endpointKey) != ed25519.PrivateKeySize {
		return DeviceCredential{}, errors.New("invalid endpoint signing key")
	}
	c.EndpointSignature = nil
	preimage, err := CredentialSigningBytes(c)
	if err != nil {
		return DeviceCredential{}, err
	}
	c.EndpointSignature = ed25519.Sign(endpointKey, preimage)
	return c, nil
}

// EncodeDeviceCredentialJSON returns the strict publication representation.
// JSON is transport only; signatures always cover CredentialSigningBytes.
func EncodeDeviceCredentialJSON(c DeviceCredential) ([]byte, error) {
	if err := validateCredential(c, true); err != nil {
		return nil, err
	}
	return json.Marshal(wireDeviceCredential{
		Schema: MLSDeviceCredentialSchema, NetworkID: c.Network.NetworkId,
		GenesisRootHash: c.Network.GenesisRootHash, GenesisFileHash: c.Network.GenesisFileHash,
		AgentID: c.AgentID, EndpointID: c.EndpointID, DeviceID: c.DeviceID,
		DeviceSetDigest: c.DeviceSetDigest, LeafSignaturePublicKeyHex: hex.EncodeToString(c.LeafSignaturePublicKey),
		CipherSuite: MLSCipherSuite, KeyPackageBase64: base64.StdEncoding.EncodeToString(c.KeyPackage),
		IssuedAtUnix: c.IssuedAtUnix, ExpiresAtUnix: c.ExpiresAtUnix,
		EndpointSignatureHex: hex.EncodeToString(c.EndpointSignature),
	})
}

// DecodeDeviceCredentialJSON rejects unknown/trailing fields and any suite
// other than the single TOS-MLS v1 candidate suite.
func DecodeDeviceCredentialJSON(raw []byte) (DeviceCredential, error) {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	var value wireDeviceCredential
	if err := decoder.Decode(&value); err != nil {
		return DeviceCredential{}, err
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return DeviceCredential{}, errors.New("MLS credential has trailing JSON")
	}
	if value.Schema != MLSDeviceCredentialSchema || value.CipherSuite != MLSCipherSuite {
		return DeviceCredential{}, errors.New("unsupported MLS credential profile")
	}
	leafKey, err := hex.DecodeString(value.LeafSignaturePublicKeyHex)
	if err != nil || len(leafKey) != ed25519.PublicKeySize {
		return DeviceCredential{}, errors.New("invalid MLS leaf signature key")
	}
	keyPackage, err := base64.StdEncoding.Strict().DecodeString(value.KeyPackageBase64)
	if err != nil {
		return DeviceCredential{}, errors.New("invalid MLS KeyPackage encoding")
	}
	signature, err := hex.DecodeString(value.EndpointSignatureHex)
	if err != nil || len(signature) != ed25519.SignatureSize {
		return DeviceCredential{}, errors.New("invalid MLS credential signature")
	}
	c := DeviceCredential{Network: &nativev1.NetworkDomain{NetworkId: value.NetworkID, GenesisRootHash: value.GenesisRootHash, GenesisFileHash: value.GenesisFileHash}, AgentID: value.AgentID, EndpointID: value.EndpointID, DeviceID: value.DeviceID, DeviceSetDigest: value.DeviceSetDigest, LeafSignaturePublicKey: ed25519.PublicKey(leafKey), KeyPackage: keyPackage, IssuedAtUnix: value.IssuedAtUnix, ExpiresAtUnix: value.ExpiresAtUnix, EndpointSignature: signature}
	if err := validateCredential(c, true); err != nil {
		return DeviceCredential{}, err
	}
	return c, nil
}

// BindDeviceCredential verifies current TOS authority before an MLS library is
// allowed to consume the KeyPackage. The library must separately parse and
// validate the RFC 9420 KeyPackage and match its LeafNode key to this object.
func BindDeviceCredential(delegation identity.Delegation, c DeviceCredential, currentSet e2ee.SetSummary, now time.Time) error {
	if now.IsZero() {
		return errors.New("invalid credential verification time")
	}
	if err := validateCredential(c, true); err != nil {
		return err
	}
	if err := identity.CheckWindow(delegation, now); err != nil {
		return err
	}
	if c.AgentID != delegation.AgentID || c.EndpointID != delegation.EndpointID || currentSet.EndpointID != c.EndpointID {
		return errors.New("MLS credential identity does not match current authority")
	}
	if bytes.Equal(c.LeafSignaturePublicKey, delegation.IdentityPublicKey) {
		return errors.New("MLS leaf signature key must be distinct from the delegated endpoint key")
	}
	if c.Network.NetworkId != delegation.Network.NetworkId || c.Network.GenesisRootHash != delegation.Network.GenesisRootHash || c.Network.GenesisFileHash != delegation.Network.GenesisFileHash {
		return errors.New("MLS credential belongs to another network")
	}
	if c.DeviceSetDigest != currentSet.Digest || !contains(currentSet.DeviceIDs, c.DeviceID) {
		return errors.New("MLS credential is stale or its device is not current")
	}
	if c.ExpiresAtUnix > delegation.ExpiresAtUnix {
		return errors.New("MLS credential outlives its delegation")
	}
	seconds := now.Unix()
	if seconds < 0 || uint64(seconds) < c.IssuedAtUnix || uint64(seconds) >= c.ExpiresAtUnix {
		return errors.New("MLS credential is outside its validity window")
	}
	preimage, err := CredentialSigningBytes(c)
	if err != nil {
		return err
	}
	if !ed25519.Verify(delegation.IdentityPublicKey, preimage, c.EndpointSignature) {
		return errors.New("MLS credential is not signed by the delegated endpoint")
	}
	return nil
}

func validateCredential(c DeviceCredential, signed bool) error {
	if c.Network == nil || c.Network.NetworkId == "" || len(c.Network.NetworkId) > 128 || !canon.HashPattern.MatchString(c.Network.GenesisRootHash) || !canon.HashPattern.MatchString(c.Network.GenesisFileHash) {
		return errors.New("invalid MLS credential network")
	}
	if !ids.Agent.MatchString(c.AgentID) || !ids.Endpoint.MatchString(c.EndpointID) || !ids.Device.MatchString(c.DeviceID) || !canon.ValidDigest(c.DeviceSetDigest) {
		return errors.New("invalid MLS credential identity")
	}
	if len(c.LeafSignaturePublicKey) != ed25519.PublicKeySize || canon.IsZero(c.LeafSignaturePublicKey) {
		return errors.New("invalid MLS leaf signature key")
	}
	if len(c.KeyPackage) == 0 || len(c.KeyPackage) > MaxKeyPackageBytes || canon.IsZero(c.KeyPackage) {
		return errors.New("invalid MLS KeyPackage")
	}
	if c.IssuedAtUnix == 0 || c.ExpiresAtUnix <= c.IssuedAtUnix || c.ExpiresAtUnix-c.IssuedAtUnix > MaxCredentialLifetimeSeconds {
		return errors.New("invalid MLS credential validity window")
	}
	if signed && len(c.EndpointSignature) != ed25519.SignatureSize {
		return errors.New("invalid MLS credential signature")
	}
	return nil
}

// Leaf is the TOS authority attached to one MLS leaf.
type Leaf struct{ AgentID, EndpointID, DeviceID, DeviceSetDigest, KeyPackageRef string }

type LeafOperationKind string

const (
	LeafAdd    LeafOperationKind = "add"
	LeafRemove LeafOperationKind = "remove"
	LeafUpdate LeafOperationKind = "update"
)

type LeafOperation struct {
	Kind  LeafOperationKind
	Prior *Leaf
	Next  *Leaf
}

// PlanDeviceSuccession converts one accepted endpoint device succession into
// deterministic leaf work. Retained devices update because their credential
// must bind the newly current set digest; a revoked device is only removed.
func PlanDeviceSuccession(agentID, endpointID string, current []Leaf, succession e2ee.Succession, credentials map[string]DeviceCredential) ([]LeafOperation, error) {
	if !ids.Agent.MatchString(agentID) || !ids.Endpoint.MatchString(endpointID) || succession.Accepted.EndpointID != endpointID || !canon.ValidDigest(succession.Accepted.Digest) {
		return nil, errors.New("invalid device succession authority")
	}
	byDevice := make(map[string]Leaf, len(current))
	for _, leaf := range current {
		if leaf.AgentID != agentID || leaf.EndpointID != endpointID || !ids.Device.MatchString(leaf.DeviceID) {
			return nil, errors.New("current MLS leaf belongs to another authority")
		}
		if _, duplicate := byDevice[leaf.DeviceID]; duplicate {
			return nil, errors.New("duplicate current MLS leaf")
		}
		byDevice[leaf.DeviceID] = leaf
	}
	accepted := append([]string(nil), succession.Accepted.DeviceIDs...)
	sort.Strings(accepted)
	unchanged := len(current) == len(accepted)
	if unchanged {
		for _, leaf := range current {
			if leaf.DeviceSetDigest != succession.Accepted.Digest || !contains(accepted, leaf.DeviceID) {
				unchanged = false
				break
			}
		}
	}
	if unchanged {
		return nil, nil
	}
	ops := make([]LeafOperation, 0, len(current)+len(accepted))
	for _, deviceID := range accepted {
		credential, ok := credentials[deviceID]
		if !ok || credential.AgentID != agentID || credential.EndpointID != endpointID || credential.DeviceID != deviceID || credential.DeviceSetDigest != succession.Accepted.Digest {
			return nil, errors.New("missing current MLS credential for accepted device")
		}
		ref, err := KeyPackageRef(credential)
		if err != nil {
			return nil, err
		}
		next := Leaf{AgentID: agentID, EndpointID: endpointID, DeviceID: deviceID, DeviceSetDigest: succession.Accepted.Digest, KeyPackageRef: ref}
		if prior, exists := byDevice[deviceID]; exists {
			p := prior
			n := next
			ops = append(ops, LeafOperation{Kind: LeafUpdate, Prior: &p, Next: &n})
			delete(byDevice, deviceID)
		} else {
			n := next
			ops = append(ops, LeafOperation{Kind: LeafAdd, Next: &n})
		}
	}
	removed := make([]string, 0, len(byDevice))
	for device := range byDevice {
		removed = append(removed, device)
	}
	sort.Strings(removed)
	for _, device := range removed {
		p := byDevice[device]
		ops = append(ops, LeafOperation{Kind: LeafRemove, Prior: &p})
	}
	return ops, nil
}

func contains(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}
