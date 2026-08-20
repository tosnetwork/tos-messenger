package room

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"time"

	"github.com/tosnetwork/tos-messenger/internal/canon"
	"github.com/tosnetwork/tos-messenger/internal/ids"
	"github.com/tosnetwork/tos-messenger/pkg/identity"
	nativev1 "github.com/tosnetwork/tos-service-protocol/gen/tos/service/v1"
)

const (
	AuthorityTransferSchema          = "tos.messaging.room-authority-transfer.v1"
	MembershipAuthorizationSchema    = "tos.messaging.room-membership-authorization.v1"
	MaxAuthorityTransferWindow       = 24 * time.Hour
	MaxMembershipAuthorizationWindow = 24 * time.Hour
)

// Authority is the one Agent and delegated Messaging Endpoint allowed to
// serialize membership-changing commits for the current room epoch.
type Authority struct {
	AgentID    string `json:"agent_id"`
	EndpointID string `json:"messaging_endpoint_id"`
}

func (a Authority) Validate() error {
	if !ids.Agent.MatchString(a.AgentID) || !ids.Endpoint.MatchString(a.EndpointID) {
		return errors.New("invalid room authority")
	}
	return nil
}

// MembershipAuthorization is the current Endpoint's bounded signature over
// one exact room membership. A caller cannot advance the durable ledger by
// merely repeating the authority's identifiers.
type MembershipAuthorization struct {
	Network           *nativev1.NetworkDomain
	RoomID            string
	Epoch             uint64
	MembershipDigest  string
	Authority         Authority
	IssuedAtUnix      uint64
	ExpiresAtUnix     uint64
	EndpointSignature []byte
}

func MembershipAuthorizationSigningBytes(value MembershipAuthorization) ([]byte, error) {
	if err := validateMembershipAuthorization(value, false); err != nil {
		return nil, err
	}
	b := bytes.NewBufferString(canon.DomainRoomMembershipAuthorization)
	canon.Text(b, MembershipAuthorizationSchema)
	if err := appendAuthorityNetwork(b, value.Network); err != nil {
		return nil, err
	}
	canon.Text(b, value.RoomID)
	canon.Uint64(b, value.Epoch)
	canon.Text(b, value.MembershipDigest)
	canon.Text(b, value.Authority.AgentID)
	canon.Text(b, value.Authority.EndpointID)
	canon.Uint64(b, value.IssuedAtUnix)
	canon.Uint64(b, value.ExpiresAtUnix)
	return b.Bytes(), nil
}

func SignMembershipAuthorization(value MembershipAuthorization, endpointKey ed25519.PrivateKey) (MembershipAuthorization, error) {
	if len(endpointKey) != ed25519.PrivateKeySize {
		return MembershipAuthorization{}, errors.New("invalid room membership signing key")
	}
	value.EndpointSignature = nil
	preimage, err := MembershipAuthorizationSigningBytes(value)
	if err != nil {
		return MembershipAuthorization{}, err
	}
	value.EndpointSignature = ed25519.Sign(endpointKey, preimage)
	return value, nil
}

// VerifyMembershipAuthorization checks one exact membership against a live,
// finalized delegation supplied by the caller.
func VerifyMembershipAuthorization(membership Membership, value MembershipAuthorization, delegation identity.Delegation, now time.Time) error {
	if now.IsZero() || now.Unix() < 0 {
		return errors.New("invalid room membership verification time")
	}
	if err := validateMembershipAuthorization(value, true); err != nil {
		return err
	}
	if err := membership.usable(); err != nil {
		return err
	}
	if membership.RoomID != value.RoomID || membership.Epoch != value.Epoch || membership.Digest != value.MembershipDigest {
		return errors.New("room authorization names another membership")
	}
	if value.Authority.AgentID != delegation.AgentID || value.Authority.EndpointID != delegation.EndpointID ||
		!membership.Contains(value.Authority.AgentID) {
		return errors.New("room authorization is not from a member authority")
	}
	if err := verifyAuthorityDelegation(delegation, now); err != nil {
		return err
	}
	if !sameAuthorityNetwork(value.Network, delegation.Network) {
		return errors.New("room authorization belongs to another network")
	}
	seconds := uint64(now.Unix())
	if seconds < value.IssuedAtUnix || seconds >= value.ExpiresAtUnix || value.ExpiresAtUnix > delegation.ExpiresAtUnix {
		return errors.New("room membership authorization is outside its validity window")
	}
	preimage, err := MembershipAuthorizationSigningBytes(value)
	if err != nil {
		return err
	}
	if !ed25519.Verify(delegation.IdentityPublicKey, preimage, value.EndpointSignature) {
		return errors.New("room membership authorization signature is invalid")
	}
	return nil
}

func validateMembershipAuthorization(value MembershipAuthorization, signed bool) error {
	if !ids.Room.MatchString(value.RoomID) || value.Epoch == 0 || !canon.ValidDigest(value.MembershipDigest) ||
		value.Authority.Validate() != nil || value.IssuedAtUnix == 0 || value.ExpiresAtUnix <= value.IssuedAtUnix ||
		value.ExpiresAtUnix-value.IssuedAtUnix > uint64(MaxMembershipAuthorizationWindow/time.Second) {
		return errors.New("invalid room membership authorization")
	}
	if err := appendAuthorityNetwork(bytes.NewBuffer(nil), value.Network); err != nil {
		return err
	}
	if signed && len(value.EndpointSignature) != ed25519.SignatureSize {
		return errors.New("invalid room membership authorization signature")
	}
	return nil
}

// AuthorityTransfer is a single-step, current-Endpoint-signed change of the
// room's serializer. MLS itself and Relay arrival order grant no such power.
type AuthorityTransfer struct {
	Network                  *nativev1.NetworkDomain
	RoomID                   string
	PriorEpoch               uint64
	NextEpoch                uint64
	PriorMembershipDigest    string
	NextMembershipDigest     string
	From                     Authority
	To                       Authority
	IssuedAtUnix             uint64
	ExpiresAtUnix            uint64
	CurrentEndpointSignature []byte
}

// AuthorityTransferSigningBytes is the exact Ed25519 preimage. Genesis hashes
// are decoded from strict bare hex and committed as raw 32-byte values.
func AuthorityTransferSigningBytes(value AuthorityTransfer) ([]byte, error) {
	if err := validateAuthorityTransfer(value, false); err != nil {
		return nil, err
	}
	b := bytes.NewBufferString(canon.DomainRoomAuthorityTransfer)
	canon.Text(b, AuthorityTransferSchema)
	if err := appendAuthorityNetwork(b, value.Network); err != nil {
		return nil, err
	}
	canon.Text(b, value.RoomID)
	canon.Uint64(b, value.PriorEpoch)
	canon.Uint64(b, value.NextEpoch)
	canon.Text(b, value.PriorMembershipDigest)
	canon.Text(b, value.NextMembershipDigest)
	canon.Text(b, value.From.AgentID)
	canon.Text(b, value.From.EndpointID)
	canon.Text(b, value.To.AgentID)
	canon.Text(b, value.To.EndpointID)
	canon.Uint64(b, value.IssuedAtUnix)
	canon.Uint64(b, value.ExpiresAtUnix)
	return b.Bytes(), nil
}

func SignAuthorityTransfer(value AuthorityTransfer, endpointKey ed25519.PrivateKey) (AuthorityTransfer, error) {
	if len(endpointKey) != ed25519.PrivateKeySize {
		return AuthorityTransfer{}, errors.New("invalid room authority signing key")
	}
	value.CurrentEndpointSignature = nil
	preimage, err := AuthorityTransferSigningBytes(value)
	if err != nil {
		return AuthorityTransfer{}, err
	}
	value.CurrentEndpointSignature = ed25519.Sign(endpointKey, preimage)
	return value, nil
}

// VerifyAuthorityTransfer binds a transfer to the recorded authority, adjacent
// room memberships, and a finalized live delegation for the current Endpoint.
func VerifyAuthorityTransfer(current Authority, prior, next Membership, value AuthorityTransfer, currentDelegation, nextDelegation identity.Delegation, now time.Time) error {
	if now.IsZero() || now.Unix() < 0 {
		return errors.New("invalid room authority verification time")
	}
	if err := validateAuthorityTransfer(value, true); err != nil {
		return err
	}
	if current != value.From || currentDelegation.AgentID != value.From.AgentID || currentDelegation.EndpointID != value.From.EndpointID {
		return errors.New("room transfer was not made by the current authority")
	}
	if nextDelegation.AgentID != value.To.AgentID || nextDelegation.EndpointID != value.To.EndpointID {
		return errors.New("new room authority is not a finalized Endpoint for its Agent")
	}
	if err := verifyAuthorityDelegation(currentDelegation, now); err != nil {
		return err
	}
	if err := verifyAuthorityDelegation(nextDelegation, now); err != nil {
		return err
	}
	if !sameAuthorityNetwork(value.Network, currentDelegation.Network) || !sameAuthorityNetwork(value.Network, nextDelegation.Network) {
		return errors.New("room transfer belongs to another network")
	}
	if prior.RoomID != value.RoomID || next.RoomID != value.RoomID ||
		prior.Epoch != value.PriorEpoch || next.Epoch != value.NextEpoch ||
		prior.Digest != value.PriorMembershipDigest || next.Digest != value.NextMembershipDigest ||
		next.Epoch != prior.Epoch+1 {
		return errors.New("room transfer is not bound to one successor epoch")
	}
	if err := prior.usable(); err != nil {
		return err
	}
	if err := next.usable(); err != nil {
		return err
	}
	if !prior.Contains(value.From.AgentID) || !next.Contains(value.To.AgentID) {
		return errors.New("room transfer authority is not a member of its epoch")
	}
	seconds := uint64(now.Unix())
	if seconds < value.IssuedAtUnix || seconds >= value.ExpiresAtUnix ||
		value.ExpiresAtUnix > currentDelegation.ExpiresAtUnix || value.ExpiresAtUnix > nextDelegation.ExpiresAtUnix {
		return errors.New("room authority transfer is outside its validity window")
	}
	preimage, err := AuthorityTransferSigningBytes(value)
	if err != nil {
		return err
	}
	if !ed25519.Verify(currentDelegation.IdentityPublicKey, preimage, value.CurrentEndpointSignature) {
		return errors.New("room authority transfer signature is invalid")
	}
	return nil
}

func validateAuthorityTransfer(value AuthorityTransfer, signed bool) error {
	if !ids.Room.MatchString(value.RoomID) || value.PriorEpoch == 0 ||
		value.NextEpoch <= value.PriorEpoch || value.NextEpoch != value.PriorEpoch+1 ||
		!canon.ValidDigest(value.PriorMembershipDigest) || !canon.ValidDigest(value.NextMembershipDigest) ||
		value.PriorMembershipDigest == value.NextMembershipDigest || value.From.Validate() != nil || value.To.Validate() != nil ||
		value.From == value.To || value.IssuedAtUnix == 0 || value.ExpiresAtUnix <= value.IssuedAtUnix ||
		value.ExpiresAtUnix-value.IssuedAtUnix > uint64(MaxAuthorityTransferWindow/time.Second) {
		return errors.New("invalid room authority transfer")
	}
	if err := appendAuthorityNetwork(bytes.NewBuffer(nil), value.Network); err != nil {
		return err
	}
	if signed && len(value.CurrentEndpointSignature) != ed25519.SignatureSize {
		return errors.New("invalid room authority transfer signature")
	}
	return nil
}

func appendAuthorityNetwork(b *bytes.Buffer, network *nativev1.NetworkDomain) error {
	if b == nil || network == nil || network.NetworkId == "" || len(network.NetworkId) > 128 ||
		!canon.HashPattern.MatchString(network.GenesisRootHash) || !canon.HashPattern.MatchString(network.GenesisFileHash) {
		return errors.New("invalid room authority network")
	}
	root, rootErr := hex.DecodeString(network.GenesisRootHash)
	file, fileErr := hex.DecodeString(network.GenesisFileHash)
	if rootErr != nil || fileErr != nil || len(root) != sha256.Size || len(file) != sha256.Size {
		return errors.New("invalid room authority genesis hashes")
	}
	canon.Text(b, network.NetworkId)
	canon.Bytes(b, root)
	canon.Bytes(b, file)
	return nil
}

func sameAuthorityNetwork(first, second *nativev1.NetworkDomain) bool {
	return first != nil && second != nil && first.NetworkId == second.NetworkId &&
		first.GenesisRootHash == second.GenesisRootHash && first.GenesisFileHash == second.GenesisFileHash
}

func verifyAuthorityDelegation(delegation identity.Delegation, now time.Time) error {
	if err := identity.CheckWindow(delegation, now); err != nil {
		return err
	}
	if len(delegation.IdentityPublicKey) != ed25519.PublicKeySize {
		return errors.New("room authority delegation has no Endpoint key")
	}
	derived, err := identity.DeriveEndpointID(delegation.Network, delegation.AgentID, delegation.IdentityPublicKey)
	if err != nil || derived != delegation.EndpointID {
		return errors.New("room authority delegation key does not derive its Endpoint")
	}
	return nil
}
