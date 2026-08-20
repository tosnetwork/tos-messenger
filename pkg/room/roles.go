package room

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
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
	RolePolicySchema    = "tos.messaging.room-role-policy.v1"
	MaxRolePolicyBytes  = 32 << 10
	MaxRoomAdmins       = 4
	MaxRoomModerators   = 16
	MaxRolePolicyWindow = 24 * time.Hour
)

// Role names an elevated room power. Ordinary current members need no
// assignment: membership itself grants posting and decryption, while this
// policy grants only the smaller administrative surface.
type Role string

const (
	RoleAdministrator Role = "administrator"
	RoleModerator     Role = "moderator"
)

// Action is a local authorization question. Transport arrival and MLS leaf
// ownership never imply one of these powers.
type Action string

const (
	ActionPost              Action = "post"
	ActionModerate          Action = "moderate"
	ActionChangeMembership  Action = "change-membership"
	ActionChangeRoles       Action = "change-roles"
	ActionTransferAuthority Action = "transfer-authority"
)

type RoleAssignment struct {
	AgentID string `json:"agent_id"`
	Role    Role   `json:"role"`
}

// RolePolicy is an epoch-bound, authority-signed list of elevated roles. It
// becomes stale on every membership transition, so removal cannot leave an
// administrative grant alive under a later member set.
type RolePolicy struct {
	Network           *nativev1.NetworkDomain
	RoomID            string
	MembershipEpoch   uint64
	MembershipDigest  string
	Revision          uint64
	Assignments       []RoleAssignment
	Authority         Authority
	IssuedAtUnix      uint64
	ExpiresAtUnix     uint64
	EndpointSignature []byte
}

type wireRolePolicy struct {
	Schema                  string                  `json:"schema"`
	Network                 *nativev1.NetworkDomain `json:"network"`
	RoomID                  string                  `json:"room_id"`
	MembershipEpoch         uint64                  `json:"membership_epoch"`
	MembershipDigest        string                  `json:"membership_digest"`
	Revision                uint64                  `json:"revision"`
	Assignments             []RoleAssignment        `json:"assignments"`
	Authority               Authority               `json:"authority"`
	IssuedAtUnix            uint64                  `json:"issued_at_unix"`
	ExpiresAtUnix           uint64                  `json:"expires_at_unix"`
	EndpointSignatureBase64 string                  `json:"endpoint_signature_base64"`
}

func RolePolicySigningBytes(value RolePolicy) ([]byte, error) {
	if err := validateRolePolicy(value, false); err != nil {
		return nil, err
	}
	b := bytes.NewBufferString(canon.DomainRoomRolePolicy)
	canon.Text(b, RolePolicySchema)
	if err := appendAuthorityNetwork(b, value.Network); err != nil {
		return nil, err
	}
	canon.Text(b, value.RoomID)
	canon.Uint64(b, value.MembershipEpoch)
	canon.Text(b, value.MembershipDigest)
	canon.Uint64(b, value.Revision)
	canon.Uint32(b, uint32(len(value.Assignments)))
	for _, assignment := range value.Assignments {
		canon.Text(b, assignment.AgentID)
		canon.Text(b, string(assignment.Role))
	}
	canon.Text(b, value.Authority.AgentID)
	canon.Text(b, value.Authority.EndpointID)
	canon.Uint64(b, value.IssuedAtUnix)
	canon.Uint64(b, value.ExpiresAtUnix)
	return b.Bytes(), nil
}

func SignRolePolicy(value RolePolicy, endpointKey ed25519.PrivateKey) (RolePolicy, error) {
	if len(endpointKey) != ed25519.PrivateKeySize {
		return RolePolicy{}, errors.New("invalid room role-policy signing key")
	}
	value.EndpointSignature = nil
	preimage, err := RolePolicySigningBytes(value)
	if err != nil {
		return RolePolicy{}, err
	}
	value.EndpointSignature = ed25519.Sign(endpointKey, preimage)
	return value, nil
}

// VerifyRolePolicy binds elevated powers to the exact current member set and
// a live finalized Endpoint delegation of the recorded room authority.
func VerifyRolePolicy(value RolePolicy, membership Membership, current Authority, delegation identity.Delegation, now time.Time) error {
	if now.IsZero() || now.Unix() < 0 {
		return errors.New("invalid room role-policy verification time")
	}
	if err := validateRolePolicy(value, true); err != nil {
		return err
	}
	commitment, err := membership.Announce()
	if err != nil {
		return err
	}
	if value.RoomID != membership.RoomID || value.MembershipEpoch != membership.Epoch ||
		value.MembershipDigest != commitment.MembershipDigest {
		return errors.New("room role policy names another membership")
	}
	if value.Authority != current || value.Authority.AgentID != delegation.AgentID ||
		value.Authority.EndpointID != delegation.EndpointID {
		return errors.New("room role policy was not made by the current authority")
	}
	if err := verifyAuthorityDelegation(delegation, now); err != nil {
		return err
	}
	if !sameAuthorityNetwork(value.Network, delegation.Network) {
		return errors.New("room role policy belongs to another network")
	}
	seconds := uint64(now.Unix())
	if seconds < value.IssuedAtUnix || seconds >= value.ExpiresAtUnix || value.ExpiresAtUnix > delegation.ExpiresAtUnix {
		return errors.New("room role policy is outside its validity window")
	}
	for _, assignment := range value.Assignments {
		if !membership.Contains(assignment.AgentID) {
			return errors.New("room role policy assigns a non-member")
		}
	}
	if value.RoleOf(value.Authority.AgentID) != RoleAdministrator {
		return errors.New("room authority must remain an administrator")
	}
	preimage, err := RolePolicySigningBytes(value)
	if err != nil {
		return err
	}
	if !ed25519.Verify(delegation.IdentityPublicKey, preimage, value.EndpointSignature) {
		return errors.New("room role-policy signature is invalid")
	}
	return nil
}

func (p RolePolicy) RoleOf(agentID string) Role {
	index := sort.Search(len(p.Assignments), func(i int) bool { return p.Assignments[i].AgentID >= agentID })
	if index < len(p.Assignments) && p.Assignments[index].AgentID == agentID {
		return p.Assignments[index].Role
	}
	return ""
}

// Allows evaluates role powers only after membership is checked. Administrator
// status does not override removal, and a default member can only post.
func (p RolePolicy) Allows(membership Membership, agentID string, action Action) bool {
	if !membership.Contains(agentID) || p.RoomID != membership.RoomID ||
		p.MembershipEpoch != membership.Epoch || p.MembershipDigest != membership.Digest {
		return false
	}
	role := p.RoleOf(agentID)
	switch action {
	case ActionPost:
		return true
	case ActionModerate:
		return role == RoleAdministrator || role == RoleModerator
	case ActionChangeMembership, ActionChangeRoles, ActionTransferAuthority:
		return role == RoleAdministrator
	default:
		return false
	}
}

func EncodeRolePolicyJSON(value RolePolicy) ([]byte, error) {
	if err := validateRolePolicy(value, true); err != nil {
		return nil, err
	}
	wire := wireRolePolicy{Schema: RolePolicySchema, Network: value.Network, RoomID: value.RoomID,
		MembershipEpoch: value.MembershipEpoch, MembershipDigest: value.MembershipDigest, Revision: value.Revision,
		Assignments: value.Assignments, Authority: value.Authority, IssuedAtUnix: value.IssuedAtUnix,
		ExpiresAtUnix: value.ExpiresAtUnix, EndpointSignatureBase64: base64.RawStdEncoding.EncodeToString(value.EndpointSignature)}
	raw, err := json.Marshal(wire)
	if err != nil || len(raw) > MaxRolePolicyBytes {
		return nil, errors.New("encode room role policy")
	}
	return raw, nil
}

func DecodeRolePolicyJSON(raw []byte) (RolePolicy, error) {
	if len(raw) == 0 || len(raw) > MaxRolePolicyBytes {
		return RolePolicy{}, errors.New("room role-policy wire is outside its bound")
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	var wire wireRolePolicy
	if err := decoder.Decode(&wire); err != nil {
		return RolePolicy{}, err
	}
	if err := decoder.Decode(new(any)); !errors.Is(err, io.EOF) {
		return RolePolicy{}, errors.New("room role policy has trailing JSON")
	}
	if wire.Schema != RolePolicySchema {
		return RolePolicy{}, errors.New("unsupported room role-policy schema")
	}
	signature, err := base64.RawStdEncoding.Strict().DecodeString(wire.EndpointSignatureBase64)
	if err != nil {
		return RolePolicy{}, errors.New("invalid room role-policy signature encoding")
	}
	value := RolePolicy{Network: wire.Network, RoomID: wire.RoomID, MembershipEpoch: wire.MembershipEpoch,
		MembershipDigest: wire.MembershipDigest, Revision: wire.Revision, Assignments: wire.Assignments,
		Authority: wire.Authority, IssuedAtUnix: wire.IssuedAtUnix, ExpiresAtUnix: wire.ExpiresAtUnix,
		EndpointSignature: signature}
	if err := validateRolePolicy(value, true); err != nil {
		return RolePolicy{}, err
	}
	return value, nil
}

func validateRolePolicy(value RolePolicy, signed bool) error {
	if !ids.Room.MatchString(value.RoomID) || value.MembershipEpoch == 0 || !canon.ValidDigest(value.MembershipDigest) ||
		value.Revision == 0 || value.Authority.Validate() != nil || value.IssuedAtUnix == 0 ||
		value.ExpiresAtUnix <= value.IssuedAtUnix ||
		value.ExpiresAtUnix-value.IssuedAtUnix > uint64(MaxRolePolicyWindow/time.Second) ||
		len(value.Assignments) == 0 || len(value.Assignments) > MaxRoomAdmins+MaxRoomModerators {
		return errors.New("invalid room role policy")
	}
	if err := appendAuthorityNetwork(bytes.NewBuffer(nil), value.Network); err != nil {
		return err
	}
	admins, moderators := 0, 0
	for index, assignment := range value.Assignments {
		if !ids.Agent.MatchString(assignment.AgentID) || index > 0 && value.Assignments[index-1].AgentID >= assignment.AgentID {
			return errors.New("room role assignments must be unique and sorted")
		}
		switch assignment.Role {
		case RoleAdministrator:
			admins++
		case RoleModerator:
			moderators++
		default:
			return errors.New("invalid room role")
		}
	}
	if admins == 0 || admins > MaxRoomAdmins || moderators > MaxRoomModerators {
		return errors.New("room elevated roles exceed their bounds")
	}
	if signed && len(value.EndpointSignature) != ed25519.SignatureSize {
		return errors.New("invalid room role-policy signature")
	}
	return nil
}
