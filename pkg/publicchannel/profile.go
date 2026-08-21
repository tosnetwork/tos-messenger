// Package publicchannel defines the route-neutral authority, signed-event and
// convergent-history core for public Agent channels. Overlay, RLDP and Sites
// are transports for these objects; none is an ordering or role authority.
package publicchannel

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"regexp"
	"sort"
	"time"

	"github.com/tosnetwork/tos-messenger/internal/canon"
	"github.com/tosnetwork/tos-messenger/internal/ids"
	"github.com/tosnetwork/tos-messenger/pkg/identity"
	nativev1 "github.com/tosnetwork/tos-service-protocol/gen/tos/service/v1"
)

const (
	ProfileSchema    = "tos.messaging.public-channel-profile.v1"
	MaxPrincipals    = 64
	MaxProfileWindow = 30 * 24 * time.Hour
)

var channelPattern = regexp.MustCompile(`^channel_[0-9a-f]{64}$`)

// Principal is one finalized Messaging Endpoint and the powers the channel
// authority grants it for this exact profile epoch.
type Principal struct {
	AgentID    string `json:"agent_id"`
	EndpointID string `json:"messaging_endpoint_id"`
	Publisher  bool   `json:"publisher"`
	Moderator  bool   `json:"moderator"`
}

// Profile is one authority-serialized publisher/moderator roster. Changing a
// role creates a successor epoch; transport membership never changes it.
type Profile struct {
	Network               *nativev1.NetworkDomain
	ChannelID             string
	Epoch                 uint64
	PreviousProfileDigest string
	AuthorityAgentID      string
	AuthorityEndpointID   string
	Principals            []Principal
	IssuedAtUnix          uint64
	ExpiresAtUnix         uint64
	AuthoritySignature    []byte
}

// DeriveID creates a public channel identity from finalized network/authority
// identity and an operator-generated non-zero 32-byte seed.
func DeriveID(network *nativev1.NetworkDomain, authorityAgentID, authorityEndpointID string, seed []byte) (string, error) {
	if !ids.Agent.MatchString(authorityAgentID) || !ids.Endpoint.MatchString(authorityEndpointID) ||
		len(seed) != 32 || canon.IsZero(seed) {
		return "", errors.New("invalid public channel identity input")
	}
	b := bytes.NewBufferString(canon.DomainPublicChannelID)
	if err := appendNetwork(b, network); err != nil {
		return "", err
	}
	canon.Text(b, authorityAgentID)
	canon.Text(b, authorityEndpointID)
	canon.Bytes(b, seed)
	digest := sha256.Sum256(b.Bytes())
	return "channel_" + hex.EncodeToString(digest[:]), nil
}

// ProfileSigningBytes returns the exact Endpoint-signed role roster.
func ProfileSigningBytes(profile Profile) ([]byte, error) {
	if err := validateProfile(profile, false); err != nil {
		return nil, err
	}
	b := bytes.NewBufferString(canon.DomainPublicChannelProfile)
	canon.Text(b, ProfileSchema)
	if err := appendNetwork(b, profile.Network); err != nil {
		return nil, err
	}
	canon.Text(b, profile.ChannelID)
	canon.Uint64(b, profile.Epoch)
	canon.Text(b, profile.PreviousProfileDigest)
	canon.Text(b, profile.AuthorityAgentID)
	canon.Text(b, profile.AuthorityEndpointID)
	canon.Uint32(b, uint32(len(profile.Principals)))
	for _, principal := range profile.Principals {
		canon.Text(b, principal.AgentID)
		canon.Text(b, principal.EndpointID)
		canon.Bool(b, principal.Publisher)
		canon.Bool(b, principal.Moderator)
	}
	canon.Uint64(b, profile.IssuedAtUnix)
	canon.Uint64(b, profile.ExpiresAtUnix)
	return b.Bytes(), nil
}

func SignProfile(profile Profile, key ed25519.PrivateKey) (Profile, error) {
	if len(key) != ed25519.PrivateKeySize {
		return Profile{}, errors.New("invalid public channel authority key")
	}
	profile.AuthoritySignature = nil
	preimage, err := ProfileSigningBytes(profile)
	if err != nil {
		return Profile{}, err
	}
	profile.AuthoritySignature = ed25519.Sign(key, preimage)
	return profile, nil
}

// VerifyProfile accepts authority only from a caller-supplied finalized
// delegation. Every role Endpoint must also be supplied as a finalized
// delegation; a profile signature cannot mint an Agent identity.
func VerifyProfile(profile Profile, authority identity.Delegation, principals map[string]identity.Delegation, now time.Time) error {
	if now.IsZero() || now.Unix() < 0 || uint64(now.Unix()) < profile.IssuedAtUnix {
		return errors.New("invalid public channel profile verification time")
	}
	if err := validateProfile(profile, true); err != nil {
		return err
	}
	if authority.AgentID != profile.AuthorityAgentID || authority.EndpointID != profile.AuthorityEndpointID ||
		!sameNetwork(profile.Network, authority.Network) || !identity.AllowsEventClass(authority, "public.channel") {
		return errors.New("public channel profile authority is not finalized or delegated")
	}
	issued := time.Unix(int64(profile.IssuedAtUnix), 0)
	if err := identity.Validate(authority); err != nil || identity.CheckWindow(authority, issued) != nil ||
		profile.ExpiresAtUnix > authority.ExpiresAtUnix {
		return errors.New("public channel profile exceeds authority")
	}
	for _, principal := range profile.Principals {
		delegation, found := principals[principal.EndpointID]
		if !found || delegation.AgentID != principal.AgentID || delegation.EndpointID != principal.EndpointID ||
			!sameNetwork(profile.Network, delegation.Network) || identity.Validate(delegation) != nil ||
			identity.CheckWindow(delegation, issued) != nil || !identity.AllowsEventClass(delegation, "public.channel") {
			return errors.New("public channel principal is not finalized or delegated")
		}
	}
	preimage, err := ProfileSigningBytes(profile)
	if err != nil {
		return err
	}
	if !ed25519.Verify(authority.IdentityPublicKey, preimage, profile.AuthoritySignature) {
		return errors.New("invalid public channel profile signature")
	}
	return nil
}

// VerifySuccessor requires one authority-signed adjacent profile transition.
// Equal-epoch alternatives are forks; arrival order and digest order choose
// neither.
func VerifySuccessor(current, next Profile, authority identity.Delegation,
	principals map[string]identity.Delegation, now time.Time) error {
	if err := VerifyProfile(current, authority, principals, now); err != nil {
		return err
	}
	if err := VerifyProfile(next, authority, principals, now); err != nil {
		return err
	}
	currentDigest, _ := current.Digest()
	if next.ChannelID != current.ChannelID || !sameNetwork(next.Network, current.Network) ||
		next.AuthorityAgentID != current.AuthorityAgentID || next.AuthorityEndpointID != current.AuthorityEndpointID ||
		next.Epoch != current.Epoch+1 || next.PreviousProfileDigest != currentDigest ||
		next.IssuedAtUnix < current.IssuedAtUnix {
		return errors.New("public channel profile is not an adjacent successor")
	}
	return nil
}

// ProfilesConflict reports two signed, non-identical branches occupying the
// same channel epoch and predecessor. It deliberately does not select either.
func ProfilesConflict(first, second Profile) (bool, error) {
	if err := validateProfile(first, true); err != nil {
		return false, err
	}
	if err := validateProfile(second, true); err != nil {
		return false, err
	}
	firstDigest, _ := first.Digest()
	secondDigest, _ := second.Digest()
	return first.ChannelID == second.ChannelID && first.Epoch == second.Epoch &&
		first.PreviousProfileDigest == second.PreviousProfileDigest && firstDigest != secondDigest, nil
}

func (p Profile) Digest() (string, error) {
	if err := validateProfile(p, true); err != nil {
		return "", err
	}
	preimage, err := ProfileSigningBytes(p)
	if err != nil {
		return "", err
	}
	b := bytes.NewBuffer(preimage)
	canon.Bytes(b, p.AuthoritySignature)
	return canon.Digest(b.Bytes()), nil
}

func (p Profile) role(agentID, endpointID string) (Principal, bool) {
	key := agentID + "\x00" + endpointID
	index := sort.Search(len(p.Principals), func(i int) bool {
		return p.Principals[i].AgentID+"\x00"+p.Principals[i].EndpointID >= key
	})
	if index < len(p.Principals) && p.Principals[index].AgentID == agentID && p.Principals[index].EndpointID == endpointID {
		return p.Principals[index], true
	}
	return Principal{}, false
}

func validateProfile(profile Profile, signed bool) error {
	if !channelPattern.MatchString(profile.ChannelID) || profile.Epoch == 0 ||
		!ids.Agent.MatchString(profile.AuthorityAgentID) || !ids.Endpoint.MatchString(profile.AuthorityEndpointID) ||
		len(profile.Principals) == 0 || len(profile.Principals) > MaxPrincipals || profile.IssuedAtUnix == 0 ||
		profile.ExpiresAtUnix <= profile.IssuedAtUnix ||
		profile.ExpiresAtUnix-profile.IssuedAtUnix > uint64(MaxProfileWindow/time.Second) {
		return errors.New("invalid public channel profile")
	}
	if err := appendNetwork(bytes.NewBuffer(nil), profile.Network); err != nil {
		return err
	}
	if profile.Epoch == 1 {
		if profile.PreviousProfileDigest != "" {
			return errors.New("first public channel profile has a predecessor")
		}
	} else if !canon.ValidDigest(profile.PreviousProfileDigest) {
		return errors.New("public channel profile needs its predecessor digest")
	}
	foundAuthority := false
	for index, principal := range profile.Principals {
		if !ids.Agent.MatchString(principal.AgentID) || !ids.Endpoint.MatchString(principal.EndpointID) ||
			!principal.Publisher && !principal.Moderator || index > 0 &&
			(profile.Principals[index-1].AgentID > principal.AgentID ||
				profile.Principals[index-1].AgentID == principal.AgentID && profile.Principals[index-1].EndpointID >= principal.EndpointID) {
			return errors.New("invalid or unordered public channel principal")
		}
		if principal.AgentID == profile.AuthorityAgentID && principal.EndpointID == profile.AuthorityEndpointID {
			foundAuthority = principal.Publisher && principal.Moderator
		}
	}
	if !foundAuthority {
		return errors.New("public channel authority must publish and moderate")
	}
	if signed && len(profile.AuthoritySignature) != ed25519.SignatureSize {
		return errors.New("invalid public channel profile signature")
	}
	return nil
}

func appendNetwork(b *bytes.Buffer, network *nativev1.NetworkDomain) error {
	if network == nil || network.NetworkId == "" || len(network.NetworkId) > 128 ||
		!canon.HashPattern.MatchString(network.GenesisRootHash) || !canon.HashPattern.MatchString(network.GenesisFileHash) {
		return errors.New("invalid public channel network")
	}
	root, rootErr := hex.DecodeString(network.GenesisRootHash)
	file, fileErr := hex.DecodeString(network.GenesisFileHash)
	if rootErr != nil || fileErr != nil || len(root) != 32 || len(file) != 32 || canon.IsZero(root) || canon.IsZero(file) {
		return errors.New("invalid public channel network")
	}
	canon.Text(b, network.NetworkId)
	canon.Bytes(b, root)
	canon.Bytes(b, file)
	return nil
}

func sameNetwork(first, second *nativev1.NetworkDomain) bool {
	return first != nil && second != nil && first.NetworkId == second.NetworkId &&
		first.GenesisRootHash == second.GenesisRootHash && first.GenesisFileHash == second.GenesisFileHash
}
