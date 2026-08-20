package group

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"

	"github.com/tosnetwork/tos-messenger/internal/canon"
	"github.com/tosnetwork/tos-messenger/internal/ids"
	nativev1 "github.com/tosnetwork/tos-service-protocol/gen/tos/service/v1"
)

const (
	// MLSBasicCredentialSchema fixes the application-defined opaque identity
	// bytes carried inside the interoperable RFC 9420 BasicCredential.
	MLSBasicCredentialSchema = "tos.messaging.mls-basic-credential.v1"
	// MLSGroupIDSchema fixes the derivation of the opaque MLS group_id vector.
	MLSGroupIDSchema = "tos.messaging.mls-group-id.v1"
	// MLSGroupIDBytes is a SHA-256 output, short enough for every MLS codec and
	// collision-resistant without exposing the textual room identifier.
	MLSGroupIDBytes = sha256.Size
)

// BasicCredentialIdentity returns the exact bytes placed in the MLS
// BasicCredential identity field. This is an application identity binding,
// not authority: callers must still verify DeviceCredential against finalized
// Endpoint and current device-set state before admitting its KeyPackage.
func BasicCredentialIdentity(c DeviceCredential) ([]byte, error) {
	if err := validateCredential(c, false); err != nil {
		return nil, err
	}
	b := bytes.NewBufferString(canon.DomainMLSBasicCredential)
	canon.Text(b, MLSBasicCredentialSchema)
	if err := appendMLSNetwork(b, c.Network); err != nil {
		return nil, err
	}
	canon.Text(b, c.AgentID)
	canon.Text(b, c.EndpointID)
	canon.Text(b, c.DeviceID)
	canon.Text(b, c.DeviceSetDigest)
	canon.Bytes(b, c.LeafSignaturePublicKey)
	canon.Uint32(b, uint32(MLSCipherSuite))
	return b.Bytes(), nil
}

// MLSGroupID derives the exact opaque group_id from the TOS network and room.
// The genesis hashes enter as raw bytes, so their JSON/display encoding cannot
// create a second identity for the same network.
func MLSGroupID(network *nativev1.NetworkDomain, roomID string) ([]byte, error) {
	b, err := MLSGroupIDCanonicalBytes(network, roomID)
	if err != nil {
		return nil, err
	}
	sum := sha256.Sum256(b)
	return append([]byte(nil), sum[:]...), nil
}

// MLSGroupIDCanonicalBytes returns the preimage consumed by MLSGroupID for
// cross-implementation vectors.
func MLSGroupIDCanonicalBytes(network *nativev1.NetworkDomain, roomID string) ([]byte, error) {
	if !ids.Room.MatchString(roomID) {
		return nil, errors.New("invalid MLS room identifier")
	}
	b := bytes.NewBufferString(canon.DomainMLSGroupID)
	canon.Text(b, MLSGroupIDSchema)
	if err := appendMLSNetwork(b, network); err != nil {
		return nil, err
	}
	canon.Text(b, roomID)
	return b.Bytes(), nil
}

func appendMLSNetwork(b *bytes.Buffer, network *nativev1.NetworkDomain) error {
	if b == nil || network == nil || network.NetworkId == "" || len(network.NetworkId) > 128 ||
		!canon.HashPattern.MatchString(network.GenesisRootHash) ||
		!canon.HashPattern.MatchString(network.GenesisFileHash) {
		return errors.New("invalid MLS network")
	}
	root, rootErr := hex.DecodeString(network.GenesisRootHash)
	file, fileErr := hex.DecodeString(network.GenesisFileHash)
	if rootErr != nil || fileErr != nil || len(root) != sha256.Size || len(file) != sha256.Size {
		return errors.New("invalid MLS genesis hashes")
	}
	canon.Text(b, network.NetworkId)
	canon.Bytes(b, root)
	canon.Bytes(b, file)
	return nil
}
