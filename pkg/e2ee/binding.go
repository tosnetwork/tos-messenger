package e2ee

import (
	"bytes"
	"errors"

	"github.com/tosnetwork/tos-messenger/internal/canon"
	"github.com/tosnetwork/tos-messenger/internal/ids"
	nativev1 "github.com/tosnetwork/tos-service-protocol/gen/tos/service/v1"
)

// Binding names exactly where one ciphertext belongs.
//
// It is passed to Seal and Open as associated data, so a ciphertext that is
// lifted out of its conversation, replayed in the other direction, or
// presented under a different suite fails to open rather than decrypting into
// the wrong context. None of this is confidentiality: it is the reason a
// message means what its position says it means.
type Binding struct {
	Network             *nativev1.NetworkDomain
	AlgorithmID         string
	ConversationID      string
	SenderAgentID       string
	SenderEndpointID    string
	SenderDeviceID      string
	RecipientAgentID    string
	RecipientEndpointID string
	RecipientDeviceID   string
}

// Bytes returns the canonical associated data.
func (b Binding) Bytes() ([]byte, error) {
	if err := b.Validate(); err != nil {
		return nil, err
	}
	buffer := bytes.NewBufferString(canon.DomainE2EEBinding)
	canon.Text(buffer, b.Network.NetworkId)
	if err := canon.Hash32(buffer, b.Network.GenesisRootHash); err != nil {
		return nil, err
	}
	if err := canon.Hash32(buffer, b.Network.GenesisFileHash); err != nil {
		return nil, err
	}
	canon.Text(buffer, b.AlgorithmID)
	canon.Text(buffer, b.ConversationID)
	canon.Text(buffer, b.SenderAgentID)
	canon.Text(buffer, b.SenderEndpointID)
	canon.Text(buffer, b.SenderDeviceID)
	canon.Text(buffer, b.RecipientAgentID)
	canon.Text(buffer, b.RecipientEndpointID)
	canon.Text(buffer, b.RecipientDeviceID)
	return buffer.Bytes(), nil
}

// Reply returns the binding for a message travelling the other way. Direction
// is part of the binding, so the two are never interchangeable.
func (b Binding) Reply() Binding {
	return Binding{
		Network:             b.Network,
		AlgorithmID:         b.AlgorithmID,
		ConversationID:      b.ConversationID,
		SenderAgentID:       b.RecipientAgentID,
		SenderEndpointID:    b.RecipientEndpointID,
		SenderDeviceID:      b.RecipientDeviceID,
		RecipientAgentID:    b.SenderAgentID,
		RecipientEndpointID: b.SenderEndpointID,
		RecipientDeviceID:   b.SenderDeviceID,
	}
}

// Validate enforces every structural rule.
func (b Binding) Validate() error {
	if b.Network == nil || b.Network.NetworkId == "" || len(b.Network.NetworkId) > 128 ||
		!canon.HashPattern.MatchString(b.Network.GenesisRootHash) ||
		!canon.HashPattern.MatchString(b.Network.GenesisFileHash) {
		return errors.New("invalid binding network domain")
	}
	if err := ValidateAlgorithmID(b.AlgorithmID); err != nil {
		return err
	}
	if !ids.Conversation.MatchString(b.ConversationID) {
		return errors.New("invalid binding conversation identifier")
	}
	if !ids.Agent.MatchString(b.SenderAgentID) || !ids.Endpoint.MatchString(b.SenderEndpointID) ||
		!ids.Device.MatchString(b.SenderDeviceID) {
		return errors.New("invalid binding sender identity")
	}
	if !ids.Agent.MatchString(b.RecipientAgentID) || !ids.Endpoint.MatchString(b.RecipientEndpointID) ||
		!ids.Device.MatchString(b.RecipientDeviceID) {
		return errors.New("invalid binding recipient identity")
	}
	if b.SenderDeviceID == b.RecipientDeviceID {
		return errors.New("a device cannot hold a session with itself")
	}
	return nil
}
