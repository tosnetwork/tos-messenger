package e2ee

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"

	"github.com/tosnetwork/tos-messenger/internal/canon"
	nativev1 "github.com/tosnetwork/tos-service-protocol/gen/tos/service/v1"
)

const (
	// FirstContactSchema identifies the public, transportable evidence needed
	// by a recipient device to accept an asynchronous first-contact session.
	FirstContactSchema = "tos.messaging.e2ee.first-contact.v1"
	// MaxInitialMessageBytes bounds suite-specific asynchronous handshake data.
	MaxInitialMessageBytes = 4 << 10
)

// FirstContact contains no secret material. The recipient independently
// verifies SenderBundle under finalized Endpoint authority and selects the
// exact local private prekey named by RecipientBundleDigest before accepting
// the session. Binding is the authority-bearing context used as AEAD AAD.
type FirstContact struct {
	Binding               Binding
	SenderBundle          Bundle
	RecipientBundleDigest string
	Initial               []byte
}

type wireFirstContact struct {
	Schema                string `json:"schema"`
	NetworkID             string `json:"network_id"`
	GenesisRootHash       string `json:"genesis_root_hash"`
	GenesisFileHash       string `json:"genesis_file_hash"`
	AlgorithmID           string `json:"algorithm_id"`
	ConversationID        string `json:"conversation_id"`
	SenderAgentID         string `json:"sender_agent_id"`
	SenderEndpointID      string `json:"sender_messaging_endpoint_id"`
	SenderDeviceID        string `json:"sender_device_id"`
	RecipientAgentID      string `json:"recipient_agent_id"`
	RecipientEndpointID   string `json:"recipient_messaging_endpoint_id"`
	RecipientDeviceID     string `json:"recipient_device_id"`
	SenderBundleBase64    string `json:"sender_bundle_base64"`
	SenderBundleDigest    string `json:"sender_bundle_digest"`
	RecipientBundleDigest string `json:"recipient_bundle_digest"`
	InitialBase64         string `json:"initial_base64"`
	InitialDigest         string `json:"initial_digest"`
}

// EncodeFirstContactJSON returns the strict public bootstrap wire value.
func EncodeFirstContactJSON(value FirstContact) ([]byte, error) {
	if err := ValidateFirstContact(value); err != nil {
		return nil, err
	}
	bundleJSON, err := EncodeBundleJSON(value.SenderBundle)
	if err != nil {
		return nil, err
	}
	bundleDigest, err := BundleDigest(value.SenderBundle)
	if err != nil {
		return nil, err
	}
	b := value.Binding
	return json.Marshal(wireFirstContact{
		Schema: FirstContactSchema, NetworkID: b.Network.NetworkId,
		GenesisRootHash: b.Network.GenesisRootHash, GenesisFileHash: b.Network.GenesisFileHash,
		AlgorithmID: b.AlgorithmID, ConversationID: b.ConversationID,
		SenderAgentID: b.SenderAgentID, SenderEndpointID: b.SenderEndpointID,
		SenderDeviceID: b.SenderDeviceID, RecipientAgentID: b.RecipientAgentID,
		RecipientEndpointID: b.RecipientEndpointID, RecipientDeviceID: b.RecipientDeviceID,
		SenderBundleBase64: base64.StdEncoding.EncodeToString(bundleJSON), SenderBundleDigest: bundleDigest,
		RecipientBundleDigest: value.RecipientBundleDigest,
		InitialBase64:         base64.StdEncoding.EncodeToString(value.Initial), InitialDigest: canon.Digest(value.Initial),
	})
}

// DecodeFirstContactJSON rejects ambiguous encodings and revalidates every
// digest and identity relationship before returning bootstrap evidence.
func DecodeFirstContactJSON(raw []byte) (FirstContact, error) {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	var wire wireFirstContact
	if err := decoder.Decode(&wire); err != nil {
		return FirstContact{}, errors.New("invalid first-contact bootstrap")
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return FirstContact{}, errors.New("first-contact bootstrap has trailing content")
	}
	if wire.Schema != FirstContactSchema {
		return FirstContact{}, errors.New("unsupported first-contact bootstrap schema")
	}
	bundleJSON, err := base64.StdEncoding.Strict().DecodeString(wire.SenderBundleBase64)
	if err != nil {
		return FirstContact{}, errors.New("invalid first-contact sender bundle")
	}
	bundle, err := DecodeBundleJSON(bundleJSON)
	if err != nil {
		return FirstContact{}, errors.New("invalid first-contact sender bundle")
	}
	bundleDigest, err := BundleDigest(bundle)
	if err != nil || bundleDigest != wire.SenderBundleDigest {
		return FirstContact{}, errors.New("first-contact sender bundle digest mismatch")
	}
	initial, err := base64.StdEncoding.Strict().DecodeString(wire.InitialBase64)
	if err != nil || canon.Digest(initial) != wire.InitialDigest {
		return FirstContact{}, errors.New("first-contact initial message digest mismatch")
	}
	value := FirstContact{Binding: Binding{
		Network: &nativev1.NetworkDomain{NetworkId: wire.NetworkID, GenesisRootHash: wire.GenesisRootHash,
			GenesisFileHash: wire.GenesisFileHash}, AlgorithmID: wire.AlgorithmID,
		ConversationID: wire.ConversationID, SenderAgentID: wire.SenderAgentID,
		SenderEndpointID: wire.SenderEndpointID, SenderDeviceID: wire.SenderDeviceID,
		RecipientAgentID: wire.RecipientAgentID, RecipientEndpointID: wire.RecipientEndpointID,
		RecipientDeviceID: wire.RecipientDeviceID,
	}, SenderBundle: bundle, RecipientBundleDigest: wire.RecipientBundleDigest, Initial: initial}
	if err := ValidateFirstContact(value); err != nil {
		return FirstContact{}, err
	}
	return value, nil
}

// ValidateFirstContact binds the independently signed sender prekey to the
// asserted sender and the exact directional session context.
func ValidateFirstContact(value FirstContact) error {
	if _, err := value.Binding.Bytes(); err != nil {
		return err
	}
	if err := ValidateBundle(value.SenderBundle, true); err != nil {
		return err
	}
	b := value.Binding
	bundle := value.SenderBundle
	if bundle.Network.NetworkId != b.Network.NetworkId ||
		bundle.Network.GenesisRootHash != b.Network.GenesisRootHash ||
		bundle.Network.GenesisFileHash != b.Network.GenesisFileHash ||
		bundle.AgentID != b.SenderAgentID || bundle.EndpointID != b.SenderEndpointID ||
		bundle.DeviceID != b.SenderDeviceID || bundle.AlgorithmID != b.AlgorithmID {
		return errors.New("first-contact sender bundle does not match its binding")
	}
	if !canon.ValidDigest(value.RecipientBundleDigest) {
		return errors.New("invalid first-contact recipient bundle digest")
	}
	if len(value.Initial) == 0 || len(value.Initial) > MaxInitialMessageBytes {
		return errors.New("invalid first-contact initial message")
	}
	return nil
}
