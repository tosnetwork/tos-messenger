// Package publicationops assembles the operator-owned resources used to
// publish public Messenger prekey generations. It deliberately accepts only
// public material and a narrow local signer socket; Endpoint private key bytes
// never cross this boundary.
package publicationops

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"io"
	"path/filepath"
	"strings"
	"time"

	"github.com/tosnetwork/tos-messenger/internal/securefile"
	"github.com/tosnetwork/tos-messenger/pkg/directory"
	"github.com/tosnetwork/tos-messenger/pkg/identity"
	"github.com/tosnetwork/tos-messenger/pkg/signerapi"
	nativev1 "github.com/tosnetwork/tos-service-protocol/gen/tos/service/v1"
	"github.com/tosnetwork/tosutils-go/adnl"
	"github.com/tosnetwork/tosutils-go/adnl/dht"
	"github.com/tosnetwork/tosutils-go/liteclient"
)

const (
	ConfigSchema      = "tos.messaging.publication-operator.v1"
	MaxConfigBytes    = 32 << 10
	maxGlobalConfig   = 1 << 20
	maxBootstrapNodes = 256
)

// Config names every operator-controlled resource required by the stock
// daemon's public-generation publisher. Identity and authority fields are not
// configurable here; Assemble derives them from the finalized delegation.
type Config struct {
	Schema                  string   `json:"schema"`
	HTTPSPublicationRoot    string   `json:"https_publication_root"`
	DHTGlobalConfigPath     string   `json:"dht_global_config_path"`
	DescriptorPolicyPath    string   `json:"descriptor_policy_path"`
	EndpointSignerSocket    string   `json:"endpoint_signer_socket"`
	SignerTimeoutSeconds    uint64   `json:"signer_timeout_seconds"`
	PublishIntervalSeconds  uint64   `json:"publish_interval_seconds"`
	HTTPSEndpoint           string   `json:"https_endpoint"`
	MessagingVersions       []uint32 `json:"messaging_versions"`
	A2AVersions             []string `json:"a2a_versions,omitempty"`
	MCPVersions             []string `json:"mcp_versions,omitempty"`
	MailboxRelaySetDigest   string   `json:"mailbox_relay_set_digest,omitempty"`
	AttachmentServiceDigest string   `json:"attachment_service_digest,omitempty"`
	MaximumEnvelopeBytes    uint32   `json:"maximum_envelope_bytes"`
}

// Load reads a strict, bounded operator configuration. Referenced resources
// are opened only by Assemble, after the daemon has verified live authority.
func Load(path string) (Config, error) {
	raw, err := securefile.ReadBoundedRegular(path, MaxConfigBytes)
	if err != nil {
		return Config{}, errors.New("read publication operator configuration: " + err.Error())
	}
	return Decode(raw)
}

// Decode rejects unknown fields, trailing JSON, relative paths, and resource
// combinations that cannot possibly form a valid publisher.
func Decode(raw []byte) (Config, error) {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	var config Config
	if err := decoder.Decode(&config); err != nil {
		return Config{}, err
	}
	if err := decoder.Decode(new(any)); !errors.Is(err, io.EOF) {
		return Config{}, errors.New("publication operator configuration has trailing content")
	}
	if err := config.Validate(); err != nil {
		return Config{}, err
	}
	return config, nil
}

func (c Config) Validate() error {
	if c.Schema != ConfigSchema {
		return errors.New("unsupported publication operator configuration schema")
	}
	for _, path := range []string{c.HTTPSPublicationRoot, c.DHTGlobalConfigPath, c.DescriptorPolicyPath, c.EndpointSignerSocket} {
		if !filepath.IsAbs(path) || filepath.Clean(path) != path {
			return errors.New("publication operator paths must be absolute and clean")
		}
	}
	if c.SignerTimeoutSeconds == 0 || c.SignerTimeoutSeconds > 60 {
		return errors.New("publication signer timeout is outside its bound")
	}
	if c.PublishIntervalSeconds < 60 || c.PublishIntervalSeconds > 3600 {
		return errors.New("publication interval is outside its bound")
	}
	// Use a structurally valid placeholder for fields that Assemble derives
	// from finalized authority, then reuse the protocol's single validator for
	// the operator-selected capability and route fields.
	descriptor := directory.Descriptor{
		Network: &nativev1.NetworkDomain{NetworkId: "check", GenesisRootHash: strings.Repeat("a", 64), GenesisFileHash: strings.Repeat("b", 64)},
		AgentID: "agent_" + strings.Repeat("1", 64), EndpointID: "mep_" + strings.Repeat("2", 64),
		DelegationDigest: digest("3"), SupportedMessagingVersions: c.MessagingVersions,
		SupportedA2AVersions: c.A2AVersions, SupportedMCPVersions: c.MCPVersions,
		HTTPSEndpoint: c.HTTPSEndpoint, PrekeyBundleDigest: digest("4"),
		MailboxRelaySetDigest: c.MailboxRelaySetDigest, InboxAdmissionPolicyDigest: digest("5"),
		AttachmentServiceDigest: c.AttachmentServiceDigest, MaximumEnvelopeBytes: c.MaximumEnvelopeBytes,
		IssuedAtUnix: 1, ExpiresAtUnix: 2,
	}
	if err := directory.ValidateDescriptor(descriptor, false); err != nil {
		return errors.New("invalid publication descriptor template: " + err.Error())
	}
	return nil
}

// Runtime owns the network resources behind one assembled publisher.
type Runtime struct {
	Publisher *directory.GenerationPublisher
	client    *dht.Client
}

func (r *Runtime) Close() error {
	if r != nil && r.client != nil {
		r.client.Close()
	}
	return nil
}

// Assemble binds operator-selected public resources to the exact finalized
// Endpoint delegation. No identity, network, ADNL, admission-policy, or
// signing-key field can be substituted by the operator configuration.
func Assemble(config Config, delegation identity.Delegation) (*Runtime, error) {
	if err := config.Validate(); err != nil {
		return nil, err
	}
	policyRaw, err := securefile.ReadBoundedRegular(config.DescriptorPolicyPath, directory.MaxDescriptorPolicyWireBytes)
	if err != nil {
		return nil, errors.New("read publication descriptor policy: " + err.Error())
	}
	policy, err := directory.DecodeDescriptorPolicyJSON(policyRaw)
	if err != nil {
		return nil, errors.New("decode publication descriptor policy: " + err.Error())
	}
	policyDigest, err := policy.Digest()
	if err != nil || policyDigest != delegation.ContactDescriptorPolicyDigest {
		return nil, errors.New("publication descriptor policy does not match finalized delegation")
	}
	descriptor, err := descriptorFor(config, delegation)
	if err != nil {
		return nil, err
	}
	if config.PublishIntervalSeconds > policy.MaxLifetimeSeconds/2 {
		return nil, errors.New("publication interval cannot cover the descriptor renewal window")
	}
	if err := policy.Permits(descriptor); err != nil {
		return nil, errors.New("publication descriptor template exceeds committed policy: " + err.Error())
	}
	objects, err := directory.OpenHTTPSPublisher(config.HTTPSPublicationRoot)
	if err != nil {
		return nil, errors.New("open HTTPS publication root: " + err.Error())
	}
	signer, err := signerapi.NewClient(config.EndpointSignerSocket, delegation.IdentityPublicKey,
		time.Duration(config.SignerTimeoutSeconds)*time.Second)
	if err != nil {
		return nil, err
	}
	client, err := openDHT(config.DHTGlobalConfigPath)
	if err != nil {
		return nil, err
	}
	publisher := &directory.GenerationPublisher{
		Objects: objects, Locators: directory.TOSDHT{Client: client}, Signer: signer, Delegation: delegation,
		Policy: policy, PublishInterval: time.Duration(config.PublishIntervalSeconds) * time.Second,
		Descriptor: descriptor,
	}
	if err := publisher.Validate(); err != nil {
		client.Close()
		return nil, errors.New("validate generation publisher: " + err.Error())
	}
	return &Runtime{Publisher: publisher, client: client}, nil
}

func descriptorFor(config Config, delegation identity.Delegation) (directory.Descriptor, error) {
	delegationDigest, err := identity.Digest(delegation)
	if err != nil {
		return directory.Descriptor{}, err
	}
	for _, version := range config.MessagingVersions {
		if !identity.AllowsProtocolVersion(delegation, version) {
			return directory.Descriptor{}, errors.New("publication advertises an undelegated messaging version")
		}
	}
	descriptor := directory.Descriptor{
		Network: delegation.Network, AgentID: delegation.AgentID, EndpointID: delegation.EndpointID,
		DelegationDigest: delegationDigest, SupportedMessagingVersions: append([]uint32(nil), config.MessagingVersions...),
		SupportedA2AVersions: append([]string(nil), config.A2AVersions...),
		SupportedMCPVersions: append([]string(nil), config.MCPVersions...), ADNLID: delegation.ADNLID,
		HTTPSEndpoint: config.HTTPSEndpoint, PrekeyBundleDigest: digest("4"),
		MailboxRelaySetDigest:      config.MailboxRelaySetDigest,
		InboxAdmissionPolicyDigest: delegation.InboxAdmissionPolicyDigest,
		AttachmentServiceDigest:    config.AttachmentServiceDigest, MaximumEnvelopeBytes: config.MaximumEnvelopeBytes,
		IssuedAtUnix: delegation.NotBeforeUnix, ExpiresAtUnix: delegation.NotBeforeUnix + 1,
	}
	if err := directory.ValidateDescriptor(descriptor, false); err != nil {
		return directory.Descriptor{}, errors.New("invalid publication descriptor template: " + err.Error())
	}
	return descriptor, nil
}

func openDHT(path string) (*dht.Client, error) {
	raw, err := securefile.ReadBoundedRegular(path, maxGlobalConfig)
	if err != nil {
		return nil, errors.New("read publication DHT global configuration: " + err.Error())
	}
	var global liteclient.GlobalConfig
	if err := json.Unmarshal(raw, &global); err != nil {
		return nil, errors.New("decode publication DHT global configuration")
	}
	nodes, err := dht.BootstrapNodesFromConfig(&global)
	if err != nil || len(nodes) == 0 || len(nodes) > maxBootstrapNodes {
		return nil, errors.New("publication DHT global configuration has an invalid bootstrap set")
	}
	_, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, errors.New("generate publication DHT client identity")
	}
	gateway := adnl.NewGateway(private)
	if err := gateway.StartClient(); err != nil {
		return nil, errors.New("start publication DHT client")
	}
	client, err := dht.NewClientFromConfig(gateway, &global)
	if err != nil {
		_ = gateway.Close()
		return nil, errors.New("construct publication DHT client")
	}
	if client.RoutingTableStats().ActiveNodes == 0 {
		client.Close()
		return nil, errors.New("publication DHT configuration has no verified bootstrap node")
	}
	return client, nil
}

func digest(character string) string { return "sha256:" + strings.Repeat(character, 64) }
