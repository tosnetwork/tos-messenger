package publicationops

import (
	"crypto/ed25519"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/tosnetwork/tos-messenger/pkg/directory"
	"github.com/tosnetwork/tos-messenger/pkg/identity"
	nativev1 "github.com/tosnetwork/tos-service-protocol/gen/tos/service/v1"
)

func validConfig() Config {
	return Config{
		Schema: ConfigSchema, HTTPSPublicationRoot: "/srv/messenger-public",
		DHTGlobalConfigPath: "/etc/tos/global.json", DescriptorPolicyPath: "/etc/tos/policy.json",
		EndpointSignerSocket: "/run/tos/endpoint-signer.sock", SignerTimeoutSeconds: 10,
		PublishIntervalSeconds: 300, HTTPSEndpoint: "https://agent.example/messaging",
		MessagingVersions: []uint32{1}, A2AVersions: []string{"1.0"}, MCPVersions: []string{"2025-06-18"},
		MaximumEnvelopeBytes: 64 << 10,
	}
}

func TestDecodeIsStrict(t *testing.T) {
	raw, err := json.Marshal(validConfig())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Decode(raw); err != nil {
		t.Fatalf("valid operator configuration: %v", err)
	}
	cases := map[string][]byte{
		"unknown":  append(raw[:len(raw)-1], []byte(`,"endpoint_private_key":"secret"}`)...),
		"trailing": append(append([]byte(nil), raw...), []byte(`{}`)...),
		"schema":   []byte(strings.Replace(string(raw), ConfigSchema, "tos.messaging.publication-operator.v2", 1)),
		"relative": []byte(strings.Replace(string(raw), "/run/tos/endpoint-signer.sock", "endpoint-signer.sock", 1)),
	}
	for name, candidate := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := Decode(candidate); err == nil {
				t.Fatal("unsafe operator configuration was accepted")
			}
		})
	}
}

func TestConfigRefusesAmbiguousDescriptorCapabilities(t *testing.T) {
	for name, mutate := range map[string]func(*Config){
		"unsorted messaging": func(c *Config) { c.MessagingVersions = []uint32{2, 1} },
		"duplicate adapter":  func(c *Config) { c.A2AVersions = []string{"1.0", "1.0"} },
		"plaintext endpoint": func(c *Config) { c.HTTPSEndpoint = "http://agent.example/messaging" },
		"bad relay digest":   func(c *Config) { c.MailboxRelaySetDigest = "sha256:no" },
		"oversized envelope": func(c *Config) { c.MaximumEnvelopeBytes = directory.MaxEnvelopeBytes + 1 },
	} {
		t.Run(name, func(t *testing.T) {
			config := validConfig()
			mutate(&config)
			if err := config.Validate(); err == nil {
				t.Fatal("ambiguous descriptor capability was accepted")
			}
		})
	}
}

func TestDescriptorTemplateDerivesAuthorityFromDelegation(t *testing.T) {
	config := validConfig()
	delegation := validDelegation(t)
	descriptor, err := descriptorFor(config, delegation)
	if err != nil {
		t.Fatal(err)
	}
	wantDigest, err := identity.Digest(delegation)
	if err != nil {
		t.Fatal(err)
	}
	if descriptor.AgentID != delegation.AgentID || descriptor.EndpointID != delegation.EndpointID ||
		descriptor.DelegationDigest != wantDigest || descriptor.ADNLID != delegation.ADNLID ||
		descriptor.InboxAdmissionPolicyDigest != delegation.InboxAdmissionPolicyDigest ||
		string(descriptor.Network.GenesisRootHash) != delegation.Network.GenesisRootHash {
		t.Fatal("descriptor authority was not derived from the finalized delegation")
	}
	config.MessagingVersions = []uint32{2}
	if _, err := descriptorFor(config, delegation); err == nil {
		t.Fatal("undelegated messaging version was accepted")
	}
}

func TestAssembleRefusesAuthorityMismatchBeforeExternalMutation(t *testing.T) {
	temporary := t.TempDir()
	policyPath := filepath.Join(temporary, "policy.json")
	policy := directory.DescriptorPolicy{MaxEnvelopeBytes: 32 << 10, MaxLifetimeSeconds: 3600, AllowHTTPSEndpoint: true}
	raw, err := directory.EncodeDescriptorPolicyJSON(policy)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(policyPath, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	config := validConfig()
	config.DescriptorPolicyPath = policyPath
	config.HTTPSPublicationRoot = filepath.Join(temporary, "must-not-exist")
	config.DHTGlobalConfigPath = filepath.Join(temporary, "unopened-dht.json")
	config.EndpointSignerSocket = filepath.Join(temporary, "unopened-signer.sock")
	if _, err := Assemble(config, validDelegation(t)); err == nil || !strings.Contains(err.Error(), "does not match finalized delegation") {
		t.Fatalf("expected authority mismatch, got %v", err)
	}
	if _, err := os.Lstat(config.HTTPSPublicationRoot); !os.IsNotExist(err) {
		t.Fatal("authority mismatch mutated the HTTPS publication root")
	}
}

func validDelegation(t *testing.T) identity.Delegation {
	t.Helper()
	public := ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize)).Public().(ed25519.PublicKey)
	network := &nativev1.NetworkDomain{NetworkId: "tos-test", GenesisRootHash: strings.Repeat("a", 64), GenesisFileHash: strings.Repeat("b", 64)}
	agentID := "agent_" + strings.Repeat("1", 64)
	endpointID, err := identity.DeriveEndpointID(network, agentID, public)
	if err != nil {
		t.Fatal(err)
	}
	policy := directory.DescriptorPolicy{MaxEnvelopeBytes: 64 << 10, MaxLifetimeSeconds: 3600, AllowHTTPSEndpoint: true}
	policyDigest, err := policy.Digest()
	if err != nil {
		t.Fatal(err)
	}
	return identity.Delegation{
		Network: network, AgentID: agentID, EndpointID: endpointID,
		IdentityPublicKey: public, ADNLID: "adnl:" + strings.Repeat("3", 64), AllowedProtocolVersions: []uint32{1},
		AllowedOutboundEventClasses: []string{"message"}, NotBeforeUnix: 1, ExpiresAtUnix: 3601,
		MaximumSessionLifetimeSeconds: 60, ContactDescriptorPolicyDigest: policyDigest,
		InboxAdmissionPolicyDigest: digest("5"),
	}
}
