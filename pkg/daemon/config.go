// Package daemon assembles the Messenger into something that runs.
//
// It owns one state directory, one socket, and one schedule. Everything it
// composes already decides its own behaviour; what is decided here is what an
// operator must say out loud before the daemon will start.
package daemon

import (
	"bytes"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"time"

	"github.com/tosnetwork/tos-messenger/internal/canon"
	"github.com/tosnetwork/tos-messenger/pkg/dispatch"
	"github.com/tosnetwork/tos-messenger/pkg/eventlog"
	"github.com/tosnetwork/tos-messenger/pkg/firewall"
	"github.com/tosnetwork/tos-messenger/pkg/identity"
	"github.com/tosnetwork/tos-messenger/pkg/tosaddr"
	nativev1 "github.com/tosnetwork/tos-service-protocol/gen/tos/service/v1"
	"github.com/tosnetwork/tos-service-protocol/pkg/toschain"
)

// ConfigSchema is the strict schema of a daemon configuration.
const ConfigSchema = "tos.messaging.daemon-config.v2"

// TransportMode names how this installation carries messages.
type TransportMode string

const (
	// TransportNone carries nothing. Outbound events are queued durably and
	// never sealed, because no route has been chosen and sealing for a
	// transport that does not exist would spend message keys on nothing.
	TransportNone TransportMode = "none"
)

var transports = map[TransportMode]struct{}{TransportNone: {}}

// Defaults for the schedule. They are conservative on purpose: an installation
// with no transport spends its time doing maintenance, and maintenance that
// runs constantly is a busy loop with a filesystem attached.
const (
	DefaultSweepInterval       = 5 * time.Second
	DefaultMaintenanceInterval = time.Hour
	MinSweepInterval           = time.Second
	MinMaintenanceInterval     = time.Minute
)

// Config is what an operator supplies.
type Config struct {
	Schema string `json:"schema"`
	// StateDir holds the journal, the install salt, and nothing else. One
	// daemon owns it at a time.
	StateDir string `json:"state_dir"`
	// SocketPath is where the Agent runtime connects. It carries no approval
	// operations at all.
	SocketPath string `json:"socket_path"`
	// OwnerSocketPath is where the owner decides. The separation is the point:
	// the party that asks for an approval must not be able to grant it, and a
	// single socket with a uid check cannot tell the two apart.
	OwnerSocketPath string `json:"owner_socket_path"`

	NetworkID       string `json:"network_id"`
	GenesisRootHash string `json:"genesis_root_hash"`
	GenesisFileHash string `json:"genesis_file_hash"`

	// Registries are the registry contracts whose finalized state this
	// installation accepts. Each carries its code as well as its hash, because
	// an account address is recomputed from the code: pinning only the hash
	// would leave the installation unable to check that a resolver's answer
	// came from the account it must come from.
	Registries []RegistryConfig `json:"registries"`
	// MinFinalizedCheckpoint refuses state older than a point the operator
	// already knows about.
	MinFinalizedCheckpoint uint64 `json:"min_finalized_checkpoint,omitempty"`

	// ChainEndpoints are independent JSON-RPC authorities queried for a
	// strict-majority finalized view. NativeRegistryCodeHash selects the one
	// registry version whose deterministic account layout the live resolver
	// uses; Registries remains the complete set accepted by the verifier.
	ChainEndpoints              []string `json:"chain_endpoints"`
	ChainQuorum                 int      `json:"chain_quorum"`
	ChainQueryTimeoutSeconds    uint64   `json:"chain_query_timeout_seconds,omitempty"`
	ChainMaxResponseBytes       int64    `json:"chain_max_response_bytes,omitempty"`
	ChainReadinessMaxAgeSeconds uint64   `json:"chain_readiness_max_age_seconds,omitempty"`
	NativeRegistryCodeHash      string   `json:"native_registry_code_hash"`
	ChainCheckpointPath         string   `json:"chain_checkpoint_path"`
	DelegationPath              string   `json:"delegation_path"`

	// AgentID, EndpointID and DeviceID are who this installation speaks for.
	// Outbound events must say they came from here, so an installation that
	// does not know its own identity cannot send at all.
	AgentID    string `json:"agent_id"`
	EndpointID string `json:"endpoint_id"`
	DeviceID   string `json:"device_id"`

	// OwnerPublicKeyHex is the key the owner signs decisions with.
	//
	// It is required, and it is the boundary. The runtime and the owner
	// interface commonly run as the same Unix user, so peer credentials cannot
	// tell them apart: a runtime that asked for an approval could otherwise
	// connect to the owner's socket and grant its own request. The private
	// half must live somewhere the runtime cannot read -- a hardware token, a
	// separate user's keyring, another machine -- or this check is theatre.
	OwnerPublicKeyHex string `json:"owner_public_key"`

	// Firewall is what the Agent may reach unattended. Like the transport it
	// must be stated: an operator should have to write down what their Agent
	// may do because a stranger asked, and a permissive value nobody chose is
	// the one that would be copied forward.
	Firewall FirewallConfig `json:"firewall"`

	// Transport must be stated. There is no default, because a daemon that
	// quietly carried nothing would look like a working one.
	Transport TransportMode `json:"transport"`

	SweepIntervalSeconds       uint64 `json:"sweep_interval_seconds,omitempty"`
	MaintenanceIntervalSeconds uint64 `json:"maintenance_interval_seconds,omitempty"`
	RetentionSeconds           uint64 `json:"retention_seconds,omitempty"`
}

// Network returns the configured network tuple.
func (c Config) Network() *nativev1.NetworkDomain {
	return &nativev1.NetworkDomain{
		NetworkId:       c.NetworkID,
		GenesisRootHash: c.GenesisRootHash,
		GenesisFileHash: c.GenesisFileHash,
	}
}

// Identity returns who this installation speaks for.
func (c Config) Identity() dispatch.Identity {
	return dispatch.Identity{AgentID: c.AgentID, EndpointID: c.EndpointID, DeviceID: c.DeviceID}
}

// OwnerKey returns the configured owner public key.
func (c Config) OwnerKey() (ed25519.PublicKey, error) {
	raw, err := hex.DecodeString(c.OwnerPublicKeyHex)
	if err != nil || len(raw) != ed25519.PublicKeySize || canon.IsZero(raw) {
		return nil, errors.New("owner_public_key must be a 32-byte ed25519 key in hex")
	}
	return ed25519.PublicKey(raw), nil
}

// FirewallConfig is the pair of ceilings the context firewall applies.
type FirewallConfig struct {
	// UnattendedCeiling is the strongest effect an action derived from
	// received content may have without an owner decision.
	UnattendedCeiling string `json:"unattended_ceiling"`
	// OwnInitiativeCeiling is the same for an action no received content
	// contributed to.
	OwnInitiativeCeiling string `json:"own_initiative_ceiling"`
}

// FirewallPolicy returns the configured context-firewall policy.
func (c Config) FirewallPolicy() firewall.Policy {
	return firewall.Policy{
		UnattendedCeiling:    firewall.Effect(c.Firewall.UnattendedCeiling),
		OwnInitiativeCeiling: firewall.Effect(c.Firewall.OwnInitiativeCeiling),
	}
}

// RegistryConfig is one registry contract and everything needed to address
// objects under it.
type RegistryConfig struct {
	CodeHash string `json:"code_hash"`
	// CodeBOC is the contract code itself, base64 BOC. It must hash to
	// CodeHash, so a mismatched pair is a configuration error rather than a
	// quiet acceptance of whatever code was supplied.
	CodeBOC   string `json:"code_boc"`
	Workchain int32  `json:"workchain"`
}

// Chain returns the configured acceptance rules for finalized state, including
// the locator that recomputes account addresses.
func (c Config) Chain() (identity.ChainPolicy, error) {
	hashes := make([]string, 0, len(c.Registries))
	registries := make([]tosaddr.Registry, 0, len(c.Registries))
	for _, registry := range c.Registries {
		hashes = append(hashes, registry.CodeHash)
		registries = append(registries, tosaddr.Registry{
			CodeHash: registry.CodeHash, CodeBOC: registry.CodeBOC, Workchain: registry.Workchain,
		})
	}
	policy := identity.ChainPolicy{
		RegistryCodeHashes:     hashes,
		MinFinalizedCheckpoint: c.MinFinalizedCheckpoint,
	}
	// The policy is checked before the locator is built, so an operator with a
	// malformed registry list is told about the list rather than about a
	// derived failure further down.
	if err := policy.Validate(); err != nil && len(hashes) == 0 {
		return identity.ChainPolicy{}, err
	}
	locator, err := tosaddr.New(c.Network(), registries)
	if err != nil {
		return identity.ChainPolicy{}, err
	}
	policy.Locator = locator
	return policy, nil
}

// NativeRegistry returns the explicitly selected contract layout used for
// direct finalized Agent reads.
func (c Config) NativeRegistry() (RegistryConfig, error) {
	for _, registry := range c.Registries {
		if registry.CodeHash == c.NativeRegistryCodeHash {
			return registry, nil
		}
	}
	return RegistryConfig{}, errors.New("native_registry_code_hash must select a configured registry")
}

// ChainAdapter builds the bounded, strict-majority finalized-state client.
// Construction performs all endpoint and policy validation without issuing a
// network request, so config checking remains offline.
func (c Config) ChainAdapter() (*toschain.Adapter, error) {
	if c.ChainQueryTimeoutSeconds > 30 {
		return nil, errors.New("chain_query_timeout_seconds exceeds 30 seconds")
	}
	if c.ChainReadinessMaxAgeSeconds > 3600 {
		return nil, errors.New("chain_readiness_max_age_seconds exceeds one hour")
	}
	if c.ChainMaxResponseBytes < 0 || c.ChainMaxResponseBytes > 16<<20 {
		return nil, errors.New("chain_max_response_bytes exceeds 16 MiB")
	}
	return toschain.New(toschain.Config{
		Network:          c.NetworkID,
		Endpoints:        c.ChainEndpoints,
		Quorum:           c.ChainQuorum,
		QueryTimeout:     time.Duration(c.ChainQueryTimeoutSeconds) * time.Second,
		MaxResponseBytes: c.ChainMaxResponseBytes,
		ReadinessMaxAge:  time.Duration(c.ChainReadinessMaxAgeSeconds) * time.Second,
	})
}

// SweepInterval is how often queued events are attempted.
func (c Config) SweepInterval() time.Duration {
	if c.SweepIntervalSeconds == 0 {
		return DefaultSweepInterval
	}
	return time.Duration(c.SweepIntervalSeconds) * time.Second
}

// MaintenanceInterval is how often expiry and pruning run.
func (c Config) MaintenanceInterval() time.Duration {
	if c.MaintenanceIntervalSeconds == 0 {
		return DefaultMaintenanceInterval
	}
	return time.Duration(c.MaintenanceIntervalSeconds) * time.Second
}

// Retention is how long finished records are kept.
func (c Config) Retention() time.Duration {
	if c.RetentionSeconds == 0 {
		return eventlog.MinClaimRetention
	}
	return time.Duration(c.RetentionSeconds) * time.Second
}

// Validate enforces what must be true before anything starts.
func (c Config) Validate() error {
	if c.Schema != ConfigSchema {
		return errors.New("unsupported daemon configuration schema")
	}
	if !filepath.IsAbs(c.StateDir) || filepath.Clean(c.StateDir) != c.StateDir {
		return errors.New("state_dir must be an absolute, clean path")
	}
	if !filepath.IsAbs(c.SocketPath) || filepath.Clean(c.SocketPath) != c.SocketPath {
		return errors.New("socket_path must be an absolute, clean path")
	}
	if !filepath.IsAbs(c.OwnerSocketPath) || filepath.Clean(c.OwnerSocketPath) != c.OwnerSocketPath {
		return errors.New("owner_socket_path must be an absolute, clean path")
	}
	if c.OwnerSocketPath == c.SocketPath {
		return errors.New("the runtime and owner sockets must be different")
	}
	if filepath.Dir(c.SocketPath) == c.StateDir || filepath.Dir(c.OwnerSocketPath) == c.StateDir {
		// The state directory is owned through a lock file; a socket living in
		// it would make a stale socket look like contested ownership.
		return errors.New("socket_path must not live inside state_dir")
	}
	if c.NetworkID == "" || len(c.NetworkID) > 128 ||
		!canon.HashPattern.MatchString(c.GenesisRootHash) ||
		!canon.HashPattern.MatchString(c.GenesisFileHash) {
		return errors.New("invalid network domain")
	}
	chain, err := c.Chain()
	if err != nil {
		return err
	}
	if err := chain.Validate(); err != nil {
		return err
	}
	if _, err := c.NativeRegistry(); err != nil {
		return err
	}
	if _, err := c.ChainAdapter(); err != nil {
		return err
	}
	if !filepath.IsAbs(c.ChainCheckpointPath) || filepath.Clean(c.ChainCheckpointPath) != c.ChainCheckpointPath {
		return errors.New("chain_checkpoint_path must be an absolute, clean path")
	}
	if c.ChainCheckpointPath != filepath.Join(c.StateDir, "chain.checkpoint") {
		return errors.New("chain_checkpoint_path must be the daemon-owned state checkpoint")
	}
	if !filepath.IsAbs(c.DelegationPath) || filepath.Clean(c.DelegationPath) != c.DelegationPath {
		return errors.New("delegation_path must be an absolute, clean path")
	}
	if err := c.Identity().Validate(); err != nil {
		return err
	}
	if err := c.FirewallPolicy().Validate(); err != nil {
		return err
	}
	if _, err := c.OwnerKey(); err != nil {
		return err
	}
	if _, known := transports[c.Transport]; !known {
		return errors.New("transport must be stated explicitly")
	}
	if c.SweepInterval() < MinSweepInterval {
		return errors.New("sweep interval is below its floor")
	}
	if c.MaintenanceInterval() < MinMaintenanceInterval {
		return errors.New("maintenance interval is below its floor")
	}
	if c.Retention() < eventlog.MinClaimRetention {
		return errors.New("retention is shorter than the replay window it must cover")
	}
	return nil
}

// LoadConfig reads a configuration file.
func LoadConfig(path string) (Config, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return Config{}, errors.New("read daemon configuration")
	}
	return DecodeConfig(raw)
}

// DecodeConfig parses a configuration, refusing anything it does not
// understand rather than ignoring it. A misspelled key that is silently
// dropped is a setting an operator believes is in force.
func DecodeConfig(raw []byte) (Config, error) {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	var config Config
	if err := decoder.Decode(&config); err != nil {
		return Config{}, err
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return Config{}, errors.New("configuration has trailing content")
	}
	if err := config.Validate(); err != nil {
		return Config{}, err
	}
	return config, nil
}
