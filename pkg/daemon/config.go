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
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/tosnetwork/tos-messenger/internal/canon"
	"github.com/tosnetwork/tos-messenger/internal/ids"
	"github.com/tosnetwork/tos-messenger/internal/securefile"
	"github.com/tosnetwork/tos-messenger/pkg/admission"
	"github.com/tosnetwork/tos-messenger/pkg/attachmentapi"
	"github.com/tosnetwork/tos-messenger/pkg/attachments"
	"github.com/tosnetwork/tos-messenger/pkg/dispatch"
	"github.com/tosnetwork/tos-messenger/pkg/e2ee"
	"github.com/tosnetwork/tos-messenger/pkg/envelope"
	"github.com/tosnetwork/tos-messenger/pkg/eventlog"
	"github.com/tosnetwork/tos-messenger/pkg/firewall"
	"github.com/tosnetwork/tos-messenger/pkg/identity"
	"github.com/tosnetwork/tos-messenger/pkg/tosaddr"
	nativev1 "github.com/tosnetwork/tos-service-protocol/gen/tos/service/v1"
	"github.com/tosnetwork/tos-service-protocol/pkg/nativeclient"
	"github.com/tosnetwork/tos-service-protocol/pkg/toschain"
)

// ConfigSchema is the strict schema of a daemon configuration.
const ConfigSchema = "tos.messaging.daemon-config.v10"

// PublicationMode names the route-independent public material maintained by
// this installation. It does not select an HTTPS, DHT, or message transport.
type PublicationMode string

const (
	PublicationNone    PublicationMode = "none"
	PublicationPrekeys PublicationMode = "prekeys"

	MinPrekeyGenerationLifetime = time.Minute
	MaxPrekeyPlannerInterval    = time.Hour
)

// TransportMode names how this installation carries messages.
type TransportMode string

const (
	// TransportNone carries nothing. Outbound events are queued durably and
	// never sealed, because no route has been chosen and sealing for a
	// transport that does not exist would spend message keys on nothing.
	TransportNone TransportMode = "none"
	// TransportHTTPSBootstrap is the descriptor-bound HTTPS fallback. It is
	// useful for real-network bootstrap but is not an M0-R route decision.
	TransportHTTPSBootstrap TransportMode = "https-bootstrap"
)

var transports = map[TransportMode]struct{}{TransportNone: {}, TransportHTTPSBootstrap: {}}

// DiscoveryMode names whether this installation refreshes provisioned peers.
type DiscoveryMode string

const (
	DiscoveryNone        DiscoveryMode = "none"
	DiscoveryTOSDHTHTTPS DiscoveryMode = "tos-dht-https"
)

const (
	DefaultDirectoryRefreshInterval = 5 * time.Minute
	DefaultDirectoryRefreshLead     = 5 * time.Minute
	MinDirectoryRefreshInterval     = 30 * time.Second
	MaxDirectoryRefreshInterval     = 24 * time.Hour
)

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
	// EscrowCodeHash and EscrowCheckpointPath explicitly enable finalized
	// Accepted Quote verification for the runtime API. They are separate from
	// Registry state because the two contract types and rollback high-waters
	// are independent authority domains.
	EscrowCodeHash       string `json:"escrow_code_hash,omitempty"`
	EscrowCheckpointPath string `json:"escrow_checkpoint_path,omitempty"`
	DelegationPath       string `json:"delegation_path"`

	// Discovery is stated separately from Transport: refreshing verified
	// identity and prekeys is route-neutral and does not authorize carrying a
	// message over the same network path.
	Discovery DiscoveryConfig `json:"discovery"`

	// ContactDNS optionally enables human .tos recipient input at the runtime
	// socket. It is only a canonicalization transport: the returned AgentID
	// must still pass Discovery's delegation, descriptor, endpoint, device and
	// prekey verification chain.
	ContactDNS *ContactDNSConfig `json:"contact_dns,omitempty"`

	// Publication must be stated separately from Discovery and Transport. In
	// prekeys mode the daemon plans public generations and accepts public,
	// device-signed contributions; it never creates or stores device secrets.
	Publication PublicationConfig `json:"publication"`

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

	// EconomicAuthorities pins the independent keys allowed to issue OpenFox
	// writer fences. Empty disables autonomous economic messaging; the ordinary
	// human messaging API remains available.
	EconomicAuthorities []EconomicAuthorityConfig `json:"economic_authorities,omitempty"`

	// Admission is the recipient's explicit first-contact policy. Its public
	// document must hash to the digest in the finalized local delegation; the
	// private rosters remain local and never enter that digest.
	Admission AdmissionConfig `json:"admission"`

	// Firewall is what the Agent may reach unattended. Like the transport it
	// must be stated: an operator should have to write down what their Agent
	// may do because a stranger asked, and a permissive value nobody chose is
	// the one that would be copied forward.
	Firewall FirewallConfig `json:"firewall"`

	// Transport must be stated. There is no default, because a daemon that
	// quietly carried nothing would look like a working one.
	Transport TransportMode `json:"transport"`

	// AgentPacketReceiverSocket enables the daemon-owned typed Agent Packet
	// adapter. Packets are verified and durably claimed here, then handed to an
	// independently verifying OpenFox provider over this private Unix socket;
	// they are never exposed through the general runtime inbox.
	AgentPacketReceiverSocket         string `json:"agent_packet_receiver_socket,omitempty"`
	AgentPacketReceiverTimeoutSeconds uint64 `json:"agent_packet_receiver_timeout_seconds,omitempty"`

	// A2AReceiverSocket and MCPReceiverSocket are separate fail-closed local
	// consumption boundaries. Foreign protocol events never fall through to
	// the general model inbox, including when these receivers are absent.
	A2AReceiverSocket              string `json:"a2a_receiver_socket,omitempty"`
	MCPReceiverSocket              string `json:"mcp_receiver_socket,omitempty"`
	ProtocolReceiverTimeoutSeconds uint64 `json:"protocol_receiver_timeout_seconds,omitempty"`

	// AttachmentAdmission enables daemon-owned fetch, AEAD opening and pinned
	// scanning. When absent, artifact.encrypted stays reserved and no secret
	// Reference or capability key is released through the runtime socket.
	AttachmentAdmission *AttachmentAdmissionConfig `json:"attachment_admission,omitempty"`

	SweepIntervalSeconds       uint64 `json:"sweep_interval_seconds,omitempty"`
	MaintenanceIntervalSeconds uint64 `json:"maintenance_interval_seconds,omitempty"`
	RetentionSeconds           uint64 `json:"retention_seconds,omitempty"`
}

type EconomicAuthorityConfig struct {
	AuthorityID  string `json:"authority_id"`
	PublicKeyHex string `json:"public_key_hex"`
}

func (c Config) EconomicAuthorityKeys() (map[string]ed25519.PublicKey, error) {
	keys := make(map[string]ed25519.PublicKey, len(c.EconomicAuthorities))
	last := ""
	for _, authority := range c.EconomicAuthorities {
		raw, err := hex.DecodeString(authority.PublicKeyHex)
		if authority.AuthorityID == "" || len(authority.AuthorityID) > 256 || authority.AuthorityID <= last ||
			err != nil || len(raw) != ed25519.PublicKeySize || canon.IsZero(raw) {
			return nil, errors.New("economic_authorities must be strictly sorted and contain valid ed25519 keys")
		}
		keys[authority.AuthorityID] = ed25519.PublicKey(raw)
		last = authority.AuthorityID
	}
	return keys, nil
}

// ContactDNSConfig authenticates the daemon to a TOS Native DNS gateway.
// The bearer itself is read from a bounded regular file so it is not copied
// into the reviewable daemon configuration.
type ContactDNSConfig struct {
	BaseURL         string `json:"base_url"`
	BearerTokenFile string `json:"bearer_token_file"`
	TimeoutSeconds  uint64 `json:"timeout_seconds,omitempty"`
	MaxMessageBytes int    `json:"max_message_bytes,omitempty"`
	Insecure        bool   `json:"insecure,omitempty"`
	ServerName      string `json:"server_name,omitempty"`
	CAFile          string `json:"ca_file,omitempty"`
	ClientCertFile  string `json:"client_cert_file,omitempty"`
	ClientKeyFile   string `json:"client_key_file,omitempty"`
}

func (c ContactDNSConfig) Validate() error {
	parsed, err := url.Parse(c.BaseURL)
	if err != nil || parsed.Host == "" || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" ||
		parsed.Path != "" || parsed.Scheme != "https" && !(parsed.Scheme == "http" && c.Insecure) {
		return errors.New("contact DNS gateway URL is invalid")
	}
	for label, path := range map[string]string{
		"bearer token": c.BearerTokenFile, "CA": c.CAFile,
		"client certificate": c.ClientCertFile, "client key": c.ClientKeyFile,
	} {
		if path != "" && (!filepath.IsAbs(path) || filepath.Clean(path) != path) {
			return errors.New("contact DNS " + label + " path must be absolute and clean")
		}
	}
	if c.BearerTokenFile == "" || (c.ClientCertFile == "") != (c.ClientKeyFile == "") {
		return errors.New("contact DNS credentials are incomplete")
	}
	if c.TimeoutSeconds > 15*60 || c.MaxMessageBytes < 0 || c.MaxMessageBytes > 64<<20 {
		return errors.New("contact DNS resource bound is invalid")
	}
	return nil
}

func (c ContactDNSConfig) Client() (*nativeclient.Client, error) {
	if err := c.Validate(); err != nil {
		return nil, err
	}
	raw, err := securefile.ReadBoundedRegular(c.BearerTokenFile, 16<<10)
	if err != nil {
		return nil, errors.New("read contact DNS bearer token: " + err.Error())
	}
	token := strings.TrimSpace(string(raw))
	clear(raw)
	client, err := nativeclient.New(nativeclient.Config{
		BaseURL: c.BaseURL, BearerToken: token, Timeout: time.Duration(c.TimeoutSeconds) * time.Second,
		MaxMessageBytes: c.MaxMessageBytes, Insecure: c.Insecure, ServerName: c.ServerName,
		CAFile: c.CAFile, ClientCertFile: c.ClientCertFile, ClientKeyFile: c.ClientKeyFile,
	})
	if err != nil {
		return nil, errors.New("construct contact DNS client: " + err.Error())
	}
	return client, nil
}

type AttachmentScannerConfig struct {
	ID               string                            `json:"id"`
	Executable       string                            `json:"executable"`
	ExecutableDigest string                            `json:"executable_digest"`
	Args             []string                          `json:"args,omitempty"`
	Resources        []AttachmentScannerResourceConfig `json:"resources,omitempty"`
}

type AttachmentScannerResourceConfig struct {
	Name       string `json:"name"`
	Path       string `json:"path"`
	Digest     string `json:"digest"`
	Executable bool   `json:"executable,omitempty"`
}

type AttachmentScannerCgroupConfig struct {
	SystemdRunDigest string `json:"systemd_run_digest"`
	MemoryMaxBytes   uint64 `json:"memory_max_bytes"`
	TasksMax         uint64 `json:"tasks_max"`
}

type AttachmentAdmissionConfig struct {
	MaxPlaintextBytes          uint64                         `json:"max_plaintext_bytes"`
	AllowedMediaTypes          []string                       `json:"allowed_media_types"`
	Scanners                   []AttachmentScannerConfig      `json:"scanners"`
	BubblewrapDigest           string                         `json:"bubblewrap_digest"`
	PrlimitDigest              string                         `json:"prlimit_digest"`
	ScannerTimeoutSeconds      uint64                         `json:"scanner_timeout_seconds,omitempty"`
	AddressSpaceBytes          uint64                         `json:"address_space_bytes,omitempty"`
	CPUSeconds                 uint64                         `json:"cpu_seconds,omitempty"`
	MaxProcesses               uint64                         `json:"max_processes,omitempty"`
	Cgroup                     *AttachmentScannerCgroupConfig `json:"cgroup,omitempty"`
	HTTPSRequestTimeoutSeconds uint64                         `json:"https_request_timeout_seconds,omitempty"`
	HTTPSConnectTimeoutSeconds uint64                         `json:"https_connect_timeout_seconds,omitempty"`
}

func (a AttachmentAdmissionConfig) Policies() (attachments.Policy, attachments.AgentContentPolicy, attachmentapi.HTTPSConfig, error) {
	// The admitted plaintext is eventually projected into an Event-sized
	// OpenFox input. Refuse a larger operator promise here, during offline
	// configuration validation, rather than discovering the mismatch after a
	// remote object has already been fetched and opened.
	if a.MaxPlaintextBytes == 0 || a.MaxPlaintextBytes > envelope.MaxContentBytes {
		return attachments.Policy{}, attachments.AgentContentPolicy{}, attachmentapi.HTTPSConfig{},
			errors.New("attachment admission max_plaintext_bytes must be within the Event content bound")
	}
	if len(a.AllowedMediaTypes) == 0 || !sort.StringsAreSorted(a.AllowedMediaTypes) {
		return attachments.Policy{}, attachments.AgentContentPolicy{}, attachmentapi.HTTPSConfig{},
			errors.New("attachment admission media types must be non-empty and sorted")
	}
	allowed := make(map[string]struct{}, len(a.AllowedMediaTypes))
	for index, mediaType := range a.AllowedMediaTypes {
		if index > 0 && a.AllowedMediaTypes[index-1] == mediaType {
			return attachments.Policy{}, attachments.AgentContentPolicy{}, attachmentapi.HTTPSConfig{},
				errors.New("attachment admission media types must be unique")
		}
		allowed[mediaType] = struct{}{}
	}
	scanners := make([]attachments.ScannerSpec, len(a.Scanners))
	for index, scanner := range a.Scanners {
		resources := make([]attachments.ScannerResource, len(scanner.Resources))
		for resourceIndex, resource := range scanner.Resources {
			resources[resourceIndex] = attachments.ScannerResource{Name: resource.Name, Path: resource.Path,
				Digest: resource.Digest, Executable: resource.Executable}
		}
		scanners[index] = attachments.ScannerSpec{ID: scanner.ID, Executable: scanner.Executable,
			ExecutableDigest: scanner.ExecutableDigest, Args: append([]string(nil), scanner.Args...),
			Resources: resources}
	}
	var cgroup *attachments.ScannerCgroupPolicy
	if a.Cgroup != nil {
		cgroup = &attachments.ScannerCgroupPolicy{SystemdRunDigest: a.Cgroup.SystemdRunDigest,
			MemoryMaxBytes: a.Cgroup.MemoryMaxBytes, TasksMax: a.Cgroup.TasksMax}
	}
	content := attachments.AgentContentPolicy{MaxPlaintextBytes: a.MaxPlaintextBytes,
		AllowedMediaTypes: allowed, Scanners: scanners, BubblewrapDigest: a.BubblewrapDigest,
		PrlimitDigest: a.PrlimitDigest, ScannerTimeout: time.Duration(a.ScannerTimeoutSeconds) * time.Second,
		AddressSpaceBytes: a.AddressSpaceBytes, CPUSeconds: a.CPUSeconds, MaxProcesses: a.MaxProcesses,
		Cgroup: cgroup}
	if err := attachments.ValidateAgentContentPolicy(content); err != nil {
		return attachments.Policy{}, attachments.AgentContentPolicy{}, attachmentapi.HTTPSConfig{}, err
	}
	if _, ok := allowed["text/plain"]; !ok {
		return attachments.Policy{}, attachments.AgentContentPolicy{}, attachmentapi.HTTPSConfig{},
			errors.New("OpenFox attachment admission currently requires text/plain")
	}
	requestTimeout := time.Duration(a.HTTPSRequestTimeoutSeconds) * time.Second
	connectTimeout := time.Duration(a.HTTPSConnectTimeoutSeconds) * time.Second
	if requestTimeout == 0 {
		requestTimeout = attachmentapi.DefaultTimeout
	}
	if connectTimeout == 0 {
		connectTimeout = 5 * time.Second
	}
	if requestTimeout < time.Second || requestTimeout > 5*time.Minute || connectTimeout < time.Second || connectTimeout > time.Minute {
		return attachments.Policy{}, attachments.AgentContentPolicy{}, attachmentapi.HTTPSConfig{},
			errors.New("attachment HTTPS timeout is outside its bound")
	}
	return attachments.Policy{MaxPlaintextBytes: a.MaxPlaintextBytes, AllowedMediaTypes: allowed}, content,
		attachmentapi.HTTPSConfig{RequestTimeout: requestTimeout, ConnectTimeout: connectTimeout}, nil
}

// AdmissionConfig is the daemon-owned form of the inbox policy and its
// private roster. Sorted lists make configuration reviews deterministic.
type AdmissionConfig struct {
	Rule                admission.InboxRule         `json:"rule"`
	Unknown             admission.UnknownSenderRule `json:"unknown,omitempty"`
	KnownAgentIDs       []string                    `json:"known_agent_ids,omitempty"`
	BlockedAgentIDs     []string                    `json:"blocked_agent_ids,omitempty"`
	MaxContentBytes     int                         `json:"max_content_bytes"`
	MaxClockSkewSeconds uint64                      `json:"max_clock_skew_seconds"`
}

func (a AdmissionConfig) Validate() error {
	document := admission.InboxPolicyDocument{Rule: a.Rule, Unknown: a.Unknown}
	if err := document.Validate(); err != nil {
		return err
	}
	if a.MaxContentBytes <= 0 || a.MaxContentBytes > envelope.MaxContentBytes {
		return errors.New("admission max_content_bytes is outside its bound")
	}
	if a.MaxClockSkewSeconds == 0 || a.MaxClockSkewSeconds > 3600 {
		return errors.New("admission max_clock_skew_seconds is outside its bound")
	}
	if len(a.KnownAgentIDs)+len(a.BlockedAgentIDs) > 4096 ||
		!sort.StringsAreSorted(a.KnownAgentIDs) || !sort.StringsAreSorted(a.BlockedAgentIDs) {
		return errors.New("admission rosters must be bounded and sorted")
	}
	seen := make(map[string]struct{}, len(a.KnownAgentIDs)+len(a.BlockedAgentIDs))
	for _, roster := range [][]string{a.KnownAgentIDs, a.BlockedAgentIDs} {
		for _, agentID := range roster {
			if !ids.Agent.MatchString(agentID) {
				return errors.New("invalid Agent identifier in admission roster")
			}
			if _, exists := seen[agentID]; exists {
				return errors.New("duplicate Agent identifier in admission rosters")
			}
			seen[agentID] = struct{}{}
		}
	}
	if a.Rule == admission.RuleOpen && len(seen) != 0 {
		return errors.New("open inbox cannot carry unused private rosters")
	}
	return nil
}

// AdmissionPolicy derives behavior and the published digest from the same
// configuration, preventing a daemon from advertising one rule and enforcing
// another.
func (c Config) AdmissionPolicy() (admission.ContactPolicy, error) {
	if err := c.Admission.Validate(); err != nil {
		return admission.ContactPolicy{}, err
	}
	known := make(map[string]struct{}, len(c.Admission.KnownAgentIDs))
	blocked := make(map[string]struct{}, len(c.Admission.BlockedAgentIDs))
	for _, agentID := range c.Admission.KnownAgentIDs {
		known[agentID] = struct{}{}
	}
	for _, agentID := range c.Admission.BlockedAgentIDs {
		blocked[agentID] = struct{}{}
	}
	return admission.NewContactPolicy(
		admission.InboxPolicyDocument{Rule: c.Admission.Rule, Unknown: c.Admission.Unknown},
		admission.Roster{Known: known, Blocked: blocked},
	)
}

// PublicationConfig fixes the complete roster and cadence of public prekey
// generations. Durations are explicit because silently chosen rotation
// policy would become security policy.
type PublicationConfig struct {
	Mode                      PublicationMode `json:"mode"`
	DeviceSocketPath          string          `json:"device_socket_path,omitempty"`
	DeviceIDs                 []string        `json:"device_ids,omitempty"`
	AlgorithmID               string          `json:"algorithm_id,omitempty"`
	GenerationLifetimeSeconds uint64          `json:"generation_lifetime_seconds,omitempty"`
	ReplenishBeforeSeconds    uint64          `json:"replenish_before_seconds,omitempty"`
	CheckIntervalSeconds      uint64          `json:"check_interval_seconds,omitempty"`
}

func (p PublicationConfig) Validate(localDeviceID, stateDir, runtimeSocket, ownerSocket string) error {
	switch p.Mode {
	case PublicationNone:
		if p.DeviceSocketPath != "" || len(p.DeviceIDs) != 0 || p.AlgorithmID != "" ||
			p.GenerationLifetimeSeconds != 0 || p.ReplenishBeforeSeconds != 0 || p.CheckIntervalSeconds != 0 {
			return errors.New("publication none cannot carry unused settings")
		}
		return nil
	case PublicationPrekeys:
	default:
		return errors.New("publication mode must be stated explicitly")
	}
	if !filepath.IsAbs(p.DeviceSocketPath) || filepath.Clean(p.DeviceSocketPath) != p.DeviceSocketPath {
		return errors.New("publication device_socket_path must be absolute and clean")
	}
	if p.DeviceSocketPath == runtimeSocket || p.DeviceSocketPath == ownerSocket {
		return errors.New("publication device socket must be independent")
	}
	if pathWithin(p.DeviceSocketPath, stateDir) {
		return errors.New("publication device socket must not live inside state_dir")
	}
	if len(p.DeviceIDs) == 0 || len(p.DeviceIDs) > e2ee.MaxDevicesPerSet || !sort.StringsAreSorted(p.DeviceIDs) {
		return errors.New("publication device roster must be non-empty, bounded, and sorted")
	}
	foundLocal := false
	for index, deviceID := range p.DeviceIDs {
		if !ids.Device.MatchString(deviceID) || index > 0 && p.DeviceIDs[index-1] == deviceID {
			return errors.New("invalid publication device roster")
		}
		foundLocal = foundLocal || deviceID == localDeviceID
	}
	if !foundLocal {
		return errors.New("publication device roster must include the configured device")
	}
	if err := e2ee.ValidateAlgorithmID(p.AlgorithmID); err != nil {
		return err
	}
	if p.GenerationLifetimeSeconds < uint64(MinPrekeyGenerationLifetime/time.Second) ||
		p.GenerationLifetimeSeconds > e2ee.MaxBundleLifetimeSeconds {
		return errors.New("publication generation lifetime is outside its bound")
	}
	if p.ReplenishBeforeSeconds == 0 || p.ReplenishBeforeSeconds >= p.GenerationLifetimeSeconds {
		return errors.New("publication replenish lead must be positive and shorter than its generation")
	}
	if p.CheckIntervalSeconds == 0 || p.CheckIntervalSeconds > p.ReplenishBeforeSeconds ||
		p.CheckIntervalSeconds > uint64(MaxPrekeyPlannerInterval/time.Second) {
		return errors.New("publication check interval is outside its bound")
	}
	return nil
}

func (p PublicationConfig) GenerationLifetime() time.Duration {
	return time.Duration(p.GenerationLifetimeSeconds) * time.Second
}

func (p PublicationConfig) ReplenishBefore() time.Duration {
	return time.Duration(p.ReplenishBeforeSeconds) * time.Second
}

func (p PublicationConfig) CheckInterval() time.Duration {
	return time.Duration(p.CheckIntervalSeconds) * time.Second
}

func pathWithin(path, directory string) bool {
	relative, err := filepath.Rel(directory, path)
	return err == nil && relative != ".." &&
		!strings.HasPrefix(relative, ".."+string(filepath.Separator))
}

// DiscoveryConfig provisions the out-of-band information that cannot be
// derived from an Agent identifier: a peer delegation document and the local
// DHT bootstrap table. Neither replaces finalized verification.
type DiscoveryConfig struct {
	Mode                       DiscoveryMode          `json:"mode"`
	DHTGlobalConfigPath        string                 `json:"dht_global_config_path,omitempty"`
	Peers                      []PeerDelegationConfig `json:"peers,omitempty"`
	RefreshIntervalSeconds     uint64                 `json:"refresh_interval_seconds,omitempty"`
	RefreshLeadSeconds         uint64                 `json:"refresh_lead_seconds,omitempty"`
	HTTPSRequestTimeoutSeconds uint64                 `json:"https_request_timeout_seconds,omitempty"`
	HTTPSConnectTimeoutSeconds uint64                 `json:"https_connect_timeout_seconds,omitempty"`
}

type PeerDelegationConfig struct {
	AgentID              string `json:"agent_id"`
	DelegationPath       string `json:"delegation_path"`
	DescriptorPolicyPath string `json:"descriptor_policy_path"`
}

func (d DiscoveryConfig) RefreshInterval() time.Duration {
	if d.RefreshIntervalSeconds == 0 {
		return DefaultDirectoryRefreshInterval
	}
	return time.Duration(d.RefreshIntervalSeconds) * time.Second
}

func (d DiscoveryConfig) RefreshLead() time.Duration {
	if d.RefreshLeadSeconds == 0 {
		return DefaultDirectoryRefreshLead
	}
	return time.Duration(d.RefreshLeadSeconds) * time.Second
}

func (d DiscoveryConfig) Validate(localAgentID string) error {
	switch d.Mode {
	case DiscoveryNone:
		if d.DHTGlobalConfigPath != "" || len(d.Peers) != 0 || d.RefreshIntervalSeconds != 0 ||
			d.RefreshLeadSeconds != 0 || d.HTTPSRequestTimeoutSeconds != 0 || d.HTTPSConnectTimeoutSeconds != 0 {
			return errors.New("discovery none cannot carry unused settings")
		}
		return nil
	case DiscoveryTOSDHTHTTPS:
	default:
		return errors.New("discovery mode must be stated explicitly")
	}
	if !filepath.IsAbs(d.DHTGlobalConfigPath) || filepath.Clean(d.DHTGlobalConfigPath) != d.DHTGlobalConfigPath {
		return errors.New("dht_global_config_path must be absolute and clean")
	}
	if len(d.Peers) == 0 || len(d.Peers) > 4096 {
		return errors.New("discovery peer set must contain 1 to 4096 peers")
	}
	seen := make(map[string]struct{}, len(d.Peers))
	for _, peer := range d.Peers {
		if !identity.AgentPattern.MatchString(peer.AgentID) || peer.AgentID == localAgentID {
			return errors.New("invalid discovery peer Agent identifier")
		}
		if !filepath.IsAbs(peer.DelegationPath) || filepath.Clean(peer.DelegationPath) != peer.DelegationPath {
			return errors.New("peer delegation_path must be absolute and clean")
		}
		if !filepath.IsAbs(peer.DescriptorPolicyPath) || filepath.Clean(peer.DescriptorPolicyPath) != peer.DescriptorPolicyPath {
			return errors.New("peer descriptor_policy_path must be absolute and clean")
		}
		if _, duplicate := seen[peer.AgentID]; duplicate {
			return errors.New("duplicate discovery peer")
		}
		seen[peer.AgentID] = struct{}{}
	}
	if d.RefreshIntervalSeconds > uint64(MaxDirectoryRefreshInterval/time.Second) ||
		d.RefreshLeadSeconds > uint64(MaxDirectoryRefreshInterval/time.Second) {
		return errors.New("directory refresh duration exceeds one day")
	}
	interval := d.RefreshInterval()
	if interval < MinDirectoryRefreshInterval || interval > MaxDirectoryRefreshInterval {
		return errors.New("directory refresh interval is outside its bound")
	}
	if lead := d.RefreshLead(); lead < 0 || lead > interval {
		return errors.New("directory refresh lead exceeds its interval")
	}
	if d.HTTPSRequestTimeoutSeconds > 30 || d.HTTPSConnectTimeoutSeconds > 10 {
		return errors.New("discovery HTTPS timeout exceeds its bound")
	}
	return nil
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

func (c Config) AgentPacketReceiverTimeout() time.Duration {
	if c.AgentPacketReceiverTimeoutSeconds == 0 {
		return 30 * time.Second
	}
	return time.Duration(c.AgentPacketReceiverTimeoutSeconds) * time.Second
}

func (c Config) ProtocolReceiverTimeout() time.Duration {
	if c.ProtocolReceiverTimeoutSeconds == 0 {
		return 30 * time.Second
	}
	return time.Duration(c.ProtocolReceiverTimeoutSeconds) * time.Second
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
	if pathWithin(c.SocketPath, c.StateDir) || pathWithin(c.OwnerSocketPath, c.StateDir) {
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
	if c.EscrowCodeHash == "" || c.EscrowCheckpointPath == "" {
		if c.EscrowCodeHash != "" || c.EscrowCheckpointPath != "" {
			return errors.New("escrow code hash and checkpoint must be configured together")
		}
	} else {
		const prefix = "tvm-cell-sha256:"
		raw, err := hex.DecodeString(strings.TrimPrefix(c.EscrowCodeHash, prefix))
		if !strings.HasPrefix(c.EscrowCodeHash, prefix) || len(raw) != 32 || err != nil || canon.IsZero(raw) {
			return errors.New("escrow_code_hash must be a non-zero TVM cell digest")
		}
		if !filepath.IsAbs(c.EscrowCheckpointPath) || filepath.Clean(c.EscrowCheckpointPath) != c.EscrowCheckpointPath ||
			c.EscrowCheckpointPath != filepath.Join(c.StateDir, "escrow.checkpoint") {
			return errors.New("escrow_checkpoint_path must be the daemon-owned escrow checkpoint")
		}
	}
	if !filepath.IsAbs(c.DelegationPath) || filepath.Clean(c.DelegationPath) != c.DelegationPath {
		return errors.New("delegation_path must be an absolute, clean path")
	}
	if err := c.Discovery.Validate(c.AgentID); err != nil {
		return err
	}
	if c.ContactDNS != nil {
		if c.Discovery.Mode == DiscoveryNone {
			return errors.New("contact DNS requires verified directory discovery")
		}
		if err := c.ContactDNS.Validate(); err != nil {
			return err
		}
	}
	if err := c.Identity().Validate(); err != nil {
		return err
	}
	if err := c.Publication.Validate(c.DeviceID, c.StateDir, c.SocketPath, c.OwnerSocketPath); err != nil {
		return err
	}
	if _, err := c.AdmissionPolicy(); err != nil {
		return err
	}
	if err := c.FirewallPolicy().Validate(); err != nil {
		return err
	}
	if _, err := c.OwnerKey(); err != nil {
		return err
	}
	if _, err := c.EconomicAuthorityKeys(); err != nil {
		return err
	}
	if _, known := transports[c.Transport]; !known {
		return errors.New("transport must be stated explicitly")
	}
	if c.Transport == TransportHTTPSBootstrap {
		if c.Discovery.Mode != DiscoveryTOSDHTHTTPS {
			return errors.New("https-bootstrap requires verified TOS DHT/HTTPS discovery")
		}
		if c.Publication.Mode != PublicationPrekeys {
			return errors.New("https-bootstrap requires public prekey publication")
		}
	}
	if c.AgentPacketReceiverSocket == "" {
		if c.AgentPacketReceiverTimeoutSeconds != 0 {
			return errors.New("Agent Packet receiver timeout requires a receiver socket")
		}
	} else {
		if !filepath.IsAbs(c.AgentPacketReceiverSocket) || filepath.Clean(c.AgentPacketReceiverSocket) != c.AgentPacketReceiverSocket {
			return errors.New("agent_packet_receiver_socket must be an absolute, clean path")
		}
		if c.AgentPacketReceiverSocket == c.SocketPath || c.AgentPacketReceiverSocket == c.OwnerSocketPath ||
			(c.Publication.DeviceSocketPath != "" && c.AgentPacketReceiverSocket == c.Publication.DeviceSocketPath) {
			return errors.New("Agent Packet receiver socket must be independent")
		}
		if pathWithin(c.AgentPacketReceiverSocket, c.StateDir) {
			return errors.New("Agent Packet receiver socket must not live inside state_dir")
		}
		if timeout := c.AgentPacketReceiverTimeout(); timeout < time.Second || timeout > 5*time.Minute {
			return errors.New("Agent Packet receiver timeout is outside 1s..5m")
		}
	}
	protocolSockets := []string{c.A2AReceiverSocket, c.MCPReceiverSocket}
	if c.A2AReceiverSocket == "" && c.MCPReceiverSocket == "" {
		if c.ProtocolReceiverTimeoutSeconds != 0 {
			return errors.New("protocol receiver timeout requires a receiver socket")
		}
	} else {
		for _, socket := range protocolSockets {
			if socket == "" {
				continue
			}
			if !filepath.IsAbs(socket) || filepath.Clean(socket) != socket {
				return errors.New("protocol receiver socket must be an absolute, clean path")
			}
			if socket == c.SocketPath || socket == c.OwnerSocketPath || socket == c.AgentPacketReceiverSocket ||
				(c.Publication.DeviceSocketPath != "" && socket == c.Publication.DeviceSocketPath) {
				return errors.New("protocol receiver socket must be independent")
			}
			if pathWithin(socket, c.StateDir) {
				return errors.New("protocol receiver socket must not live inside state_dir")
			}
		}
		if c.A2AReceiverSocket != "" && c.A2AReceiverSocket == c.MCPReceiverSocket {
			return errors.New("A2A and MCP receiver sockets must be different")
		}
		if timeout := c.ProtocolReceiverTimeout(); timeout < time.Second || timeout > 5*time.Minute {
			return errors.New("protocol receiver timeout is outside 1s..5m")
		}
	}
	if c.AttachmentAdmission != nil {
		if _, _, _, err := c.AttachmentAdmission.Policies(); err != nil {
			return err
		}
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
