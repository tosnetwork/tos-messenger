// Package daemon assembles the Messenger into something that runs.
//
// It owns one state directory, one socket, and one schedule. Everything it
// composes already decides its own behaviour; what is decided here is what an
// operator must say out loud before the daemon will start.
package daemon

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"time"

	"github.com/tosnetwork/tos-messenger/internal/canon"
	"github.com/tosnetwork/tos-messenger/pkg/eventlog"
	"github.com/tosnetwork/tos-messenger/pkg/identity"
	nativev1 "github.com/tosnetwork/tos-service-protocol/gen/tos/service/v1"
)

// ConfigSchema is the strict schema of a daemon configuration.
const ConfigSchema = "tos.messaging.daemon-config.v1"

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
	// SocketPath is the owner-private local API.
	SocketPath string `json:"socket_path"`

	NetworkID       string `json:"network_id"`
	GenesisRootHash string `json:"genesis_root_hash"`
	GenesisFileHash string `json:"genesis_file_hash"`

	// RegistryCodeHashes are the registry contracts whose finalized state this
	// installation accepts.
	RegistryCodeHashes []string `json:"registry_code_hashes"`
	// MinFinalizedCheckpoint refuses state older than a point the operator
	// already knows about.
	MinFinalizedCheckpoint uint64 `json:"min_finalized_checkpoint,omitempty"`

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

// Chain returns the configured acceptance rules for finalized state.
func (c Config) Chain() identity.ChainPolicy {
	return identity.ChainPolicy{
		RegistryCodeHashes:     c.RegistryCodeHashes,
		MinFinalizedCheckpoint: c.MinFinalizedCheckpoint,
	}
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
	if filepath.Dir(c.SocketPath) == c.StateDir {
		// The state directory is owned through a lock file; a socket living in
		// it would make a stale socket look like contested ownership.
		return errors.New("socket_path must not live inside state_dir")
	}
	if c.NetworkID == "" || len(c.NetworkID) > 128 ||
		!canon.HashPattern.MatchString(c.GenesisRootHash) ||
		!canon.HashPattern.MatchString(c.GenesisFileHash) {
		return errors.New("invalid network domain")
	}
	if err := c.Chain().Validate(); err != nil {
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
