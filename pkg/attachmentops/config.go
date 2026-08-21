// Package attachmentops assembles the operator-owned resources and
// daemon-owned durable transaction used to emit encrypted attachments.
// OpenFox supplies bounded plaintext semantics; storage authority, fresh
// encryption/capability keys, Endpoint signatures, locator, retention, Event
// identity, and upload ordering remain outside the Agent runtime.
package attachmentops

import (
	"bytes"
	"crypto"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"mime"
	"path/filepath"
	"sort"
	"time"

	"github.com/tosnetwork/tos-messenger/internal/canon"
	"github.com/tosnetwork/tos-messenger/internal/securefile"
	"github.com/tosnetwork/tos-messenger/pkg/attachmentapi"
	"github.com/tosnetwork/tos-messenger/pkg/attachments"
	"github.com/tosnetwork/tos-messenger/pkg/dispatch"
	"github.com/tosnetwork/tos-messenger/pkg/identity"
	"github.com/tosnetwork/tos-messenger/pkg/signerapi"
)

const (
	ConfigSchema   = "tos.messaging.attachment-emission-operator.v1"
	MaxConfigBytes = 32 << 10
)

// Config contains only operator policy and public/narrow resource locators.
// Agent, Endpoint and network authority are derived from finalized state.
type Config struct {
	Schema                     string   `json:"schema"`
	StorageOrigin              string   `json:"storage_origin"`
	StoragePublicKeyHex        string   `json:"storage_public_key_hex"`
	EndpointSignerSocket       string   `json:"endpoint_signer_socket"`
	SignerTimeoutSeconds       uint64   `json:"signer_timeout_seconds"`
	RetentionSeconds           uint64   `json:"retention_seconds"`
	MaxPlaintextBytes          uint64   `json:"max_plaintext_bytes"`
	AllowedMediaTypes          []string `json:"allowed_media_types"`
	HTTPSRequestTimeoutSeconds uint64   `json:"https_request_timeout_seconds,omitempty"`
	HTTPSConnectTimeoutSeconds uint64   `json:"https_connect_timeout_seconds,omitempty"`
}

func Load(path string) (Config, error) {
	raw, err := securefile.ReadBoundedRegular(path, MaxConfigBytes)
	if err != nil {
		return Config{}, errors.New("read attachment emission operator configuration: " + err.Error())
	}
	return Decode(raw)
}

func Decode(raw []byte) (Config, error) {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	var config Config
	if err := decoder.Decode(&config); err != nil {
		return Config{}, err
	}
	if err := decoder.Decode(new(any)); !errors.Is(err, io.EOF) {
		return Config{}, errors.New("attachment emission operator configuration has trailing content")
	}
	if err := config.Validate(); err != nil {
		return Config{}, err
	}
	return config, nil
}

func (c Config) Validate() error {
	if c.Schema != ConfigSchema {
		return errors.New("unsupported attachment emission operator configuration schema")
	}
	if !filepath.IsAbs(c.EndpointSignerSocket) || filepath.Clean(c.EndpointSignerSocket) != c.EndpointSignerSocket {
		return errors.New("attachment Endpoint signer socket must be absolute and clean")
	}
	if c.SignerTimeoutSeconds == 0 || c.SignerTimeoutSeconds > 60 {
		return errors.New("attachment signer timeout is outside its bound")
	}
	if c.RetentionSeconds < 60 || c.RetentionSeconds > uint64(attachments.MaxGrantLifetime/time.Second) {
		return errors.New("attachment retention is outside 1m..30d")
	}
	if c.MaxPlaintextBytes == 0 || c.MaxPlaintextBytes > attachments.MaxPlaintextBytes {
		return errors.New("attachment plaintext limit is outside its protocol bound")
	}
	storage, err := hex.DecodeString(c.StoragePublicKeyHex)
	if err != nil || len(storage) != ed25519.PublicKeySize || canon.IsZero(storage) || hex.EncodeToString(storage) != c.StoragePublicKeyHex {
		return errors.New("invalid attachment storage public key")
	}
	if _, err := attachments.HTTPSLocator(c.StorageOrigin, "sha256:"+string(bytes.Repeat([]byte{'a'}, 64))); err != nil {
		return errors.New("invalid attachment storage origin: " + err.Error())
	}
	if len(c.AllowedMediaTypes) == 0 || len(c.AllowedMediaTypes) > 32 || !sort.StringsAreSorted(c.AllowedMediaTypes) {
		return errors.New("attachment media types must be non-empty and sorted")
	}
	for index, value := range c.AllowedMediaTypes {
		mediaType, params, err := mime.ParseMediaType(value)
		if err != nil || mediaType != value || len(params) != 0 || index > 0 && c.AllowedMediaTypes[index-1] == value {
			return errors.New("attachment media types must be unique canonical type/subtype values")
		}
	}
	if _, err := c.httpsConfig(); err != nil {
		return err
	}
	return nil
}

func (c Config) httpsConfig() (attachmentapi.HTTPSConfig, error) {
	request := time.Duration(c.HTTPSRequestTimeoutSeconds) * time.Second
	connect := time.Duration(c.HTTPSConnectTimeoutSeconds) * time.Second
	if request == 0 {
		request = attachmentapi.DefaultTimeout
	}
	if connect == 0 {
		connect = 5 * time.Second
	}
	if request < time.Second || request > time.Minute || connect < time.Second || connect > time.Minute || connect > request {
		return attachmentapi.HTTPSConfig{}, errors.New("attachment HTTPS timeouts are outside their bounds")
	}
	return attachmentapi.HTTPSConfig{RequestTimeout: request, ConnectTimeout: connect}, nil
}

type Resources struct {
	Config     Config
	Signer     crypto.Signer
	StorageKey ed25519.PublicKey
	HTTPS      attachmentapi.HTTPSConfig
}

// Assemble pins the external signer to the live finalized Endpoint key and
// proves all three authority keys are distinct before the daemon starts.
func Assemble(config Config, delegation identity.Delegation) (Resources, error) {
	if err := config.Validate(); err != nil {
		return Resources{}, err
	}
	storageRaw, _ := hex.DecodeString(config.StoragePublicKeyHex)
	storage := ed25519.PublicKey(storageRaw)
	if storage.Equal(delegation.IdentityPublicKey) {
		return Resources{}, errors.New("attachment storage and Endpoint keys must be distinct")
	}
	signer, err := signerapi.NewClient(config.EndpointSignerSocket, delegation.IdentityPublicKey,
		time.Duration(config.SignerTimeoutSeconds)*time.Second)
	if err != nil {
		return Resources{}, err
	}
	https, err := config.httpsConfig()
	if err != nil {
		return Resources{}, err
	}
	return Resources{Config: config, Signer: signer, StorageKey: append(ed25519.PublicKey(nil), storage...), HTTPS: https}, nil
}

// NewEmitter binds assembled operator resources to the sole-writer daemon
// journal and its daemon-owned canonical Event dispatcher.
func (r Resources) NewEmitter(stateDir string, dispatcher *dispatch.Dispatcher) (*Emitter, error) {
	return newEmitter(r, stateDir, dispatcher)
}
