package eventlog

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"sort"
	"time"

	"github.com/tosnetwork/tos-messenger/internal/canon"
	"github.com/tosnetwork/tos-messenger/internal/ids"
	"github.com/tosnetwork/tos-messenger/pkg/e2ee"
	"github.com/tosnetwork/tos-messenger/pkg/identity"
)

const (
	localPrekeyDir = "local-prekeys"

	// LocalPrekeyRecordSchema identifies local publication state. It is not a
	// wire object: only the bounded bundle-set JSON leaves the installation.
	LocalPrekeyRecordSchema = "tos.messaging.local-prekeys.v1"

	// MaxPrivatePrekeyBytes bounds one suite's unpublished answering material.
	// The current candidate uses 65 bytes; the larger ceiling leaves migration
	// room without letting an implementation expand private state without end.
	MaxPrivatePrekeyBytes = 4 << 10
	// MaxRetiredPrekeySecrets bounds live answering material retained across
	// rotations. Reaching the bound refuses another rotation rather than
	// forgetting a still-valid bundle that a sender may already have used.
	MaxRetiredPrekeySecrets = 80
	// MaxLocalPrekeyTombstones bounds permanent local device revocations.
	MaxLocalPrekeyTombstones = 256
)

var (
	// ErrPrekeyEquivocation reports an attempt to produce different signed
	// material at a publication timestamp already used by this endpoint.
	ErrPrekeyEquivocation = errors.New("prekey publication would equivocate")
	// ErrPrekeyUnavailable reports that no unexpired answering material matches
	// the exact bundle a sender used.
	ErrPrekeyUnavailable = errors.New("prekey private material is unavailable")
)

// PrekeyPlan is the complete device set an endpoint intends to publish.
// Every device rotates together. This creates one unambiguous generation and
// makes an equal-time different digest an equivocation rather than an ordering
// choice delegated to whichever directory response arrived last.
type PrekeyPlan struct {
	DeviceIDs       []string
	Lifetime        time.Duration
	ReplenishBefore time.Duration
}

// PrekeyPublication is the immutable object prepared for a descriptor. The
// bundle-set bytes are persisted before EnsurePrekeys returns, so a crash and
// retry republishes these bytes instead of signing a competing generation.
type PrekeyPublication struct {
	EndpointID    string
	SetDigest     string
	IssuedAt      uint64
	ExpiresAt     uint64
	Bundles       []e2ee.Bundle
	BundleSetJSON []byte
}

// PrekeyObjectSink is the route-neutral boundary for a content-addressed
// publication store. Implementations may write an HTTPS origin, replicated
// object store, or test fixture; they do not choose a message route.
type PrekeyObjectSink interface {
	PutPrekeySet(context.Context, string, []byte) error
}

// PublishCurrentPrekeys reloads and checks the durable artifact before
// releasing it to a sink. It returns the artifact that was put so the caller
// can subsequently sign a descriptor naming that exact digest.
func (l *LocalPrekeyLedger) PublishCurrentPrekeys(ctx context.Context, sink PrekeyObjectSink,
	endpointID string) (PrekeyPublication, error) {
	if ctx == nil || sink == nil {
		return PrekeyPublication{}, errors.New("prekey publication needs a context and object sink")
	}
	if err := ctx.Err(); err != nil {
		return PrekeyPublication{}, err
	}
	publication, found, err := l.CurrentPrekeys(endpointID)
	if err != nil {
		return PrekeyPublication{}, err
	}
	if !found {
		return PrekeyPublication{}, errors.New("prekey publication is not prepared")
	}
	bundles, err := e2ee.DecodeBundleSetJSON(publication.BundleSetJSON)
	if err != nil {
		return PrekeyPublication{}, err
	}
	digest, err := e2ee.SetDigest(bundles)
	if err != nil {
		return PrekeyPublication{}, err
	}
	if digest != publication.SetDigest || bundles[0].EndpointID != publication.EndpointID {
		return PrekeyPublication{}, errors.New("prekey publication artifact is inconsistent")
	}
	if err := sink.PutPrekeySet(ctx, digest, append([]byte(nil), publication.BundleSetJSON...)); err != nil {
		return PrekeyPublication{}, err
	}
	return publication, nil
}

type storedPrekeySecret struct {
	BundleDigest  string `json:"bundle_digest"`
	DeviceID      string `json:"device_id"`
	AlgorithmID   string `json:"algorithm_id"`
	PrivateBase64 string `json:"private_material_base64"`
	PrivateDigest string `json:"private_material_digest"`
	ExpiresAtUnix uint64 `json:"expires_at_unix"`
}

type localPrekeyRecord struct {
	Schema              string               `json:"schema"`
	EndpointID          string               `json:"messaging_endpoint_id"`
	SetDigest           string               `json:"set_digest"`
	IssuedAtUnix        uint64               `json:"issued_at_unix"`
	ExpiresAtUnix       uint64               `json:"expires_at_unix"`
	BundleSetJSONBase64 string               `json:"bundle_set_json_base64"`
	CurrentSecrets      []storedPrekeySecret `json:"current_secrets,omitempty"`
	RetiredSecrets      []storedPrekeySecret `json:"retired_secrets,omitempty"`
	Tombstones          []string             `json:"tombstones,omitempty"`
	UpdatedAtUnix       uint64               `json:"updated_at_unix"`
}

// LocalPrekeyLedger owns publication generations and their answering secrets.
// It shares the Journal's single-writer lock and crash-safe replacement.
type LocalPrekeyLedger struct{ journal *Journal }

// OpenLocalPrekeys returns this installation's publication ledger.
func (j *Journal) OpenLocalPrekeys() (*LocalPrekeyLedger, error) {
	if err := j.usable(); err != nil {
		return nil, err
	}
	return &LocalPrekeyLedger{journal: j}, nil
}

// EnsurePrekeys returns the current publication while it covers the requested
// devices and has more than the replenishment horizon left. Otherwise it
// generates, endpoint-signs, and atomically records a complete replacement.
// The boolean reports whether a replacement was created.
func (l *LocalPrekeyLedger) EnsurePrekeys(delegation identity.Delegation, signer crypto.Signer,
	suite e2ee.Suite, plan PrekeyPlan, now time.Time) (PrekeyPublication, bool, error) {
	if l == nil || l.journal == nil {
		return PrekeyPublication{}, false, errors.New("no local prekey ledger")
	}
	if err := l.journal.usable(); err != nil {
		return PrekeyPublication{}, false, err
	}
	devices, lifetime, lead, err := validatePrekeyInputs(delegation, signer, suite, plan, now)
	if err != nil {
		return PrekeyPublication{}, false, err
	}

	l.journal.mutex.Lock()
	defer l.journal.mutex.Unlock()
	record, found, err := l.read(delegation.EndpointID)
	if err != nil {
		return PrekeyPublication{}, false, err
	}
	if found {
		publication, err := publicationFromRecord(record)
		if err != nil {
			return PrekeyPublication{}, false, err
		}
		if sameDevices(publication.Bundles, devices) && publication.Bundles[0].AlgorithmID == suite.AlgorithmID() &&
			publication.ExpiresAt > uint64(now.Unix())+lead &&
			e2ee.BindBundleSet(delegation, publication.Bundles, publication.SetDigest, now) == nil {
			return publication, false, nil
		}
		if uint64(now.Unix()) <= record.IssuedAtUnix {
			return PrekeyPublication{}, false, ErrPrekeyEquivocation
		}
		for _, deviceID := range devices {
			if contains(record.Tombstones, deviceID) {
				return PrekeyPublication{}, false, errors.New("a revoked local device cannot return")
			}
		}
		liveRetired := liveSecretsForDevices(record.RetiredSecrets, devices, uint64(now.Unix()))
		liveCurrent := liveSecretsForDevices(record.CurrentSecrets, devices, uint64(now.Unix()))
		if len(liveRetired)+len(liveCurrent) > MaxRetiredPrekeySecrets {
			return PrekeyPublication{}, false, errors.New("too many live retired prekey secrets")
		}
		newTombstones := 0
		for _, old := range currentDeviceIDs(record) {
			if !contains(devices, old) && !contains(record.Tombstones, old) {
				newTombstones++
			}
		}
		if len(record.Tombstones)+newTombstones > MaxLocalPrekeyTombstones {
			return PrekeyPublication{}, false, errors.New("too many local device revocations")
		}
	}

	expires := uint64(now.Unix()) + lifetime
	if expires > delegation.ExpiresAtUnix {
		expires = delegation.ExpiresAtUnix
	}
	if expires <= uint64(now.Unix())+lead {
		return PrekeyPublication{}, false, errors.New("delegation cannot cover the prekey replenishment horizon")
	}
	bundles := make([]e2ee.Bundle, 0, len(devices))
	secrets := make([]storedPrekeySecret, 0, len(devices))
	for _, deviceID := range devices {
		public, private, err := suite.NewPrekeyMaterial()
		if err != nil {
			clearSecrets(secrets)
			return PrekeyPublication{}, false, errors.New("generate prekey material")
		}
		if len(private) == 0 || len(private) > MaxPrivatePrekeyBytes || canon.IsZero(private) {
			clear(private)
			clearSecrets(secrets)
			return PrekeyPublication{}, false, errors.New("invalid private prekey material")
		}
		bundle, err := e2ee.SignBundleWith(e2ee.Bundle{
			Network: delegation.Network, AgentID: delegation.AgentID, EndpointID: delegation.EndpointID,
			DeviceID: deviceID, AlgorithmID: suite.AlgorithmID(), Material: append([]byte(nil), public...),
			IssuedAtUnix: uint64(now.Unix()), ExpiresAtUnix: expires,
		}, signer)
		if err != nil {
			clear(private)
			clearSecrets(secrets)
			return PrekeyPublication{}, false, err
		}
		digest, err := e2ee.BundleDigest(bundle)
		if err != nil {
			clear(private)
			clearSecrets(secrets)
			return PrekeyPublication{}, false, err
		}
		bundles = append(bundles, bundle)
		secrets = append(secrets, storedPrekeySecret{
			BundleDigest: digest, DeviceID: deviceID, AlgorithmID: suite.AlgorithmID(),
			PrivateBase64: base64.StdEncoding.EncodeToString(private), PrivateDigest: canon.Digest(private),
			ExpiresAtUnix: expires,
		})
		clear(private)
	}
	setDigest, err := e2ee.SetDigest(bundles)
	if err != nil {
		clearSecrets(secrets)
		return PrekeyPublication{}, false, err
	}
	wire, err := e2ee.EncodeBundleSetJSON(bundles)
	if err != nil {
		clearSecrets(secrets)
		return PrekeyPublication{}, false, err
	}
	if err := e2ee.BindBundleSet(delegation, bundles, setDigest, now); err != nil {
		clearSecrets(secrets)
		return PrekeyPublication{}, false, err
	}

	retired := []storedPrekeySecret(nil)
	tombstones := []string(nil)
	if found {
		retired = append(retired, liveSecretsForDevices(record.RetiredSecrets, devices, uint64(now.Unix()))...)
		retired = append(retired, liveSecretsForDevices(record.CurrentSecrets, devices, uint64(now.Unix()))...)
		tombstones = append(tombstones, record.Tombstones...)
		for _, old := range currentDeviceIDs(record) {
			if !contains(devices, old) && !contains(tombstones, old) {
				tombstones = append(tombstones, old)
			}
		}
	}
	sort.Strings(tombstones)
	record = localPrekeyRecord{
		Schema: LocalPrekeyRecordSchema, EndpointID: delegation.EndpointID,
		SetDigest: setDigest, IssuedAtUnix: uint64(now.Unix()), ExpiresAtUnix: expires,
		BundleSetJSONBase64: base64.StdEncoding.EncodeToString(wire), CurrentSecrets: secrets,
		RetiredSecrets: retired, Tombstones: tombstones, UpdatedAtUnix: uint64(now.Unix()),
	}
	encoded, err := json.Marshal(record)
	if err != nil {
		clearSecrets(secrets)
		return PrekeyPublication{}, false, err
	}
	if err := l.journal.replace(l.path(delegation.EndpointID), encoded); err != nil {
		clearSecrets(secrets)
		return PrekeyPublication{}, false, err
	}
	publication, err := publicationFromRecord(record)
	return publication, true, err
}

// CurrentPrekeys reloads the exact publication prepared for an endpoint.
func (l *LocalPrekeyLedger) CurrentPrekeys(endpointID string) (PrekeyPublication, bool, error) {
	if l == nil || l.journal == nil {
		return PrekeyPublication{}, false, errors.New("no local prekey ledger")
	}
	if err := l.journal.usable(); err != nil {
		return PrekeyPublication{}, false, err
	}
	if !ids.Endpoint.MatchString(endpointID) {
		return PrekeyPublication{}, false, errors.New("invalid endpoint identifier")
	}
	l.journal.mutex.Lock()
	defer l.journal.mutex.Unlock()
	record, found, err := l.read(endpointID)
	if err != nil || !found {
		return PrekeyPublication{}, found, err
	}
	publication, err := publicationFromRecord(record)
	return publication, true, err
}

// PrekeyPrivate returns a copy of the answering material for the exact bundle
// digest carried by a bootstrap target. Current and superseded publications
// remain answerable only until their signed expiry.
func (l *LocalPrekeyLedger) PrekeyPrivate(endpointID, bundleDigest string, now time.Time) ([]byte, error) {
	if l == nil || l.journal == nil {
		return nil, errors.New("no local prekey ledger")
	}
	if err := l.journal.usable(); err != nil {
		return nil, err
	}
	if !ids.Endpoint.MatchString(endpointID) || !canon.ValidDigest(bundleDigest) || now.IsZero() || now.Unix() < 0 {
		return nil, errors.New("invalid prekey selection")
	}
	l.journal.mutex.Lock()
	defer l.journal.mutex.Unlock()
	record, found, err := l.read(endpointID)
	if err != nil {
		return nil, err
	}
	if !found {
		return nil, ErrPrekeyUnavailable
	}
	for _, secret := range append(append([]storedPrekeySecret(nil), record.CurrentSecrets...), record.RetiredSecrets...) {
		if secret.BundleDigest == bundleDigest && uint64(now.Unix()) < secret.ExpiresAtUnix {
			private, err := decodePrivate(secret.PrivateBase64)
			if err != nil {
				return nil, err
			}
			return private, nil
		}
	}
	return nil, ErrPrekeyUnavailable
}

// PrunePrekeys removes expired private material while retaining the public
// generation and revocation history. Filesystems may retain old blocks, so
// this is logical key erasure; storage-level secure deletion is an operator
// property, not something an atomic journal can promise.
func (l *LocalPrekeyLedger) PrunePrekeys(endpointID string, now time.Time) error {
	if l == nil || l.journal == nil {
		return errors.New("no local prekey ledger")
	}
	if err := l.journal.usable(); err != nil {
		return err
	}
	if !ids.Endpoint.MatchString(endpointID) || now.IsZero() || now.Unix() < 0 {
		return errors.New("invalid prekey pruning request")
	}
	l.journal.mutex.Lock()
	defer l.journal.mutex.Unlock()
	record, found, err := l.read(endpointID)
	if err != nil || !found {
		return err
	}
	current := liveSecrets(record.CurrentSecrets, uint64(now.Unix()))
	retired := liveSecrets(record.RetiredSecrets, uint64(now.Unix()))
	if len(current) == len(record.CurrentSecrets) && len(retired) == len(record.RetiredSecrets) {
		return nil
	}
	record.CurrentSecrets = current
	record.RetiredSecrets = retired
	record.UpdatedAtUnix = uint64(now.Unix())
	encoded, err := json.Marshal(record)
	if err != nil {
		return err
	}
	return l.journal.replace(l.path(endpointID), encoded)
}

func validatePrekeyInputs(delegation identity.Delegation, signer crypto.Signer, suite e2ee.Suite,
	plan PrekeyPlan, now time.Time) ([]string, uint64, uint64, error) {
	if err := identity.CheckWindow(delegation, now); err != nil {
		return nil, 0, 0, err
	}
	if signer == nil || suite == nil {
		return nil, 0, 0, errors.New("prekey publication needs a signer and suite")
	}
	public, ok := signer.Public().(ed25519.PublicKey)
	if !ok || !bytes.Equal(public, delegation.IdentityPublicKey) {
		return nil, 0, 0, errors.New("prekey signer is not the delegated endpoint key")
	}
	if err := e2ee.ValidateAlgorithmID(suite.AlgorithmID()); err != nil {
		return nil, 0, 0, err
	}
	if plan.Lifetime < time.Second || plan.Lifetime%time.Second != 0 ||
		plan.Lifetime > time.Duration(e2ee.MaxBundleLifetimeSeconds)*time.Second {
		return nil, 0, 0, errors.New("invalid prekey lifetime")
	}
	if plan.ReplenishBefore < 0 || plan.ReplenishBefore%time.Second != 0 || plan.ReplenishBefore >= plan.Lifetime {
		return nil, 0, 0, errors.New("invalid prekey replenishment horizon")
	}
	if len(plan.DeviceIDs) == 0 || len(plan.DeviceIDs) > e2ee.MaxDevicesPerSet {
		return nil, 0, 0, errors.New("invalid prekey device set size")
	}
	devices := append([]string(nil), plan.DeviceIDs...)
	sort.Strings(devices)
	for index, deviceID := range devices {
		if !ids.Device.MatchString(deviceID) || index > 0 && devices[index-1] == deviceID {
			return nil, 0, 0, errors.New("invalid prekey device set")
		}
	}
	return devices, uint64(plan.Lifetime / time.Second), uint64(plan.ReplenishBefore / time.Second), nil
}

func (l *LocalPrekeyLedger) read(endpointID string) (localPrekeyRecord, bool, error) {
	raw, err := os.ReadFile(l.path(endpointID))
	if errors.Is(err, os.ErrNotExist) {
		return localPrekeyRecord{}, false, nil
	}
	if err != nil {
		return localPrekeyRecord{}, false, errors.New("read local prekey record")
	}
	if len(raw) == 0 || len(raw) > MaxRecordBytes {
		return localPrekeyRecord{}, false, errors.New("local prekey record exceeds its bound")
	}
	var record localPrekeyRecord
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&record); err != nil {
		return localPrekeyRecord{}, false, errors.New("invalid local prekey record")
	}
	if err := decoder.Decode(new(any)); !errors.Is(err, io.EOF) {
		return localPrekeyRecord{}, false, errors.New("local prekey record has trailing JSON")
	}
	if record.Schema != LocalPrekeyRecordSchema || record.EndpointID != endpointID || record.UpdatedAtUnix == 0 {
		return localPrekeyRecord{}, false, errors.New("local prekey record describes another endpoint")
	}
	publication, err := publicationFromRecord(record)
	if err != nil {
		return localPrekeyRecord{}, false, err
	}
	if record.IssuedAtUnix != publication.IssuedAt || record.ExpiresAtUnix != publication.ExpiresAt {
		return localPrekeyRecord{}, false, errors.New("local prekey record has inconsistent bounds")
	}
	if err := validateStoredSecrets(record, publication); err != nil {
		return localPrekeyRecord{}, false, err
	}
	return record, true, nil
}

func publicationFromRecord(record localPrekeyRecord) (PrekeyPublication, error) {
	wire, err := base64.StdEncoding.Strict().DecodeString(record.BundleSetJSONBase64)
	if err != nil {
		return PrekeyPublication{}, errors.New("invalid stored prekey publication")
	}
	bundles, err := e2ee.DecodeBundleSetJSON(wire)
	if err != nil {
		return PrekeyPublication{}, errors.New("invalid stored prekey publication")
	}
	digest, err := e2ee.SetDigest(bundles)
	if err != nil || digest != record.SetDigest || bundles[0].EndpointID != record.EndpointID {
		return PrekeyPublication{}, errors.New("stored prekey publication has inconsistent identity")
	}
	issued, expires := bundles[0].IssuedAtUnix, bundles[0].ExpiresAtUnix
	for _, bundle := range bundles {
		if bundle.IssuedAtUnix != issued || bundle.ExpiresAtUnix != expires {
			return PrekeyPublication{}, errors.New("stored prekey publication is not one generation")
		}
	}
	return PrekeyPublication{
		EndpointID: record.EndpointID, SetDigest: digest, IssuedAt: issued, ExpiresAt: expires,
		Bundles: append([]e2ee.Bundle(nil), bundles...), BundleSetJSON: append([]byte(nil), wire...),
	}, nil
}

func validateStoredSecrets(record localPrekeyRecord, publication PrekeyPublication) error {
	if len(record.RetiredSecrets) > MaxRetiredPrekeySecrets || len(record.Tombstones) > MaxLocalPrekeyTombstones {
		return errors.New("local prekey history exceeds its bound")
	}
	expected := make(map[string]e2ee.Bundle, len(publication.Bundles))
	for _, bundle := range publication.Bundles {
		digest, _ := e2ee.BundleDigest(bundle)
		expected[digest] = bundle
	}
	seen := make(map[string]struct{}, len(record.CurrentSecrets)+len(record.RetiredSecrets))
	for _, secret := range append(append([]storedPrekeySecret(nil), record.CurrentSecrets...), record.RetiredSecrets...) {
		if !canon.ValidDigest(secret.BundleDigest) || !ids.Device.MatchString(secret.DeviceID) ||
			e2ee.ValidateAlgorithmID(secret.AlgorithmID) != nil || secret.ExpiresAtUnix == 0 {
			return errors.New("invalid stored prekey secret")
		}
		if _, duplicate := seen[secret.BundleDigest]; duplicate {
			return errors.New("duplicate stored prekey secret")
		}
		seen[secret.BundleDigest] = struct{}{}
		private, err := decodePrivate(secret.PrivateBase64)
		if err != nil {
			return err
		}
		if !canon.ValidDigest(secret.PrivateDigest) || canon.Digest(private) != secret.PrivateDigest {
			clear(private)
			return errors.New("stored private prekey material changed")
		}
		clear(private)
	}
	if len(record.CurrentSecrets) != 0 && len(record.CurrentSecrets) != len(expected) {
		return errors.New("stored current prekey secrets are incomplete")
	}
	if len(record.CurrentSecrets) == 0 && record.ExpiresAtUnix > record.UpdatedAtUnix {
		return errors.New("live current prekey secrets are missing")
	}
	for _, secret := range record.CurrentSecrets {
		bundle, ok := expected[secret.BundleDigest]
		if !ok || bundle.DeviceID != secret.DeviceID || bundle.AlgorithmID != secret.AlgorithmID ||
			bundle.ExpiresAtUnix != secret.ExpiresAtUnix {
			return errors.New("stored current prekey secret does not match its bundle")
		}
	}
	for index, tombstone := range record.Tombstones {
		if !ids.Device.MatchString(tombstone) || index > 0 && record.Tombstones[index-1] >= tombstone ||
			contains(currentDeviceIDs(record), tombstone) {
			return errors.New("invalid local prekey tombstone")
		}
		for _, secret := range record.RetiredSecrets {
			if secret.DeviceID == tombstone {
				return errors.New("a revoked device retains private prekey material")
			}
		}
	}
	return nil
}

func decodePrivate(encoded string) ([]byte, error) {
	private, err := base64.StdEncoding.Strict().DecodeString(encoded)
	if err != nil || len(private) == 0 || len(private) > MaxPrivatePrekeyBytes || canon.IsZero(private) {
		return nil, errors.New("invalid stored private prekey material")
	}
	return private, nil
}

func currentDeviceIDs(record localPrekeyRecord) []string {
	publication, err := publicationFromRecord(record)
	if err != nil {
		return nil
	}
	devices := make([]string, 0, len(publication.Bundles))
	for _, bundle := range publication.Bundles {
		devices = append(devices, bundle.DeviceID)
	}
	return devices
}

func sameDevices(bundles []e2ee.Bundle, devices []string) bool {
	if len(bundles) != len(devices) {
		return false
	}
	held := make([]string, 0, len(bundles))
	for _, bundle := range bundles {
		held = append(held, bundle.DeviceID)
	}
	sort.Strings(held)
	return equalStrings(held, devices)
}

func liveSecrets(secrets []storedPrekeySecret, now uint64) []storedPrekeySecret {
	live := make([]storedPrekeySecret, 0, len(secrets))
	for _, secret := range secrets {
		if now < secret.ExpiresAtUnix {
			live = append(live, secret)
		}
	}
	return live
}

func liveSecretsForDevices(secrets []storedPrekeySecret, devices []string, now uint64) []storedPrekeySecret {
	live := make([]storedPrekeySecret, 0, len(secrets))
	for _, secret := range secrets {
		if now < secret.ExpiresAtUnix && contains(devices, secret.DeviceID) {
			live = append(live, secret)
		}
	}
	return live
}

func clearSecrets(secrets []storedPrekeySecret) {
	for index := range secrets {
		secrets[index].PrivateBase64 = ""
	}
}

func contains(values []string, value string) bool {
	for _, candidate := range values {
		if candidate == value {
			return true
		}
	}
	return false
}

func equalStrings(first, second []string) bool {
	if len(first) != len(second) {
		return false
	}
	for index := range first {
		if first[index] != second[index] {
			return false
		}
	}
	return true
}

func (l *LocalPrekeyLedger) path(endpointID string) string {
	return filepath.Join(l.journal.root, localPrekeyDir, endpointID[len("mep_"):]+".json")
}
