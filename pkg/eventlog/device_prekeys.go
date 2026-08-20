package eventlog

import (
	"bytes"
	"crypto"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"time"

	"github.com/tosnetwork/tos-messenger/internal/canon"
	"github.com/tosnetwork/tos-messenger/internal/ids"
	"github.com/tosnetwork/tos-messenger/pkg/e2ee"
	"github.com/tosnetwork/tos-messenger/pkg/identity"
)

const (
	devicePrekeyDir = "device-prekeys"

	// DevicePrekeyRecordSchema identifies private state owned by one local
	// device. Endpoint publication records deliberately never contain it.
	DevicePrekeyRecordSchema = "tos.messaging.device-prekeys.v1"
	// MaxPrivatePrekeyBytes bounds one suite's unpublished answering material.
	MaxPrivatePrekeyBytes = 4 << 10
	// MaxRetiredDevicePrekeys bounds live old generations for one device.
	MaxRetiredDevicePrekeys = 32
)

var (
	// ErrPrekeyEquivocation reports an attempt to create different device
	// material at an issuance timestamp this device already used.
	ErrPrekeyEquivocation = errors.New("prekey publication would equivocate")
	// ErrPrekeyUnavailable reports no live local secret for an exact bundle.
	ErrPrekeyUnavailable = errors.New("prekey private material is unavailable")
	// ErrDevicePrekeyRevoked reports a local device whose bootstrap authority
	// was permanently retired.
	ErrDevicePrekeyRevoked = errors.New("local device prekeys are revoked")
)

// DevicePrekeyPlan is an Endpoint-coordinated publication window. Separate
// devices receive the same issuance and expiry values, but each device creates
// and retains only its own opaque private material.
type DevicePrekeyPlan struct {
	IssuedAt        time.Time
	ExpiresAt       time.Time
	ReplenishBefore time.Duration
}

// DevicePrekey is the public contribution one device gives the Endpoint
// publication aggregator. Private material never appears in this value.
type DevicePrekey struct {
	Bundle       e2ee.Bundle
	BundleDigest string
}

type storedDevicePrekey struct {
	BundleJSONBase64 string `json:"bundle_json_base64"`
	BundleDigest     string `json:"bundle_digest"`
	PrivateBase64    string `json:"private_material_base64"`
	PrivateDigest    string `json:"private_material_digest"`
	ExpiresAtUnix    uint64 `json:"expires_at_unix"`
}

type devicePrekeyRecord struct {
	Schema        string               `json:"schema"`
	EndpointID    string               `json:"messaging_endpoint_id"`
	DeviceID      string               `json:"device_id"`
	LastIssuedAt  uint64               `json:"last_issued_at_unix"`
	Revoked       bool                 `json:"revoked,omitempty"`
	Current       *storedDevicePrekey  `json:"current,omitempty"`
	Retired       []storedDevicePrekey `json:"retired,omitempty"`
	UpdatedAtUnix uint64               `json:"updated_at_unix"`
}

// DevicePrekeyLedger owns private bootstrap material for local devices.
type DevicePrekeyLedger struct{ journal *Journal }

// OpenDevicePrekeys opens the private per-device ledger.
func (j *Journal) OpenDevicePrekeys() (*DevicePrekeyLedger, error) {
	if err := j.usable(); err != nil {
		return nil, err
	}
	return &DevicePrekeyLedger{journal: j}, nil
}

// EnsureDevicePrekey creates or reuses one device's contribution. The
// Endpoint signer authenticates the public bundle, while the private half is
// committed only into this device's private journal record.
func (l *DevicePrekeyLedger) EnsureDevicePrekey(delegation identity.Delegation, signer crypto.Signer,
	suite e2ee.Suite, deviceID string, plan DevicePrekeyPlan, now time.Time) (DevicePrekey, bool, error) {
	if l == nil || l.journal == nil {
		return DevicePrekey{}, false, errors.New("no device prekey ledger")
	}
	if err := l.journal.usable(); err != nil {
		return DevicePrekey{}, false, err
	}
	issued, expires, lead, err := validateDevicePrekeyInputs(delegation, signer, suite, deviceID, plan, now)
	if err != nil {
		return DevicePrekey{}, false, err
	}

	l.journal.mutex.Lock()
	defer l.journal.mutex.Unlock()
	record, found, err := l.read(delegation.EndpointID, deviceID)
	if err != nil {
		return DevicePrekey{}, false, err
	}
	if found {
		if record.Revoked {
			return DevicePrekey{}, false, ErrDevicePrekeyRevoked
		}
		if record.Current != nil {
			current, err := devicePrekeyFromStored(*record.Current)
			if err != nil {
				return DevicePrekey{}, false, err
			}
			if current.Bundle.AlgorithmID == suite.AlgorithmID() && current.Bundle.IssuedAtUnix == issued &&
				current.Bundle.ExpiresAtUnix == expires && expires > uint64(now.Unix())+lead &&
				e2ee.BindBundle(delegation, current.Bundle, now) == nil {
				return current, false, nil
			}
		}
		if issued <= record.LastIssuedAt {
			return DevicePrekey{}, false, ErrPrekeyEquivocation
		}
		live := liveDevicePrekeys(record.Retired, uint64(now.Unix()))
		if record.Current != nil && record.Current.ExpiresAtUnix > uint64(now.Unix()) {
			live = append(live, *record.Current)
		}
		if len(live) > MaxRetiredDevicePrekeys {
			return DevicePrekey{}, false, errors.New("too many live retired device prekeys")
		}
	}

	public, private, err := suite.NewPrekeyMaterial()
	if err != nil {
		return DevicePrekey{}, false, errors.New("generate device prekey material")
	}
	defer clear(private)
	if len(private) == 0 || len(private) > MaxPrivatePrekeyBytes || canon.IsZero(private) {
		return DevicePrekey{}, false, errors.New("invalid private device prekey material")
	}
	bundle, err := e2ee.SignBundleWith(e2ee.Bundle{
		Network: delegation.Network, AgentID: delegation.AgentID, EndpointID: delegation.EndpointID,
		DeviceID: deviceID, AlgorithmID: suite.AlgorithmID(), Material: append([]byte(nil), public...),
		IssuedAtUnix: issued, ExpiresAtUnix: expires,
	}, signer)
	if err != nil {
		return DevicePrekey{}, false, err
	}
	digest, err := e2ee.BundleDigest(bundle)
	if err != nil {
		return DevicePrekey{}, false, err
	}
	bundleJSON, err := e2ee.EncodeBundleJSON(bundle)
	if err != nil {
		return DevicePrekey{}, false, err
	}
	stored := storedDevicePrekey{
		BundleJSONBase64: base64.StdEncoding.EncodeToString(bundleJSON), BundleDigest: digest,
		PrivateBase64: base64.StdEncoding.EncodeToString(private), PrivateDigest: canon.Digest(private),
		ExpiresAtUnix: expires,
	}
	retired := []storedDevicePrekey(nil)
	if found {
		retired = liveDevicePrekeys(record.Retired, uint64(now.Unix()))
		if record.Current != nil && record.Current.ExpiresAtUnix > uint64(now.Unix()) {
			retired = append(retired, *record.Current)
		}
	}
	record = devicePrekeyRecord{
		Schema: DevicePrekeyRecordSchema, EndpointID: delegation.EndpointID, DeviceID: deviceID,
		LastIssuedAt: issued, Current: &stored, Retired: retired,
		UpdatedAtUnix: uint64(now.Unix()),
	}
	if err := l.write(record); err != nil {
		return DevicePrekey{}, false, err
	}
	return DevicePrekey{Bundle: bundle, BundleDigest: digest}, true, nil
}

// DevicePrekeyPrivate returns the answering material for one exact local
// device bundle. A caller cannot accidentally select another device's secret.
func (l *DevicePrekeyLedger) DevicePrekeyPrivate(endpointID, deviceID, bundleDigest string, now time.Time) ([]byte, error) {
	if l == nil || l.journal == nil {
		return nil, errors.New("no device prekey ledger")
	}
	if err := l.journal.usable(); err != nil {
		return nil, err
	}
	if !ids.Endpoint.MatchString(endpointID) || !ids.Device.MatchString(deviceID) ||
		!canon.ValidDigest(bundleDigest) || now.IsZero() || now.Unix() < 0 {
		return nil, errors.New("invalid device prekey selection")
	}
	l.journal.mutex.Lock()
	defer l.journal.mutex.Unlock()
	record, found, err := l.read(endpointID, deviceID)
	if err != nil {
		return nil, err
	}
	if !found || record.Revoked {
		return nil, ErrPrekeyUnavailable
	}
	values := append([]storedDevicePrekey(nil), record.Retired...)
	if record.Current != nil {
		values = append(values, *record.Current)
	}
	for _, value := range values {
		if value.BundleDigest == bundleDigest && uint64(now.Unix()) < value.ExpiresAtUnix {
			return decodeDevicePrivate(value)
		}
	}
	return nil, ErrPrekeyUnavailable
}

// RevokeDevicePrekeys permanently removes a local device's answering material
// before recording the tombstone. An exact retry is idempotent.
func (l *DevicePrekeyLedger) RevokeDevicePrekeys(endpointID, deviceID string, now time.Time) error {
	if l == nil || l.journal == nil {
		return errors.New("no device prekey ledger")
	}
	if err := l.journal.usable(); err != nil {
		return err
	}
	if !ids.Endpoint.MatchString(endpointID) || !ids.Device.MatchString(deviceID) || now.IsZero() || now.Unix() < 0 {
		return errors.New("invalid device prekey revocation")
	}
	l.journal.mutex.Lock()
	defer l.journal.mutex.Unlock()
	record, found, err := l.read(endpointID, deviceID)
	if err != nil {
		return err
	}
	if !found {
		return ErrPrekeyUnavailable
	}
	if record.Revoked {
		return nil
	}
	record.Revoked = true
	record.Current = nil
	record.Retired = nil
	record.UpdatedAtUnix = uint64(now.Unix())
	return l.write(record)
}

// PruneDevicePrekeys logically removes expired private generations.
func (l *DevicePrekeyLedger) PruneDevicePrekeys(endpointID, deviceID string, now time.Time) error {
	if l == nil || l.journal == nil {
		return errors.New("no device prekey ledger")
	}
	if err := l.journal.usable(); err != nil {
		return err
	}
	if !ids.Endpoint.MatchString(endpointID) || !ids.Device.MatchString(deviceID) || now.IsZero() || now.Unix() < 0 {
		return errors.New("invalid device prekey pruning request")
	}
	l.journal.mutex.Lock()
	defer l.journal.mutex.Unlock()
	record, found, err := l.read(endpointID, deviceID)
	if err != nil || !found || record.Revoked {
		return err
	}
	changed := false
	if record.Current != nil && record.Current.ExpiresAtUnix <= uint64(now.Unix()) {
		record.Current = nil
		changed = true
	}
	retired := liveDevicePrekeys(record.Retired, uint64(now.Unix()))
	if len(retired) != len(record.Retired) {
		record.Retired = retired
		changed = true
	}
	if !changed {
		return nil
	}
	record.UpdatedAtUnix = uint64(now.Unix())
	return l.write(record)
}

func validateDevicePrekeyInputs(delegation identity.Delegation, signer crypto.Signer, suite e2ee.Suite,
	deviceID string, plan DevicePrekeyPlan, now time.Time) (uint64, uint64, uint64, error) {
	if err := identity.CheckWindow(delegation, now); err != nil {
		return 0, 0, 0, err
	}
	if signer == nil || suite == nil || !ids.Device.MatchString(deviceID) {
		return 0, 0, 0, errors.New("device prekey needs a signer, suite, and device")
	}
	public, ok := signer.Public().(ed25519.PublicKey)
	if !ok || !bytes.Equal(public, delegation.IdentityPublicKey) {
		return 0, 0, 0, errors.New("device prekey signer is not the delegated Endpoint key")
	}
	if err := e2ee.ValidateAlgorithmID(suite.AlgorithmID()); err != nil {
		return 0, 0, 0, err
	}
	if plan.IssuedAt.IsZero() || plan.ExpiresAt.IsZero() || plan.IssuedAt.Unix() < 0 || plan.ExpiresAt.Unix() < 0 ||
		plan.IssuedAt.Nanosecond() != 0 || plan.ExpiresAt.Nanosecond() != 0 || plan.IssuedAt.After(now) ||
		!plan.ExpiresAt.After(plan.IssuedAt) || plan.ExpiresAt.Sub(plan.IssuedAt) > time.Duration(e2ee.MaxBundleLifetimeSeconds)*time.Second ||
		uint64(plan.ExpiresAt.Unix()) > delegation.ExpiresAtUnix {
		return 0, 0, 0, errors.New("invalid device prekey publication window")
	}
	if plan.ReplenishBefore < 0 || plan.ReplenishBefore%time.Second != 0 ||
		plan.ReplenishBefore >= plan.ExpiresAt.Sub(plan.IssuedAt) {
		return 0, 0, 0, errors.New("invalid device prekey replenishment horizon")
	}
	issued, expires := uint64(plan.IssuedAt.Unix()), uint64(plan.ExpiresAt.Unix())
	lead := uint64(plan.ReplenishBefore / time.Second)
	if expires <= uint64(now.Unix())+lead {
		return 0, 0, 0, errors.New("device prekey window cannot cover its replenishment horizon")
	}
	return issued, expires, lead, nil
}

func (l *DevicePrekeyLedger) read(endpointID, deviceID string) (devicePrekeyRecord, bool, error) {
	raw, err := os.ReadFile(l.path(deviceID))
	if errors.Is(err, os.ErrNotExist) {
		return devicePrekeyRecord{}, false, nil
	}
	if err != nil {
		return devicePrekeyRecord{}, false, errors.New("read device prekey record")
	}
	if len(raw) == 0 || len(raw) > MaxRecordBytes {
		return devicePrekeyRecord{}, false, errors.New("device prekey record exceeds its bound")
	}
	var record devicePrekeyRecord
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&record); err != nil {
		return devicePrekeyRecord{}, false, errors.New("invalid device prekey record")
	}
	if err := decoder.Decode(new(any)); !errors.Is(err, io.EOF) {
		return devicePrekeyRecord{}, false, errors.New("device prekey record has trailing JSON")
	}
	if record.Schema != DevicePrekeyRecordSchema || record.EndpointID != endpointID || record.DeviceID != deviceID ||
		record.UpdatedAtUnix == 0 || record.LastIssuedAt == 0 {
		return devicePrekeyRecord{}, false, errors.New("device prekey record has inconsistent identity")
	}
	if record.Revoked {
		if record.Current != nil || len(record.Retired) != 0 {
			return devicePrekeyRecord{}, false, errors.New("revoked device retains prekey material")
		}
		return record, true, nil
	}
	if len(record.Retired) > MaxRetiredDevicePrekeys {
		return devicePrekeyRecord{}, false, errors.New("device prekey record has invalid generations")
	}
	seen := make(map[string]struct{}, len(record.Retired)+1)
	values := append([]storedDevicePrekey(nil), record.Retired...)
	if record.Current != nil {
		current, err := devicePrekeyFromStored(*record.Current)
		if err != nil || current.Bundle.IssuedAtUnix != record.LastIssuedAt {
			return devicePrekeyRecord{}, false, errors.New("stored current device prekey has inconsistent generation")
		}
		values = append(values, *record.Current)
	}
	for _, value := range values {
		prekey, err := devicePrekeyFromStored(value)
		if err != nil || prekey.Bundle.EndpointID != endpointID || prekey.Bundle.DeviceID != deviceID ||
			value.ExpiresAtUnix != prekey.Bundle.ExpiresAtUnix {
			return devicePrekeyRecord{}, false, errors.New("stored device prekey is inconsistent")
		}
		if _, duplicate := seen[value.BundleDigest]; duplicate {
			return devicePrekeyRecord{}, false, errors.New("duplicate stored device prekey")
		}
		seen[value.BundleDigest] = struct{}{}
		private, err := decodeDevicePrivate(value)
		if err != nil {
			return devicePrekeyRecord{}, false, err
		}
		clear(private)
	}
	return record, true, nil
}

func (l *DevicePrekeyLedger) write(record devicePrekeyRecord) error {
	encoded, err := json.Marshal(record)
	if err != nil {
		return err
	}
	return l.journal.replace(l.path(record.DeviceID), encoded)
}

func devicePrekeyFromStored(value storedDevicePrekey) (DevicePrekey, error) {
	raw, err := base64.StdEncoding.Strict().DecodeString(value.BundleJSONBase64)
	if err != nil {
		return DevicePrekey{}, errors.New("invalid stored device prekey bundle")
	}
	bundle, err := e2ee.DecodeBundleJSON(raw)
	if err != nil {
		return DevicePrekey{}, errors.New("invalid stored device prekey bundle")
	}
	digest, err := e2ee.BundleDigest(bundle)
	if err != nil || digest != value.BundleDigest {
		return DevicePrekey{}, errors.New("stored device prekey digest changed")
	}
	return DevicePrekey{Bundle: bundle, BundleDigest: digest}, nil
}

func decodeDevicePrivate(value storedDevicePrekey) ([]byte, error) {
	private, err := base64.StdEncoding.Strict().DecodeString(value.PrivateBase64)
	if err != nil || len(private) == 0 || len(private) > MaxPrivatePrekeyBytes || canon.IsZero(private) ||
		!canon.ValidDigest(value.PrivateDigest) || canon.Digest(private) != value.PrivateDigest {
		return nil, errors.New("invalid stored private device prekey material")
	}
	return private, nil
}

func liveDevicePrekeys(values []storedDevicePrekey, now uint64) []storedDevicePrekey {
	live := make([]storedDevicePrekey, 0, len(values))
	for _, value := range values {
		if now < value.ExpiresAtUnix {
			live = append(live, value)
		}
	}
	return live
}

func (l *DevicePrekeyLedger) path(deviceID string) string {
	return filepath.Join(l.journal.root, devicePrekeyDir, deviceID[len("dev_"):]+".json")
}
