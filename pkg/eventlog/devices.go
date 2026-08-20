package eventlog

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"time"

	"github.com/tosnetwork/tos-messenger/internal/ids"
	"github.com/tosnetwork/tos-messenger/pkg/e2ee"
	"github.com/tosnetwork/tos-messenger/pkg/identity"
)

const (
	deviceDir = "devices"

	// DeviceRecordSchema is the on-disk schema of one peer's device history.
	DeviceRecordSchema = "tos.messaging.device-ledger.v1"

	// MaxTombstones bounds how many revocations one peer's record carries.
	// Tombstones are permanent by design, so without a bound a peer could
	// grow this record forever by rotating; at the bound, further rotation
	// from that peer is refused rather than forgetting a revocation.
	MaxTombstones = 256
)

// ErrDeviceRollback reports a set older than the one on record.
var ErrDeviceRollback = e2ee.ErrSetRollback

// ErrDeviceEquivocation reports two non-retirement sets at the same freshness
// watermark. It aliases the protocol-level refusal so callers can classify it
// at either layer and inspect e2ee.SetEquivocationError for both digests.
var ErrDeviceEquivocation = e2ee.ErrSetEquivocation

// ErrRevokedDevice reports a device that was removed and came back.
var ErrRevokedDevice = errors.New("a revoked device reappeared")

// DeviceRecord is what this installation remembers about one endpoint's
// devices.
//
// It exists because a directory entry is replayable by whoever can reach the
// DHT. The descriptor's own freshness rules stop stale locators; this record
// stops a stale *device set* -- an attacker replaying the set from before a
// compromise was cleaned up would otherwise reinstate the compromised device.
type DeviceRecord struct {
	Schema     string   `json:"schema"`
	EndpointID string   `json:"messaging_endpoint_id"`
	SetDigest  string   `json:"set_digest"`
	DeviceIDs  []string `json:"device_ids"`
	// BundleDigests lets a pure retirement be recognised on the next
	// succession.
	BundleDigests      []string `json:"bundle_digests"`
	NewestIssuedAtUnix uint64   `json:"newest_issued_at_unix"`
	// Tombstones are devices that left. They never return.
	Tombstones    []string `json:"tombstones,omitempty"`
	UpdatedAtUnix uint64   `json:"updated_at_unix"`
}

// DeviceLedger records device-set successions per peer endpoint.
type DeviceLedger struct{ journal *Journal }

// OpenDevices returns the ledger for this installation.
func (j *Journal) OpenDevices() (*DeviceLedger, error) {
	if err := j.usable(); err != nil {
		return nil, err
	}
	return &DeviceLedger{journal: j}, nil
}

// AcceptSet judges a peer's published set against the record and, when it
// succeeds, records it durably.
//
// The judgement and the recording are one operation on purpose: a caller that
// judged first and recorded later could act on an accepted set that a crash
// then forgot, and the next sight of the same set would re-run removals whose
// sessions were already closed.
func (l *DeviceLedger) AcceptSet(endpointID string, bundles []e2ee.Bundle, now time.Time) (e2ee.Succession, error) {
	if l == nil {
		return e2ee.Succession{}, errors.New("no device ledger")
	}
	if err := l.journal.usable(); err != nil {
		return e2ee.Succession{}, err
	}
	if !ids.Endpoint.MatchString(endpointID) {
		return e2ee.Succession{}, errors.New("invalid endpoint identifier")
	}
	if now.IsZero() || now.Unix() < 0 {
		return e2ee.Succession{}, errors.New("invalid time")
	}
	l.journal.mutex.Lock()
	defer l.journal.mutex.Unlock()

	record, found, err := l.read(endpointID)
	if err != nil {
		return e2ee.Succession{}, err
	}
	current := e2ee.SetSummary{}
	tombstones := map[string]struct{}{}
	if found {
		current = e2ee.SetSummary{
			Digest: record.SetDigest, EndpointID: record.EndpointID,
			DeviceIDs: record.DeviceIDs, BundleDigests: record.BundleDigests,
			NewestIssuedAtUnix: record.NewestIssuedAtUnix,
		}
		for _, device := range record.Tombstones {
			tombstones[device] = struct{}{}
		}
	}
	succession, err := e2ee.Succeed(current, tombstones, bundles)
	if err != nil {
		return e2ee.Succession{}, err
	}
	if succession.Accepted.EndpointID != endpointID {
		return e2ee.Succession{}, errors.New("the set belongs to another endpoint")
	}
	if succession.Accepted.Digest == record.SetDigest {
		// Nothing changed; nothing is rewritten and nothing is re-removed.
		return e2ee.Succession{Accepted: succession.Accepted}, nil
	}
	if len(record.Tombstones)+len(succession.Removed) > MaxTombstones {
		return e2ee.Succession{}, errors.New("this peer has revoked more devices than a record may carry")
	}

	record = DeviceRecord{
		Schema: DeviceRecordSchema, EndpointID: endpointID,
		SetDigest:          succession.Accepted.Digest,
		DeviceIDs:          succession.Accepted.DeviceIDs,
		BundleDigests:      succession.Accepted.BundleDigests,
		NewestIssuedAtUnix: succession.Accepted.NewestIssuedAtUnix,
		Tombstones:         append(record.Tombstones, succession.Removed...),
		UpdatedAtUnix:      uint64(now.Unix()),
	}
	encoded, err := json.Marshal(record)
	if err != nil {
		return e2ee.Succession{}, err
	}
	if err := l.journal.replace(l.path(endpointID), encoded); err != nil {
		return e2ee.Succession{}, err
	}
	return succession, nil
}

// AdmitPublishedSet is the descriptor-fetch populate path: it takes a peer's
// published prekey set, checks it belongs to the delegated endpoint and
// matches what the descriptor committed, and only then submits it to
// succession.
//
// The three checks are one operation on purpose. Binding to the delegation
// establishes the set is signed by the endpoint's own key; matching the
// descriptor commitment establishes it is the set the peer actually published,
// not one a DHT replayer substituted; succession establishes it is newer than
// what is on record and free of revoked devices. Skipping any one of them
// would let the ledger record a set the peer never stood behind.
func (l *DeviceLedger) AdmitPublishedSet(delegation identity.Delegation, committedDigest string,
	bundles []e2ee.Bundle, now time.Time) (e2ee.Succession, error) {
	if l == nil {
		return e2ee.Succession{}, errors.New("no device ledger")
	}
	if err := e2ee.BindBundleSet(delegation, bundles, committedDigest, now); err != nil {
		return e2ee.Succession{}, err
	}
	return l.AcceptSet(delegation.EndpointID, bundles, now)
}

// Judge reports how an inbound claim of (endpoint, device) stands against the
// record.
//
// Three answers, three remedies. A revoked device is refused permanently. A
// device on the current set passes. A device this record has never seen is
// neither: the peer may have rotated since the set was last fetched, so the
// remedy is a directory refresh, not a refusal that would cut off every
// freshly added device.
type DeviceStanding string

const (
	// DeviceCurrent is on the recorded set.
	DeviceCurrent DeviceStanding = "current"
	// DeviceRevoked was removed and never returns.
	DeviceRevoked DeviceStanding = "revoked"
	// DeviceUnknown is not on record; the record may be stale.
	DeviceUnknown DeviceStanding = "unknown"
)

// Judge classifies one device claim.
func (l *DeviceLedger) Judge(endpointID, deviceID string) (DeviceStanding, error) {
	if l == nil {
		return "", errors.New("no device ledger")
	}
	if err := l.journal.usable(); err != nil {
		return "", err
	}
	if !ids.Endpoint.MatchString(endpointID) || !ids.Device.MatchString(deviceID) {
		return "", errors.New("invalid device claim")
	}
	l.journal.mutex.Lock()
	defer l.journal.mutex.Unlock()

	record, found, err := l.read(endpointID)
	if err != nil {
		return "", err
	}
	if !found {
		return DeviceUnknown, nil
	}
	for _, tombstone := range record.Tombstones {
		if tombstone == deviceID {
			return DeviceRevoked, nil
		}
	}
	for _, device := range record.DeviceIDs {
		if device == deviceID {
			return DeviceCurrent, nil
		}
	}
	return DeviceUnknown, nil
}

// Record returns what is on file for one endpoint.
func (l *DeviceLedger) Record(endpointID string) (DeviceRecord, bool, error) {
	if l == nil {
		return DeviceRecord{}, false, errors.New("no device ledger")
	}
	if err := l.journal.usable(); err != nil {
		return DeviceRecord{}, false, err
	}
	if !ids.Endpoint.MatchString(endpointID) {
		return DeviceRecord{}, false, errors.New("invalid endpoint identifier")
	}
	l.journal.mutex.Lock()
	defer l.journal.mutex.Unlock()
	return l.read(endpointID)
}

func (l *DeviceLedger) read(endpointID string) (DeviceRecord, bool, error) {
	raw, err := os.ReadFile(l.path(endpointID))
	if errors.Is(err, os.ErrNotExist) {
		return DeviceRecord{}, false, nil
	}
	if err != nil {
		return DeviceRecord{}, false, errors.New("read device record")
	}
	if len(raw) > MaxRecordBytes {
		return DeviceRecord{}, false, errors.New("device record exceeds its bound")
	}
	var record DeviceRecord
	if err := json.Unmarshal(raw, &record); err != nil {
		return DeviceRecord{}, false, errors.New("invalid device record")
	}
	if record.Schema != DeviceRecordSchema || record.EndpointID != endpointID {
		return DeviceRecord{}, false, errors.New("device record describes another endpoint")
	}
	return record, true, nil
}

func (l *DeviceLedger) path(endpointID string) string {
	return filepath.Join(l.journal.root, deviceDir, endpointID[len("mep_"):]+".json")
}
