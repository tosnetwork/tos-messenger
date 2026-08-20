package eventlog

import (
	"bytes"
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
	prekeyContributionDir = "prekey-contributions"

	// PrekeyContributionRecordSchema identifies a bounded public-only staging
	// record. The record deliberately has no field capable of carrying device
	// private material.
	PrekeyContributionRecordSchema = "tos.messaging.prekey-contributions.v1"
)

var (
	// ErrPrekeyCollectionIncomplete means not every planned device has
	// contributed. Publishing a subset would silently revoke missing devices.
	ErrPrekeyCollectionIncomplete = errors.New("prekey contribution collection is incomplete")
	// ErrPrekeyCollectionUnfinalized prevents a newer plan from discarding live
	// submitted material before a complete generation reaches publication.
	ErrPrekeyCollectionUnfinalized = errors.New("prekey contribution collection is not finalized")
)

// PrekeyCollectionPlan fixes one coordinated public generation before any
// contribution is accepted. Device identifiers are canonicalized into sorted
// order; callers cannot change the roster after seeing submitted material.
type PrekeyCollectionPlan struct {
	DeviceIDs     []string
	AlgorithmID   string
	IssuedAtUnix  uint64
	ExpiresAtUnix uint64
}

// PrekeyCollection is public aggregation state. It contains signed public
// bundles only and is complete exactly when every planned device is present.
type PrekeyCollection struct {
	EndpointID         string
	Plan               PrekeyCollectionPlan
	Contributions      []e2ee.Bundle
	Complete           bool
	FinalizedSetDigest string
}

type storedPrekeyContribution struct {
	DeviceID         string `json:"device_id"`
	BundleJSONBase64 string `json:"bundle_json_base64"`
	BundleDigest     string `json:"bundle_digest"`
	WireDigest       string `json:"wire_digest"`
}

type prekeyContributionRecord struct {
	Schema             string                     `json:"schema"`
	EndpointID         string                     `json:"messaging_endpoint_id"`
	DeviceIDs          []string                   `json:"device_ids"`
	AlgorithmID        string                     `json:"algorithm_id"`
	IssuedAtUnix       uint64                     `json:"issued_at_unix"`
	ExpiresAtUnix      uint64                     `json:"expires_at_unix"`
	Contributions      []storedPrekeyContribution `json:"contributions,omitempty"`
	FinalizedSetDigest string                     `json:"finalized_set_digest,omitempty"`
	UpdatedAtUnix      uint64                     `json:"updated_at_unix"`
}

// PrekeyContributionLedger stages independently custodied devices' signed
// public contributions before the existing publication ledger accepts a
// complete generation.
type PrekeyContributionLedger struct{ journal *Journal }

// OpenPrekeyContributions opens the public-only staging ledger.
func (j *Journal) OpenPrekeyContributions() (*PrekeyContributionLedger, error) {
	if err := j.usable(); err != nil {
		return nil, err
	}
	return &PrekeyContributionLedger{journal: j}, nil
}

// BeginPrekeyCollection durably fixes the roster, suite, and validity window.
// A later generation cannot discard live submitted material until Finalize
// has made a complete set recoverably visible to the publication ledger.
func (l *PrekeyContributionLedger) BeginPrekeyCollection(delegation identity.Delegation,
	plan PrekeyCollectionPlan, now time.Time) (PrekeyCollection, bool, error) {
	if l == nil || l.journal == nil {
		return PrekeyCollection{}, false, errors.New("no prekey contribution ledger")
	}
	if err := l.journal.usable(); err != nil {
		return PrekeyCollection{}, false, err
	}
	plan, err := normalizePrekeyCollectionPlan(delegation, plan, now)
	if err != nil {
		return PrekeyCollection{}, false, err
	}

	l.journal.mutex.Lock()
	defer l.journal.mutex.Unlock()
	record, found, err := l.read(delegation.EndpointID)
	if err != nil {
		return PrekeyCollection{}, false, err
	}
	if found {
		current, err := collectionFromContributionRecord(record)
		if err != nil {
			return PrekeyCollection{}, false, err
		}
		if equalPrekeyCollectionPlan(current.Plan, plan) {
			return current, false, nil
		}
		if plan.IssuedAtUnix < current.Plan.IssuedAtUnix {
			return PrekeyCollection{}, false, e2ee.ErrSetRollback
		}
		if plan.IssuedAtUnix == current.Plan.IssuedAtUnix {
			pureRetirement := current.FinalizedSetDigest != "" &&
				plan.AlgorithmID == current.Plan.AlgorithmID && plan.ExpiresAtUnix == current.Plan.ExpiresAtUnix &&
				strictDeviceSubset(plan.DeviceIDs, current.Plan.DeviceIDs)
			if !pureRetirement {
				return PrekeyCollection{}, false, ErrPrekeyEquivocation
			}
		}
		if len(current.Contributions) > 0 && current.FinalizedSetDigest == "" &&
			current.Plan.ExpiresAtUnix > uint64(now.Unix()) {
			return PrekeyCollection{}, false, ErrPrekeyCollectionUnfinalized
		}
	}
	record = prekeyContributionRecord{
		Schema: PrekeyContributionRecordSchema, EndpointID: delegation.EndpointID,
		DeviceIDs: append([]string(nil), plan.DeviceIDs...), AlgorithmID: plan.AlgorithmID,
		IssuedAtUnix: plan.IssuedAtUnix, ExpiresAtUnix: plan.ExpiresAtUnix,
		UpdatedAtUnix: uint64(now.Unix()),
	}
	if err := l.write(record); err != nil {
		return PrekeyCollection{}, false, err
	}
	collection, _ := collectionFromContributionRecord(record)
	return collection, true, nil
}

// AddPrekeyContribution verifies and durably adds one planned device's signed
// public bundle. Exact retries are idempotent; conflicting bytes for one
// device and generation are refused as equivocation.
func (l *PrekeyContributionLedger) AddPrekeyContribution(delegation identity.Delegation,
	bundle e2ee.Bundle, now time.Time) (PrekeyCollection, bool, error) {
	if l == nil || l.journal == nil {
		return PrekeyCollection{}, false, errors.New("no prekey contribution ledger")
	}
	if err := l.journal.usable(); err != nil {
		return PrekeyCollection{}, false, err
	}
	if err := e2ee.BindBundle(delegation, bundle, now); err != nil {
		return PrekeyCollection{}, false, err
	}
	wire, err := e2ee.EncodeBundleJSON(bundle)
	if err != nil {
		return PrekeyCollection{}, false, err
	}
	digest, err := e2ee.BundleDigest(bundle)
	if err != nil {
		return PrekeyCollection{}, false, err
	}

	l.journal.mutex.Lock()
	defer l.journal.mutex.Unlock()
	record, found, err := l.read(delegation.EndpointID)
	if err != nil {
		return PrekeyCollection{}, false, err
	}
	if !found {
		return PrekeyCollection{}, false, errors.New("prekey contribution collection is not planned")
	}
	if bundle.AlgorithmID != record.AlgorithmID || bundle.IssuedAtUnix != record.IssuedAtUnix ||
		bundle.ExpiresAtUnix != record.ExpiresAtUnix || !containsPublicationValue(record.DeviceIDs, bundle.DeviceID) {
		return PrekeyCollection{}, false, errors.New("prekey contribution is outside the planned generation")
	}
	for _, existing := range record.Contributions {
		if existing.DeviceID != bundle.DeviceID {
			continue
		}
		storedWire, decodeErr := base64.StdEncoding.Strict().DecodeString(existing.BundleJSONBase64)
		if decodeErr != nil {
			return PrekeyCollection{}, false, errors.New("invalid stored prekey contribution")
		}
		if bytes.Equal(storedWire, wire) {
			collection, err := collectionFromContributionRecord(record)
			return collection, false, err
		}
		return PrekeyCollection{}, false, ErrPrekeyEquivocation
	}
	record.Contributions = append(record.Contributions, storedPrekeyContribution{
		DeviceID: bundle.DeviceID, BundleJSONBase64: base64.StdEncoding.EncodeToString(wire),
		BundleDigest: digest, WireDigest: canon.Digest(wire),
	})
	sort.Slice(record.Contributions, func(i, j int) bool {
		return record.Contributions[i].DeviceID < record.Contributions[j].DeviceID
	})
	record.UpdatedAtUnix = uint64(now.Unix())
	if err := l.write(record); err != nil {
		return PrekeyCollection{}, false, err
	}
	collection, err := collectionFromContributionRecord(record)
	return collection, true, err
}

// CurrentPrekeyCollection reloads and reauthenticates the complete public
// staging state under the current delegation.
func (l *PrekeyContributionLedger) CurrentPrekeyCollection(delegation identity.Delegation,
	now time.Time) (PrekeyCollection, bool, error) {
	if l == nil || l.journal == nil {
		return PrekeyCollection{}, false, errors.New("no prekey contribution ledger")
	}
	if err := l.journal.usable(); err != nil {
		return PrekeyCollection{}, false, err
	}
	if err := identity.CheckWindow(delegation, now); err != nil {
		return PrekeyCollection{}, false, err
	}
	l.journal.mutex.Lock()
	defer l.journal.mutex.Unlock()
	record, found, err := l.read(delegation.EndpointID)
	if err != nil || !found {
		return PrekeyCollection{}, found, err
	}
	collection, err := collectionFromContributionRecord(record)
	if err != nil {
		return PrekeyCollection{}, false, err
	}
	for _, bundle := range collection.Contributions {
		if err := e2ee.BindBundle(delegation, bundle, now); err != nil {
			return PrekeyCollection{}, false, err
		}
	}
	return collection, true, nil
}

// StoredPrekeyCollection returns structurally verified public scheduler state
// without treating it as current endpoint authority. It exists so a planner
// can recognize an expired generation (whose bundle signatures necessarily
// fail a current-time check) and replace it. Consumers of live contributions
// must use CurrentPrekeyCollection instead.
func (l *PrekeyContributionLedger) StoredPrekeyCollection(endpointID string) (PrekeyCollection, bool, error) {
	if l == nil || l.journal == nil {
		return PrekeyCollection{}, false, errors.New("no prekey contribution ledger")
	}
	if err := l.journal.usable(); err != nil {
		return PrekeyCollection{}, false, err
	}
	if !ids.Endpoint.MatchString(endpointID) {
		return PrekeyCollection{}, false, errors.New("invalid prekey collection endpoint")
	}
	l.journal.mutex.Lock()
	defer l.journal.mutex.Unlock()
	record, found, err := l.read(endpointID)
	if err != nil || !found {
		return PrekeyCollection{}, found, err
	}
	collection, err := collectionFromContributionRecord(record)
	return collection, err == nil, err
}

// FinalizePrekeyCollection advances the publication ledger only for an exact
// complete roster, then marks the staging generation finalized. A crash
// between those writes is repaired by an idempotent retry.
func (l *PrekeyContributionLedger) FinalizePrekeyCollection(delegation identity.Delegation,
	publications *PrekeyPublicationLedger, now time.Time) (PrekeyPublication, bool, error) {
	if l == nil || l.journal == nil {
		return PrekeyPublication{}, false, errors.New("no prekey contribution ledger")
	}
	if publications == nil || publications.journal == nil {
		return PrekeyPublication{}, false, errors.New("no prekey publication ledger")
	}
	if publications.journal != l.journal {
		return PrekeyPublication{}, false, errors.New("prekey collection and publication must share one journal")
	}
	collection, found, err := l.CurrentPrekeyCollection(delegation, now)
	if err != nil {
		return PrekeyPublication{}, false, err
	}
	if !found || !collection.Complete {
		return PrekeyPublication{}, false, ErrPrekeyCollectionIncomplete
	}
	publication, created, err := publications.PreparePrekeyPublication(delegation, collection.Contributions, now)
	if err != nil {
		return PrekeyPublication{}, false, err
	}

	l.journal.mutex.Lock()
	defer l.journal.mutex.Unlock()
	record, found, err := l.read(delegation.EndpointID)
	if err != nil || !found {
		return PrekeyPublication{}, false, errors.New("prekey contribution collection disappeared during finalization")
	}
	current, err := collectionFromContributionRecord(record)
	if err != nil || !current.Complete || !equalPrekeyCollectionPlan(current.Plan, collection.Plan) {
		return PrekeyPublication{}, false, errors.New("prekey contribution collection changed during finalization")
	}
	if current.FinalizedSetDigest != "" && current.FinalizedSetDigest != publication.SetDigest {
		return PrekeyPublication{}, false, ErrPrekeyEquivocation
	}
	record.FinalizedSetDigest = publication.SetDigest
	record.UpdatedAtUnix = uint64(now.Unix())
	if err := l.write(record); err != nil {
		return PrekeyPublication{}, false, err
	}
	return publication, created, nil
}

func normalizePrekeyCollectionPlan(delegation identity.Delegation, plan PrekeyCollectionPlan,
	now time.Time) (PrekeyCollectionPlan, error) {
	if err := identity.CheckWindow(delegation, now); err != nil {
		return PrekeyCollectionPlan{}, err
	}
	if now.Unix() < 0 {
		return PrekeyCollectionPlan{}, errors.New("invalid prekey collection time")
	}
	if err := e2ee.ValidateAlgorithmID(plan.AlgorithmID); err != nil {
		return PrekeyCollectionPlan{}, err
	}
	if len(plan.DeviceIDs) == 0 || len(plan.DeviceIDs) > e2ee.MaxDevicesPerSet ||
		plan.IssuedAtUnix == 0 || plan.IssuedAtUnix > uint64(now.Unix()) ||
		plan.ExpiresAtUnix <= uint64(now.Unix()) || plan.ExpiresAtUnix <= plan.IssuedAtUnix ||
		plan.ExpiresAtUnix-plan.IssuedAtUnix > e2ee.MaxBundleLifetimeSeconds ||
		plan.ExpiresAtUnix > delegation.ExpiresAtUnix {
		return PrekeyCollectionPlan{}, errors.New("invalid prekey collection plan")
	}
	plan.DeviceIDs = append([]string(nil), plan.DeviceIDs...)
	sort.Strings(plan.DeviceIDs)
	for index, deviceID := range plan.DeviceIDs {
		if !ids.Device.MatchString(deviceID) || index > 0 && plan.DeviceIDs[index-1] == deviceID {
			return PrekeyCollectionPlan{}, errors.New("invalid prekey collection roster")
		}
	}
	return plan, nil
}

func collectionFromContributionRecord(record prekeyContributionRecord) (PrekeyCollection, error) {
	plan := PrekeyCollectionPlan{
		DeviceIDs: append([]string(nil), record.DeviceIDs...), AlgorithmID: record.AlgorithmID,
		IssuedAtUnix: record.IssuedAtUnix, ExpiresAtUnix: record.ExpiresAtUnix,
	}
	contributions := make([]e2ee.Bundle, 0, len(record.Contributions))
	for _, stored := range record.Contributions {
		wire, err := base64.StdEncoding.Strict().DecodeString(stored.BundleJSONBase64)
		if err != nil || canon.Digest(wire) != stored.WireDigest {
			return PrekeyCollection{}, errors.New("invalid stored prekey contribution")
		}
		bundle, err := e2ee.DecodeBundleJSON(wire)
		if err != nil {
			return PrekeyCollection{}, errors.New("invalid stored prekey contribution")
		}
		canonical, err := e2ee.EncodeBundleJSON(bundle)
		digest, digestErr := e2ee.BundleDigest(bundle)
		if err != nil || digestErr != nil || !bytes.Equal(canonical, wire) || digest != stored.BundleDigest ||
			bundle.DeviceID != stored.DeviceID || bundle.EndpointID != record.EndpointID ||
			bundle.AlgorithmID != record.AlgorithmID || bundle.IssuedAtUnix != record.IssuedAtUnix ||
			bundle.ExpiresAtUnix != record.ExpiresAtUnix {
			return PrekeyCollection{}, errors.New("stored prekey contribution is inconsistent")
		}
		contributions = append(contributions, bundle)
	}
	collection := PrekeyCollection{
		EndpointID: record.EndpointID, Plan: plan, Contributions: contributions,
		Complete: len(contributions) == len(plan.DeviceIDs), FinalizedSetDigest: record.FinalizedSetDigest,
	}
	if record.FinalizedSetDigest != "" {
		digest, err := e2ee.SetDigest(contributions)
		if err != nil || digest != record.FinalizedSetDigest || !collection.Complete {
			return PrekeyCollection{}, errors.New("finalized prekey contribution set is inconsistent")
		}
	}
	return collection, nil
}

func (l *PrekeyContributionLedger) read(endpointID string) (prekeyContributionRecord, bool, error) {
	raw, err := os.ReadFile(l.path(endpointID))
	if errors.Is(err, os.ErrNotExist) {
		return prekeyContributionRecord{}, false, nil
	}
	if err != nil {
		return prekeyContributionRecord{}, false, errors.New("read prekey contribution record")
	}
	if len(raw) == 0 || len(raw) > MaxRecordBytes {
		return prekeyContributionRecord{}, false, errors.New("prekey contribution record exceeds its bound")
	}
	var record prekeyContributionRecord
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&record); err != nil {
		return prekeyContributionRecord{}, false, errors.New("invalid prekey contribution record")
	}
	if err := decoder.Decode(new(any)); !errors.Is(err, io.EOF) {
		return prekeyContributionRecord{}, false, errors.New("prekey contribution record has trailing JSON")
	}
	if record.Schema != PrekeyContributionRecordSchema || record.EndpointID != endpointID ||
		!ids.Endpoint.MatchString(record.EndpointID) || record.UpdatedAtUnix == 0 ||
		len(record.DeviceIDs) == 0 || len(record.DeviceIDs) > e2ee.MaxDevicesPerSet ||
		len(record.Contributions) > len(record.DeviceIDs) || record.IssuedAtUnix == 0 ||
		record.ExpiresAtUnix <= record.IssuedAtUnix ||
		record.ExpiresAtUnix-record.IssuedAtUnix > e2ee.MaxBundleLifetimeSeconds ||
		e2ee.ValidateAlgorithmID(record.AlgorithmID) != nil {
		return prekeyContributionRecord{}, false, errors.New("prekey contribution record has inconsistent identity")
	}
	for index, deviceID := range record.DeviceIDs {
		if !ids.Device.MatchString(deviceID) || index > 0 && record.DeviceIDs[index-1] >= deviceID {
			return prekeyContributionRecord{}, false, errors.New("invalid stored prekey contribution roster")
		}
	}
	for index, stored := range record.Contributions {
		if !containsPublicationValue(record.DeviceIDs, stored.DeviceID) || !canon.ValidDigest(stored.BundleDigest) ||
			!canon.ValidDigest(stored.WireDigest) || index > 0 && record.Contributions[index-1].DeviceID >= stored.DeviceID {
			return prekeyContributionRecord{}, false, errors.New("invalid stored prekey contribution index")
		}
	}
	if record.FinalizedSetDigest != "" && !canon.ValidDigest(record.FinalizedSetDigest) {
		return prekeyContributionRecord{}, false, errors.New("invalid finalized prekey contribution digest")
	}
	if _, err := collectionFromContributionRecord(record); err != nil {
		return prekeyContributionRecord{}, false, err
	}
	return record, true, nil
}

func (l *PrekeyContributionLedger) write(record prekeyContributionRecord) error {
	encoded, err := json.Marshal(record)
	if err != nil {
		return err
	}
	return l.journal.replace(l.path(record.EndpointID), encoded)
}

func (l *PrekeyContributionLedger) path(endpointID string) string {
	return filepath.Join(l.journal.root, prekeyContributionDir, endpointID[len("mep_"):]+".json")
}

func equalPrekeyCollectionPlan(left, right PrekeyCollectionPlan) bool {
	if left.AlgorithmID != right.AlgorithmID || left.IssuedAtUnix != right.IssuedAtUnix ||
		left.ExpiresAtUnix != right.ExpiresAtUnix || len(left.DeviceIDs) != len(right.DeviceIDs) {
		return false
	}
	for index := range left.DeviceIDs {
		if left.DeviceIDs[index] != right.DeviceIDs[index] {
			return false
		}
	}
	return true
}

func strictDeviceSubset(candidate, current []string) bool {
	if len(candidate) >= len(current) {
		return false
	}
	index := 0
	for _, deviceID := range current {
		if index < len(candidate) && candidate[index] == deviceID {
			index++
		}
	}
	return index == len(candidate)
}
