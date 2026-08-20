package eventlog

import (
	"bytes"
	"context"
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
	prekeyPublicationDir = "prekey-publications"

	// PrekeyPublicationRecordSchema identifies public Endpoint aggregation
	// state. Its records contain signed bundles and revocations, never device
	// private material.
	PrekeyPublicationRecordSchema = "tos.messaging.prekey-publication-state.v1"
	// MaxPrekeyPublicationTombstones bounds permanent device revocations.
	MaxPrekeyPublicationTombstones = 256
)

// PrekeyPublication is the immutable complete device object prepared for a
// descriptor. It contains public signed bundles only.
type PrekeyPublication struct {
	EndpointID    string
	SetDigest     string
	IssuedAt      uint64
	ExpiresAt     uint64
	Bundles       []e2ee.Bundle
	BundleSetJSON []byte
}

// PrekeyObjectSink stores the content-addressed public bundle-set object.
type PrekeyObjectSink interface {
	PutPrekeySet(context.Context, string, []byte) error
}

type prekeyPublicationRecord struct {
	Schema              string   `json:"schema"`
	EndpointID          string   `json:"messaging_endpoint_id"`
	SetDigest           string   `json:"set_digest"`
	IssuedAtUnix        uint64   `json:"issued_at_unix"`
	ExpiresAtUnix       uint64   `json:"expires_at_unix"`
	BundleSetJSONBase64 string   `json:"bundle_set_json_base64"`
	BundleSetWireDigest string   `json:"bundle_set_wire_digest"`
	Tombstones          []string `json:"tombstones,omitempty"`
	UpdatedAtUnix       uint64   `json:"updated_at_unix"`
}

// PrekeyPublicationLedger aggregates already signed public contributions.
// It is intentionally separate from DevicePrekeyLedger: an Endpoint may see
// every public bundle, but that does not entitle it to every device's secret.
type PrekeyPublicationLedger struct{ journal *Journal }

// OpenPrekeyPublications opens the public Endpoint aggregation ledger.
func (j *Journal) OpenPrekeyPublications() (*PrekeyPublicationLedger, error) {
	if err := j.usable(); err != nil {
		return nil, err
	}
	return &PrekeyPublicationLedger{journal: j}, nil
}

// PreparePrekeyPublication validates and durably records one complete public
// generation. Device private material is neither accepted nor derivable here.
func (l *PrekeyPublicationLedger) PreparePrekeyPublication(delegation identity.Delegation,
	bundles []e2ee.Bundle, now time.Time) (PrekeyPublication, bool, error) {
	if l == nil || l.journal == nil {
		return PrekeyPublication{}, false, errors.New("no prekey publication ledger")
	}
	if err := l.journal.usable(); err != nil {
		return PrekeyPublication{}, false, err
	}
	if now.IsZero() || now.Unix() < 0 {
		return PrekeyPublication{}, false, errors.New("invalid prekey publication time")
	}
	bundles = append([]e2ee.Bundle(nil), bundles...)
	sort.Slice(bundles, func(i, j int) bool { return bundles[i].DeviceID < bundles[j].DeviceID })
	digest, err := e2ee.SetDigest(bundles)
	if err != nil {
		return PrekeyPublication{}, false, err
	}
	if err := e2ee.BindBundleSet(delegation, bundles, digest, now); err != nil {
		return PrekeyPublication{}, false, err
	}
	issued, expires := bundles[0].IssuedAtUnix, bundles[0].ExpiresAtUnix
	for _, bundle := range bundles {
		if bundle.IssuedAtUnix != issued || bundle.ExpiresAtUnix != expires {
			return PrekeyPublication{}, false, errors.New("prekey publication is not one coordinated generation")
		}
	}
	wire, err := e2ee.EncodeBundleSetJSON(bundles)
	if err != nil {
		return PrekeyPublication{}, false, err
	}
	publication := PrekeyPublication{
		EndpointID: delegation.EndpointID, SetDigest: digest, IssuedAt: issued, ExpiresAt: expires,
		Bundles: bundles, BundleSetJSON: wire,
	}

	l.journal.mutex.Lock()
	defer l.journal.mutex.Unlock()
	record, found, err := l.read(delegation.EndpointID)
	if err != nil {
		return PrekeyPublication{}, false, err
	}
	if found && record.SetDigest == digest {
		current, err := publicationFromRecord(record)
		return current, false, err
	}
	tombstones := []string(nil)
	if found {
		current, err := publicationFromRecord(record)
		if err != nil {
			return PrekeyPublication{}, false, err
		}
		held := make(map[string]struct{}, len(record.Tombstones))
		for _, deviceID := range record.Tombstones {
			held[deviceID] = struct{}{}
		}
		succession, err := e2ee.Succeed(summaryFromPublication(current), held, bundles)
		if err != nil {
			return PrekeyPublication{}, false, err
		}
		tombstones = append(tombstones, record.Tombstones...)
		for _, removed := range succession.Removed {
			if !containsPublicationValue(tombstones, removed) {
				tombstones = append(tombstones, removed)
			}
		}
		if len(tombstones) > MaxPrekeyPublicationTombstones {
			return PrekeyPublication{}, false, errors.New("too many prekey publication revocations")
		}
	}
	sort.Strings(tombstones)
	record = prekeyPublicationRecord{
		Schema: PrekeyPublicationRecordSchema, EndpointID: delegation.EndpointID, SetDigest: digest,
		IssuedAtUnix: issued, ExpiresAtUnix: expires,
		BundleSetJSONBase64: base64.StdEncoding.EncodeToString(wire), BundleSetWireDigest: canon.Digest(wire),
		Tombstones:    tombstones,
		UpdatedAtUnix: uint64(now.Unix()),
	}
	encoded, err := json.Marshal(record)
	if err != nil {
		return PrekeyPublication{}, false, err
	}
	if err := l.journal.replace(l.path(delegation.EndpointID), encoded); err != nil {
		return PrekeyPublication{}, false, err
	}
	return publication, true, nil
}

// CurrentPrekeyPublication reloads the exact durable public artifact.
func (l *PrekeyPublicationLedger) CurrentPrekeyPublication(endpointID string) (PrekeyPublication, bool, error) {
	if l == nil || l.journal == nil {
		return PrekeyPublication{}, false, errors.New("no prekey publication ledger")
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

// PublishCurrentPrekeys reloads the public-only durable artifact before
// passing a copy to a content-addressed sink.
func (l *PrekeyPublicationLedger) PublishCurrentPrekeys(ctx context.Context, sink PrekeyObjectSink,
	delegation identity.Delegation, now time.Time) (PrekeyPublication, error) {
	if ctx == nil || sink == nil {
		return PrekeyPublication{}, errors.New("prekey publication needs a context and object sink")
	}
	if err := ctx.Err(); err != nil {
		return PrekeyPublication{}, err
	}
	publication, found, err := l.CurrentPrekeyPublication(delegation.EndpointID)
	if err != nil {
		return PrekeyPublication{}, err
	}
	if !found {
		return PrekeyPublication{}, errors.New("prekey publication is not prepared")
	}
	if err := e2ee.BindBundleSet(delegation, publication.Bundles, publication.SetDigest, now); err != nil {
		return PrekeyPublication{}, err
	}
	if err := sink.PutPrekeySet(ctx, publication.SetDigest, append([]byte(nil), publication.BundleSetJSON...)); err != nil {
		return PrekeyPublication{}, err
	}
	return publication, nil
}

func (l *PrekeyPublicationLedger) read(endpointID string) (prekeyPublicationRecord, bool, error) {
	raw, err := os.ReadFile(l.path(endpointID))
	if errors.Is(err, os.ErrNotExist) {
		return prekeyPublicationRecord{}, false, nil
	}
	if err != nil {
		return prekeyPublicationRecord{}, false, errors.New("read prekey publication record")
	}
	if len(raw) == 0 || len(raw) > MaxRecordBytes {
		return prekeyPublicationRecord{}, false, errors.New("prekey publication record exceeds its bound")
	}
	var record prekeyPublicationRecord
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&record); err != nil {
		return prekeyPublicationRecord{}, false, errors.New("invalid prekey publication record")
	}
	if err := decoder.Decode(new(any)); !errors.Is(err, io.EOF) {
		return prekeyPublicationRecord{}, false, errors.New("prekey publication record has trailing JSON")
	}
	if record.Schema != PrekeyPublicationRecordSchema || record.EndpointID != endpointID ||
		record.UpdatedAtUnix == 0 || !canon.ValidDigest(record.BundleSetWireDigest) ||
		len(record.Tombstones) > MaxPrekeyPublicationTombstones {
		return prekeyPublicationRecord{}, false, errors.New("prekey publication record has inconsistent identity")
	}
	publication, err := publicationFromRecord(record)
	if err != nil || publication.IssuedAt != record.IssuedAtUnix || publication.ExpiresAt != record.ExpiresAtUnix {
		return prekeyPublicationRecord{}, false, errors.New("invalid stored prekey publication")
	}
	current := make(map[string]struct{}, len(publication.Bundles))
	for _, bundle := range publication.Bundles {
		current[bundle.DeviceID] = struct{}{}
	}
	for index, deviceID := range record.Tombstones {
		if !ids.Device.MatchString(deviceID) || index > 0 && record.Tombstones[index-1] >= deviceID {
			return prekeyPublicationRecord{}, false, errors.New("invalid prekey publication tombstone")
		}
		if _, present := current[deviceID]; present {
			return prekeyPublicationRecord{}, false, errors.New("revoked device appears in prekey publication")
		}
	}
	return record, true, nil
}

func publicationFromRecord(record prekeyPublicationRecord) (PrekeyPublication, error) {
	wire, err := base64.StdEncoding.Strict().DecodeString(record.BundleSetJSONBase64)
	if err != nil {
		return PrekeyPublication{}, errors.New("invalid stored prekey publication")
	}
	if canon.Digest(wire) != record.BundleSetWireDigest {
		return PrekeyPublication{}, errors.New("stored prekey publication bytes changed")
	}
	bundles, err := e2ee.DecodeBundleSetJSON(wire)
	if err != nil {
		return PrekeyPublication{}, errors.New("invalid stored prekey publication")
	}
	digest, err := e2ee.SetDigest(bundles)
	if err != nil || digest != record.SetDigest || !canon.ValidDigest(record.SetDigest) ||
		bundles[0].EndpointID != record.EndpointID {
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

func summaryFromPublication(publication PrekeyPublication) e2ee.SetSummary {
	summary, _ := e2ee.Summarize(publication.Bundles)
	return summary
}

func containsPublicationValue(values []string, value string) bool {
	for _, candidate := range values {
		if candidate == value {
			return true
		}
	}
	return false
}

func (l *PrekeyPublicationLedger) path(endpointID string) string {
	return filepath.Join(l.journal.root, prekeyPublicationDir, endpointID[len("mep_"):]+".json")
}
