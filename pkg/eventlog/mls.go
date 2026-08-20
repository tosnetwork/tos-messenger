package eventlog

// This ledger persists the application binding around an opaque MLS library
// state. It never parses or implements MLS; it makes one-time KeyPackage use,
// Welcome replay, epoch continuity, and single-parent commit acceptance survive
// a crash.

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"time"

	"github.com/tosnetwork/tos-messenger/internal/canon"
	"github.com/tosnetwork/tos-messenger/internal/ids"
	"github.com/tosnetwork/tos-messenger/pkg/group"
)

const (
	mlsDir           = "mls"
	MLSRecordSchema  = "tos.messaging.mls-state-ledger.v1"
	MaxMLSStateBytes = 512 << 10
	MaxMLSReceipts   = 4096
)

var (
	ErrMLSRollback        = errors.New("MLS state regressed")
	ErrMLSGap             = errors.New("MLS state skipped an epoch")
	ErrMLSFork            = errors.New("MLS commit is not a child of the accepted state")
	ErrKeyPackageConsumed = errors.New("MLS KeyPackage was already consumed")
	ErrWelcomeReplay      = errors.New("MLS Welcome was already processed")
)

type MLSRecord struct {
	Schema              string   `json:"schema"`
	RoomID              string   `json:"room_id"`
	RoomEpoch           uint64   `json:"room_epoch"`
	MLSEpoch            uint64   `json:"mls_epoch"`
	MembershipDigest    string   `json:"membership_digest"`
	AcceptedCommitRef   string   `json:"accepted_commit_ref,omitempty"`
	StateBase64         string   `json:"state_base64"`
	StateDigest         string   `json:"state_digest"`
	ConsumedKeyPackages []string `json:"consumed_key_packages,omitempty"`
	ProcessedWelcomes   []string `json:"processed_welcomes,omitempty"`
	UpdatedAtUnix       uint64   `json:"updated_at_unix"`
}

func (r MLSRecord) State() ([]byte, error) {
	state, err := base64.StdEncoding.Strict().DecodeString(r.StateBase64)
	if err != nil || len(state) == 0 || len(state) > MaxMLSStateBytes || canon.Digest(state) != r.StateDigest {
		return nil, errors.New("invalid persisted MLS state")
	}
	return state, nil
}

func (r MLSRecord) Binding() group.State {
	return group.State{RoomID: r.RoomID, Clock: group.Clock{RoomEpoch: r.RoomEpoch, MLSEpoch: r.MLSEpoch}, MembershipDigest: r.MembershipDigest, AcceptedCommitRef: r.AcceptedCommitRef}
}

type MLSLedger struct{ journal *Journal }

func (j *Journal) OpenMLS() (*MLSLedger, error) {
	if err := j.usable(); err != nil {
		return nil, err
	}
	return &MLSLedger{journal: j}, nil
}

// InstallWelcome atomically consumes the local one-time KeyPackage, records
// the Welcome identity, and installs the opaque joined state. None of those
// facts can survive without the others.
func (l *MLSLedger) InstallWelcome(binding group.State, opaqueState []byte, keyPackageRef, welcomeRef string, now time.Time) error {
	if l == nil {
		return errors.New("no MLS ledger")
	}
	if err := validateInitialMLS(binding, opaqueState, keyPackageRef, welcomeRef, now); err != nil {
		return err
	}
	l.journal.mutex.Lock()
	defer l.journal.mutex.Unlock()
	consumed, err := l.keyPackageConsumed(keyPackageRef)
	if err != nil {
		return err
	}
	if consumed {
		return ErrKeyPackageConsumed
	}
	record, found, err := l.read(binding.RoomID)
	if err != nil {
		return err
	}
	if found {
		if containsString(record.ConsumedKeyPackages, keyPackageRef) {
			return ErrKeyPackageConsumed
		}
		if containsString(record.ProcessedWelcomes, welcomeRef) {
			return ErrWelcomeReplay
		}
		return ErrMLSFork
	}
	record = newMLSRecord(binding, opaqueState, now)
	record.ConsumedKeyPackages = []string{keyPackageRef}
	record.ProcessedWelcomes = []string{welcomeRef}
	return l.write(record)
}

// Advance installs exactly one child of the durable state. Exact replay is
// idempotent; another child of the same parent is a fork, not "last arrival
// wins" Relay authority.
func (l *MLSLedger) Advance(transition group.Transition, opaqueState []byte, now time.Time) (bool, error) {
	if l == nil {
		return false, errors.New("no MLS ledger")
	}
	if err := group.ValidateTransition(transition); err != nil {
		return false, err
	}
	if err := validateOpaqueMLS(opaqueState, now); err != nil {
		return false, err
	}
	l.journal.mutex.Lock()
	defer l.journal.mutex.Unlock()
	record, found, err := l.read(transition.Next.RoomID)
	if err != nil {
		return false, err
	}
	if !found {
		return false, errors.New("MLS room has no installed state")
	}
	current := record.Binding()
	if sameGroupState(current, transition.Next) {
		if canon.Digest(opaqueState) != record.StateDigest {
			return false, ErrMLSFork
		}
		return false, nil
	}
	if transition.Next.Clock.MLSEpoch == current.Clock.MLSEpoch {
		return false, ErrMLSFork
	}
	if transition.Next.Clock.MLSEpoch < current.Clock.MLSEpoch {
		return false, ErrMLSRollback
	}
	if transition.Next.Clock.MLSEpoch != current.Clock.MLSEpoch+1 {
		return false, ErrMLSGap
	}
	if !sameGroupState(current, transition.Prior) {
		return false, ErrMLSFork
	}
	next := newMLSRecord(transition.Next, opaqueState, now)
	next.ConsumedKeyPackages = record.ConsumedKeyPackages
	next.ProcessedWelcomes = record.ProcessedWelcomes
	if err := l.write(next); err != nil {
		return false, err
	}
	return true, nil
}

func (l *MLSLedger) Current(roomID string) (MLSRecord, bool, error) {
	if l == nil {
		return MLSRecord{}, false, errors.New("no MLS ledger")
	}
	if err := l.journal.usable(); err != nil {
		return MLSRecord{}, false, err
	}
	if !ids.Room.MatchString(roomID) {
		return MLSRecord{}, false, errors.New("invalid MLS room")
	}
	l.journal.mutex.Lock()
	defer l.journal.mutex.Unlock()
	return l.read(roomID)
}

func validateInitialMLS(binding group.State, state []byte, keyPackageRef, welcomeRef string, now time.Time) error {
	if !ids.Room.MatchString(binding.RoomID) || binding.Clock.RoomEpoch == 0 || !canon.ValidDigest(binding.MembershipDigest) || !canon.ValidDigest(keyPackageRef) || !canon.ValidDigest(welcomeRef) {
		return errors.New("invalid initial MLS binding")
	}
	return validateOpaqueMLS(state, now)
}

func validateOpaqueMLS(state []byte, now time.Time) error {
	if now.IsZero() || now.Unix() < 0 {
		return errors.New("invalid MLS persistence time")
	}
	if len(state) == 0 || len(state) > MaxMLSStateBytes || canon.IsZero(state) {
		return errors.New("invalid opaque MLS state")
	}
	return nil
}

func newMLSRecord(binding group.State, state []byte, now time.Time) MLSRecord {
	return MLSRecord{Schema: MLSRecordSchema, RoomID: binding.RoomID, RoomEpoch: binding.Clock.RoomEpoch, MLSEpoch: binding.Clock.MLSEpoch, MembershipDigest: binding.MembershipDigest, AcceptedCommitRef: binding.AcceptedCommitRef, StateBase64: base64.StdEncoding.EncodeToString(state), StateDigest: canon.Digest(state), UpdatedAtUnix: uint64(now.Unix())}
}

func (l *MLSLedger) write(record MLSRecord) error {
	if len(record.ConsumedKeyPackages) > MaxMLSReceipts || len(record.ProcessedWelcomes) > MaxMLSReceipts {
		return errors.New("MLS receipt history reached its bound")
	}
	encoded, err := json.Marshal(record)
	if err != nil {
		return err
	}
	return l.journal.replace(l.path(record.RoomID), encoded)
}

func (l *MLSLedger) read(roomID string) (MLSRecord, bool, error) {
	raw, err := os.ReadFile(l.path(roomID))
	if errors.Is(err, os.ErrNotExist) {
		return MLSRecord{}, false, nil
	}
	if err != nil {
		return MLSRecord{}, false, errors.New("read MLS record")
	}
	if len(raw) > MaxRecordBytes {
		return MLSRecord{}, false, errors.New("MLS record exceeds its bound")
	}
	var record MLSRecord
	if err := json.Unmarshal(raw, &record); err != nil {
		return MLSRecord{}, false, errors.New("invalid MLS record")
	}
	if record.Schema != MLSRecordSchema || record.RoomID != roomID || record.RoomEpoch == 0 || !canon.ValidDigest(record.MembershipDigest) || len(record.ConsumedKeyPackages) > MaxMLSReceipts || len(record.ProcessedWelcomes) > MaxMLSReceipts {
		return MLSRecord{}, false, errors.New("invalid MLS record binding")
	}
	if record.AcceptedCommitRef != "" && !canon.ValidDigest(record.AcceptedCommitRef) {
		return MLSRecord{}, false, errors.New("invalid MLS accepted commit reference")
	}
	if _, err := record.State(); err != nil {
		return MLSRecord{}, false, err
	}
	for _, ref := range append(append([]string(nil), record.ConsumedKeyPackages...), record.ProcessedWelcomes...) {
		if !canon.ValidDigest(ref) {
			return MLSRecord{}, false, errors.New("invalid MLS receipt reference")
		}
	}
	return record, true, nil
}

func (l *MLSLedger) path(roomID string) string {
	return filepath.Join(l.journal.root, mlsDir, roomID[len("room_"):]+".json")
}

// keyPackageConsumed scans every room record while the journal mutex is held.
// A KeyPackage is one-time across the installation, not merely within one MLS
// group. Because the consuming room record is installed by one atomic rename,
// a crash exposes either the old global view or the consumed reference.
func (l *MLSLedger) keyPackageConsumed(ref string) (bool, error) {
	entries, err := os.ReadDir(filepath.Join(l.journal.root, mlsDir))
	if err != nil {
		return false, errors.New("read MLS ledger directory")
	}
	for _, entry := range entries {
		if entry.IsDir() || filepath.Ext(entry.Name()) != ".json" {
			continue
		}
		stem := entry.Name()[:len(entry.Name())-len(".json")]
		roomID := "room_" + stem
		if !ids.Room.MatchString(roomID) {
			return false, errors.New("invalid MLS receipt record name")
		}
		record, found, err := l.read(roomID)
		if err != nil || !found {
			return false, errors.New("invalid MLS receipt record")
		}
		if containsString(record.ConsumedKeyPackages, ref) {
			return true, nil
		}
	}
	return false, nil
}
func containsString(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}
func sameGroupState(a, b group.State) bool {
	return a.RoomID == b.RoomID && a.Clock == b.Clock && a.MembershipDigest == b.MembershipDigest && a.AcceptedCommitRef == b.AcceptedCommitRef
}
