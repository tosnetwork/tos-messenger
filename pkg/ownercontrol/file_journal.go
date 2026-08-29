package ownercontrol

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sync"

	"github.com/tosnetwork/tos-messenger/internal/dirlock"
	trusted "github.com/tosnetwork/tos-service-protocol/pkg/trustedcapability"
)

type JournalAuthority interface {
	InstallationID(context.Context) ([]byte, error)
	Read(context.Context, []byte) (uint64, []byte, error)
	Check(context.Context, []byte, uint64, []byte) error
	CompareAndAdvance(context.Context, []byte, uint64, uint64, []byte) error
}

type journalMetadata struct {
	SchemaVersion         uint16            `json:"schema_version"`
	InstallationID        []byte            `json:"installation_id"`
	DeploymentFormatEpoch uint64            `json:"deployment_format_epoch"`
	Revision              uint64            `json:"revision"`
	TrustedTimeEpoch      uint64            `json:"trusted_time_epoch"`
	TrustedTimeHighWater  uint64            `json:"trusted_time_high_water"`
	TrustedTimeEvidence   []byte            `json:"trusted_time_evidence"`
	RecordDigests         map[string][]byte `json:"record_digests"`
}

type pendingJournalCommit struct {
	SchemaVersion uint16          `json:"schema_version"`
	PriorRevision uint64          `json:"prior_revision"`
	NextMetadata  journalMetadata `json:"next_metadata"`
	Commitment    []byte          `json:"commitment"`
	RecordPath    string          `json:"record_path"`
	Record        Record          `json:"record"`
}

// FileJournal is the rollback-resistant local single-writer implementation.
// The external authority must be administered outside this directory.
type FileJournal struct {
	root      string
	lock      *dirlock.Lock
	mu        sync.Mutex
	authority JournalAuthority
	metadata  journalMetadata
	closed    bool
}

func OpenFileJournal(root string, authority JournalAuthority) (*FileJournal, error) {
	if root == "" || !filepath.IsAbs(root) || authority == nil {
		return nil, errors.New("owner command journal requires an absolute private directory and external rollback authority")
	}
	if err := os.MkdirAll(root, 0o700); err != nil {
		return nil, err
	}
	if err := os.Chmod(root, 0o700); err != nil {
		return nil, err
	}
	lock, err := dirlock.Acquire(root, ".owner-command.lock")
	if err != nil {
		return nil, err
	}
	journal := &FileJournal{root: root, lock: lock, authority: authority}
	installation, installErr := authority.InstallationID(context.Background())
	if installErr != nil || len(installation) != 32 {
		_ = lock.Close()
		return nil, errors.New("non-exportable journal installation identity is unavailable")
	}
	raw, err := os.ReadFile(filepath.Join(root, "journal-metadata.json"))
	if errors.Is(err, os.ErrNotExist) {
		journal.metadata = journalMetadata{SchemaVersion: 1, InstallationID: installation, DeploymentFormatEpoch: 1, RecordDigests: map[string][]byte{}}
		if err := journal.persistMetadata(); err != nil {
			_ = lock.Close()
			return nil, err
		}
	} else if err != nil || json.Unmarshal(raw, &journal.metadata) != nil || journal.metadata.SchemaVersion != 1 || !bytes.Equal(journal.metadata.InstallationID, installation) || journal.metadata.DeploymentFormatEpoch != 1 || journal.metadata.RecordDigests == nil {
		_ = lock.Close()
		return nil, errors.New("owner command journal metadata is corrupt or incompatible")
	}
	if err := journal.reconcile(); err != nil {
		_ = lock.Close()
		return nil, err
	}
	return journal, nil
}

func (journal *FileJournal) Close() error {
	if journal == nil {
		return nil
	}
	journal.mu.Lock()
	if journal.closed {
		journal.mu.Unlock()
		return nil
	}
	journal.closed = true
	lock := journal.lock
	journal.lock = nil
	journal.mu.Unlock()
	if lock == nil {
		return nil
	}
	return lock.Close()
}

func (journal *FileJournal) path(namespace, actionID []byte) (string, error) {
	if len(namespace) != 32 || len(actionID) != 32 {
		return "", errors.New("invalid owner command journal key")
	}
	dir := filepath.Join(journal.root, "records", hex.EncodeToString(namespace))
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", err
	}
	return filepath.Join(dir, hex.EncodeToString(actionID)+".json"), nil
}

func (journal *FileJournal) MultiHostSafe() bool { return false }

func (journal *FileJournal) Begin(ctx context.Context, namespace, actionID []byte, value Record, observed TrustedTimeObservation) (Record, []byte, bool, error) {
	if err := ctx.Err(); err != nil {
		return Record{}, nil, false, err
	}
	journal.mu.Lock()
	defer journal.mu.Unlock()
	if journal.closed {
		return Record{}, nil, false, errors.New("owner command journal is closed and fenced")
	}
	path, err := journal.path(namespace, actionID)
	if err != nil {
		return Record{}, nil, false, err
	}
	if prior, ok, err := journal.readTracked(path); err != nil || ok {
		return prior, append([]byte(nil), prior.FencingToken...), false, err
	}
	if err := validateTrustedTime(journal.metadata, observed); err != nil {
		return Record{}, nil, false, err
	}
	value.FencingToken = journalToken(journal.metadata.InstallationID, namespace, actionID, value)
	if err := journal.commitRecord(path, value, observed); err != nil {
		return Record{}, nil, false, err
	}
	return Record{}, append([]byte(nil), value.FencingToken...), true, nil
}

func (journal *FileJournal) Transition(ctx context.Context, namespace, actionID []byte, expectedState string, value Record, observed TrustedTimeObservation) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	journal.mu.Lock()
	defer journal.mu.Unlock()
	if journal.closed {
		return errors.New("owner command journal is closed and fenced")
	}
	path, err := journal.path(namespace, actionID)
	if err != nil {
		return err
	}
	prior, ok, err := journal.readTracked(path)
	if err != nil || !ok {
		return errors.Join(errors.New("prepared owner command record is missing"), err)
	}
	if !sameRecordIdentity(prior, value) {
		return errors.New("owner command resolution conflicts with immutable prepared record")
	}
	value.FencingToken = append([]byte(nil), prior.FencingToken...)
	priorJSON, _ := json.Marshal(prior)
	valueJSON, _ := json.Marshal(value)
	if bytes.Equal(priorJSON, valueJSON) {
		return nil
	}
	if prior.Resolution.State != expectedState || trusted.ValidateResolutionTransition(prior.Resolution.State, value.Resolution.State) != nil {
		return errors.New("owner command resolution transition CAS failed")
	}
	if err := validateTrustedTime(journal.metadata, observed); err != nil {
		return err
	}
	return journal.commitRecord(path, value, observed)
}

func (journal *FileJournal) AttachAuthorization(ctx context.Context, namespace, actionID []byte, value Record, observed TrustedTimeObservation) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	journal.mu.Lock()
	defer journal.mu.Unlock()
	if journal.closed {
		return errors.New("owner command journal is closed and fenced")
	}
	path, err := journal.path(namespace, actionID)
	if err != nil {
		return err
	}
	prior, ok, err := journal.readTracked(path)
	if err != nil || !ok {
		return errors.Join(errors.New("prepared owner command record is missing"), err)
	}
	if !sameRecordIdentity(prior, value) || prior.Resolution.State != value.Resolution.State || len(value.AuthorizationHistory) != len(prior.AuthorizationHistory)+1 {
		return errors.New("owner command authorization attachment conflicts with immutable record")
	}
	for index := range prior.AuthorizationHistory {
		if !bytes.Equal(prior.AuthorizationHistory[index].AttemptDigest, value.AuthorizationHistory[index].AttemptDigest) {
			return errors.New("owner command authorization history was rewritten")
		}
	}
	value.FencingToken = append([]byte(nil), prior.FencingToken...)
	if err := validateTrustedTime(journal.metadata, observed); err != nil {
		return err
	}
	return journal.commitRecord(path, value, observed)
}

func (journal *FileJournal) Get(ctx context.Context, namespace, actionID []byte) (Record, bool, error) {
	if err := ctx.Err(); err != nil {
		return Record{}, false, err
	}
	journal.mu.Lock()
	defer journal.mu.Unlock()
	if journal.closed {
		return Record{}, false, errors.New("owner command journal is closed and fenced")
	}
	path, err := journal.path(namespace, actionID)
	if err != nil {
		return Record{}, false, err
	}
	return journal.readTracked(path)
}

func (journal *FileJournal) commitRecord(path string, value Record, observed TrustedTimeObservation) error {
	if _, err := os.Stat(filepath.Join(journal.root, "journal-pending.json")); err == nil {
		return errors.New("prior owner command journal commit is ambiguous; reopen to reconcile")
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	raw, err := json.Marshal(value)
	if err != nil {
		return err
	}
	digest := sha256.Sum256(raw)
	next := cloneMetadata(journal.metadata)
	next.Revision++
	next.TrustedTimeEpoch = observed.Epoch
	next.TrustedTimeHighWater = observed.UnixSeconds
	next.TrustedTimeEvidence = append([]byte(nil), observed.EvidenceDigest...)
	relative, err := filepath.Rel(journal.root, path)
	if err != nil || stringsHasTraversal(relative) {
		return errors.New("owner command record path escaped journal")
	}
	next.RecordDigests[filepath.ToSlash(relative)] = digest[:]
	commitment, err := metadataCommitment(next)
	if err != nil {
		return err
	}
	pending := pendingJournalCommit{SchemaVersion: 1, PriorRevision: journal.metadata.Revision, NextMetadata: next, Commitment: commitment, RecordPath: filepath.ToSlash(relative), Record: value}
	if err := writeJSONAtomic(filepath.Join(journal.root, "journal-pending.json"), pending); err != nil {
		return err
	}
	if err := journal.authority.CompareAndAdvance(context.Background(), journal.scope(), journal.metadata.Revision, next.Revision, commitment); err != nil {
		return err
	}
	if err := replaceRecord(path, value); err != nil {
		return err
	}
	journal.metadata = next
	if err := journal.persistMetadata(); err != nil {
		return err
	}
	return journal.clearPending()
}

func (journal *FileJournal) reconcile() error {
	raw, err := os.ReadFile(filepath.Join(journal.root, "journal-pending.json"))
	if errors.Is(err, os.ErrNotExist) {
		commitment, commitmentErr := metadataCommitment(journal.metadata)
		if commitmentErr != nil {
			return commitmentErr
		}
		if err := journal.authority.Check(context.Background(), journal.scope(), journal.metadata.Revision, commitment); err != nil {
			return err
		}
		return journal.verifyTrackedRecords()
	}
	if err != nil {
		return err
	}
	var pending pendingJournalCommit
	if json.Unmarshal(raw, &pending) != nil || pending.SchemaVersion != 1 || pending.NextMetadata.Revision != pending.PriorRevision+1 || pending.PriorRevision > journal.metadata.Revision || pending.NextMetadata.Revision < journal.metadata.Revision {
		return errors.New("pending owner command transition is corrupt")
	}
	commitment, err := metadataCommitment(pending.NextMetadata)
	if err != nil || !bytes.Equal(commitment, pending.Commitment) || stringsHasTraversal(pending.RecordPath) {
		return errors.New("pending owner command commitment is invalid")
	}
	revision, external, err := journal.authority.Read(context.Background(), journal.scope())
	if err != nil {
		return err
	}
	if revision == pending.PriorRevision && journal.metadata.Revision == pending.PriorRevision {
		if err := journal.authority.CompareAndAdvance(context.Background(), journal.scope(), pending.PriorRevision, pending.NextMetadata.Revision, pending.Commitment); err != nil {
			return err
		}
	} else if revision != pending.NextMetadata.Revision || !bytes.Equal(external, pending.Commitment) {
		return errors.New("pending owner command transition conflicts with external high-water")
	}
	path := filepath.Join(journal.root, filepath.FromSlash(pending.RecordPath))
	if err := replaceRecord(path, pending.Record); err != nil {
		return err
	}
	journal.metadata = pending.NextMetadata
	if err := journal.persistMetadata(); err != nil {
		return err
	}
	if err := journal.clearPending(); err != nil {
		return err
	}
	return journal.verifyTrackedRecords()
}

func (journal *FileJournal) readTracked(path string) (Record, bool, error) {
	relative, err := filepath.Rel(journal.root, path)
	if err != nil || stringsHasTraversal(relative) {
		return Record{}, false, errors.New("journal path is invalid")
	}
	want, tracked := journal.metadata.RecordDigests[filepath.ToSlash(relative)]
	value, ok, err := readRecord(path)
	if err != nil {
		return Record{}, false, err
	}
	if tracked != ok {
		return Record{}, false, errors.New("journal record/manifest presence mismatch")
	}
	if !ok {
		return Record{}, false, nil
	}
	raw, _ := json.Marshal(value)
	digest := sha256.Sum256(raw)
	if !bytes.Equal(want, digest[:]) {
		return Record{}, false, errors.New("journal record differs from rollback-resistant manifest")
	}
	return value, true, nil
}

func (journal *FileJournal) verifyTrackedRecords() error {
	for relative := range journal.metadata.RecordDigests {
		if _, ok, err := journal.readTracked(filepath.Join(journal.root, filepath.FromSlash(relative))); err != nil || !ok {
			return errors.Join(errors.New("journal manifest references missing record"), err)
		}
	}
	return nil
}

func validateTrustedTime(metadata journalMetadata, observed TrustedTimeObservation) error {
	if observed.UnixSeconds == 0 || observed.Epoch == 0 || len(observed.EvidenceDigest) != sha256.Size ||
		observed.Epoch < metadata.TrustedTimeEpoch || observed.UnixSeconds < metadata.TrustedTimeHighWater {
		return errors.New("owner command trusted time rolled back or is invalid")
	}
	return nil
}

func metadataCommitment(metadata journalMetadata) ([]byte, error) {
	raw, err := json.Marshal(metadata)
	if err != nil {
		return nil, err
	}
	digest := sha256.Sum256(append([]byte("tos.owner-command-journal-metadata.v1\x00"), raw...))
	return digest[:], nil
}

func cloneMetadata(value journalMetadata) journalMetadata {
	raw, _ := json.Marshal(value)
	var copy journalMetadata
	_ = json.Unmarshal(raw, &copy)
	return copy
}

func (journal *FileJournal) scope() []byte {
	hash := sha256.New()
	hash.Write([]byte("tos.owner-command-journal-scope.v1\x00"))
	hash.Write(journal.metadata.InstallationID)
	return hash.Sum(nil)
}

func (journal *FileJournal) persistMetadata() error {
	return writeJSONAtomic(filepath.Join(journal.root, "journal-metadata.json"), journal.metadata)
}

func (journal *FileJournal) clearPending() error {
	if err := os.Remove(filepath.Join(journal.root, "journal-pending.json")); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return syncDirectory(journal.root)
}

func writeJSONAtomic(path string, value any) error {
	temp, err := os.CreateTemp(filepath.Dir(path), ".journal-*")
	if err != nil {
		return err
	}
	name := temp.Name()
	defer os.Remove(name)
	if err := temp.Chmod(0o600); err == nil {
		err = json.NewEncoder(temp).Encode(value)
	}
	if err == nil {
		err = temp.Sync()
	}
	if closeErr := temp.Close(); err == nil {
		err = closeErr
	}
	if err == nil {
		err = os.Rename(name, path)
	}
	if err != nil {
		return err
	}
	return syncDirectory(filepath.Dir(path))
}

func readRecord(path string) (Record, bool, error) {
	file, err := os.Open(path)
	if errors.Is(err, os.ErrNotExist) {
		return Record{}, false, nil
	}
	if err != nil {
		return Record{}, false, err
	}
	defer file.Close()
	var value Record
	decoder := json.NewDecoder(file)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&value); err != nil {
		return Record{}, false, err
	}
	return value, true, nil
}

func replaceRecord(path string, value Record) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	return writeJSONAtomic(path, value)
}

func syncDirectory(path string) error {
	directory, err := os.Open(path)
	if err != nil {
		return err
	}
	defer directory.Close()
	return directory.Sync()
}

func stringsHasTraversal(path string) bool {
	return path == "." || filepath.IsAbs(path) || path == ".." || len(path) >= 3 && path[:3] == ".."+string(filepath.Separator)
}

func sameRecordIdentity(left, right Record) bool {
	leftEffect, leftErr := trusted.MarshalBody(left.Effect)
	rightEffect, rightErr := trusted.MarshalBody(right.Effect)
	return leftErr == nil && rightErr == nil && bytes.Equal(leftEffect, rightEffect) &&
		bytes.Equal(left.Resolution.EffectDigest, right.Resolution.EffectDigest) && bytes.Equal(left.Resolution.ActionID, right.Resolution.ActionID) &&
		bytes.Equal(left.Resolution.ExactRequestDigest, right.Resolution.ExactRequestDigest) && bytes.Equal(left.Resolution.SinkIdentity, right.Resolution.SinkIdentity)
}

func journalToken(installationID, namespace, actionID []byte, record Record) []byte {
	raw, _ := json.Marshal(struct {
		Effect             trusted.OwnerCommandEffectV1
		ExactRequestDigest []byte
	}{record.Effect, record.Resolution.ExactRequestDigest})
	hash := sha256.New()
	hash.Write([]byte("tos.owner-command-journal-fence.v1\x00"))
	hash.Write(installationID)
	hash.Write(namespace)
	hash.Write(actionID)
	hash.Write(raw)
	return hash.Sum(nil)
}
