package eventlog

import (
	"errors"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"time"

	"github.com/tosnetwork/tos-messenger/internal/canon"
	"github.com/tosnetwork/tos-messenger/pkg/negotiation"
)

const (
	negotiationDir = "negotiations"

	// MaxNegotiations bounds how many exchanges one installation carries at
	// once. Each holds part of a budget and may hold a person's attention, and
	// an unbounded set of either is not a set anybody can review.
	MaxNegotiations = 512
)

// ErrNegotiationsFull reports that the installation carries as many exchanges
// as it may.
var ErrNegotiationsFull = errors.New("this installation carries as many negotiations as it may")

// NegotiationStore is where negotiations survive a restart.
type NegotiationStore struct{ journal *Journal }

// OpenNegotiations returns the store for this installation.
func (j *Journal) OpenNegotiations() (*NegotiationStore, error) {
	if err := j.usable(); err != nil {
		return nil, err
	}
	return &NegotiationStore{journal: j}, nil
}

// Save implements negotiation.Store.
//
// The snapshot is written whole and the encoding is the negotiation package's
// own, so this store never has to know what a set of terms contains. A store
// that understood the object it holds would be a second place the shape is
// defined, and the two would drift.
func (s *NegotiationStore) Save(snapshot negotiation.Snapshot) error {
	if s == nil {
		return errors.New("no negotiation store")
	}
	if err := s.journal.usable(); err != nil {
		return err
	}
	encoded, err := negotiation.EncodeSnapshotJSON(snapshot)
	if err != nil {
		return err
	}
	path, err := s.path(snapshot.ID)
	if err != nil {
		return err
	}
	s.journal.mutex.Lock()
	defer s.journal.mutex.Unlock()

	if _, err := os.Stat(path); errors.Is(err, os.ErrNotExist) {
		held, countErr := s.count()
		if countErr != nil {
			return countErr
		}
		if held >= MaxNegotiations {
			return ErrNegotiationsFull
		}
	}
	return s.journal.replace(path, encoded)
}

// Load returns one negotiation's stored state.
func (s *NegotiationStore) Load(negotiationID string) (negotiation.Snapshot, bool, error) {
	if s == nil {
		return negotiation.Snapshot{}, false, errors.New("no negotiation store")
	}
	if err := s.journal.usable(); err != nil {
		return negotiation.Snapshot{}, false, err
	}
	path, err := s.path(negotiationID)
	if err != nil {
		return negotiation.Snapshot{}, false, err
	}
	s.journal.mutex.Lock()
	defer s.journal.mutex.Unlock()
	return s.read(path)
}

// List returns every negotiation this installation carries, oldest identifier
// first, so an owner can be shown what their Agent is in the middle of.
func (s *NegotiationStore) List() ([]negotiation.Snapshot, error) {
	if s == nil {
		return nil, errors.New("no negotiation store")
	}
	if err := s.journal.usable(); err != nil {
		return nil, err
	}
	s.journal.mutex.Lock()
	defer s.journal.mutex.Unlock()
	return s.all()
}

// Drop removes a settled negotiation.
//
// Only a settled one: removing an exchange that is still open would strand the
// budget hold it carries, which is the outcome the store exists to prevent.
func (s *NegotiationStore) Drop(negotiationID string, now time.Time) error {
	if s == nil {
		return errors.New("no negotiation store")
	}
	if err := s.journal.usable(); err != nil {
		return err
	}
	if now.IsZero() || now.Unix() < 0 {
		return errors.New("invalid time")
	}
	path, err := s.path(negotiationID)
	if err != nil {
		return err
	}
	s.journal.mutex.Lock()
	defer s.journal.mutex.Unlock()

	snapshot, found, err := s.read(path)
	if err != nil {
		return err
	}
	if !found {
		return nil
	}
	if !settledState(snapshot.State) {
		return errors.New("this negotiation is still open")
	}
	if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return errors.New("remove negotiation record")
	}
	return syncDirectory(filepath.Dir(path))
}

func settledState(state string) bool {
	switch negotiation.State(state) {
	case negotiation.StateFinalized, negotiation.StateRejected,
		negotiation.StateWithdrawn, negotiation.StateExpired:
		return true
	}
	return false
}

func (s *NegotiationStore) read(path string) (negotiation.Snapshot, bool, error) {
	raw, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return negotiation.Snapshot{}, false, nil
	}
	if err != nil {
		return negotiation.Snapshot{}, false, errors.New("read negotiation record")
	}
	if len(raw) > MaxRecordBytes {
		return negotiation.Snapshot{}, false, errors.New("negotiation record exceeds its bound")
	}
	snapshot, err := negotiation.DecodeSnapshotJSON(raw)
	if err != nil {
		return negotiation.Snapshot{}, false, err
	}
	return snapshot, true, nil
}

func (s *NegotiationStore) all() ([]negotiation.Snapshot, error) {
	entries, err := os.ReadDir(s.root())
	if err != nil {
		return nil, errors.New("read negotiation directory")
	}
	snapshots := make([]negotiation.Snapshot, 0, len(entries))
	for _, entry := range entries {
		if entry.IsDir() || filepath.Ext(entry.Name()) != ".json" {
			continue
		}
		snapshot, found, err := s.read(filepath.Join(s.root(), entry.Name()))
		if err != nil || !found {
			continue
		}
		snapshots = append(snapshots, snapshot)
	}
	sort.Slice(snapshots, func(first, second int) bool {
		return snapshots[first].ID < snapshots[second].ID
	})
	return snapshots, nil
}

func (s *NegotiationStore) count() (int, error) {
	snapshots, err := s.all()
	if err != nil {
		return 0, err
	}
	open := 0
	for _, snapshot := range snapshots {
		if !settledState(snapshot.State) {
			open++
		}
	}
	return open, nil
}

var negotiationNamePattern = regexp.MustCompile(`^[\x20-\x7e]{1,128}$`)

// path names one negotiation's file by a digest of its identifier, so an
// identifier a caller chose cannot name a path.
func (s *NegotiationStore) path(negotiationID string) (string, error) {
	if !negotiationNamePattern.MatchString(negotiationID) {
		return "", errors.New("invalid negotiation identifier")
	}
	digest := canon.Digest([]byte(canon.DomainNegotiationRecord + negotiationID))
	return filepath.Join(s.root(), digest[len("sha256:"):]+".json"), nil
}

func (s *NegotiationStore) root() string {
	return filepath.Join(s.journal.root, negotiationDir)
}
