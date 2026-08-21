package publicchannel

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"

	"github.com/tosnetwork/tos-messenger/internal/canon"
	"github.com/tosnetwork/tos-messenger/internal/dirlock"
	"github.com/tosnetwork/tos-messenger/internal/securefile"
	"github.com/tosnetwork/tos-messenger/pkg/identity"
)

const (
	channelStoreLock        = ".public-channel-store.lock"
	profileCheckpointSchema = "tos.messaging.public-channel-profile-checkpoint.v1"
	historyManifestSchema   = "tos.messaging.public-channel-history-manifest.v1"
	MaxStoreRecordBytes     = 16 << 20
)

var (
	ErrProfileRollback = errors.New("public channel profile rollback")
	ErrProfileFork     = errors.New("public channel profile fork")
	ErrHistoryRollback = errors.New("public channel history rollback")
)

type profileCheckpoint struct {
	Schema        string `json:"schema"`
	ChannelID     string `json:"channel_id"`
	Epoch         uint64 `json:"epoch"`
	ProfileDigest string `json:"profile_digest"`
}

type historyManifest struct {
	Schema        string   `json:"schema"`
	ChannelID     string   `json:"channel_id"`
	ProfileDigest string   `json:"profile_digest"`
	HistoryDigest string   `json:"history_digest"`
	EventIDs      []string `json:"event_ids"`
	Tips          []string `json:"tips"`
}

// Store is one crash-safe writer for public-channel profiles and verified
// history snapshots. Immutable objects precede manifests/checkpoints, so a
// crash can leave an orphan but cannot publish an incomplete history.
type Store struct {
	root  string
	lock  *dirlock.Lock
	mutex sync.Mutex
}

func OpenStore(root string) (*Store, error) {
	if !filepath.IsAbs(root) || filepath.Clean(root) != root {
		return nil, errors.New("invalid public channel store root")
	}
	if err := os.MkdirAll(root, 0o700); err != nil {
		return nil, errors.New("create public channel store")
	}
	for _, path := range []string{root, filepath.Join(root, "profiles"), filepath.Join(root, "events"),
		filepath.Join(root, "histories"), filepath.Join(root, "heads")} {
		if err := os.MkdirAll(path, 0o700); err != nil {
			return nil, errors.New("create public channel store directory")
		}
		if err := requireStoreDirectory(path); err != nil {
			return nil, err
		}
	}
	lock, err := dirlock.Acquire(root, channelStoreLock)
	if err != nil {
		return nil, err
	}
	return &Store{root: root, lock: lock}, nil
}

func (s *Store) Close() error {
	if s == nil {
		return nil
	}
	s.mutex.Lock()
	defer s.mutex.Unlock()
	if s.lock == nil {
		return nil
	}
	lock := s.lock
	s.lock = nil
	return lock.Close()
}

// ApplyProfile advances exactly one signed epoch and persists its immutable
// bytes before the current checkpoint. Exact replay is idempotent.
func (s *Store) ApplyProfile(profile Profile, authority identity.Delegation,
	delegations map[string]identity.Delegation, now time.Time) (bool, error) {
	if err := VerifyProfile(profile, authority, delegations, now); err != nil {
		return false, err
	}
	digest, _ := profile.Digest()
	raw, _ := EncodeProfileJSON(profile)
	s.mutex.Lock()
	defer s.mutex.Unlock()
	if err := s.usableLocked(); err != nil {
		return false, err
	}
	checkpointPath := filepath.Join(s.root, "current-profile.json")
	current, found, err := s.readProfileCheckpoint(checkpointPath)
	if err != nil {
		return false, err
	}
	if found {
		if current.ChannelID != profile.ChannelID {
			return false, ErrProfileFork
		}
		if current.ProfileDigest == digest {
			return false, putStoreImmutable(s.profilePath(digest), raw)
		}
		if profile.Epoch < current.Epoch {
			return false, ErrProfileRollback
		}
		if profile.Epoch == current.Epoch {
			return false, ErrProfileFork
		}
		currentRaw, err := securefile.ReadBoundedRegular(s.profilePath(current.ProfileDigest), MaxProfileBytes)
		if err != nil {
			return false, errors.New("read current public channel profile")
		}
		prior, err := DecodeProfileJSON(currentRaw)
		if err != nil || VerifySuccessor(prior, profile, authority, delegations, now) != nil {
			return false, ErrProfileRollback
		}
	} else if profile.Epoch != 1 {
		return false, ErrProfileRollback
	}
	if err := putStoreImmutable(s.profilePath(digest), raw); err != nil {
		return false, err
	}
	checkpoint := profileCheckpoint{Schema: profileCheckpointSchema, ChannelID: profile.ChannelID,
		Epoch: profile.Epoch, ProfileDigest: digest}
	encoded, _ := json.Marshal(checkpoint)
	if err := replaceStoreFile(checkpointPath, encoded); err != nil {
		return false, err
	}
	return true, nil
}

// CommitHistory verifies a complete set, persists Event objects and an
// immutable manifest, then atomically points this profile epoch at it. A later
// snapshot must contain every previously committed Event for that epoch.
func (s *Store) CommitHistory(profile Profile, events []Event, authority identity.Delegation,
	delegations map[string]identity.Delegation, now time.Time) (History, bool, error) {
	history, err := VerifyHistory(profile, events, authority, delegations, now)
	if err != nil {
		return History{}, false, err
	}
	s.mutex.Lock()
	defer s.mutex.Unlock()
	if err := s.usableLocked(); err != nil {
		return History{}, false, err
	}
	current, found, err := s.readProfileCheckpoint(filepath.Join(s.root, "current-profile.json"))
	if err != nil || !found || current.ChannelID != profile.ChannelID || current.ProfileDigest != history.profileDigest {
		return History{}, false, errors.New("public channel history profile is not current")
	}
	headPath := s.headPath(history.profileDigest)
	prior, priorFound, err := s.readHistoryManifestPointer(headPath)
	if err != nil {
		return History{}, false, err
	}
	if priorFound {
		if prior.ChannelID != history.channelID || prior.ProfileDigest != history.profileDigest {
			return History{}, false, errors.New("public channel history head is bound to another profile")
		}
		if err := s.checkHistoryManifestObject(headPath, prior); err != nil {
			return History{}, false, err
		}
	}
	ids := make([]string, 0, len(history.events))
	for _, event := range history.events {
		id, _ := event.ID()
		ids = append(ids, id)
		raw, _ := EncodeEventJSON(event)
		if err := putStoreImmutable(s.eventPath(id), raw); err != nil {
			return History{}, false, err
		}
	}
	if priorFound && prior.HistoryDigest == history.digest {
		return history, false, nil
	}
	sortedIDs := append([]string(nil), ids...)
	sortStrings(sortedIDs)
	if priorFound && !containsAll(sortedIDs, prior.EventIDs) {
		return History{}, false, ErrHistoryRollback
	}
	manifest := historyManifest{Schema: historyManifestSchema, ChannelID: history.channelID,
		ProfileDigest: history.profileDigest, HistoryDigest: history.digest,
		EventIDs: sortedIDs, Tips: history.Tips()}
	manifestRaw, _ := json.Marshal(manifest)
	if err := putStoreImmutable(s.historyPath(history.digest), manifestRaw); err != nil {
		return History{}, false, err
	}
	if err := replaceStoreFile(headPath, manifestRaw); err != nil {
		return History{}, false, err
	}
	return history, true, nil
}

// LoadHistory follows only the committed per-profile head and re-verifies all
// immutable Event objects. Orphans are invisible; damage fails closed.
func (s *Store) LoadHistory(profile Profile, authority identity.Delegation,
	delegations map[string]identity.Delegation, now time.Time) (History, bool, error) {
	digest, err := profile.Digest()
	if err != nil {
		return History{}, false, err
	}
	s.mutex.Lock()
	defer s.mutex.Unlock()
	if err := s.usableLocked(); err != nil {
		return History{}, false, err
	}
	manifest, found, err := s.readHistoryManifestPointer(s.headPath(digest))
	if err != nil || !found {
		return History{}, found, err
	}
	if manifest.ChannelID != profile.ChannelID || manifest.ProfileDigest != digest {
		return History{}, false, errors.New("public channel history head is bound to another profile")
	}
	if err := s.checkHistoryManifestObject(s.headPath(digest), manifest); err != nil {
		return History{}, false, err
	}
	events := make([]Event, 0, len(manifest.EventIDs))
	for _, id := range manifest.EventIDs {
		raw, err := securefile.ReadBoundedRegular(s.eventPath(id), MaxEventBytes)
		if err != nil {
			return History{}, false, errors.New("read committed public channel Event")
		}
		event, err := DecodeEventJSON(raw)
		if err != nil {
			return History{}, false, err
		}
		events = append(events, event)
	}
	history, err := VerifyHistory(profile, events, authority, delegations, now)
	if err != nil || history.digest != manifest.HistoryDigest || !equalStrings(history.tips, manifest.Tips) {
		return History{}, false, errors.New("committed public channel history does not reproduce its manifest")
	}
	return history, true, nil
}

func (s *Store) checkHistoryManifestObject(headPath string, manifest historyManifest) error {
	immutable, err := securefile.ReadBoundedRegular(s.historyPath(manifest.HistoryDigest), MaxStoreRecordBytes)
	if err != nil {
		return errors.New("read immutable public channel history manifest")
	}
	head, err := securefile.ReadBoundedRegular(headPath, MaxStoreRecordBytes)
	canonical, marshalErr := json.Marshal(manifest)
	if err != nil || marshalErr != nil || !bytes.Equal(head, immutable) || !bytes.Equal(head, canonical) {
		return errors.New("public channel history head conflicts with immutable manifest")
	}
	return nil
}

func (s *Store) usableLocked() error {
	if s == nil || s.lock == nil || !s.lock.Held() {
		return errors.New("public channel store is closed")
	}
	return nil
}

func (s *Store) profilePath(digest string) string {
	return filepath.Join(s.root, "profiles", digest[len("sha256:"):]+".json")
}
func (s *Store) eventPath(id string) string {
	return filepath.Join(s.root, "events", id[len("pce_"):]+".json")
}
func (s *Store) historyPath(digest string) string {
	return filepath.Join(s.root, "histories", digest[len("sha256:"):]+".json")
}
func (s *Store) headPath(profile string) string {
	return filepath.Join(s.root, "heads", profile[len("sha256:"):]+".json")
}

func (s *Store) readProfileCheckpoint(path string) (profileCheckpoint, bool, error) {
	raw, found, err := readOptionalStoreFile(path, MaxStoreRecordBytes)
	if !found {
		return profileCheckpoint{}, false, nil
	}
	var value profileCheckpoint
	if err != nil || strictJSON(raw, &value) != nil || value.Schema != profileCheckpointSchema ||
		!channelPattern.MatchString(value.ChannelID) || value.Epoch == 0 || !canon.ValidDigest(value.ProfileDigest) {
		return profileCheckpoint{}, false, errors.New("invalid public channel profile checkpoint")
	}
	return value, true, nil
}

func (s *Store) readHistoryManifestPointer(path string) (historyManifest, bool, error) {
	raw, found, err := readOptionalStoreFile(path, MaxStoreRecordBytes)
	if !found {
		return historyManifest{}, false, nil
	}
	var value historyManifest
	if err != nil || strictJSON(raw, &value) != nil || value.Schema != historyManifestSchema ||
		!channelPattern.MatchString(value.ChannelID) || !canon.ValidDigest(value.ProfileDigest) ||
		!canon.ValidDigest(value.HistoryDigest) || len(value.EventIDs) == 0 || len(value.EventIDs) > MaxHistoryEvents {
		return historyManifest{}, false, errors.New("invalid public channel history manifest")
	}
	for index, id := range value.EventIDs {
		if !publicEventPattern.MatchString(id) || index > 0 && value.EventIDs[index-1] >= id {
			return historyManifest{}, false, errors.New("invalid public channel history manifest Events")
		}
	}
	if validateHead(Head{Schema: HeadSchema, ChannelID: value.ChannelID, ProfileDigest: value.ProfileDigest,
		EventCount: uint32(len(value.EventIDs)), Tips: value.Tips, HistoryDigest: value.HistoryDigest}) != nil {
		return historyManifest{}, false, errors.New("invalid public channel history manifest head")
	}
	return value, true, nil
}

func readOptionalStoreFile(path string, limit int64) ([]byte, bool, error) {
	if _, err := os.Lstat(path); errors.Is(err, os.ErrNotExist) {
		return nil, false, nil
	} else if err != nil {
		return nil, false, err
	}
	raw, err := securefile.ReadBoundedRegular(path, limit)
	return raw, true, err
}

func requireStoreDirectory(path string) error {
	info, err := os.Lstat(path)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm() != 0o700 {
		return errors.New("public channel store path is not a private directory")
	}
	return nil
}

func putStoreImmutable(path string, raw []byte) error {
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err == nil {
		if _, err := file.Write(raw); err != nil {
			_ = file.Close()
			_ = os.Remove(path)
			return errors.New("write public channel immutable object")
		}
		if err := file.Sync(); err != nil {
			_ = file.Close()
			_ = os.Remove(path)
			return errors.New("sync public channel immutable object")
		}
		if err := file.Close(); err != nil {
			_ = os.Remove(path)
			return errors.New("close public channel immutable object")
		}
		return syncStoreDirectory(filepath.Dir(path))
	}
	if !errors.Is(err, os.ErrExist) {
		return err
	}
	existing, err := securefile.ReadBoundedRegular(path, MaxStoreRecordBytes)
	if err != nil || !bytes.Equal(existing, raw) {
		return errors.New("public channel immutable object conflicts")
	}
	return nil
}

func replaceStoreFile(path string, raw []byte) error {
	temporary, err := os.CreateTemp(filepath.Dir(path), ".public-channel-*")
	if err != nil {
		return err
	}
	temporaryPath := temporary.Name()
	defer os.Remove(temporaryPath)
	if err := temporary.Chmod(0o600); err != nil {
		_ = temporary.Close()
		return err
	}
	if _, err := temporary.Write(raw); err != nil {
		_ = temporary.Close()
		return errors.New("write public channel checkpoint")
	}
	if err := temporary.Sync(); err != nil {
		_ = temporary.Close()
		return errors.New("sync public channel checkpoint")
	}
	if err := temporary.Close(); err != nil {
		return errors.New("close public channel checkpoint")
	}
	if err := os.Rename(temporaryPath, path); err != nil {
		return err
	}
	return syncStoreDirectory(filepath.Dir(path))
}

func syncStoreDirectory(path string) error {
	directory, err := os.Open(path)
	if err != nil {
		return err
	}
	defer directory.Close()
	return directory.Sync()
}

func sortStrings(values []string) { sort.Strings(values) }

func containsAll(have, wanted []string) bool {
	present := make(map[string]struct{}, len(have))
	for _, id := range have {
		present[id] = struct{}{}
	}
	for _, id := range wanted {
		if _, found := present[id]; !found {
			return false
		}
	}
	return true
}
