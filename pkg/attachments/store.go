package attachments

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"

	"github.com/tosnetwork/tos-messenger/internal/canon"
	"github.com/tosnetwork/tos-messenger/internal/dirlock"
)

const (
	storeLockName         = ".attachment-store.lock"
	objectsDir            = "objects"
	leasesDir             = "leases"
	leaseSchema           = "tos.messaging.attachment-lease.v1"
	MaxStoreObjects       = 100_000
	MaxStoreBytes   int64 = 1 << 40
)

type StoreQuota struct {
	MaxLeases    int
	MaxObjects   int
	MaxBytes     int64
	MaxRetention time.Duration
}

func DefaultStoreQuota() StoreQuota {
	return StoreQuota{MaxLeases: 1_024, MaxObjects: 10_000, MaxBytes: 1 << 30, MaxRetention: 30 * 24 * time.Hour}
}

func (q StoreQuota) validate() error {
	if q.MaxLeases < 1 || q.MaxLeases > MaxStoreObjects || q.MaxObjects < 1 || q.MaxObjects > MaxStoreObjects || q.MaxBytes < 1 || q.MaxBytes > MaxStoreBytes ||
		q.MaxRetention < time.Second || q.MaxRetention > 365*24*time.Hour {
		return errors.New("invalid attachment store quota")
	}
	return nil
}

type lease struct {
	Schema         string   `json:"schema"`
	ManifestDigest string   `json:"manifest_digest"`
	ChunkDigests   []string `json:"chunk_digests"`
	ExpiresAtUnix  uint64   `json:"expires_at_unix"`
}

type GCReport struct {
	ExpiredLeases  int
	ObjectsRemoved int
	BytesRemoved   int64
}

// Store is a single-writer local cache of opaque encrypted attachment chunks.
// It persists neither the attachment key nor plaintext metadata.
type Store struct {
	root  string
	quota StoreQuota
	lock  *dirlock.Lock
	mutex sync.Mutex
}

func OpenStore(root string, quota StoreQuota) (*Store, error) {
	if !filepath.IsAbs(root) || filepath.Clean(root) != root {
		return nil, errors.New("invalid attachment store root")
	}
	if err := quota.validate(); err != nil {
		return nil, err
	}
	if err := os.MkdirAll(root, 0o700); err != nil {
		return nil, errors.New("create attachment store")
	}
	if err := requirePrivateDirectory(root); err != nil {
		return nil, err
	}
	for _, name := range []string{objectsDir, leasesDir} {
		path := filepath.Join(root, name)
		if err := os.Mkdir(path, 0o700); err != nil && !errors.Is(err, os.ErrExist) {
			return nil, errors.New("create attachment store directory")
		}
		if err := requirePrivateDirectory(path); err != nil {
			return nil, err
		}
	}
	lock, err := dirlock.Acquire(root, storeLockName)
	if err != nil {
		return nil, err
	}
	return &Store{root: root, quota: quota, lock: lock}, nil
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

// Put commits all ciphertext objects before publishing their lease. A crash
// may leave unreferenced objects for GC, never a lease whose chunks are absent.
func (s *Store) Put(ref Reference, chunks []Chunk, now time.Time) (bool, error) {
	if err := s.usable(); err != nil {
		return false, err
	}
	if now.IsZero() || now.Unix() < 0 || uint64(now.Unix()) >= ref.Metadata.ExpiresAtUnix ||
		ref.Metadata.ExpiresAtUnix-uint64(now.Unix()) > uint64(s.quota.MaxRetention/time.Second) {
		return false, errors.New("attachment retention is outside store policy")
	}
	if err := validateStoredChunks(ref, chunks); err != nil {
		return false, err
	}
	manifestDigest, _ := ManifestDigest(ref.Manifest)
	wanted := lease{Schema: leaseSchema, ManifestDigest: manifestDigest,
		ChunkDigests: append([]string(nil), ref.Manifest.ChunkDigests...), ExpiresAtUnix: ref.Metadata.ExpiresAtUnix}
	s.mutex.Lock()
	defer s.mutex.Unlock()
	existing, found, err := s.readLease(manifestDigest)
	if err != nil {
		return false, err
	}
	if found {
		if !sameLease(existing, wanted) {
			return false, errors.New("attachment manifest conflicts with its stored lease")
		}
		return false, s.verifyObjects(chunks)
	}
	leases, err := s.allLeases()
	if err != nil {
		return false, err
	}
	if len(leases) >= s.quota.MaxLeases {
		return false, errors.New("attachment store lease quota exceeded")
	}
	newObjects, newBytes, err := s.newObjectCost(chunks)
	if err != nil {
		return false, err
	}
	count, heldBytes, err := s.usage()
	if err != nil {
		return false, err
	}
	if count+newObjects > s.quota.MaxObjects || heldBytes+newBytes > s.quota.MaxBytes {
		return false, errors.New("attachment store quota exceeded")
	}
	for _, chunk := range chunks {
		if err := s.putObject(chunk); err != nil {
			return false, err
		}
	}
	encoded, _ := json.Marshal(wanted)
	if err := replaceFile(s.leasePath(manifestDigest), encoded); err != nil {
		return false, err
	}
	return true, nil
}

// Fetch returns chunks in manifest order after rechecking every content digest.
func (s *Store) Fetch(ref Reference) ([]Chunk, error) {
	if err := s.usable(); err != nil {
		return nil, err
	}
	if err := ValidateReference(ref); err != nil {
		return nil, err
	}
	digest, _ := ManifestDigest(ref.Manifest)
	s.mutex.Lock()
	defer s.mutex.Unlock()
	stored, found, err := s.readLease(digest)
	if err != nil || !found {
		if err == nil {
			err = errors.New("attachment lease not found")
		}
		return nil, err
	}
	if stored.ExpiresAtUnix != ref.Metadata.ExpiresAtUnix {
		return nil, errors.New("attachment lease expiry mismatch")
	}
	if len(stored.ChunkDigests) != len(ref.Manifest.ChunkDigests) {
		return nil, errors.New("attachment lease manifest mismatch")
	}
	for index := range stored.ChunkDigests {
		if stored.ChunkDigests[index] != ref.Manifest.ChunkDigests[index] {
			return nil, errors.New("attachment lease manifest mismatch")
		}
	}
	chunks := make([]Chunk, 0, len(stored.ChunkDigests))
	for index, chunkDigest := range stored.ChunkDigests {
		raw, err := readPrivateFile(s.objectPath(chunkDigest), int64(MaxChunkBytes+32))
		if err != nil || canon.Digest(raw) != chunkDigest {
			return nil, errors.New("attachment ciphertext object is missing or corrupt")
		}
		chunks = append(chunks, Chunk{Index: uint32(index), Digest: chunkDigest, Ciphertext: raw})
	}
	return chunks, nil
}

func (s *Store) Held(ref Reference) (map[string]bool, error) {
	if err := s.usable(); err != nil {
		return nil, err
	}
	if err := ValidateReference(ref); err != nil {
		return nil, err
	}
	s.mutex.Lock()
	defer s.mutex.Unlock()
	held := make(map[string]bool, len(ref.Manifest.ChunkDigests))
	for _, digest := range ref.Manifest.ChunkDigests {
		raw, err := readPrivateFile(s.objectPath(digest), int64(MaxChunkBytes+32))
		held[digest] = err == nil && canon.Digest(raw) == digest
	}
	return held, nil
}

// Delete removes the local lease. GC separately removes chunks no remaining
// lease references; neither operation claims deletion from remote copies.
func (s *Store) Delete(manifestDigest string) (bool, error) {
	if err := s.usable(); err != nil {
		return false, err
	}
	if !validContentDigest(manifestDigest) {
		return false, errors.New("invalid attachment manifest digest")
	}
	s.mutex.Lock()
	defer s.mutex.Unlock()
	path := s.leasePath(manifestDigest)
	if _, err := os.Lstat(path); errors.Is(err, os.ErrNotExist) {
		return false, nil
	} else if err != nil {
		return false, errors.New("inspect attachment lease")
	}
	if err := os.Remove(path); err != nil {
		return false, errors.New("remove attachment lease")
	}
	return true, syncDirectory(filepath.Join(s.root, leasesDir))
}

func (s *Store) GC(now time.Time) (GCReport, error) {
	if err := s.usable(); err != nil || now.IsZero() || now.Unix() < 0 {
		if err == nil {
			err = errors.New("invalid attachment GC time")
		}
		return GCReport{}, err
	}
	s.mutex.Lock()
	defer s.mutex.Unlock()
	leases, err := s.allLeases()
	if err != nil {
		return GCReport{}, err
	}
	referenced := map[string]struct{}{}
	report := GCReport{}
	for _, held := range leases {
		if held.ExpiresAtUnix <= uint64(now.Unix()) {
			continue
		}
		for _, digest := range held.ChunkDigests {
			referenced[digest] = struct{}{}
		}
	}
	entries, err := os.ReadDir(filepath.Join(s.root, objectsDir))
	if err != nil {
		return GCReport{}, errors.New("read attachment objects")
	}
	type removable struct {
		path string
		size int64
	}
	remove := make([]removable, 0)
	for _, entry := range entries {
		if entry.IsDir() || filepath.Ext(entry.Name()) != ".bin" {
			return GCReport{}, errors.New("invalid attachment object entry")
		}
		digest := "sha256:" + entry.Name()[:len(entry.Name())-4]
		if !validContentDigest(digest) {
			return GCReport{}, errors.New("invalid attachment object name")
		}
		path := filepath.Join(s.root, objectsDir, entry.Name())
		raw, err := readPrivateFile(path, int64(MaxChunkBytes+32))
		if err != nil || canon.Digest(raw) != digest {
			return GCReport{}, errors.New("invalid attachment object")
		}
		if _, keep := referenced[digest]; keep {
			continue
		}
		info, _ := os.Lstat(path)
		remove = append(remove, removable{path: path, size: info.Size()})
	}
	// All lease and object entries are validated before the first deletion.
	// Damage therefore fails closed without a partial collection.
	for _, held := range leases {
		if held.ExpiresAtUnix > uint64(now.Unix()) {
			continue
		}
		if err := os.Remove(s.leasePath(held.ManifestDigest)); err != nil {
			return GCReport{}, errors.New("remove expired attachment lease")
		}
		report.ExpiredLeases++
	}
	for _, object := range remove {
		if err := os.Remove(object.path); err != nil {
			return GCReport{}, errors.New("remove attachment object")
		}
		report.ObjectsRemoved++
		report.BytesRemoved += object.size
	}
	if report.ExpiredLeases > 0 {
		if err := syncDirectory(filepath.Join(s.root, leasesDir)); err != nil {
			return GCReport{}, err
		}
	}
	if report.ObjectsRemoved > 0 {
		if err := syncDirectory(filepath.Join(s.root, objectsDir)); err != nil {
			return GCReport{}, err
		}
	}
	return report, nil
}

func validateStoredChunks(ref Reference, chunks []Chunk) error {
	if err := ValidateReference(ref); err != nil {
		return err
	}
	if len(chunks) != len(ref.Manifest.ChunkDigests) {
		return errors.New("attachment chunk set is incomplete")
	}
	for index, chunk := range chunks {
		if chunk.Index != uint32(index) || chunk.Digest != ref.Manifest.ChunkDigests[index] || canon.Digest(chunk.Ciphertext) != chunk.Digest || len(chunk.Ciphertext) != expectedChunkPlaintext(ref.Manifest, index)+16 {
			return errors.New("invalid attachment ciphertext chunk")
		}
	}
	return nil
}

func (s *Store) usable() error {
	if s == nil || s.lock == nil || !s.lock.Held() {
		return errors.New("attachment store is not owned")
	}
	return nil
}
func (s *Store) objectPath(d string) string {
	return filepath.Join(s.root, objectsDir, d[len("sha256:"):]+".bin")
}
func (s *Store) leasePath(d string) string {
	return filepath.Join(s.root, leasesDir, d[len("sha256:"):]+".json")
}

func (s *Store) readLease(digest string) (lease, bool, error) {
	raw, err := readPrivateFile(s.leasePath(digest), MaxReferenceBytes)
	if errors.Is(err, os.ErrNotExist) {
		return lease{}, false, nil
	}
	if err != nil {
		return lease{}, false, errors.New("read attachment lease")
	}
	var value lease
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&value); err != nil || value.Schema != leaseSchema || value.ManifestDigest != digest || !validContentDigest(digest) || len(value.ChunkDigests) == 0 || len(value.ChunkDigests) > MaxChunks || value.ExpiresAtUnix == 0 {
		return lease{}, false, errors.New("invalid attachment lease")
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return lease{}, false, errors.New("attachment lease has trailing content")
	}
	for _, chunk := range value.ChunkDigests {
		if !validContentDigest(chunk) {
			return lease{}, false, errors.New("invalid attachment lease")
		}
	}
	return value, true, nil
}

func (s *Store) allLeases() ([]lease, error) {
	entries, err := os.ReadDir(filepath.Join(s.root, leasesDir))
	if err != nil {
		return nil, errors.New("read attachment leases")
	}
	values := make([]lease, 0, len(entries))
	for _, entry := range entries {
		if entry.IsDir() || filepath.Ext(entry.Name()) != ".json" {
			return nil, errors.New("invalid attachment lease entry")
		}
		digest := "sha256:" + entry.Name()[:len(entry.Name())-5]
		value, found, err := s.readLease(digest)
		if err != nil || !found {
			return nil, errors.New("invalid attachment lease set")
		}
		values = append(values, value)
	}
	sort.Slice(values, func(i, j int) bool { return values[i].ManifestDigest < values[j].ManifestDigest })
	return values, nil
}

func (s *Store) verifyObjects(chunks []Chunk) error {
	for _, c := range chunks {
		raw, err := readPrivateFile(s.objectPath(c.Digest), int64(MaxChunkBytes+32))
		if err != nil || !bytes.Equal(raw, c.Ciphertext) {
			return errors.New("stored attachment object conflicts")
		}
	}
	return nil
}
func (s *Store) newObjectCost(chunks []Chunk) (int, int64, error) {
	count := 0
	var size int64
	for _, c := range chunks {
		raw, err := readPrivateFile(s.objectPath(c.Digest), int64(MaxChunkBytes+32))
		if errors.Is(err, os.ErrNotExist) {
			count++
			size += int64(len(c.Ciphertext))
			continue
		}
		if err != nil || !bytes.Equal(raw, c.Ciphertext) {
			return 0, 0, errors.New("stored attachment object conflicts")
		}
	}
	return count, size, nil
}
func (s *Store) usage() (int, int64, error) {
	entries, err := os.ReadDir(filepath.Join(s.root, objectsDir))
	if err != nil {
		return 0, 0, err
	}
	var size int64
	for _, e := range entries {
		if e.IsDir() || filepath.Ext(e.Name()) != ".bin" {
			return 0, 0, errors.New("invalid attachment object entry")
		}
		digest := "sha256:" + e.Name()[:len(e.Name())-4]
		if !validContentDigest(digest) {
			return 0, 0, errors.New("invalid attachment object name")
		}
		raw, err := readPrivateFile(filepath.Join(s.root, objectsDir, e.Name()), int64(MaxChunkBytes+32))
		if err != nil || canon.Digest(raw) != digest {
			return 0, 0, errors.New("invalid attachment object")
		}
		size += int64(len(raw))
	}
	return len(entries), size, nil
}
func (s *Store) putObject(c Chunk) error {
	path := s.objectPath(c.Digest)
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if errors.Is(err, os.ErrExist) {
		raw, e := readPrivateFile(path, int64(MaxChunkBytes+32))
		if e != nil || !bytes.Equal(raw, c.Ciphertext) {
			return errors.New("stored attachment object conflicts")
		}
		return nil
	}
	if err != nil {
		return errors.New("create attachment object")
	}
	return writeSync(f, path, c.Ciphertext)
}

func requirePrivateDirectory(path string) error {
	info, err := os.Lstat(path)
	if err != nil || !info.IsDir() || info.Mode().Perm() != 0o700 || info.Mode()&os.ModeSymlink != 0 {
		return errors.New("attachment store needs private directories")
	}
	return nil
}
func readPrivateFile(path string, limit int64) ([]byte, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() || info.Mode().Perm() != 0o600 || info.Size() < 1 || info.Size() > limit {
		return nil, errors.New("invalid private attachment record")
	}
	return os.ReadFile(path)
}
func writeSync(file *os.File, path string, raw []byte) error {
	if _, err := file.Write(raw); err != nil {
		_ = file.Close()
		_ = os.Remove(path)
		return errors.New("write attachment record")
	}
	if err := file.Sync(); err != nil {
		_ = file.Close()
		_ = os.Remove(path)
		return errors.New("sync attachment record")
	}
	if err := file.Close(); err != nil {
		_ = os.Remove(path)
		return errors.New("close attachment record")
	}
	return syncDirectory(filepath.Dir(path))
}
func replaceFile(path string, raw []byte) error {
	temp, err := os.CreateTemp(filepath.Dir(path), ".attachment-")
	if err != nil {
		return err
	}
	name := temp.Name()
	defer os.Remove(name)
	if err := temp.Chmod(0o600); err != nil {
		_ = temp.Close()
		return err
	}
	if err := writeSync(temp, name, raw); err != nil {
		return err
	}
	if err := os.Rename(name, path); err != nil {
		return err
	}
	return syncDirectory(filepath.Dir(path))
}
func syncDirectory(path string) error {
	dir, err := os.Open(path)
	if err != nil {
		return err
	}
	defer dir.Close()
	return dir.Sync()
}
func sameLease(a, b lease) bool {
	if a.Schema != b.Schema || a.ManifestDigest != b.ManifestDigest || a.ExpiresAtUnix != b.ExpiresAtUnix || len(a.ChunkDigests) != len(b.ChunkDigests) {
		return false
	}
	for i := range a.ChunkDigests {
		if a.ChunkDigests[i] != b.ChunkDigests[i] {
			return false
		}
	}
	return true
}
