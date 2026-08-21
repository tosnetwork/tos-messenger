package attachments

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
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
	storeLockName              = ".attachment-store.lock"
	storeGenerationName        = ".attachment-store-generation"
	storeGenerationValue       = "tos.messaging.attachment-store-generation.v2\n"
	objectsDir                 = "objects"
	leasesDir                  = "leases"
	accessClaimsDir            = "access-claims"
	leaseSchema                = "tos.messaging.attachment-lease.v1"
	MaxStoreObjects            = 100_000
	MaxStoreBytes        int64 = 1 << 40
)

var (
	ErrStoreConflict = errors.New("attachment store conflict")
	ErrStoreQuota    = errors.New("attachment store quota exceeded")
	ErrLeaseNotFound = errors.New("attachment lease not found")
)

// DefaultStagingGrace protects chunks belonging to a bounded multi-frame
// upload from periodic collection. A client that pauses longer can safely
// resume by retransmitting content-addressed chunks.
const DefaultStagingGrace = 10 * time.Minute

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

// StorageLease is the non-secret subset an untrusted storage operator needs.
// It intentionally excludes the attachment key and all plaintext metadata.
type StorageLease struct {
	ManifestDigest string
	ChunkDigests   []string
	ExpiresAtUnix  uint64
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
	if err := ensureStoreGeneration(root); err != nil {
		return nil, err
	}
	for _, name := range []string{objectsDir, leasesDir, accessClaimsDir} {
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

func ensureStoreGeneration(root string) error {
	path := filepath.Join(root, storeGenerationName)
	raw, err := readPrivateFile(path, 256)
	if err == nil {
		if string(raw) != storeGenerationValue {
			return errors.New("unsupported attachment store generation")
		}
		return nil
	}
	if !errors.Is(err, os.ErrNotExist) {
		return errors.New("invalid attachment store generation marker")
	}
	entries, readErr := os.ReadDir(root)
	if readErr != nil {
		return errors.New("inspect attachment store generation")
	}
	if len(entries) != 0 {
		return errors.New("unmarked attachment store state requires explicit migration")
	}
	file, createErr := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if errors.Is(createErr, os.ErrExist) {
		raw, createErr = readPrivateFile(path, 256)
		if createErr == nil && string(raw) == storeGenerationValue {
			return nil
		}
		return errors.New("invalid concurrent attachment store generation")
	}
	if createErr != nil {
		return errors.New("create attachment store generation")
	}
	return writeSync(file, path, []byte(storeGenerationValue))
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
	if err := validateStoredChunks(ref, chunks); err != nil {
		return false, err
	}
	manifestDigest, err := ManifestDigest(ref.Manifest)
	if err != nil {
		return false, err
	}
	return s.PutOpaque(StorageLease{ManifestDigest: manifestDigest,
		ChunkDigests: ref.Manifest.ChunkDigests, ExpiresAtUnix: ref.Metadata.ExpiresAtUnix}, chunks, now)
}

// PutOpaque durably stores the exact ciphertext objects and publishes their
// non-secret lease only after every object is synced. It is the storage-side
// primitive used by an authenticated remote protocol.
func (s *Store) PutOpaque(value StorageLease, chunks []Chunk, now time.Time) (bool, error) {
	if err := s.usable(); err != nil {
		return false, err
	}
	if err := validateStorageLease(value, chunks, now, s.quota.MaxRetention); err != nil {
		return false, err
	}
	if _, err := s.PutObjects(chunks); err != nil {
		return false, err
	}
	var total uint64
	for _, chunk := range chunks {
		total += uint64(len(chunk.Ciphertext))
	}
	return s.CommitOpaque(value, total, now)
}

// PutObjects durably stages a bounded set of content-addressed ciphertext
// objects without publishing a lease. Interrupted uploads resume by sending
// only missing objects; unreferenced objects remain inert and are removed by
// GC. Indexes are manifest positions and need not be contiguous in one batch.
func (s *Store) PutObjects(chunks []Chunk) (int, error) {
	if err := s.usable(); err != nil {
		return 0, err
	}
	if err := validateOpaqueChunkBatch(chunks); err != nil {
		return 0, err
	}
	s.mutex.Lock()
	defer s.mutex.Unlock()
	newObjects, newBytes, err := s.newObjectCost(chunks)
	if err != nil {
		return 0, err
	}
	count, heldBytes, err := s.usage()
	if err != nil {
		return 0, err
	}
	if count+newObjects > s.quota.MaxObjects || heldBytes+newBytes > s.quota.MaxBytes {
		return 0, ErrStoreQuota
	}
	for _, chunk := range chunks {
		if err := s.putObject(chunk); err != nil {
			return 0, err
		}
	}
	return newObjects, nil
}

// CommitOpaque publishes a lease only after every named object is present,
// hash-correct and has the exact aggregate byte count authorized by the grant.
func (s *Store) CommitOpaque(value StorageLease, ciphertextBytes uint64, now time.Time) (bool, error) {
	if err := s.usable(); err != nil {
		return false, err
	}
	if err := validateStorageLeaseMetadata(value, now, s.quota.MaxRetention); err != nil || ciphertextBytes == 0 {
		if err == nil {
			err = errors.New("invalid attachment ciphertext byte count")
		}
		return false, err
	}
	wanted := lease{Schema: leaseSchema, ManifestDigest: value.ManifestDigest,
		ChunkDigests: append([]string(nil), value.ChunkDigests...), ExpiresAtUnix: value.ExpiresAtUnix}
	s.mutex.Lock()
	defer s.mutex.Unlock()
	existing, found, err := s.readLease(value.ManifestDigest)
	if err != nil {
		return false, err
	}
	if found {
		if !sameLease(existing, wanted) {
			return false, fmt.Errorf("%w: manifest conflicts with its stored lease", ErrStoreConflict)
		}
		return false, s.verifyLeaseObjects(value, ciphertextBytes)
	}
	leases, err := s.allLeases()
	if err != nil {
		return false, err
	}
	if len(leases) >= s.quota.MaxLeases {
		return false, ErrStoreQuota
	}
	if err := s.verifyLeaseObjects(value, ciphertextBytes); err != nil {
		return false, err
	}
	encoded, err := json.Marshal(wanted)
	if err != nil {
		return false, errors.New("encode attachment lease")
	}
	if err := replaceFile(s.leasePath(value.ManifestDigest), encoded); err != nil {
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
	digest, err := ManifestDigest(ref.Manifest)
	if err != nil {
		return nil, err
	}
	chunks, expiresAt, err := s.fetchOpaque(digest, ref.Manifest.ChunkDigests, time.Time{}, false)
	if err != nil {
		return nil, err
	}
	if expiresAt != ref.Metadata.ExpiresAtUnix {
		return nil, errors.New("attachment lease expiry mismatch")
	}
	return chunks, nil
}

// FetchOpaque returns only the requested ciphertext objects after proving that
// they belong to one live lease. Request order is preserved and each returned
// Index is its position in the complete manifest.
func (s *Store) FetchOpaque(manifestDigest string, digests []string, now time.Time) ([]Chunk, uint64, error) {
	return s.fetchOpaque(manifestDigest, digests, now, true)
}

func (s *Store) fetchOpaque(manifestDigest string, digests []string, now time.Time, enforceExpiry bool) ([]Chunk, uint64, error) {
	if err := s.usable(); err != nil {
		return nil, 0, err
	}
	if !validContentDigest(manifestDigest) || len(digests) == 0 || len(digests) > MaxChunks ||
		enforceExpiry && (now.IsZero() || now.Unix() < 0) {
		return nil, 0, errors.New("invalid attachment object fetch")
	}
	seen := make(map[string]struct{}, len(digests))
	for _, digest := range digests {
		if !validContentDigest(digest) {
			return nil, 0, errors.New("invalid attachment object digest")
		}
		if _, duplicate := seen[digest]; duplicate {
			return nil, 0, errors.New("duplicate attachment object digest")
		}
		seen[digest] = struct{}{}
	}
	s.mutex.Lock()
	defer s.mutex.Unlock()
	stored, found, err := s.readLease(manifestDigest)
	if err != nil || !found {
		if err == nil {
			err = ErrLeaseNotFound
		}
		return nil, 0, err
	}
	if enforceExpiry && stored.ExpiresAtUnix <= uint64(now.Unix()) {
		return nil, 0, ErrLeaseNotFound
	}
	positions := make(map[string]uint32, len(stored.ChunkDigests))
	for index, digest := range stored.ChunkDigests {
		positions[digest] = uint32(index)
	}
	chunks := make([]Chunk, 0, len(digests))
	for _, chunkDigest := range digests {
		index, member := positions[chunkDigest]
		if !member {
			return nil, 0, errors.New("attachment object is outside its lease")
		}
		raw, err := readPrivateFile(s.objectPath(chunkDigest), int64(MaxChunkBytes+32))
		if err != nil || canon.Digest(raw) != chunkDigest {
			return nil, 0, errors.New("attachment ciphertext object is missing or corrupt")
		}
		chunks = append(chunks, Chunk{Index: index, Digest: chunkDigest, Ciphertext: raw})
	}
	return chunks, stored.ExpiresAtUnix, nil
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
	return s.GCWithStagingGrace(now, 0)
}

// GCWithStagingGrace removes expired leases and unreferenced ciphertext older
// than stagingGrace. Lease expiry is never delayed by the staging grace.
func (s *Store) GCWithStagingGrace(now time.Time, stagingGrace time.Duration) (GCReport, error) {
	if err := s.usable(); err != nil || now.IsZero() || now.Unix() < 0 {
		if err == nil {
			err = errors.New("invalid attachment GC time")
		}
		return GCReport{}, err
	}
	if stagingGrace < 0 || stagingGrace > 24*time.Hour {
		return GCReport{}, errors.New("invalid attachment staging grace")
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
		info, err := os.Lstat(path)
		if err != nil {
			return GCReport{}, errors.New("inspect attachment object")
		}
		if stagingGrace > 0 && now.Before(info.ModTime().Add(stagingGrace)) {
			continue
		}
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

func validateStorageLease(value StorageLease, chunks []Chunk, now time.Time, maxRetention time.Duration) error {
	if err := validateStorageLeaseMetadata(value, now, maxRetention); err != nil {
		return err
	}
	if len(chunks) != len(value.ChunkDigests) {
		return errors.New("attachment storage lease is incomplete")
	}
	for index, digest := range value.ChunkDigests {
		chunk := chunks[index]
		if chunk.Index != uint32(index) || chunk.Digest != digest || len(chunk.Ciphertext) <= 16 ||
			len(chunk.Ciphertext) > MaxChunkBytes+16 || canon.Digest(chunk.Ciphertext) != digest {
			return errors.New("invalid opaque attachment ciphertext chunk")
		}
	}
	return nil
}

func validateStorageLeaseMetadata(value StorageLease, now time.Time, maxRetention time.Duration) error {
	if !validContentDigest(value.ManifestDigest) || len(value.ChunkDigests) == 0 || len(value.ChunkDigests) > MaxChunks ||
		now.IsZero() || now.Unix() < 0 || value.ExpiresAtUnix <= uint64(now.Unix()) ||
		value.ExpiresAtUnix-uint64(now.Unix()) > uint64(maxRetention/time.Second) {
		return errors.New("invalid attachment storage lease")
	}
	seen := make(map[string]struct{}, len(value.ChunkDigests))
	for _, digest := range value.ChunkDigests {
		if !validContentDigest(digest) {
			return errors.New("invalid attachment storage lease digest")
		}
		if _, duplicate := seen[digest]; duplicate {
			return errors.New("duplicate attachment storage lease digest")
		}
		seen[digest] = struct{}{}
	}
	return nil
}

func validateOpaqueChunkBatch(chunks []Chunk) error {
	if len(chunks) == 0 || len(chunks) > MaxChunks {
		return errors.New("invalid opaque attachment chunk batch")
	}
	seen := make(map[string]struct{}, len(chunks))
	var total uint64
	for _, chunk := range chunks {
		if chunk.Index >= uint32(MaxChunks) || !validContentDigest(chunk.Digest) || len(chunk.Ciphertext) <= 16 ||
			len(chunk.Ciphertext) > MaxChunkBytes+16 || canon.Digest(chunk.Ciphertext) != chunk.Digest {
			return errors.New("invalid opaque attachment ciphertext chunk")
		}
		if _, duplicate := seen[chunk.Digest]; duplicate {
			return errors.New("duplicate opaque attachment ciphertext chunk")
		}
		seen[chunk.Digest] = struct{}{}
		total += uint64(len(chunk.Ciphertext))
		if total > MaxPlaintextBytes+uint64(MaxChunks*16) {
			return errors.New("opaque attachment ciphertext exceeds its bound")
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
			return fmt.Errorf("%w: stored object differs", ErrStoreConflict)
		}
	}
	return nil
}

func (s *Store) verifyLeaseObjects(value StorageLease, expectedBytes uint64) error {
	var total uint64
	for _, digest := range value.ChunkDigests {
		raw, err := readPrivateFile(s.objectPath(digest), int64(MaxChunkBytes+32))
		if err != nil || canon.Digest(raw) != digest {
			return ErrLeaseNotFound
		}
		total += uint64(len(raw))
	}
	if total != expectedBytes {
		return fmt.Errorf("%w: ciphertext byte count differs", ErrStoreConflict)
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
			return 0, 0, fmt.Errorf("%w: stored object differs", ErrStoreConflict)
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
			return fmt.Errorf("%w: stored object differs", ErrStoreConflict)
		}
		// A valid retransmission is durable evidence that this staged object is
		// part of an active multi-frame upload. Refresh its collection grace;
		// the content itself remains immutable and hash-addressed.
		now := time.Now()
		if err := os.Chtimes(path, now, now); err != nil {
			return errors.New("refresh attachment object staging time")
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
