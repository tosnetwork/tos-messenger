package mailbox

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
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
	"github.com/tosnetwork/tos-messenger/internal/ids"
	"github.com/tosnetwork/tos-messenger/pkg/envelope"
)

const (
	recordSchema   = "tos.messaging.mailbox-record.v1"
	lockName       = ".mailbox-relay.lock"
	mailboxesDir   = "mailboxes"
	MaxListResults = 256
	MaxRecordBytes = envelope.MaxCiphertextBytes + 2048
)

var (
	ErrConflict = errors.New("Relay message identity conflicts with stored ciphertext")
	ErrQuota    = errors.New("Mailbox Relay quota exceeded")
)

// Quota bounds ciphertext retained by one Relay installation.
type Quota struct {
	MaxMessages       int
	MaxMessagesPerBox int
	MaxBytes          int64
	MaxBytesPerBox    int64
	MaxRetention      time.Duration
}

func DefaultQuota() Quota {
	return Quota{MaxMessages: 10_000, MaxMessagesPerBox: 1_000, MaxBytes: 256 << 20,
		MaxBytesPerBox: 32 << 20, MaxRetention: 7 * 24 * time.Hour}
}

func (q Quota) validate() error {
	if q.MaxMessages < 1 || q.MaxMessages > 1_000_000 || q.MaxMessagesPerBox < 1 || q.MaxMessagesPerBox > q.MaxMessages ||
		q.MaxBytes < envelope.MinCiphertextBytes || q.MaxBytes > 1<<40 || q.MaxBytesPerBox < envelope.MinCiphertextBytes ||
		q.MaxBytesPerBox > q.MaxBytes || q.MaxRetention < time.Second || q.MaxRetention > time.Duration(envelope.MaxEnvelopeLifetimeSeconds)*time.Second {
		return errors.New("invalid Mailbox Relay quota")
	}
	return nil
}

type record struct {
	Schema           string `json:"schema"`
	MailboxID        string `json:"opaque_mailbox_id"`
	MessageID        string `json:"message_id"`
	CiphertextBase64 string `json:"ciphertext_base64"`
	CiphertextDigest string `json:"ciphertext_digest"`
	StorageToken     string `json:"storage_token,omitempty"`
	StoredAtUnix     uint64 `json:"stored_at_unix"`
	ExpiresAtUnix    uint64 `json:"expires_at_unix"`
}

func (r record) relayEnvelope() (envelope.RelayEnvelope, error) {
	ciphertext, err := base64.StdEncoding.Strict().DecodeString(r.CiphertextBase64)
	if err != nil || canon.Digest(ciphertext) != r.CiphertextDigest {
		return envelope.RelayEnvelope{}, errors.New("stored Relay ciphertext is corrupt")
	}
	value := envelope.RelayEnvelope{OpaqueMailboxID: r.MailboxID, MessageID: r.MessageID,
		Ciphertext: ciphertext, StorageToken: r.StorageToken, ExpiresAtUnix: r.ExpiresAtUnix}
	if err := envelope.ValidateRelay(value); err != nil {
		return envelope.RelayEnvelope{}, err
	}
	return value, nil
}

// Store is a single-writer, crash-safe opaque Mailbox Relay store.
type Store struct {
	root  string
	quota Quota
	key   ed25519.PrivateKey
	lock  *dirlock.Lock
	mutex sync.Mutex
}

func Open(root string, quota Quota, key ed25519.PrivateKey) (*Store, error) {
	if !filepath.IsAbs(root) || filepath.Clean(root) != root {
		return nil, errors.New("invalid Mailbox Relay root")
	}
	if err := quota.validate(); err != nil {
		return nil, err
	}
	if len(key) != ed25519.PrivateKeySize {
		return nil, errors.New("invalid Mailbox Relay signing key")
	}
	if err := os.MkdirAll(root, 0o700); err != nil {
		return nil, errors.New("create Mailbox Relay root")
	}
	info, err := os.Lstat(root)
	if err != nil || !info.IsDir() || info.Mode().Perm() != 0o700 || info.Mode()&os.ModeSymlink != 0 {
		return nil, errors.New("Mailbox Relay root must be a private directory")
	}
	mailboxes := filepath.Join(root, mailboxesDir)
	if err := os.Mkdir(mailboxes, 0o700); err != nil && !errors.Is(err, os.ErrExist) {
		return nil, errors.New("create Mailbox Relay mailboxes")
	}
	mailboxesInfo, err := os.Lstat(mailboxes)
	if err != nil || !mailboxesInfo.IsDir() || mailboxesInfo.Mode().Perm() != 0o700 || mailboxesInfo.Mode()&os.ModeSymlink != 0 {
		return nil, errors.New("invalid Mailbox Relay mailboxes directory")
	}
	lock, err := dirlock.Acquire(root, lockName)
	if err != nil {
		return nil, err
	}
	return &Store{root: root, quota: quota, key: append(ed25519.PrivateKey(nil), key...), lock: lock}, nil
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
	for i := range s.key {
		s.key[i] = 0
	}
	return lock.Close()
}

// Put returns fresh only after the record is synced. A byte-identical retry
// receives another valid StoredAck without consuming quota a second time.
func (s *Store) Put(value envelope.RelayEnvelope, now time.Time) (fresh bool, ack StoredAck, err error) {
	if err = s.usable(); err != nil {
		return false, StoredAck{}, err
	}
	if err = envelope.AcceptedForStorage(value, now, s.quota.MaxRetention); err != nil {
		return false, StoredAck{}, err
	}
	s.mutex.Lock()
	defer s.mutex.Unlock()
	box, err := s.ensureBox(value.OpaqueMailboxID)
	if err != nil {
		return false, StoredAck{}, err
	}
	path := filepath.Join(box, value.MessageID[4:]+".json")
	digest := canon.Digest(value.Ciphertext)
	stored := record{Schema: recordSchema, MailboxID: value.OpaqueMailboxID, MessageID: value.MessageID,
		CiphertextBase64: base64.StdEncoding.EncodeToString(value.Ciphertext), CiphertextDigest: digest,
		StorageToken: value.StorageToken, StoredAtUnix: uint64(now.Unix()), ExpiresAtUnix: value.ExpiresAtUnix}
	encoded, err := json.Marshal(stored)
	if err != nil || len(encoded) > MaxRecordBytes {
		return false, StoredAck{}, errors.New("encode Mailbox Relay record")
	}
	_, statErr := os.Lstat(path)
	if errors.Is(statErr, os.ErrNotExist) {
		if err := s.checkQuota(value.OpaqueMailboxID, int64(len(value.Ciphertext))); err != nil {
			return false, StoredAck{}, err
		}
		file, createErr := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
		if createErr != nil {
			return false, StoredAck{}, errors.New("create Mailbox Relay record")
		}
		if err := writeSync(file, encoded); err != nil {
			_ = os.Remove(path)
			return false, StoredAck{}, err
		}
		if err := syncDir(box); err != nil {
			_ = os.Remove(path)
			return false, StoredAck{}, err
		}
		fresh = true
	} else if statErr == nil {
		existing, readErr := readRecord(path)
		if readErr != nil {
			return false, StoredAck{}, readErr
		}
		if existing.MailboxID != value.OpaqueMailboxID || existing.MessageID != value.MessageID || existing.CiphertextDigest != digest || existing.ExpiresAtUnix != value.ExpiresAtUnix || existing.StorageToken != value.StorageToken {
			return false, StoredAck{}, ErrConflict
		}
		stored = existing
	} else {
		return false, StoredAck{}, errors.New("inspect Mailbox Relay record")
	}
	ack, err = SignAck(StoredAck{MailboxID: stored.MailboxID, MessageID: stored.MessageID,
		CiphertextDigest: stored.CiphertextDigest, StoredAtUnix: stored.StoredAtUnix, ExpiresAtUnix: stored.ExpiresAtUnix}, s.key)
	return fresh, ack, err
}

// List returns live ciphertext in durable receipt order. Expired records are
// never handed out even if a maintenance sweep has not removed them yet.
func (s *Store) List(mailboxID string, now time.Time, limit int) ([]envelope.RelayEnvelope, error) {
	if err := s.usable(); err != nil {
		return nil, err
	}
	if !ids.Mailbox.MatchString(mailboxID) {
		return nil, errors.New("invalid mailbox identifier")
	}
	if limit < 1 || limit > MaxListResults || now.IsZero() || now.Unix() < 0 {
		return nil, errors.New("invalid Mailbox Relay list request")
	}
	s.mutex.Lock()
	defer s.mutex.Unlock()
	entries, err := os.ReadDir(s.boxPath(mailboxID))
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, errors.New("read mailbox")
	}
	var records []record
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		r, err := readRecord(filepath.Join(s.boxPath(mailboxID), entry.Name()))
		if err != nil {
			return nil, err
		}
		if r.MailboxID != mailboxID || entry.Name() != r.MessageID[4:]+".json" {
			return nil, errors.New("Mailbox Relay record is in the wrong mailbox")
		}
		if r.ExpiresAtUnix > uint64(now.Unix()) {
			records = append(records, r)
		}
	}
	sort.Slice(records, func(i, j int) bool {
		if records[i].StoredAtUnix != records[j].StoredAtUnix {
			return records[i].StoredAtUnix < records[j].StoredAtUnix
		}
		return records[i].MessageID < records[j].MessageID
	})
	if len(records) > limit {
		records = records[:limit]
	}
	result := make([]envelope.RelayEnvelope, 0, len(records))
	for _, r := range records {
		value, err := r.relayEnvelope()
		if err != nil {
			return nil, err
		}
		result = append(result, value)
	}
	return result, nil
}

// Delete acknowledges retrieval by exact ciphertext digest. Authentication of
// the mailbox operation belongs to the caller-facing adapter; a blind message
// identifier alone is insufficient to remove stored data.
func (s *Store) Delete(mailboxID, messageID, ciphertextDigest string) (bool, error) {
	if err := s.usable(); err != nil {
		return false, err
	}
	if !ids.Mailbox.MatchString(mailboxID) || !ids.RelayMessage.MatchString(messageID) || !canon.ValidDigest(ciphertextDigest) {
		return false, errors.New("invalid Mailbox Relay deletion")
	}
	s.mutex.Lock()
	defer s.mutex.Unlock()
	path := filepath.Join(s.boxPath(mailboxID), messageID[4:]+".json")
	r, err := readRecord(path)
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	if r.MailboxID != mailboxID || r.MessageID != messageID || r.CiphertextDigest != ciphertextDigest {
		return false, ErrConflict
	}
	if err := os.Remove(path); err != nil {
		return false, errors.New("remove Mailbox Relay record")
	}
	return true, syncDir(s.boxPath(mailboxID))
}

func (s *Store) Sweep(now time.Time) (int, error) {
	if err := s.usable(); err != nil {
		return 0, err
	}
	if now.IsZero() || now.Unix() < 0 {
		return 0, errors.New("invalid sweep time")
	}
	s.mutex.Lock()
	defer s.mutex.Unlock()
	removed := 0
	boxes, err := os.ReadDir(filepath.Join(s.root, mailboxesDir))
	if err != nil {
		return 0, err
	}
	for _, box := range boxes {
		if !box.IsDir() {
			continue
		}
		path := filepath.Join(s.root, mailboxesDir, box.Name())
		entries, err := os.ReadDir(path)
		if err != nil {
			return removed, err
		}
		for _, entry := range entries {
			r, err := readRecord(filepath.Join(path, entry.Name()))
			if err != nil {
				return removed, err
			}
			if r.ExpiresAtUnix <= uint64(now.Unix()) {
				if err := os.Remove(filepath.Join(path, entry.Name())); err != nil {
					return removed, err
				}
				removed++
			}
		}
		if removed > 0 {
			if err := syncDir(path); err != nil {
				return removed, err
			}
		}
	}
	return removed, nil
}

func (s *Store) usable() error {
	if s == nil || s.lock == nil || !s.lock.Held() {
		return errors.New("Mailbox Relay store is not owned")
	}
	return nil
}
func (s *Store) boxPath(id string) string { return filepath.Join(s.root, mailboxesDir, id[4:]) }
func (s *Store) ensureBox(id string) (string, error) {
	if !ids.Mailbox.MatchString(id) {
		return "", errors.New("invalid mailbox identifier")
	}
	path := s.boxPath(id)
	if err := os.Mkdir(path, 0o700); err != nil && !errors.Is(err, os.ErrExist) {
		return "", errors.New("create mailbox")
	}
	info, err := os.Lstat(path)
	if err != nil || !info.IsDir() || info.Mode().Perm() != 0o700 || info.Mode()&os.ModeSymlink != 0 {
		return "", errors.New("invalid mailbox directory")
	}
	return path, nil
}

func (s *Store) checkQuota(mailboxID string, additional int64) error {
	boxes, err := os.ReadDir(filepath.Join(s.root, mailboxesDir))
	if err != nil {
		return err
	}
	totalCount, boxCount := 0, 0
	var totalBytes, boxBytes int64
	for _, box := range boxes {
		if !box.IsDir() {
			continue
		}
		entries, err := os.ReadDir(filepath.Join(s.root, mailboxesDir, box.Name()))
		if err != nil {
			return err
		}
		for _, entry := range entries {
			r, err := readRecord(filepath.Join(s.root, mailboxesDir, box.Name(), entry.Name()))
			if err != nil {
				return err
			}
			value, err := r.relayEnvelope()
			if err != nil {
				return err
			}
			totalCount++
			totalBytes += int64(len(value.Ciphertext))
			if box.Name() == mailboxID[4:] {
				boxCount++
				boxBytes += int64(len(value.Ciphertext))
			}
		}
	}
	if totalCount+1 > s.quota.MaxMessages || boxCount+1 > s.quota.MaxMessagesPerBox || totalBytes+additional > s.quota.MaxBytes || boxBytes+additional > s.quota.MaxBytesPerBox {
		return ErrQuota
	}
	return nil
}

func readRecord(path string) (record, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return record{}, err
	}
	if len(raw) > MaxRecordBytes {
		return record{}, errors.New("Mailbox Relay record exceeds bound")
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	var r record
	if decoder.Decode(&r) != nil || r.Schema != recordSchema || r.StoredAtUnix == 0 || r.ExpiresAtUnix <= r.StoredAtUnix || !canon.ValidDigest(r.CiphertextDigest) {
		return record{}, errors.New("invalid Mailbox Relay record")
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return record{}, errors.New("Mailbox Relay record has trailing JSON")
	}
	if _, err := r.relayEnvelope(); err != nil {
		return record{}, err
	}
	return r, nil
}
func writeSync(file *os.File, raw []byte) error {
	if _, err := file.Write(raw); err != nil {
		_ = file.Close()
		return errors.New("write Mailbox Relay record")
	}
	if err := file.Sync(); err != nil {
		_ = file.Close()
		return errors.New("sync Mailbox Relay record")
	}
	if err := file.Close(); err != nil {
		return errors.New("close Mailbox Relay record")
	}
	return nil
}
func syncDir(path string) error {
	directory, err := os.Open(path)
	if err != nil {
		return err
	}
	defer directory.Close()
	return directory.Sync()
}
