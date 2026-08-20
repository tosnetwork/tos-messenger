package mailbox

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"time"

	"github.com/tosnetwork/tos-messenger/internal/canon"
)

const (
	accessClaimSchema = "tos.messaging.mailbox-access-claim.v1"
	MaxAccessClaims   = 100_000
	MaxClaimBytes     = 1024
)

var ErrAccessReplay = errors.New("Mailbox access request was replayed")

type accessClaim struct {
	Schema        string `json:"schema"`
	GrantDigest   string `json:"grant_digest"`
	NonceHex      string `json:"nonce_hex"`
	ExpiresAtUnix uint64 `json:"expires_at_unix"`
}

// claimAccess commits the nonce before the caller performs an operation. A
// crash after this point consumes the request rather than reopening it; the
// client uses a new nonce and the underlying store's idempotent operation.
func (s *Store) claimAccess(request AccessRequest, now time.Time) error {
	if err := s.usable(); err != nil {
		return err
	}
	if _, err := AccessRequestCanonicalBytes(request); err != nil {
		return err
	}
	if now.IsZero() || now.Unix() < 0 {
		return errors.New("invalid Mailbox access claim time")
	}
	s.mutex.Lock()
	defer s.mutex.Unlock()

	directory := filepath.Join(s.root, accessClaimsDir)
	entries, err := os.ReadDir(directory)
	if err != nil {
		return errors.New("read Mailbox access claims")
	}
	live := 0
	removed := false
	for _, entry := range entries {
		if entry.IsDir() {
			return errors.New("invalid Mailbox access claim entry")
		}
		path := filepath.Join(directory, entry.Name())
		claim, err := readAccessClaim(path)
		if err != nil {
			return err
		}
		if claim.ExpiresAtUnix <= uint64(now.Unix()) {
			if err := os.Remove(path); err != nil {
				return errors.New("remove expired Mailbox access claim")
			}
			removed = true
			continue
		}
		live++
	}
	if removed {
		if err := syncDir(directory); err != nil {
			return err
		}
	}
	if live >= MaxAccessClaims {
		return ErrQuota
	}
	claim := accessClaim{Schema: accessClaimSchema, GrantDigest: request.GrantDigest,
		NonceHex: request.NonceHex, ExpiresAtUnix: request.ExpiresAtUnix}
	encoded, err := json.Marshal(claim)
	if err != nil || len(encoded) > MaxClaimBytes {
		return errors.New("encode Mailbox access claim")
	}
	path := filepath.Join(directory, accessClaimName(request.GrantDigest, request.NonceHex)+".json")
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if errors.Is(err, os.ErrExist) {
		return ErrAccessReplay
	}
	if err != nil {
		return errors.New("create Mailbox access claim")
	}
	if err := writeSync(file, encoded); err != nil {
		_ = os.Remove(path)
		return err
	}
	return syncDir(directory)
}

func accessClaimName(grantDigest, nonceHex string) string {
	b := bytes.NewBufferString(canon.DomainMailboxAccessClaim)
	canon.Text(b, grantDigest)
	canon.Text(b, nonceHex)
	return canon.Digest(b.Bytes())[7:]
}

func readAccessClaim(path string) (accessClaim, error) {
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0o600 {
		return accessClaim{}, errors.New("invalid Mailbox access claim file")
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return accessClaim{}, err
	}
	if len(raw) == 0 || len(raw) > MaxClaimBytes {
		return accessClaim{}, errors.New("Mailbox access claim exceeds its bound")
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	var claim accessClaim
	if decoder.Decode(&claim) != nil || claim.Schema != accessClaimSchema ||
		!canon.ValidDigest(claim.GrantDigest) || claim.ExpiresAtUnix == 0 {
		return accessClaim{}, errors.New("invalid Mailbox access claim")
	}
	if _, err := decodeFixedHex(claim.NonceHex, 32); err != nil {
		return accessClaim{}, errors.New("invalid Mailbox access claim nonce")
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return accessClaim{}, errors.New("Mailbox access claim has trailing JSON")
	}
	expected := accessClaimName(claim.GrantDigest, claim.NonceHex) + ".json"
	if filepath.Base(path) != expected {
		return accessClaim{}, errors.New("Mailbox access claim is under the wrong name")
	}
	return claim, nil
}
