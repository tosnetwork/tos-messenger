package attachments

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"time"

	"github.com/tosnetwork/tos-messenger/internal/canon"
)

const (
	accessClaimSchema = "tos.messaging.attachment-access-claim.v1"
	MaxAccessClaims   = 100_000
	MaxClaimBytes     = 1024
)

var ErrAccessReplay = errors.New("attachment access request was replayed")

type accessClaim struct {
	Schema        string `json:"schema"`
	GrantDigest   string `json:"grant_digest"`
	NonceHex      string `json:"nonce_hex"`
	ExpiresAtUnix uint64 `json:"expires_at_unix"`
}

// claimAccess persists the nonce before an operation. A crash consumes the
// request; a caller retries the idempotent operation with a fresh nonce.
func (s *Store) claimAccess(request AccessRequest, now time.Time) error {
	if err := s.usable(); err != nil {
		return err
	}
	if _, err := AccessRequestCanonicalBytes(request); err != nil {
		return err
	}
	if now.IsZero() || now.Unix() < 0 {
		return errors.New("invalid attachment access claim time")
	}
	s.mutex.Lock()
	defer s.mutex.Unlock()

	directory := filepath.Join(s.root, accessClaimsDir)
	entries, err := os.ReadDir(directory)
	if err != nil {
		return errors.New("read attachment access claims")
	}
	type heldClaim struct {
		path  string
		claim accessClaim
	}
	claims := make([]heldClaim, 0, len(entries))
	for _, entry := range entries {
		if entry.IsDir() {
			return errors.New("invalid attachment access claim entry")
		}
		path := filepath.Join(directory, entry.Name())
		claim, err := readAccessClaim(path)
		if err != nil {
			return err
		}
		claims = append(claims, heldClaim{path: path, claim: claim})
	}
	live := 0
	for _, held := range claims {
		if held.claim.ExpiresAtUnix > uint64(now.Unix()) {
			live++
		}
	}
	if live >= MaxAccessClaims {
		return ErrStoreQuota
	}
	removed := false
	for _, held := range claims {
		if held.claim.ExpiresAtUnix > uint64(now.Unix()) {
			continue
		}
		if err := os.Remove(held.path); err != nil {
			return errors.New("remove expired attachment access claim")
		}
		removed = true
	}
	if removed {
		if err := syncDirectory(directory); err != nil {
			return err
		}
	}
	claim := accessClaim{Schema: accessClaimSchema, GrantDigest: request.GrantDigest,
		NonceHex: request.NonceHex, ExpiresAtUnix: request.ExpiresAtUnix}
	encoded, err := json.Marshal(claim)
	if err != nil || len(encoded) > MaxClaimBytes {
		return errors.New("encode attachment access claim")
	}
	path := filepath.Join(directory, accessClaimName(request.GrantDigest, request.NonceHex)+".json")
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if errors.Is(err, os.ErrExist) {
		return ErrAccessReplay
	}
	if err != nil {
		return errors.New("create attachment access claim")
	}
	return writeSync(file, path, encoded)
}

func accessClaimName(grantDigest, nonceHex string) string {
	b := bytes.NewBufferString(canon.DomainAttachmentAccessClaim)
	canon.Text(b, grantDigest)
	canon.Text(b, nonceHex)
	return canon.Digest(b.Bytes())[len("sha256:"):]
}

func readAccessClaim(path string) (accessClaim, error) {
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0o600 {
		return accessClaim{}, errors.New("invalid attachment access claim file")
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return accessClaim{}, err
	}
	var claim accessClaim
	if err := strictAuthJSON(raw, MaxClaimBytes, &claim); err != nil || claim.Schema != accessClaimSchema ||
		!canon.ValidDigest(claim.GrantDigest) || claim.ExpiresAtUnix == 0 {
		return accessClaim{}, errors.New("invalid attachment access claim")
	}
	if nonce, err := decodeFixedHex(claim.NonceHex, 32); err != nil || canon.IsZero(nonce) {
		return accessClaim{}, errors.New("invalid attachment access claim nonce")
	}
	expected := accessClaimName(claim.GrantDigest, claim.NonceHex) + ".json"
	if filepath.Base(path) != expected {
		return accessClaim{}, errors.New("attachment access claim is under the wrong name")
	}
	return claim, nil
}
