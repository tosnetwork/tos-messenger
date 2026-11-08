package economicaction

import (
	"bytes"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"

	commerce "github.com/tosnetwork/tos-service-protocol/pkg/agentcommerce"
	"github.com/tosnetwork/tos-service-protocol/pkg/mldsa44"
)

// publicKeyHexBytes is the length of a 1,312-byte ML-DSA-44 public key in
// lowercase hex.
const publicKeyHexBytes = 2 * mldsa44.PublicKeySize

// ParseConfiguredAuthority reads the operator configuration form of one pin:
// the mldsa44:<64 lowercase hex> key ID and the 2,624-character lowercase hex
// public key, which must derive that key ID. An Ed25519 key ID is refused
// with the protocol's Ed25519 diagnostic.
func ParseConfiguredAuthority(keyIDText, publicKeyHex string) (PinnedAuthority, error) {
	keyID, err := commerce.ParseActionAuthorityKeyID(keyIDText)
	if err != nil {
		return PinnedAuthority{}, err
	}
	key, err := decodePublicKeyHex([]byte(publicKeyHex))
	if err != nil {
		return PinnedAuthority{}, err
	}
	derived, err := mldsa44.KeyID(key)
	if err != nil || derived != keyID {
		return PinnedAuthority{}, errors.New("economic authority public key does not derive its key ID")
	}
	return PinnedAuthority{KeyID: keyID, PublicKey: key}, nil
}

// ParseAuthorityPin reads one pin of the form
// AUTHORITY_ID=mldsa44:<64 lowercase hex key ID>@<absolute key file>. The key
// file must be an owner-only regular file holding exactly the public key in
// lowercase hex, optionally followed by one newline.
func ParseAuthorityPin(value string) (string, PinnedAuthority, error) {
	authorityID, reference, found := strings.Cut(value, "=")
	if !found || authorityID == "" || len(authorityID) > 256 || strings.TrimSpace(authorityID) != authorityID {
		return "", PinnedAuthority{}, errors.New("authority pin must be AUTHORITY_ID=mldsa44:<key ID>@<key file>")
	}
	keyIDText, path, found := strings.Cut(reference, "@")
	if !found {
		if _, err := commerce.ParseActionAuthorityKeyID(reference); errors.Is(err, commerce.ErrEd25519ActionAuthority) {
			return "", PinnedAuthority{}, err
		}
		return "", PinnedAuthority{}, errors.New("authority pin must be AUTHORITY_ID=mldsa44:<key ID>@<key file>")
	}
	if _, err := commerce.ParseActionAuthorityKeyID(keyIDText); err != nil {
		return "", PinnedAuthority{}, err
	}
	raw, err := readKeyFile(path)
	if err != nil {
		return "", PinnedAuthority{}, err
	}
	pin, err := ParseConfiguredAuthority(keyIDText, string(raw))
	if err != nil {
		return "", PinnedAuthority{}, err
	}
	return authorityID, pin, nil
}

// ParseAuthorityPins parses each pin and refuses a duplicated authority.
func ParseAuthorityPins(values []string) (map[string]PinnedAuthority, error) {
	pins := make(map[string]PinnedAuthority, len(values))
	for _, value := range values {
		authorityID, pin, err := ParseAuthorityPin(value)
		if err != nil {
			return nil, err
		}
		if _, duplicate := pins[authorityID]; duplicate {
			return nil, errors.New("authority pin is duplicated")
		}
		pins[authorityID] = pin
	}
	return pins, nil
}

func readKeyFile(path string) ([]byte, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return nil, errors.New("authority pin key file path must be absolute and clean")
	}
	before, err := os.Lstat(path)
	if err != nil || !before.Mode().IsRegular() || !keyFileOwner(before) || before.Mode().Perm() != 0o600 ||
		before.Size() < publicKeyHexBytes || before.Size() > publicKeyHexBytes+1 {
		return nil, errors.New("authority pin key file must be an owner-only mode-0600 regular file of one ML-DSA-44 key")
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, errors.New("authority pin key file cannot be opened")
	}
	defer file.Close()
	after, err := file.Stat()
	if err != nil || !os.SameFile(before, after) {
		return nil, errors.New("authority pin key file changed while opening")
	}
	raw, err := io.ReadAll(io.LimitReader(file, publicKeyHexBytes+2))
	if err != nil {
		return nil, errors.New("authority pin key file cannot be read")
	}
	return bytes.TrimSuffix(raw, []byte("\n")), nil
}

func decodePublicKeyHex(text []byte) ([]byte, error) {
	if len(text) != publicKeyHexBytes {
		return nil, errors.New("economic authority public key must be 1,312 bytes of lowercase hex; Ed25519 keys are not accepted")
	}
	for _, character := range text {
		if (character < '0' || character > '9') && (character < 'a' || character > 'f') {
			return nil, errors.New("economic authority public key must be lowercase hex")
		}
	}
	key := make([]byte, mldsa44.PublicKeySize)
	if _, err := hex.Decode(key, text); err != nil {
		return nil, errors.New("economic authority public key must be lowercase hex")
	}
	return key, nil
}
