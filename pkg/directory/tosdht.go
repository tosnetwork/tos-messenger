package directory

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"errors"
	"math"
	"time"

	"github.com/tosnetwork/tos-messenger/internal/canon"
	"github.com/tosnetwork/tos-messenger/pkg/identity"
	"github.com/tosnetwork/tosutils-go/adnl/dht"
	"github.com/tosnetwork/tosutils-go/adnl/keys"
	"github.com/tosnetwork/tosutils-go/tl"
)

const (
	// MaxTOSDHTValueTTLSeconds mirrors the native DHT value bound. Locator
	// validity may be longer: the same inner locator can be republished in a
	// newly signed outer DHT value before this cache TTL expires.
	MaxTOSDHTValueTTLSeconds = 3600 + 60
	// DefaultTOSDHTPublishTTL leaves the network's 60-second tolerance unused.
	// A caller can schedule publication before this outer cache entry expires
	// without changing the signed inner locator.
	DefaultTOSDHTPublishTTL = time.Hour
)

// TOSDHTClient is the exact tosutils-go surface the Messenger uses. Keeping
// the boundary narrow makes malformed native values testable, while the
// compile-time assertion below prevents a fake-only adapter from drifting
// away from the production client.
type TOSDHTClient interface {
	FindValue(context.Context, *dht.Key, ...*dht.Continuation) (*dht.Value, *dht.Continuation, error)
	Store(context.Context, any, []byte, int32, []byte, any, time.Duration, ed25519.PrivateKey) (int, []byte, error)
}

var _ TOSDHTClient = (*dht.Client)(nil)

// TOSDHT adapts the production TOS DHT client to the locator half of
// RefreshSource. It accepts no generic DHT values: both layers of native DHT
// signatures and the inner Messenger locator signature are rechecked.
type TOSDHT struct {
	Client TOSDHTClient
	Now    func() time.Time
}

// Locator retrieves one locator under the exact Messenger DHT key. The
// upstream client verifies values while traversing the network; repeating the
// checks here makes this package's authority boundary explicit and keeps a
// substituted client or future upstream regression from becoming trust.
func (t TOSDHT) Locator(ctx context.Context, key DHTKey) ([]byte, error) {
	if ctx == nil {
		return nil, errors.New("TOS DHT lookup needs a context")
	}
	if t.Client == nil {
		return nil, errors.New("no TOS DHT client")
	}
	if err := validateDHTKey(key); err != nil {
		return nil, err
	}
	value, _, err := t.Client.FindValue(ctx, nativeDHTKey(key))
	if err != nil {
		return nil, err
	}
	now, err := t.now()
	if err != nil {
		return nil, err
	}
	return verifyNativeLocatorValue(key, value, now)
}

// PublishLocator signs the native DHT envelope with the same delegated
// Endpoint key that signed the locator. That key remains an online messaging
// key; this operation grants no Agent-controller, wallet, or execution power.
func (t TOSDHT) PublishLocator(ctx context.Context, delegation identity.Delegation,
	locator Locator, endpointKey ed25519.PrivateKey) (int, error) {
	if ctx == nil {
		return 0, errors.New("TOS DHT publication needs a context")
	}
	if t.Client == nil {
		return 0, errors.New("no TOS DHT client")
	}
	now, err := t.now()
	if err != nil {
		return 0, err
	}
	if len(endpointKey) != ed25519.PrivateKeySize ||
		!bytes.Equal(endpointKey.Public().(ed25519.PublicKey), delegation.IdentityPublicKey) {
		return 0, errors.New("DHT publishing key is not the delegated Endpoint key")
	}
	if err := VerifyLocator(delegation, locator, now); err != nil {
		return 0, err
	}
	key, err := LocatorKey(delegation)
	if err != nil {
		return 0, err
	}
	raw, err := EncodeLocator(locator)
	if err != nil {
		return 0, err
	}
	remaining := time.Duration(locator.ExpiresAtUnix-uint64(now.Unix())) * time.Second
	ttl := remaining
	if ttl > DefaultTOSDHTPublishTTL {
		ttl = DefaultTOSDHTPublishTTL
	}
	if ttl < time.Second {
		return 0, errors.New("locator expires before a DHT value can be published")
	}
	public := append(ed25519.PublicKey(nil), delegation.IdentityPublicKey...)
	stored, storedKey, err := t.Client.Store(ctx, keys.PublicKeyED25519{Key: public},
		[]byte(key.Name), int32(key.Index), raw, dht.UpdateRuleSignature{}, ttl, endpointKey)
	if err != nil {
		return 0, err
	}
	expectedKey, err := tl.Hash(nativeDHTKey(key))
	if err != nil {
		return 0, err
	}
	if stored < 1 || !bytes.Equal(storedKey, expectedKey) {
		return 0, errors.New("TOS DHT stored the locator under an unexpected key")
	}
	return stored, nil
}

func (t TOSDHT) now() (time.Time, error) {
	now := time.Now()
	if t.Now != nil {
		now = t.Now()
	}
	if now.IsZero() || now.Unix() < 0 || now.Unix() > math.MaxInt32-MaxTOSDHTValueTTLSeconds {
		return time.Time{}, errors.New("invalid TOS DHT time")
	}
	return now, nil
}

func validateDHTKey(key DHTKey) error {
	if canon.IsZero(key.ID[:]) || key.Name != LocatorKeyName || key.Index != LocatorKeyIndex {
		return errors.New("invalid Messenger DHT locator key")
	}
	return nil
}

func nativeDHTKey(key DHTKey) *dht.Key {
	return &dht.Key{ID: append([]byte(nil), key.ID[:]...), Name: []byte(key.Name), Index: int32(key.Index)}
}

func verifyNativeLocatorValue(expected DHTKey, value *dht.Value, now time.Time) ([]byte, error) {
	if value == nil {
		return nil, errors.New("TOS DHT returned no locator value")
	}
	key := value.KeyDescription.Key
	if !bytes.Equal(key.ID, expected.ID[:]) || !bytes.Equal(key.Name, []byte(expected.Name)) ||
		key.Index != int32(expected.Index) {
		return nil, errors.New("TOS DHT returned another locator key")
	}
	publicValue, ok := value.KeyDescription.ID.(keys.PublicKeyED25519)
	if !ok || len(publicValue.Key) != ed25519.PublicKeySize || canon.IsZero(publicValue.Key) {
		return nil, errors.New("TOS DHT locator is not owned by an Ed25519 key")
	}
	ownerID, err := tl.Hash(publicValue)
	if err != nil || !bytes.Equal(ownerID, expected.ID[:]) {
		return nil, errors.New("TOS DHT locator owner does not match its key")
	}
	if _, ok := value.KeyDescription.UpdateRule.(dht.UpdateRuleSignature); !ok {
		return nil, errors.New("TOS DHT locator does not use the signature update rule")
	}
	if value.TTL <= int32(now.Unix()) || int64(value.TTL) > now.Unix()+MaxTOSDHTValueTTLSeconds {
		return nil, errors.New("TOS DHT locator value is outside its cache TTL bound")
	}
	if len(value.Data) == 0 || len(value.Data) > MaxLocatorBytes || len(value.Data) > MaxDHTValueBytes {
		return nil, errors.New("TOS DHT locator value exceeds its bound")
	}
	if err := verifyNativeDHTSignatures(value, publicValue.Key); err != nil {
		return nil, err
	}
	locator, err := DecodeLocator(value.Data)
	if err != nil {
		return nil, err
	}
	preimage, err := LocatorSigningBytes(locator)
	if err != nil || !ed25519.Verify(publicValue.Key, preimage, locator.EndpointSignature) {
		return nil, errors.New("inner locator signature is not from its DHT owner")
	}
	return append([]byte(nil), value.Data...), nil
}

func verifyNativeDHTSignatures(value *dht.Value, public ed25519.PublicKey) error {
	if len(value.KeyDescription.Signature) != ed25519.SignatureSize || len(value.Signature) != ed25519.SignatureSize {
		return errors.New("invalid TOS DHT locator signature length")
	}
	keyDescription := value.KeyDescription
	keySignature := append([]byte(nil), keyDescription.Signature...)
	keyDescription.Signature = nil
	keyPreimage, err := tl.Serialize(keyDescription, true)
	if err != nil || !ed25519.Verify(public, keyPreimage, keySignature) {
		return errors.New("invalid TOS DHT locator key-description signature")
	}
	valueCopy := *value
	valueSignature := append([]byte(nil), value.Signature...)
	valueCopy.Signature = nil
	valuePreimage, err := tl.Serialize(valueCopy, true)
	if err != nil || !ed25519.Verify(public, valuePreimage, valueSignature) {
		return errors.New("invalid TOS DHT locator value signature")
	}
	return nil
}
