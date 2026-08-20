package directory

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ed25519"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/tosnetwork/tosutils-go/adnl/dht"
	"github.com/tosnetwork/tosutils-go/adnl/keys"
	"github.com/tosnetwork/tosutils-go/tl"
)

type fakeTOSDHTClient struct {
	value       *dht.Value
	findErr     error
	findKey     *dht.Key
	storeErr    error
	storedCount int
	storedKey   []byte
	storeID     any
	storeName   []byte
	storeIndex  int32
	storeData   []byte
	storeRule   any
	storeTTL    time.Duration
	storeOwner  crypto.Signer
}

func (f *fakeTOSDHTClient) FindValue(_ context.Context, key *dht.Key,
	_ ...*dht.Continuation) (*dht.Value, *dht.Continuation, error) {
	f.findKey = key
	return f.value, nil, f.findErr
}

func (f *fakeTOSDHTClient) StoreWithSigner(_ context.Context, id any, name []byte, index int32,
	value []byte, rule any, ttl time.Duration, owner crypto.Signer) (int, []byte, error) {
	f.storeID = id
	f.storeName = append([]byte(nil), name...)
	f.storeIndex = index
	f.storeData = append([]byte(nil), value...)
	f.storeRule = rule
	f.storeTTL = ttl
	f.storeOwner = owner
	return f.storedCount, append([]byte(nil), f.storedKey...), f.storeErr
}

func dhtLocatorFixture(t *testing.T) (identityKey ed25519.PrivateKey, delegationKey DHTKey, locator Locator) {
	t.Helper()
	identityKey = endpointKey(t, 0x11)
	delegation := testDelegation(t, identityKey)
	descriptor := signedDescriptor(t, delegation, identityKey)
	locator = signedLocator(t, descriptor, identityKey, "https://directory.example/descriptor")
	var err error
	delegationKey, err = LocatorKey(delegation)
	if err != nil {
		t.Fatal(err)
	}
	return identityKey, delegationKey, locator
}

func nativeLocatorValue(t *testing.T, key DHTKey, locator Locator,
	owner ed25519.PrivateKey, ttl int32) *dht.Value {
	t.Helper()
	raw, err := EncodeLocator(locator)
	if err != nil {
		t.Fatal(err)
	}
	public := owner.Public().(ed25519.PublicKey)
	value := &dht.Value{KeyDescription: dht.KeyDescription{
		Key: dht.Key{ID: append([]byte(nil), key.ID[:]...), Name: []byte(key.Name), Index: int32(key.Index)},
		ID:  keys.PublicKeyED25519{Key: append(ed25519.PublicKey(nil), public...)}, UpdateRule: dht.UpdateRuleSignature{},
	}, Data: raw, TTL: ttl}
	keyPreimage, err := tl.Serialize(value.KeyDescription, true)
	if err != nil {
		t.Fatal(err)
	}
	value.KeyDescription.Signature = ed25519.Sign(owner, keyPreimage)
	valuePreimage, err := tl.Serialize(*value, true)
	if err != nil {
		t.Fatal(err)
	}
	value.Signature = ed25519.Sign(owner, valuePreimage)
	return value
}

func cloneDHTValue(value *dht.Value) *dht.Value {
	copyValue := *value
	copyValue.KeyDescription = value.KeyDescription
	copyValue.KeyDescription.Key = value.KeyDescription.Key
	copyValue.KeyDescription.Key.ID = append([]byte(nil), value.KeyDescription.Key.ID...)
	copyValue.KeyDescription.Key.Name = append([]byte(nil), value.KeyDescription.Key.Name...)
	if public, ok := value.KeyDescription.ID.(keys.PublicKeyED25519); ok {
		copyValue.KeyDescription.ID = keys.PublicKeyED25519{Key: append(ed25519.PublicKey(nil), public.Key...)}
	}
	copyValue.KeyDescription.Signature = append([]byte(nil), value.KeyDescription.Signature...)
	copyValue.Data = append([]byte(nil), value.Data...)
	copyValue.Signature = append([]byte(nil), value.Signature...)
	return &copyValue
}

func TestTOSDHTReadsNativeSignedLocator(t *testing.T) {
	owner, key, locator := dhtLocatorFixture(t)
	now := time.Unix(int64(baseUnix)+60, 0)
	value := nativeLocatorValue(t, key, locator, owner, int32(now.Unix()+3000))
	client := &fakeTOSDHTClient{value: value}
	adapter := TOSDHT{Client: client, Now: func() time.Time { return now }}

	raw, err := adapter.Locator(context.Background(), key)
	if err != nil {
		t.Fatal(err)
	}
	want, err := EncodeLocator(locator)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(raw, want) || client.findKey == nil ||
		!bytes.Equal(client.findKey.ID, key.ID[:]) || string(client.findKey.Name) != LocatorKeyName ||
		client.findKey.Index != LocatorKeyIndex {
		t.Fatal("native DHT lookup or returned locator changed")
	}
}

func TestTOSDHTRejectsSubstitutedNativeValues(t *testing.T) {
	owner, key, locator := dhtLocatorFixture(t)
	now := time.Unix(int64(baseUnix)+60, 0)
	baseline := nativeLocatorValue(t, key, locator, owner, int32(now.Unix()+3000))
	other := endpointKey(t, 0x22)

	cases := map[string]func(*dht.Value){
		"another key name": func(value *dht.Value) { value.KeyDescription.Key.Name = []byte("address") },
		"another index":    func(value *dht.Value) { value.KeyDescription.Key.Index = 1 },
		"another owner": func(value *dht.Value) {
			value.KeyDescription.ID = keys.PublicKeyED25519{Key: other.Public().(ed25519.PublicKey)}
		},
		"anybody update":    func(value *dht.Value) { value.KeyDescription.UpdateRule = dht.UpdateRuleAnybody{} },
		"expired outer ttl": func(value *dht.Value) { value.TTL = int32(now.Unix()) },
		"excess outer ttl": func(value *dht.Value) {
			value.TTL = int32(now.Unix() + MaxTOSDHTValueTTLSeconds + 1)
		},
		"key signature":   func(value *dht.Value) { value.KeyDescription.Signature[0] ^= 0xff },
		"value signature": func(value *dht.Value) { value.Signature[0] ^= 0xff },
		"truncated inner": func(value *dht.Value) { value.Data = value.Data[:10] },
		"foreign inner signature": func(value *dht.Value) {
			foreign, err := SignLocator(locator, other)
			if err != nil {
				t.Fatal(err)
			}
			value.Data, err = EncodeLocator(foreign)
			if err != nil {
				t.Fatal(err)
			}
			value.KeyDescription.Signature = nil
			keyPreimage, err := tl.Serialize(value.KeyDescription, true)
			if err != nil {
				t.Fatal(err)
			}
			value.KeyDescription.Signature = ed25519.Sign(owner, keyPreimage)
			value.Signature = nil
			valuePreimage, err := tl.Serialize(*value, true)
			if err != nil {
				t.Fatal(err)
			}
			value.Signature = ed25519.Sign(owner, valuePreimage)
		},
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			value := cloneDHTValue(baseline)
			mutate(value)
			adapter := TOSDHT{Client: &fakeTOSDHTClient{value: value}, Now: func() time.Time { return now }}
			if _, err := adapter.Locator(context.Background(), key); err == nil {
				t.Fatal("substituted native DHT value was accepted")
			}
		})
	}
}

func TestTOSDHTPublishesUnderTheLiveTOSKeyEncoding(t *testing.T) {
	owner, key, locator := dhtLocatorFixture(t)
	delegation := testDelegation(t, owner)
	now := time.Unix(int64(baseUnix)+60, 0)
	nativePublicHash, err := tl.Hash(keys.PublicKeyED25519{Key: owner.Public().(ed25519.PublicKey)})
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(nativePublicHash, key.ID[:]) {
		t.Fatal("Messenger EndpointKeyID disagrees with the live tosutils TL encoder")
	}
	expectedStoredKey, err := tl.Hash(nativeDHTKey(key))
	if err != nil {
		t.Fatal(err)
	}
	client := &fakeTOSDHTClient{storedCount: 3, storedKey: expectedStoredKey}
	adapter := TOSDHT{Client: client, Now: func() time.Time { return now }}
	stored, err := adapter.PublishLocator(context.Background(), delegation, locator, owner)
	if err != nil || stored != 3 {
		t.Fatalf("stored=%d err=%v", stored, err)
	}
	public, ok := client.storeID.(keys.PublicKeyED25519)
	if !ok || !bytes.Equal(public.Key, delegation.IdentityPublicKey) ||
		string(client.storeName) != LocatorKeyName || client.storeIndex != LocatorKeyIndex {
		t.Fatal("publication used another native DHT key")
	}
	if _, ok := client.storeRule.(dht.UpdateRuleSignature); !ok {
		t.Fatal("publication did not require the native signature update rule")
	}
	storedPublic, ok := client.storeOwner.Public().(ed25519.PublicKey)
	if !ok || !bytes.Equal(storedPublic, owner.Public().(ed25519.PublicKey)) {
		t.Fatal("publication did not preserve the Endpoint signer boundary")
	}
	wantTTL := time.Duration(locator.ExpiresAtUnix-uint64(now.Unix())) * time.Second
	if client.storeTTL != wantTTL || client.storeTTL > DefaultTOSDHTPublishTTL {
		t.Fatalf("ttl=%v want=%v", client.storeTTL, wantTTL)
	}
	decoded, err := DecodeLocator(client.storeData)
	if err != nil || decoded.DescriptorDigest != locator.DescriptorDigest {
		t.Fatalf("published locator=%+v err=%v", decoded, err)
	}
}

func TestTOSDHTCapsTheOuterCacheTTLWithoutShorteningTheLocator(t *testing.T) {
	owner := endpointKey(t, 0x11)
	delegation := testDelegation(t, owner)
	descriptor := testDescriptor(t, delegation)
	descriptor.ExpiresAtUnix = baseUnix + 7200
	descriptor, err := SignDescriptor(descriptor, owner)
	if err != nil {
		t.Fatal(err)
	}
	locator, err := NewLocator(descriptor, "https://directory.example/descriptor", baseUnix, baseUnix+7200)
	if err != nil {
		t.Fatal(err)
	}
	locator, err = SignLocator(locator, owner)
	if err != nil {
		t.Fatal(err)
	}
	key, err := LocatorKey(delegation)
	if err != nil {
		t.Fatal(err)
	}
	expected, err := tl.Hash(nativeDHTKey(key))
	if err != nil {
		t.Fatal(err)
	}
	client := &fakeTOSDHTClient{storedCount: 1, storedKey: expected}
	adapter := TOSDHT{Client: client, Now: func() time.Time { return time.Unix(int64(baseUnix)+60, 0) }}
	if _, err := adapter.PublishLocator(context.Background(), delegation, locator, owner); err != nil {
		t.Fatal(err)
	}
	if client.storeTTL != DefaultTOSDHTPublishTTL || locator.ExpiresAtUnix != baseUnix+7200 {
		t.Fatalf("outer ttl=%v inner expiry=%d", client.storeTTL, locator.ExpiresAtUnix)
	}
}

func TestTOSDHTPublicationFailsClosed(t *testing.T) {
	owner, key, locator := dhtLocatorFixture(t)
	delegation := testDelegation(t, owner)
	now := time.Unix(int64(baseUnix)+60, 0)
	expected, err := tl.Hash(nativeDHTKey(key))
	if err != nil {
		t.Fatal(err)
	}
	for name, client := range map[string]*fakeTOSDHTClient{
		"no replicas":    {storedCount: 0, storedKey: expected},
		"unexpected key": {storedCount: 1, storedKey: bytes.Repeat([]byte{0xff}, 32)},
		"client error":   {storeErr: errors.New("network unavailable")},
	} {
		t.Run(name, func(t *testing.T) {
			adapter := TOSDHT{Client: client, Now: func() time.Time { return now }}
			if _, err := adapter.PublishLocator(context.Background(), delegation, locator, owner); err == nil {
				t.Fatal("failed native publication was reported as stored")
			}
		})
	}
	wrong := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x77}, ed25519.SeedSize))
	client := &fakeTOSDHTClient{storedCount: 1, storedKey: expected}
	adapter := TOSDHT{Client: client, Now: func() time.Time { return now }}
	if _, err := adapter.PublishLocator(context.Background(), delegation, locator, nil); err == nil ||
		!strings.Contains(err.Error(), "no DHT Endpoint signer") {
		t.Fatalf("missing signer error=%v", err)
	}
	if _, err := adapter.PublishLocator(context.Background(), delegation, locator, wrong); err == nil ||
		!strings.Contains(err.Error(), "delegated Endpoint") {
		t.Fatalf("wrong key error=%v", err)
	}
}
