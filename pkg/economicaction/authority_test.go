package economicaction

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/tosnetwork/tos-messenger/internal/actionauthoritytest"
	commerce "github.com/tosnetwork/tos-service-protocol/pkg/agentcommerce"
	"github.com/tosnetwork/tos-service-protocol/pkg/mldsa44"
	"github.com/tosnetwork/tos-service-protocol/pkg/mldsa44/mldsa44test"
)

func writeKeyFile(t *testing.T, directory, name, contents string, mode os.FileMode) string {
	t.Helper()
	path := filepath.Join(directory, name)
	if err := os.WriteFile(path, []byte(contents), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, mode); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestAuthorityPinsAreOwnerOnlyMLDSA44Keys(t *testing.T) {
	fake := &mldsa44test.Fake{}
	key, other := fake.PublicKey("pinned"), fake.PublicKey("other")
	keyID := fake.KeyID("pinned")
	directory := t.TempDir()
	bare := writeKeyFile(t, directory, "bare.hex", hex.EncodeToString(key), 0o600)
	newline := writeKeyFile(t, directory, "newline.hex", hex.EncodeToString(key)+"\n", 0o600)
	for _, path := range []string{bare, newline} {
		authorityID, pin, err := ParseAuthorityPin("authority:test=" + keyID + "@" + path)
		if err != nil || authorityID != "authority:test" || mldsa44.KeyIDText(pin.KeyID) != keyID {
			t.Fatalf("pin %s: %q %v", path, authorityID, err)
		}
	}
	link := filepath.Join(directory, "link.hex")
	if err := os.Symlink(bare, link); err != nil {
		t.Fatal(err)
	}
	body := strings.TrimPrefix(keyID, mldsa44.KeyIDPrefix)
	for name, value := range map[string]string{
		"no key file":             "authority:test=" + keyID,
		"upper-case key ID":       "authority:test=mldsa44:" + strings.ToUpper(body) + "@" + bare,
		"all-zero key ID":         "authority:test=mldsa44:" + strings.Repeat("0", 64) + "@" + bare,
		"relative path":           "authority:test=" + keyID + "@bare.hex",
		"symlinked key file":      "authority:test=" + keyID + "@" + link,
		"group-readable key file": "authority:test=" + keyID + "@" + writeKeyFile(t, directory, "group.hex", hex.EncodeToString(key), 0o640),
		"Ed25519-length key":      "authority:test=" + keyID + "@" + writeKeyFile(t, directory, "short.hex", strings.Repeat("ab", 32), 0o600),
		"trailing space":          "authority:test=" + keyID + "@" + writeKeyFile(t, directory, "space.hex", hex.EncodeToString(key)+" ", 0o600),
		"key of another key ID":   "authority:test=" + keyID + "@" + writeKeyFile(t, directory, "other.hex", hex.EncodeToString(other), 0o600),
	} {
		if _, _, err := ParseAuthorityPin(value); err == nil {
			t.Fatalf("%s was accepted", name)
		}
	}
	if _, _, err := ParseAuthorityPin("authority:test=ed25519:" + strings.Repeat("ab", 32)); !errors.Is(err, commerce.ErrEd25519ActionAuthority) {
		t.Fatalf("an Ed25519 pin was not refused with the Ed25519 diagnostic: %v", err)
	}
	if _, err := ParseConfiguredAuthority("ed25519:"+strings.Repeat("ab", 32), hex.EncodeToString(key)); !errors.Is(err, commerce.ErrEd25519ActionAuthority) {
		t.Fatalf("an Ed25519 configured key ID was not refused with the Ed25519 diagnostic: %v", err)
	}
	if _, err := ParseConfiguredAuthority(keyID, strings.Repeat("ab", 32)); err == nil || !strings.Contains(err.Error(), "Ed25519") {
		t.Fatalf("an Ed25519-length configured key was not refused with the Ed25519 diagnostic: %v", err)
	}
	if _, err := ParseConfiguredAuthority(keyID, hex.EncodeToString(other)); err == nil {
		t.Fatal("a configured key of another key ID was accepted")
	}
	if _, err := ParseAuthorityPins([]string{"authority:test=" + keyID + "@" + bare, "authority:test=" + keyID + "@" + newline}); err == nil {
		t.Fatal("a duplicated authority pin was accepted")
	}
}

func TestOpenRefusesUnverifiablePins(t *testing.T) {
	fake := &mldsa44test.Fake{}
	pinned, _ := mldsa44.ParseKeyIDText(fake.KeyID("pinned"))
	pin := PinnedAuthority{KeyID: pinned, PublicKey: fake.PublicKey("pinned")}
	for name, pins := range map[string]map[string]PinnedAuthority{
		"empty set":         {},
		"key of another ID": {"authority": {KeyID: pinned, PublicKey: fake.PublicKey("other")}},
		"short key":         {"authority": {KeyID: pinned, PublicKey: make([]byte, 32)}},
	} {
		if _, err := Open(t.TempDir(), pins, fake); err == nil {
			t.Fatalf("%s was accepted", name)
		}
	}
	if _, err := Open(t.TempDir(), map[string]PinnedAuthority{"authority": pin}, nil); err == nil {
		t.Fatal("pins without a verifier were accepted")
	}
}

type admissionFixture struct {
	custody   *actionauthoritytest.Custody
	store     *Store
	root      string
	now       time.Time
	fence     commerce.WriterFence
	action    commerce.AuthorizedAction
	fields    map[string]commerce.SemanticValue
	request   []byte
	owner     string
	directory string
}

func signFence(t *testing.T, custody *actionauthoritytest.Custody, controller string, now time.Time) commerce.WriterFence {
	t.Helper()
	fence, err := commerce.SignWriterFence(context.Background(), commerce.WriterFenceBody{SchemaVersion: 1, OwnerID: "owner-1",
		AgentID: "agent-1", InstanceID: "instance-1", LeaseID: "lease-1", WriterGeneration: 1,
		IssuedAtUnix: uint64(now.Add(-time.Minute).Unix()), ExpiresAtUnix: uint64(now.Add(time.Hour).Unix()),
		AuthorityID: "authority-1", Scope: []string{"messenger.contact"}}, custody.Signer, controller)
	if err != nil {
		t.Fatal(err)
	}
	return fence
}

func (fixture *admissionFixture) signAction(t *testing.T, controller string, fence commerce.WriterFence) commerce.AuthorizedAction {
	t.Helper()
	action, err := commerce.BuildAuthorizedAction("owner-1", "agent-1", "messenger.contact", fixture.fields, fixture.request, fence,
		1, "sha256:"+strings.Repeat("3", 64), "", "no-contact", uint64(fixture.now.Add(30*time.Minute).Unix()))
	if err != nil {
		t.Fatal(err)
	}
	action, err = commerce.SignAuthorizedAction(context.Background(), action, fixture.custody.KeyID(t, controller),
		fixture.custody.Signer, controller)
	if err != nil {
		t.Fatal(err)
	}
	return action
}

func (fixture *admissionFixture) controllerOf(t *testing.T, keyID string) string {
	t.Helper()
	for _, name := range []string{actionauthoritytest.Controller, "second-key", "foreign"} {
		if fixture.custody.KeyID(t, name) == keyID {
			return name
		}
	}
	t.Fatalf("no custody controller has key ID %s", keyID)
	return ""
}

func (fixture *admissionFixture) state(t *testing.T) string {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(fixture.root, "economic-actions-v1.json"))
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}

// newAdmissionFixture opens a store pinning a real ML-DSA-44 controller for
// authority-1 and another for authority-foreign.
func newAdmissionFixture(t *testing.T) *admissionFixture {
	t.Helper()
	custody := actionauthoritytest.NewCustody(t, actionauthoritytest.Controller, "second-key", "foreign")
	pinOf := func(name string) PinnedAuthority {
		keyID, err := mldsa44.ParseKeyIDText(custody.KeyID(t, name))
		if err != nil {
			t.Fatal(err)
		}
		return PinnedAuthority{KeyID: keyID, PublicKey: custody.PublicKeys[name]}
	}
	root := t.TempDir()
	store, err := Open(root, map[string]PinnedAuthority{"authority-1": pinOf(actionauthoritytest.Controller),
		"authority-foreign": pinOf("foreign")}, custody.Signer)
	if err != nil {
		t.Fatal(err)
	}
	request, err := commerce.CanonicalMessengerEffectRequest(commerce.MessengerEffectRequestV1{SchemaVersion: 1,
		RecipientAgentIDs: []string{"agent-2"}, EventKind: "text", ContentType: "text/plain", Payload: []byte("hello")})
	if err != nil {
		t.Fatal(err)
	}
	fixture := &admissionFixture{custody: custody, store: store, root: root, now: time.Unix(1_800_000_000, 0).UTC(), request: request,
		fields: map[string]commerce.SemanticValue{"owner_id": commerce.ID("owner-1"), "agent_id": commerce.ID("agent-1"),
			"recipient_agent_id": commerce.ID("agent-2"), "intent_reference_digest": commerce.Digest32("sha256:" + strings.Repeat("1", 64)),
			"authority_instance_id": commerce.Digest32("sha256:" + strings.Repeat("a", 64))}}
	fixture.fence = signFence(t, custody, actionauthoritytest.Controller, fixture.now)
	fixture.action = fixture.signAction(t, actionauthoritytest.Controller, fixture.fence)
	return fixture
}

func TestAdmitRefusesEveryNonActionAuthorityFenceAndAction(t *testing.T) {
	fixture := newAdmissionFixture(t)
	before := fixture.state(t)
	fenceMessage, err := commerce.WriterFenceSignatureMessage(fixture.fence.Body)
	if err != nil {
		t.Fatal(err)
	}
	for _, variant := range actionauthoritytest.Variants(t, fixture.custody, actionauthoritytest.Controller, "second-key",
		fixture.fence.KeyID, fixture.fence.Proof, fenceMessage) {
		// A variant that still encodes canonically gets an action freshly
		// bound to it and validly signed by the controller holding its key
		// ID, so only the fence check can refuse it.
		bad := fixture.fence
		bad.KeyID, bad.Proof = variant.KeyID, variant.Signature
		action := fixture.action
		if _, digestErr := commerce.WriterFenceDigest(bad); digestErr == nil {
			action = fixture.signAction(t, fixture.controllerOf(t, bad.KeyID), bad)
		}
		if _, err := fixture.store.Admit(action, bad, fixture.fields, fixture.request, fixture.now); err == nil {
			t.Fatalf("Admit accepted a fence with %s", variant.Name)
		}
		if fixture.state(t) != before {
			t.Fatalf("Admit wrote state for a fence with %s", variant.Name)
		}
	}
	actionMessage, err := commerce.AuthorizedActionSignatureMessage(fixture.action)
	if err != nil {
		t.Fatal(err)
	}
	for _, variant := range actionauthoritytest.Variants(t, fixture.custody, actionauthoritytest.Controller, "second-key",
		fixture.action.AuthorityKeyID, fixture.action.AuthorizationProof, actionMessage) {
		bad := fixture.action
		bad.AuthorityKeyID, bad.AuthorizationProof = variant.KeyID, variant.Signature
		if _, err := fixture.store.Admit(bad, fixture.fence, fixture.fields, fixture.request, fixture.now); err == nil {
			t.Fatalf("Admit accepted an action with %s", variant.Name)
		}
		if fixture.state(t) != before {
			t.Fatalf("Admit wrote state for an action with %s", variant.Name)
		}
	}
	if _, err := fixture.store.Admit(fixture.action, fixture.fence, fixture.fields, fixture.request, fixture.now); err != nil {
		t.Fatalf("the real ML-DSA-44 action was refused: %v", err)
	}
}

// TestAdmitRefusesAKeyPinnedForAnotherAuthority checks that a key is
// authorized only for the authority it is pinned under.
func TestAdmitRefusesAKeyPinnedForAnotherAuthority(t *testing.T) {
	fixture := newAdmissionFixture(t)
	fence := signFence(t, fixture.custody, "foreign", fixture.now)
	action := fixture.signAction(t, "foreign", fence)
	before := fixture.state(t)
	if _, err := fixture.store.Admit(action, fence, fixture.fields, fixture.request, fixture.now); err == nil {
		t.Fatal("Admit accepted a fence signed by a key pinned for another authority")
	}
	if fixture.state(t) != before {
		t.Fatal("Admit wrote state for a foreign authority key")
	}
}
