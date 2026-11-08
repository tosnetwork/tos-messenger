package intentcarrier

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/tosnetwork/tos-messenger/internal/actionauthoritytest"
	"github.com/tosnetwork/tos-messenger/pkg/economicaction"
	commerce "github.com/tosnetwork/tos-service-protocol/pkg/agentcommerce"
	"github.com/tosnetwork/tos-service-protocol/pkg/codec"
)

type publicationFixture struct {
	custody *actionauthoritytest.Custody
	owner   testAuthority
	store   *Store
	root    string
	now     time.Time
	intent  commerce.SignedAgentIntent
	proof   commerce.OperationAdmissionProof
	action  commerce.AuthorizedAction
	fence   commerce.WriterFence
}

func custodyAuthority(t *testing.T, custody *actionauthoritytest.Custody, controller string) testAuthority {
	t.Helper()
	return testAuthority{signer: custody.Signer, verifier: custody.Signer, controller: controller,
		keyID: custody.KeyID(t, controller), publicKey: custody.PublicKeys[controller]}
}

// publicationActionWithFence binds a publication action to fence and signs it
// with authority.
func publicationActionWithFence(t *testing.T, store *Store, intent commerce.SignedAgentIntent, authority testAuthority,
	fence commerce.WriterFence, now time.Time) commerce.AuthorizedAction {
	t.Helper()
	exact, err := codec.Marshal(intent)
	if err != nil {
		t.Fatal(err)
	}
	opDigest, err := codec.Digest("tos.agent-intent-publication-operation.v1", intent)
	if err != nil {
		t.Fatal(err)
	}
	fields := map[string]commerce.SemanticValue{"owner_id": commerce.ID("owner:test"), "agent_id": commerce.ID(intent.Body.IssuerAgentID),
		"carrier_id": commerce.ID(store.carrierID), "intent_object_id": commerce.ID(intent.Body.ObjectID),
		"revision": commerce.U64(intent.Body.Revision), "operation_digest": commerce.Digest32(opDigest)}
	action, err := commerce.BuildAuthorizedAction("owner:test", intent.Body.IssuerAgentID, "publication.publish", fields, exact,
		fence, 1, "sha256:"+strings.Repeat("1", 64), "", "not-published", uint64(now.Add(time.Hour).Unix()))
	if err != nil {
		t.Fatal(err)
	}
	action, err = commerce.SignAuthorizedAction(context.Background(), action, authority.keyID, authority.signer, authority.controller)
	if err != nil {
		t.Fatal(err)
	}
	return action
}

// newPublicationFixture opens a Messenger Carrier pinning a real ML-DSA-44
// controller for authority:test and another for authority:foreign, and
// prepares one valid admission proof and publication.
func newPublicationFixture(t *testing.T) *publicationFixture {
	t.Helper()
	custody := actionauthoritytest.NewCustody(t, actionauthoritytest.Controller, "second-key", "foreign")
	owner := custodyAuthority(t, custody, actionauthoritytest.Controller)
	root := filepath.Join(t.TempDir(), "messenger-carrier")
	if err := os.Mkdir(root, 0o700); err != nil {
		t.Fatal(err)
	}
	store, err := Open(root, "carrier:messenger-pq", 20, 5, map[string]economicaction.PinnedAuthority{
		"authority:test": owner.pin(t), "authority:foreign": custodyAuthority(t, custody, "foreign").pin(t)}, custody.Signer)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	now := time.Unix(2_000_000_000, 0).UTC()
	store.now = func() time.Time { return now }
	intent := testIntent(t, now)
	exact, err := codec.Marshal(intent)
	if err != nil {
		t.Fatal(err)
	}
	challenge, err := store.IssueAdmission("publication.publish", intent.Body.IssuerAgentID, intent.Body.Audience, uint64(len(exact)))
	if err != nil {
		t.Fatal(err)
	}
	proof, err := commerce.SolveOperationAdmission(challenge, 1<<24)
	if err != nil {
		t.Fatal(err)
	}
	action, fence := testPublicationAction(t, store, intent, owner, now)
	return &publicationFixture{custody: custody, owner: owner, store: store, root: root, now: now, intent: intent,
		proof: proof, action: action, fence: fence}
}

func (fixture *publicationFixture) authorityNamed(t *testing.T, keyID string) testAuthority {
	t.Helper()
	for _, name := range []string{actionauthoritytest.Controller, "second-key", "foreign"} {
		if fixture.custody.KeyID(t, name) == keyID {
			return custodyAuthority(t, fixture.custody, name)
		}
	}
	t.Fatalf("no custody controller has key ID %s", keyID)
	return testAuthority{}
}

// carrierState digests the Carrier journal and the economic action store,
// excluding the lock.
func carrierState(t *testing.T, root string) string {
	t.Helper()
	var names []string
	contents := map[string][]byte{}
	err := filepath.WalkDir(root, func(path string, entry fs.DirEntry, err error) error {
		if err != nil || entry.IsDir() || strings.Contains(entry.Name(), "lock") {
			return err
		}
		raw, readErr := os.ReadFile(path)
		if readErr != nil {
			return readErr
		}
		names = append(names, path)
		contents[path] = raw
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	sort.Strings(names)
	hash := sha256.New()
	for _, name := range names {
		_, _ = hash.Write([]byte(name))
		_, _ = hash.Write(contents[name])
	}
	return hex.EncodeToString(hash.Sum(nil))
}

func TestCarrierRefusesEveryNonActionAuthorityPublication(t *testing.T) {
	fixture := newPublicationFixture(t)
	before := carrierState(t, fixture.root)
	fenceMessage, err := commerce.WriterFenceSignatureMessage(fixture.fence.Body)
	if err != nil {
		t.Fatal(err)
	}
	for _, variant := range actionauthoritytest.Variants(t, fixture.custody, fixture.owner.controller, "second-key",
		fixture.fence.KeyID, fixture.fence.Proof, fenceMessage) {
		// A variant that still encodes canonically gets an action freshly
		// bound to it and validly signed by the controller holding its key
		// ID, so only the fence check can refuse it.
		bad := fixture.fence
		bad.KeyID, bad.Proof = variant.KeyID, variant.Signature
		action := fixture.action
		if _, digestErr := commerce.WriterFenceDigest(bad); digestErr == nil {
			action = publicationActionWithFence(t, fixture.store, fixture.intent, fixture.authorityNamed(t, bad.KeyID), bad, fixture.now)
		}
		if _, _, err := fixture.store.Publish(fixture.intent, fixture.proof, action, bad); err == nil {
			t.Fatalf("Carrier published with a fence with %s", variant.Name)
		}
		if carrierState(t, fixture.root) != before {
			t.Fatalf("Carrier wrote state for a fence with %s", variant.Name)
		}
	}
	actionMessage, err := commerce.AuthorizedActionSignatureMessage(fixture.action)
	if err != nil {
		t.Fatal(err)
	}
	for _, variant := range actionauthoritytest.Variants(t, fixture.custody, fixture.owner.controller, "second-key",
		fixture.action.AuthorityKeyID, fixture.action.AuthorizationProof, actionMessage) {
		bad := fixture.action
		bad.AuthorityKeyID, bad.AuthorizationProof = variant.KeyID, variant.Signature
		if _, _, err := fixture.store.Publish(fixture.intent, fixture.proof, bad, fixture.fence); err == nil {
			t.Fatalf("Carrier published with an action with %s", variant.Name)
		}
		if carrierState(t, fixture.root) != before {
			t.Fatalf("Carrier wrote state for an action with %s", variant.Name)
		}
	}
	if _, resolution, err := fixture.store.Publish(fixture.intent, fixture.proof, fixture.action, fixture.fence); err != nil ||
		resolution.State != commerce.ActionAccepted {
		t.Fatalf("the real ML-DSA-44 publication was refused: %+v %v", resolution, err)
	}
}

// TestCarrierRefusesAKeyPinnedForAnotherAuthority checks that a key is
// authorized only for the authority it is pinned under.
func TestCarrierRefusesAKeyPinnedForAnotherAuthority(t *testing.T) {
	fixture := newPublicationFixture(t)
	action, fence := testPublicationAction(t, fixture.store, fixture.intent, custodyAuthority(t, fixture.custody, "foreign"), fixture.now)
	before := carrierState(t, fixture.root)
	if _, _, err := fixture.store.Publish(fixture.intent, fixture.proof, action, fence); err == nil {
		t.Fatal("Carrier published with a fence signed by a key pinned for another authority")
	}
	if carrierState(t, fixture.root) != before {
		t.Fatal("Carrier wrote state for a foreign authority key")
	}
}
