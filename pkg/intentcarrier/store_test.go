package intentcarrier

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/tosnetwork/tos-messenger/internal/actionauthoritytest"
	"github.com/tosnetwork/tos-messenger/pkg/economicaction"
	commerce "github.com/tosnetwork/tos-service-protocol/pkg/agentcommerce"
	"github.com/tosnetwork/tos-service-protocol/pkg/codec"
	"github.com/tosnetwork/tos-service-protocol/pkg/mldsa44"
	"github.com/tosnetwork/tos-service-protocol/pkg/mldsa44/mldsa44test"
)

func TestIndependentJournalPublishSearchResolveRestartAndHTTP(t *testing.T) {
	root := filepath.Join(t.TempDir(), "messenger-carrier")
	if err := os.Mkdir(root, 0o700); err != nil {
		t.Fatal(err)
	}
	authorityKey := fakeAuthority()
	store, err := Open(root, "carrier:messenger-independent", 20, 5,
		authorityKey.pins(t), authorityKey.verifier)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Unix(2_000_000_000, 0).UTC()
	store.now = func() time.Time { return now }
	intent := testIntent(t, now)
	exact, _ := codec.Marshal(intent)
	challenge, err := store.IssueAdmission("publication.publish", intent.Body.IssuerAgentID, intent.Body.Audience, uint64(len(exact)))
	if err != nil {
		t.Fatal(err)
	}
	proof, err := commerce.SolveOperationAdmission(challenge, 1<<24)
	if err != nil {
		t.Fatal(err)
	}
	action, fence := testPublicationAction(t, store, intent, authorityKey, now)
	result, resolution, err := store.Publish(intent, proof, action, fence)
	if err != nil || resolution.State != commerce.ActionAccepted {
		t.Fatalf("publish result=%+v resolution=%+v err=%v", result, resolution, err)
	}
	page, err := store.Search(Query{Modes: []commerce.IntentMode{commerce.IntentRequest}, Keywords: []string{"review"}, Limit: 10})
	if err != nil || len(page.Results) != 1 || page.Results[0].IntentDigest != result.IntentDigest || page.CarrierID != store.carrierID {
		t.Fatalf("page=%+v err=%v", page, err)
	}
	handler := Handler(store, testAuthorizer{})
	request := httptest.NewRequest(http.MethodGet, "/v1/intents?limit=10&keyword=review", nil)
	request.Header.Set("Authorization", "Bearer read")
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusOK || !strings.Contains(response.Body.String(), result.IntentDigest) {
		t.Fatalf("HTTP search status=%d body=%s", response.Code, response.Body.String())
	}
	request = httptest.NewRequest(http.MethodGet, "/v1/intents/"+strings.TrimPrefix(result.IntentDigest, "sha256:"), nil)
	request.Header.Set("Authorization", "Bearer read")
	response = httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("HTTP resolve status=%d body=%s", response.Code, response.Body.String())
	}
	if concurrent, openErr := Open(root, store.carrierID, 20, 5,
		authorityKey.pins(t), authorityKey.verifier); openErr == nil {
		_ = concurrent.Close()
		t.Fatal("second process acquired the Messenger Carrier journal")
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	restarted, err := Open(root, "carrier:messenger-independent", 20, 5,
		authorityKey.pins(t), authorityKey.verifier)
	if err != nil {
		t.Fatal(err)
	}
	defer restarted.Close()
	restarted.now = func() time.Time { return now }
	if retained, getErr := restarted.Get(result.IntentDigest); getErr != nil || retained.IntentDigest != result.IntentDigest {
		t.Fatalf("restart retained=%+v err=%v", retained, getErr)
	}
	if _, err := os.Stat(filepath.Join(root, "intent-carrier-journal-v1.json")); err != nil {
		t.Fatal("independent append journal was not persisted", err)
	}
}

func TestHTTPPublicationRequiresWriteToken(t *testing.T) {
	root := filepath.Join(t.TempDir(), "messenger-carrier")
	if err := os.Mkdir(root, 0o700); err != nil {
		t.Fatal(err)
	}
	authorityKey := fakeAuthority()
	store, err := Open(root, "carrier:messenger-http", 20, 5,
		authorityKey.pins(t), authorityKey.verifier)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	now := time.Unix(2_000_000_000, 0).UTC()
	store.now = func() time.Time { return now }
	intent := testIntent(t, now)
	exact, _ := codec.Marshal(intent)
	challenge, _ := store.IssueAdmission("publication.publish", intent.Body.IssuerAgentID, intent.Body.Audience, uint64(len(exact)))
	proof, _ := commerce.SolveOperationAdmission(challenge, 1<<24)
	action, fence := testPublicationAction(t, store, intent, authorityKey, now)
	raw, _ := json.Marshal(struct {
		Intent    commerce.SignedAgentIntent       `json:"intent"`
		Admission commerce.OperationAdmissionProof `json:"admission"`
		Action    commerce.AuthorizedAction        `json:"authorized_action"`
		Fence     commerce.WriterFence             `json:"writer_fence"`
	}{intent, proof, action, fence})
	request := httptest.NewRequest(http.MethodPost, "/v1/intents", bytes.NewReader(raw))
	request.Header.Set("Authorization", "Bearer read")
	response := httptest.NewRecorder()
	Handler(store, testAuthorizer{}).ServeHTTP(response, request)
	if response.Code != http.StatusUnauthorized {
		t.Fatalf("read token published an Intent: %d", response.Code)
	}
}

func testIntent(t *testing.T, now time.Time) commerce.SignedAgentIntent {
	t.Helper()
	_, issuer, _ := ed25519.GenerateKey(rand.Reader)
	detail := []byte("review this source tree")
	digest := sha256.Sum256(detail)
	agent := "agent:" + strings.Repeat("a", 64)
	body := commerce.AgentIntentBody{SchemaVersion: 1, NetworkID: "tos:testnet", IssuerAgentID: agent,
		Audience: "public:indexable", ObjectID: "intent:" + strings.Repeat("b", 64), Revision: 1,
		CreatedAtUnix: uint64(now.Unix()), ExpiresAtUnix: uint64(now.Add(time.Hour).Unix()),
		Payload: commerce.AgentIntentPayload{DiscoveryCard: commerce.DiscoveryCard{Summary: "Review source",
			IntentModes: []commerce.IntentMode{commerce.IntentRequest}, SubjectClasses: []commerce.SubjectClass{commerce.SubjectService},
			TaxonomyPaths: []string{"tos.taxonomy.v1/service/security/review"}, Keywords: []commerce.IntentKeyword{{Text: "review", Language: "en"}},
			ValueState: commerce.ValueSpecified, ValueHints: []commerce.ValueHint{{Role: "budget", AssetNamespace: "tos.asset", AssetIdentifier: "native", AmountKind: "exact", MinimumDecimal: "50", MaximumDecimal: "50", Unit: "total"}},
			Schedule: commerce.IntentSchedule{Flexibility: "flexible"}, FulfillmentModes: []string{"remote"}},
			DetailDescriptor: commerce.ContentDescriptor{ContentType: "text/plain", ContentDigest: "sha256:" + hex.EncodeToString(digest[:]), ContentSize: uint64(len(detail)), InlineContent: detail},
			ReplyRoutes:      []commerce.ReplyRoute{{ProfileURI: "tos.messenger.direct.v1", AgentID: agent}}}}
	intent, err := commerce.SignIntent(body, issuer)
	if err != nil {
		t.Fatal(err)
	}
	return intent
}

func testPublicationAction(t *testing.T, store *Store, intent commerce.SignedAgentIntent,
	authorityKey testAuthority, now time.Time) (commerce.AuthorizedAction, commerce.WriterFence) {
	t.Helper()
	fence, err := commerce.SignWriterFence(context.Background(), commerce.WriterFenceBody{SchemaVersion: 1, OwnerID: "owner:test",
		AgentID: intent.Body.IssuerAgentID, InstanceID: "instance:test", LeaseID: "lease:test", WriterGeneration: 1,
		IssuedAtUnix: uint64(now.Add(-time.Second).Unix()), ExpiresAtUnix: uint64(now.Add(time.Hour).Unix()),
		AuthorityID: "authority:test", Scope: []string{"publication.publish"}}, authorityKey.signer, authorityKey.controller)
	if err != nil {
		t.Fatal(err)
	}
	exact, _ := codec.Marshal(intent)
	opDigest, _ := codec.Digest("tos.agent-intent-publication-operation.v1", intent)
	fields := map[string]commerce.SemanticValue{"owner_id": commerce.ID("owner:test"), "agent_id": commerce.ID(intent.Body.IssuerAgentID),
		"carrier_id": commerce.ID(store.carrierID), "intent_object_id": commerce.ID(intent.Body.ObjectID),
		"revision": commerce.U64(intent.Body.Revision), "operation_digest": commerce.Digest32(opDigest)}
	action, err := commerce.BuildAuthorizedAction("owner:test", intent.Body.IssuerAgentID, "publication.publish", fields, exact,
		fence, 1, "sha256:"+strings.Repeat("1", 64), "", "not-published", uint64(now.Add(time.Hour).Unix()))
	if err == nil {
		action, err = commerce.SignAuthorizedAction(context.Background(), action, authorityKey.keyID, authorityKey.signer, authorityKey.controller)
	}
	if err != nil {
		t.Fatal(err)
	}
	return action, fence
}

// testAuthority names an Action Authority controller in custody and the
// verifier that checks its signatures.
type testAuthority struct {
	signer     mldsa44.Signer
	verifier   mldsa44.Verifier
	controller string
	keyID      string
	publicKey  []byte
}

// fakeAuthority is the deterministic in-process stand-in used by pure-logic
// tests.
func fakeAuthority() testAuthority {
	fake := &mldsa44test.Fake{}
	return testAuthority{signer: fake, verifier: fake, controller: actionauthoritytest.Controller,
		keyID: fake.KeyID(actionauthoritytest.Controller), publicKey: fake.PublicKey(actionauthoritytest.Controller)}
}

func (authority testAuthority) pin(t *testing.T) economicaction.PinnedAuthority {
	t.Helper()
	keyID, err := mldsa44.ParseKeyIDText(authority.keyID)
	if err != nil {
		t.Fatal(err)
	}
	return economicaction.PinnedAuthority{KeyID: keyID, PublicKey: authority.publicKey}
}

// pins pins the authority's key for authority:test.
func (authority testAuthority) pins(t *testing.T) map[string]economicaction.PinnedAuthority {
	t.Helper()
	return map[string]economicaction.PinnedAuthority{"authority:test": authority.pin(t)}
}

type testAuthorizer struct{}

func (testAuthorizer) Authorize(header string, write bool) error {
	want := "Bearer read"
	if write {
		want = "Bearer write"
	}
	if header != want {
		return os.ErrPermission
	}
	return nil
}
