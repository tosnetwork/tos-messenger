package economicaction

import (
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"strings"
	"testing"
	"time"

	commerce "github.com/tosnetwork/tos-service-protocol/pkg/agentcommerce"
)

func TestStoreFencesTakeoverAndRecoversExactAction(t *testing.T) {
	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	publicKey := privateKey.Public().(ed25519.PublicKey)
	root := t.TempDir()
	store, err := Open(root, map[string]ed25519.PublicKey{"authority-1": publicKey})
	if err != nil {
		t.Fatal(err)
	}
	now := time.Unix(1_800_000_000, 0).UTC()
	fence := func(generation uint64) commerce.WriterFence {
		result, signErr := commerce.SignWriterFence(commerce.WriterFenceBody{SchemaVersion: 1, OwnerID: "owner-1",
			AgentID: "agent-1", InstanceID: "instance-1", LeaseID: "lease-1", WriterGeneration: generation,
			IssuedAtUnix: uint64(now.Add(-time.Minute).Unix()), ExpiresAtUnix: uint64(now.Add(time.Hour).Unix()),
			AuthorityID: "authority-1", Scope: []string{"messenger.contact"}}, privateKey)
		if signErr != nil {
			t.Fatal(signErr)
		}
		return result
	}
	build := func(instanceByte string, writer commerce.WriterFence) (commerce.AuthorizedAction, map[string]commerce.SemanticValue, []byte) {
		request, requestErr := commerce.CanonicalMessengerEffectRequest(commerce.MessengerEffectRequestV1{SchemaVersion: 1,
			RecipientAgentIDs: []string{"agent-2"}, EventKind: "text", ContentType: "text/plain", Payload: []byte("hello")})
		if requestErr != nil {
			t.Fatal(requestErr)
		}
		fields := map[string]commerce.SemanticValue{"owner_id": commerce.ID("owner-1"), "agent_id": commerce.ID("agent-1"),
			"recipient_agent_id": commerce.ID("agent-2"), "intent_reference_digest": commerce.Digest32("sha256:" + strings.Repeat("1", 64)),
			"authority_instance_id": commerce.Digest32("sha256:" + strings.Repeat(instanceByte, 64))}
		action, actionErr := commerce.BuildAuthorizedAction("owner-1", "agent-1", "messenger.contact", fields, request, writer,
			1, "sha256:"+strings.Repeat("3", 64), "", "no-contact", uint64(now.Add(30*time.Minute).Unix()))
		if actionErr != nil {
			t.Fatal(actionErr)
		}
		action, actionErr = commerce.SignAuthorizedAction(action, privateKey)
		if actionErr != nil {
			t.Fatal(actionErr)
		}
		return action, fields, request
	}
	fence1 := fence(1)
	action1, fields1, request1 := build("a", fence1)
	prepared, err := store.Admit(action1, fence1, fields1, request1, now)
	if err != nil || prepared.State != commerce.ActionPrepared {
		t.Fatalf("first admission: %+v %v", prepared, err)
	}
	accepted, err := store.Accept(action1.StableActionID, action1.ExactRequestDigest, "evt_"+strings.Repeat("4", 64))
	if err != nil || accepted.State != commerce.ActionAccepted {
		t.Fatalf("accept: %+v %v", accepted, err)
	}
	retry, err := store.Admit(action1, fence1, fields1, request1, now)
	if err != nil || retry.State != accepted.State || retry.SinkReference != accepted.SinkReference || retry.StateRevision != accepted.StateRevision {
		t.Fatalf("exact retry changed result: %+v %v", retry, err)
	}
	fence2 := fence(2)
	action2, fields2, request2 := build("b", fence2)
	if _, err := store.Admit(action2, fence2, fields2, request2, now); err != nil {
		t.Fatal(err)
	}
	equivocatedFence, err := commerce.SignWriterFence(commerce.WriterFenceBody{SchemaVersion: 1, OwnerID: "owner-1",
		AgentID: "agent-1", InstanceID: "instance-2", LeaseID: "lease-2", WriterGeneration: 2,
		IssuedAtUnix: uint64(now.Add(-time.Minute).Unix()), ExpiresAtUnix: uint64(now.Add(time.Hour).Unix()),
		AuthorityID: "authority-1", Scope: []string{"messenger.contact"}}, privateKey)
	if err != nil {
		t.Fatal(err)
	}
	equivocated, equivocatedFields, equivocatedRequest := build("d", equivocatedFence)
	if _, err := store.Admit(equivocated, equivocatedFence, equivocatedFields, equivocatedRequest, now); err == nil {
		t.Fatal("same writer generation with a different authority fence was admitted")
	}
	stale, staleFields, staleRequest := build("c", fence1)
	if _, err := store.Admit(stale, fence1, staleFields, staleRequest, now); !errors.Is(err, ErrStaleWriter) {
		t.Fatalf("stale writer was not fenced: %v", err)
	}
	reopened, err := Open(root, map[string]ed25519.PublicKey{"authority-1": publicKey})
	if err != nil {
		t.Fatal(err)
	}
	resolved, err := reopened.Resolve(action1.StableActionID, action1.ExactRequestDigest)
	if err != nil || resolved.State != commerce.ActionAccepted {
		t.Fatalf("recovery lost accepted action: %+v %v", resolved, err)
	}
	submitted, err := reopened.Resolve(action2.StableActionID, action2.ExactRequestDigest)
	if err != nil || submitted.State != commerce.ActionPrepared {
		t.Fatalf("prepared action was not recoverable: %+v %v", submitted, err)
	}
	if submitted, err = reopened.Submit(action2.StableActionID, action2.ExactRequestDigest); err != nil || submitted.State != commerce.ActionSubmitted {
		t.Fatalf("submission was not durable: %+v %v", submitted, err)
	}
	reopened, err = Open(root, map[string]ed25519.PublicKey{"authority-1": publicKey})
	if err != nil {
		t.Fatal(err)
	}
	submitted, err = reopened.Resolve(action2.StableActionID, action2.ExactRequestDigest)
	if err != nil || submitted.State != commerce.ActionSubmitted {
		t.Fatalf("ambiguous submitted action was lost across restart: %+v %v", submitted, err)
	}
}
