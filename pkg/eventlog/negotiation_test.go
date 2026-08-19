package eventlog

import (
	"errors"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/tosnetwork/tos-messenger/pkg/negotiation"
)

func testSnapshot(id, state string) negotiation.Snapshot {
	snapshot := negotiation.Snapshot{
		Schema: negotiation.SnapshotSchema, ID: id,
		ConversationID:      "conv_" + strings.Repeat("1", 64),
		CounterpartyAgentID: "agent_" + strings.Repeat("2", 64),
		MandateDigest:       "sha256:" + strings.Repeat("3", 64),
		State:               state,
	}
	if negotiation.State(state) == negotiation.StateFinalized {
		snapshot.Commitment = "sha256:" + strings.Repeat("4", 64)
	}
	return snapshot
}

func negotiationStore(t *testing.T) *NegotiationStore {
	t.Helper()
	journal := approvalJournal(t)
	store, err := journal.OpenNegotiations()
	if err != nil {
		t.Fatalf("open negotiations: %v", err)
	}
	return store
}

func TestNegotiationsSurviveAndAreListed(t *testing.T) {
	store := negotiationStore(t)
	if err := store.Save(testSnapshot("neg-1", string(negotiation.StateDiscussing))); err != nil {
		t.Fatalf("save: %v", err)
	}
	if err := store.Save(testSnapshot("neg-2", string(negotiation.StateIntentAgreed))); err != nil {
		t.Fatalf("save: %v", err)
	}
	loaded, found, err := store.Load("neg-1")
	if err != nil || !found {
		t.Fatalf("load: found=%v err=%v", found, err)
	}
	if loaded.State != string(negotiation.StateDiscussing) {
		t.Fatalf("unexpected state: %q", loaded.State)
	}
	listed, err := store.List()
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(listed) != 2 {
		t.Fatalf("expected two negotiations, got %d", len(listed))
	}
	if _, found, err := store.Load("neg-3"); err != nil || found {
		t.Fatalf("an absent negotiation was found: %v %v", found, err)
	}
}

// Removing an exchange that is still open would strand the budget hold it
// carries, which is the outcome the store exists to prevent.
func TestOnlySettledNegotiationsAreDropped(t *testing.T) {
	store := negotiationStore(t)
	now := time.Unix(1_800_000_000, 0)
	if err := store.Save(testSnapshot("neg-1", string(negotiation.StateIntentAgreed))); err != nil {
		t.Fatalf("save: %v", err)
	}
	if err := store.Drop("neg-1", now); err == nil {
		t.Fatal("an open negotiation was dropped")
	}
	if err := store.Save(testSnapshot("neg-1", string(negotiation.StateWithdrawn))); err != nil {
		t.Fatalf("save: %v", err)
	}
	if err := store.Drop("neg-1", now); err != nil {
		t.Fatalf("drop: %v", err)
	}
	if _, found, err := store.Load("neg-1"); err != nil || found {
		t.Fatalf("a dropped negotiation remained: %v %v", found, err)
	}
	// Dropping something that is not there is not an error.
	if err := store.Drop("neg-1", now); err != nil {
		t.Fatalf("drop absent: %v", err)
	}
}

// Each open exchange holds part of a budget and may hold a person's attention.
func TestOpenNegotiationsAreBounded(t *testing.T) {
	store := negotiationStore(t)
	for index := 0; index < MaxNegotiations; index++ {
		id := "neg-" + strings.Repeat("0", 4) + string(rune('a'+index%26)) + strings.Repeat("z", index/26)
		if err := store.Save(testSnapshot(id, string(negotiation.StateDiscussing))); err != nil {
			t.Fatalf("save %d: %v", index, err)
		}
	}
	if err := store.Save(testSnapshot("one-too-many", string(negotiation.StateDiscussing))); !errors.Is(err, ErrNegotiationsFull) {
		t.Fatalf("the bound did not apply: %v", err)
	}
	// An existing negotiation may still advance.
	if err := store.Save(testSnapshot("neg-0000a", string(negotiation.StateIntentAgreed))); err != nil {
		t.Fatalf("an existing negotiation could not advance: %v", err)
	}
}

// The identifier is chosen by whoever started the exchange, so it must not be
// able to name a path. It never becomes one: the file is named by a digest of
// it, and an identifier that looks like a traversal is stored beside every
// other one.
func TestNegotiationIdentifiersCannotNameAPath(t *testing.T) {
	store := negotiationStore(t)
	traversal := "../../escape"
	if err := store.Save(testSnapshot(traversal, string(negotiation.StateDiscussing))); err != nil {
		t.Fatalf("save: %v", err)
	}
	path, err := store.path(traversal)
	if err != nil {
		t.Fatalf("path: %v", err)
	}
	if filepath.Dir(path) != store.root() {
		t.Fatalf("an identifier named a path outside the store: %s", path)
	}
	if _, found, err := store.Load(traversal); err != nil || !found {
		t.Fatalf("load: found=%v err=%v", found, err)
	}

	for _, invalid := range []string{"", strings.Repeat("x", 129), "with\nnewline", "with\x00null"} {
		if err := store.Save(testSnapshot(invalid, string(negotiation.StateDiscussing))); err == nil {
			t.Fatalf("expected %q to be refused", invalid)
		}
	}
}
