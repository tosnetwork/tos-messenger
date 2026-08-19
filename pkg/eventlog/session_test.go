package eventlog

import (
	"bytes"
	"errors"
	"testing"
	"time"

	"github.com/tosnetwork/tos-messenger/pkg/e2ee"
)

const algorithm = "tos.messaging.e2ee.example-suite.v1"

func session(seed byte) string {
	id, err := NewSessionID(bytes.Repeat([]byte{seed}, 32))
	if err != nil {
		panic(err)
	}
	return id
}

func TestSessionStateRoundTrip(t *testing.T) {
	journal, _ := openJournal(t)
	now := time.Unix(int64(acceptAt), 0)
	state := e2ee.State("ratchet position one")

	if _, found, err := journal.SessionState(session(0x11)); err != nil || found {
		t.Fatalf("expected no session yet: found=%v err=%v", found, err)
	}
	if err := journal.PutSessionState(session(0x11), algorithm, state, now); err != nil {
		t.Fatalf("put: %v", err)
	}
	record, found, err := journal.SessionState(session(0x11))
	if err != nil || !found {
		t.Fatalf("lookup: found=%v err=%v", found, err)
	}
	restored, err := record.State()
	if err != nil {
		t.Fatalf("state: %v", err)
	}
	if !bytes.Equal(restored, state) {
		t.Fatalf("state changed on disk: %q", restored)
	}
	if record.AlgorithmID != algorithm {
		t.Fatalf("the suite was not recorded: %+v", record)
	}
}

// The inbound order: the event is durable before the session advances. A crash
// between them must leave the event, because the other order loses it forever.
func TestCommitInboundStoresTheEventBeforeAdvancing(t *testing.T) {
	journal, _ := openJournal(t)
	now := time.Unix(int64(acceptAt), 0)

	fresh, record, err := journal.CommitInbound(session(0x11), algorithm,
		e2ee.State("advanced"), entry(eventA, endpoint), now)
	if err != nil {
		t.Fatalf("commit: %v", err)
	}
	if !fresh || record.Application != StateQueued {
		t.Fatalf("unexpected record: fresh=%v %+v", fresh, record)
	}
	stored, found, err := journal.SessionState(session(0x11))
	if err != nil || !found {
		t.Fatalf("session: found=%v err=%v", found, err)
	}
	state, err := stored.State()
	if err != nil {
		t.Fatalf("state: %v", err)
	}
	if string(state) != "advanced" {
		t.Fatalf("the session did not advance: %q", state)
	}

	// A redelivery is a duplicate and still advances nothing that matters.
	fresh, _, err = journal.CommitInbound(session(0x11), algorithm,
		e2ee.State("advanced again"), entry(eventA, endpoint), now)
	if err != nil {
		t.Fatalf("commit: %v", err)
	}
	if fresh {
		t.Fatal("a redelivery was reported as fresh")
	}
}

// The outbound order is the opposite: the session advances first, so a crash
// costs a ciphertext that can be produced again rather than a reused key.
func TestCommitSealedAdvancesBeforeStoringTheCiphertext(t *testing.T) {
	journal, _ := openJournal(t)
	now := time.Unix(int64(acceptAt), 0)

	if _, _, err := journal.Enqueue(outbound(eventA)); err != nil {
		t.Fatalf("enqueue: %v", err)
	}
	queued, found, err := journal.LookupDelivery(eventA)
	if err != nil || !found {
		t.Fatalf("lookup: found=%v err=%v", found, err)
	}
	// Before sealing there is a plaintext to seal and no ciphertext.
	payload, err := queued.Payload()
	if err != nil || len(payload) == 0 {
		t.Fatalf("queued event carries no payload: %v", err)
	}
	if ciphertext, err := queued.Ciphertext(); err != nil || ciphertext != nil {
		t.Fatalf("an unsealed delivery already had a ciphertext: %v", err)
	}

	delivery, err := journal.CommitSealed(session(0x11), algorithm,
		e2ee.State("advanced"), eventA, []byte("sealed bytes"), now)
	if err != nil {
		t.Fatalf("commit sealed: %v", err)
	}
	if delivery.SessionID != session(0x11) {
		t.Fatalf("the delivery was not bound to its session: %+v", delivery)
	}
	sealed, err := delivery.Ciphertext()
	if err != nil {
		t.Fatalf("ciphertext: %v", err)
	}
	if string(sealed) != "sealed bytes" {
		t.Fatalf("the stored ciphertext is wrong: %q", sealed)
	}
	stored, found, err := journal.SessionState(session(0x11))
	if err != nil || !found {
		t.Fatalf("session: found=%v err=%v", found, err)
	}
	if state, err := stored.State(); err != nil || string(state) != "advanced" {
		t.Fatalf("the session did not advance: %q %v", state, err)
	}
}

// A retry sends the ciphertext that was committed. Sealing again for every
// network retry would consume another message key each time.
func TestSealedCiphertextSurvivesRestart(t *testing.T) {
	journal, root := openJournal(t)
	now := time.Unix(int64(acceptAt), 0)
	if _, _, err := journal.Enqueue(outbound(eventA)); err != nil {
		t.Fatalf("enqueue: %v", err)
	}
	if _, err := journal.CommitSealed(session(0x11), algorithm,
		e2ee.State("advanced"), eventA, []byte("sealed bytes"), now); err != nil {
		t.Fatalf("commit sealed: %v", err)
	}
	if err := journal.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	reopened, err := Open(root)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	defer reopened.Close()

	due, err := reopened.Due(now)
	if err != nil {
		t.Fatalf("due: %v", err)
	}
	if len(due) != 1 {
		t.Fatalf("expected the sealed delivery to be due, got %d", len(due))
	}
	ciphertext, err := due[0].Ciphertext()
	if err != nil || string(ciphertext) != "sealed bytes" {
		t.Fatalf("the sealed message did not survive: %q %v", ciphertext, err)
	}
	stored, found, err := reopened.SessionState(session(0x11))
	if err != nil || !found {
		t.Fatalf("session: found=%v err=%v", found, err)
	}
	if state, err := stored.State(); err != nil || string(state) != "advanced" {
		t.Fatalf("session state did not survive: %q %v", state, err)
	}
}

func TestSessionCommitsRejectUnusableInput(t *testing.T) {
	journal, _ := openJournal(t)
	now := time.Unix(int64(acceptAt), 0)
	state := e2ee.State("advanced")

	if err := journal.PutSessionState("ses_bad", algorithm, state, now); err == nil {
		t.Fatal("an invalid session identifier was accepted")
	}
	if err := journal.PutSessionState(session(0x11), "homegrown", state, now); err == nil {
		t.Fatal("an unnamed suite was accepted")
	}
	if err := journal.PutSessionState(session(0x11), algorithm, nil, now); err == nil {
		t.Fatal("empty state was accepted")
	}
	oversized := make(e2ee.State, e2ee.MaxSessionStateBytes+1)
	if err := journal.PutSessionState(session(0x11), algorithm, oversized, now); err == nil {
		t.Fatal("unbounded state was accepted")
	}
	if err := journal.PutSessionState(session(0x11), algorithm, state, time.Time{}); err == nil {
		t.Fatal("a zero clock was accepted")
	}
	if _, err := journal.CommitSealed(session(0x11), algorithm, state, eventA, []byte("x"), now); !errors.Is(err, ErrUnknown) {
		t.Fatalf("sealing an unqueued event produced %v", err)
	}
	if _, _, err := journal.Enqueue(outbound(eventA)); err != nil {
		t.Fatalf("enqueue: %v", err)
	}
	if _, err := journal.CommitSealed(session(0x11), algorithm, state, eventA, nil, now); err == nil {
		t.Fatal("an empty ciphertext was accepted")
	}
	if _, err := journal.CommitSealed(session(0x11), algorithm, state, eventA,
		make([]byte, MaxCiphertextBytes+1), now); err == nil {
		t.Fatal("an unbounded ciphertext was accepted")
	}
}

func TestClosedJournalRefusesSessionWork(t *testing.T) {
	journal, _ := openJournal(t)
	if err := journal.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	now := time.Unix(int64(acceptAt), 0)
	if err := journal.PutSessionState(session(0x11), algorithm, e2ee.State("x"), now); err == nil {
		t.Fatal("a closed journal wrote session state")
	}
	if _, _, err := journal.SessionState(session(0x11)); err == nil {
		t.Fatal("a closed journal read session state")
	}
	if _, _, err := journal.CommitInbound(session(0x11), algorithm, e2ee.State("x"), entry(eventA, endpoint), now); err == nil {
		t.Fatal("a closed journal committed inbound")
	}
	if _, err := journal.CommitSealed(session(0x11), algorithm, e2ee.State("x"), eventA, []byte("y"), now); err == nil {
		t.Fatal("a closed journal committed a sealed message")
	}
}
