package eventlog

import (
	"bytes"
	"errors"
	"path/filepath"
	"strings"
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

	fresh, record, err := journal.CommitInbound(session(0x11), algorithm, 0,
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
	fresh, _, err = journal.CommitInbound(session(0x11), algorithm, 1,
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

	delivery, err := journal.CommitSealed(session(0x11), algorithm, 0,
		e2ee.State("advanced"), eventA, heldAttempt(t, journal, eventA, now), []byte("sealed bytes"), now)
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
	if _, err := journal.CommitSealed(session(0x11), algorithm, 0,
		e2ee.State("advanced"), eventA, heldAttempt(t, journal, eventA, now), []byte("sealed bytes"), now); err != nil {
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

	// The attempt that sealed it did not survive the restart, so its lease
	// expires and the delivery becomes due again with the ciphertext intact.
	due, err := reopened.Due(now.Add(2 * time.Minute))
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
	if _, err := journal.CommitSealed(session(0x11), algorithm, 1, state, eventA, unheldAttempt, []byte("x"), now); !errors.Is(err, ErrUnknown) {
		t.Fatalf("sealing an unqueued event produced %v", err)
	}
	if _, _, err := journal.Enqueue(outbound(eventA)); err != nil {
		t.Fatalf("enqueue: %v", err)
	}
	if _, err := journal.CommitSealed(session(0x11), algorithm, 1, state, eventA, heldAttempt(t, journal, eventA, now), nil, now); err == nil {
		t.Fatal("an empty ciphertext was accepted")
	}
	if _, err := journal.CommitSealed(session(0x11), algorithm, 1, state, eventA, heldAttempt(t, journal, eventA, now), make([]byte, MaxCiphertextBytes+1), now); err == nil {
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
	if _, _, err := journal.CommitInbound(session(0x11), algorithm, 1, e2ee.State("x"), entry(eventA, endpoint), now); err == nil {
		t.Fatal("a closed journal committed inbound")
	}
	if _, err := journal.CommitSealed(session(0x11), algorithm, 1, e2ee.State("x"), eventA, unheldAttempt, []byte("y"), now); err == nil {
		t.Fatal("a closed journal committed a sealed message")
	}
}

func sessionGeneration(t *testing.T, journal *Journal, sessionID string) uint64 {
	t.Helper()
	record, found, err := journal.SessionState(sessionID)
	if err != nil || !found {
		t.Fatalf("session state: found=%v err=%v", found, err)
	}
	return record.Generation
}

// Two sweeps preparing a transition from the same session must not both commit
// it: one ratchet advance would be lost and two messages would go out under
// the same message key.
func TestConcurrentTransitionsConflict(t *testing.T) {
	journal, _ := openJournal(t)
	now := time.Unix(int64(acceptAt), 0)
	if err := journal.PutSessionState(session(0x11), algorithm, e2ee.State("start"), now); err != nil {
		t.Fatalf("put: %v", err)
	}
	generation := sessionGeneration(t, journal, session(0x11))

	if _, _, err := journal.Enqueue(outbound(eventA)); err != nil {
		t.Fatalf("enqueue: %v", err)
	}
	if _, _, err := journal.Enqueue(outbound(eventB)); err != nil {
		t.Fatalf("enqueue: %v", err)
	}

	// Both read the same generation, as two concurrent sweeps would.
	if _, err := journal.CommitSealed(session(0x11), algorithm, generation,
		e2ee.State("advanced by A"), eventA, heldAttempt(t, journal, eventA, now), []byte("ciphertext A"), now); err != nil {
		t.Fatalf("first commit: %v", err)
	}
	if _, err := journal.CommitSealed(session(0x11), algorithm, generation,
		e2ee.State("advanced by B"), eventB, heldAttempt(t, journal, eventB, now), []byte("ciphertext B"), now); !errors.Is(err, ErrSessionConflict) {
		t.Fatalf("a stale transition was committed: %v", err)
	}

	// The loser's transition was discarded, not persisted.
	record, _, err := journal.SessionState(session(0x11))
	if err != nil {
		t.Fatalf("session: %v", err)
	}
	state, err := record.State()
	if err != nil {
		t.Fatalf("state: %v", err)
	}
	if string(state) != "advanced by A" {
		t.Fatalf("the losing transition was persisted: %q", state)
	}
	// And the loser's delivery was not left holding a ciphertext.
	losing, _, err := journal.LookupDelivery(eventB)
	if err != nil {
		t.Fatalf("lookup: %v", err)
	}
	if ciphertext, err := losing.Ciphertext(); err != nil || ciphertext != nil {
		t.Fatalf("a discarded transition left a ciphertext: %v", err)
	}
}

// One sweep at a time owns a delivery, and a sweep that dies holding one does
// not strand it.
func TestSendAttemptIsLeased(t *testing.T) {
	journal, _ := openJournal(t)
	now := time.Unix(int64(acceptAt), 0)
	if _, _, err := journal.Enqueue(outbound(eventA)); err != nil {
		t.Fatalf("enqueue: %v", err)
	}
	first := attempt(0x50)
	if _, err := journal.ClaimForSend(eventA, first, now, time.Minute); err != nil {
		t.Fatalf("claim: %v", err)
	}
	if _, err := journal.ClaimForSend(eventA, attempt(0x51), now, time.Minute); !errors.Is(err, ErrLeaseMismatch) {
		t.Fatalf("a second sweep took a leased delivery: %v", err)
	}
	if due, err := journal.Due(now); err != nil || len(due) != 0 {
		t.Fatalf("a leased delivery was still due: %+v %v", due, err)
	}
	// A settlement from a sweep that does not hold the attempt is refused.
	if _, err := journal.Delivered(eventA, attempt(0x51), now); !errors.Is(err, ErrLeaseMismatch) {
		t.Fatalf("a foreign attempt settled the delivery: %v", err)
	}

	expired := now.Add(2 * time.Minute)
	if due, err := journal.Due(expired); err != nil || len(due) != 1 {
		t.Fatalf("an expired lease did not return the delivery: %+v %v", due, err)
	}
	if _, err := journal.ClaimForSend(eventA, attempt(0x51), expired, time.Minute); err != nil {
		t.Fatalf("reclaim: %v", err)
	}
	if _, err := journal.Delivered(eventA, first, expired); !errors.Is(err, ErrLeaseMismatch) {
		t.Fatalf("a superseded attempt settled the delivery: %v", err)
	}
	if _, err := journal.Delivered(eventA, attempt(0x51), expired); err != nil {
		t.Fatalf("delivered: %v", err)
	}
}

// unheldAttempt is a well-formed attempt identifier that holds nothing. It is
// for the cases where the claim is not what is being tested.
const unheldAttempt = "send_" + "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"

// heldAttempt claims a delivery and returns the attempt that now holds it.
// Sealing is bound to the attempt, so a test that invented an identifier would
// be exercising a path the journal refuses.
func heldAttempt(t *testing.T, journal *Journal, eventID string, now time.Time) string {
	t.Helper()
	attemptID := "send_" + strings.Repeat("c", 64)
	if _, err := journal.ClaimForSend(eventID, attemptID, now, time.Minute); err != nil {
		t.Fatalf("claim: %v", err)
	}
	return attemptID
}

// An event must not reach a runtime before the session records that its
// ciphertext was opened. Between the two writes the event exists, and a
// runtime acting on it would be acting on a message the session still
// considers unread.
func TestStagedInboundIsNotOfferedToARuntime(t *testing.T) {
	journal, _ := openJournal(t)
	now := time.Unix(1_800_000_000, 0)

	fresh, record, err := journal.CommitInbound(session(0x11), algorithm, 0,
		e2ee.State("opened"), entry(eventA, endpoint), now)
	if err != nil {
		t.Fatalf("commit inbound: %v", err)
	}
	if !fresh || record.Crypto != CryptoCommitted {
		t.Fatalf("a committed inbound event was not marked as such: %+v", record)
	}
	pending, err := journal.ListPending(now, 10)
	if err != nil {
		t.Fatalf("pending: %v", err)
	}
	if len(pending) != 1 {
		t.Fatalf("a committed event was not offered: %+v", pending)
	}

	// A record staged and never committed is invisible, whatever its admission
	// and application states say.
	staged := record
	staged.Crypto = CryptoStaged
	if _, err := journal.commit(journal.path(record.EventID), staged); err != nil {
		t.Fatalf("stage: %v", err)
	}
	if pending, err := journal.ListPending(now, 10); err != nil {
		t.Fatalf("pending: %v", err)
	} else if len(pending) != 0 {
		t.Fatalf("an uncommitted transition was handed to a runtime: %+v", pending)
	}
}

// A process that died between staging an event and advancing its session must
// not leave that decision to the sender's retry.
func TestStagedInboundIsFinishedOnRestart(t *testing.T) {
	root := filepath.Join(t.TempDir(), "state")
	now := time.Unix(1_800_000_000, 0)

	journal, err := Open(root)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	entry := entry(eventA, endpoint)
	entry.Transition = &Transition{
		SessionID: session(0x11), Algorithm: algorithm,
		ExpectedGeneration: 0, NextState: e2ee.State("opened"),
	}
	if _, _, err := journal.Accept(entry); err != nil {
		t.Fatalf("accept: %v", err)
	}
	// The session was never advanced: this is the crash.
	if err := journal.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}

	reopened, err := Open(root)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	defer reopened.Close()

	record, found, err := reopened.Lookup(eventA)
	if err != nil || !found {
		t.Fatalf("lookup: found=%v err=%v", found, err)
	}
	if record.Crypto != CryptoCommitted {
		t.Fatalf("a staged event was left unresolved: %+v", record)
	}
	state, found, err := reopened.SessionState(session(0x11))
	if err != nil || !found {
		t.Fatalf("session: found=%v err=%v", found, err)
	}
	if state.Generation != 1 || state.LastInboundEventID != eventA {
		t.Fatalf("the interrupted transition was not applied: %+v", state)
	}
	if pending, err := reopened.ListPending(now, 10); err != nil {
		t.Fatalf("pending: %v", err)
	} else if len(pending) != 1 {
		t.Fatalf("the recovered event was not offered: %+v", pending)
	}
}

// A transition that can no longer be applied is abandoned rather than
// delivered. Its ciphertext was never consumed, so a resend opens normally.
func TestStagedInboundIsAbandonedWhenTheSessionMovedOn(t *testing.T) {
	root := filepath.Join(t.TempDir(), "state")
	now := time.Unix(1_800_000_000, 0)

	journal, err := Open(root)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	entry := entry(eventA, endpoint)
	entry.Transition = &Transition{
		SessionID: session(0x11), Algorithm: algorithm,
		ExpectedGeneration: 0, NextState: e2ee.State("opened"),
	}
	if _, _, err := journal.Accept(entry); err != nil {
		t.Fatalf("accept: %v", err)
	}
	// Something else advanced the session past the staged transition.
	if err := journal.PutSessionState(session(0x11), algorithm, e2ee.State("elsewhere"), now); err != nil {
		t.Fatalf("put session: %v", err)
	}
	if err := journal.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}

	reopened, err := Open(root)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	defer reopened.Close()

	record, found, err := reopened.Lookup(eventA)
	if err != nil || !found {
		t.Fatalf("lookup: found=%v err=%v", found, err)
	}
	if record.Crypto != CryptoAbandoned {
		t.Fatalf("an unapplicable transition was not abandoned: %+v", record)
	}
	if pending, err := reopened.ListPending(now, 10); err != nil {
		t.Fatalf("pending: %v", err)
	} else if len(pending) != 0 {
		t.Fatalf("an abandoned event was offered to a runtime: %+v", pending)
	}
}

// Leases expire, and that is how work is recovered from a worker that died.
// The attempt that lost the delivery must not still be able to advance the
// ratchet for it.
func TestOnlyTheHoldingAttemptMaySeal(t *testing.T) {
	journal, _ := openJournal(t)
	now := time.Unix(1_800_000_000, 0)
	if _, _, err := journal.Enqueue(outbound(eventA)); err != nil {
		t.Fatalf("enqueue: %v", err)
	}

	first := "send_" + strings.Repeat("a", 64)
	if _, err := journal.ClaimForSend(eventA, first, now, time.Minute); err != nil {
		t.Fatalf("claim: %v", err)
	}
	// The lease expires and another attempt takes over.
	later := now.Add(2 * time.Minute)
	second := "send_" + strings.Repeat("b", 64)
	if _, err := journal.ClaimForSend(eventA, second, later, time.Minute); err != nil {
		t.Fatalf("second claim: %v", err)
	}

	if _, err := journal.CommitSealed(session(0x11), algorithm, 0, e2ee.State("advanced"),
		eventA, first, []byte("stale ciphertext"), later); !errors.Is(err, ErrLeaseMismatch) {
		t.Fatalf("an attempt that lost the delivery sealed it anyway: %v", err)
	}
	// The ratchet did not move for the attempt that no longer holds it.
	if _, found, err := journal.SessionState(session(0x11)); err != nil {
		t.Fatalf("session: %v", err)
	} else if found {
		t.Fatal("a losing attempt advanced the session")
	}

	sealed, err := journal.CommitSealed(session(0x11), algorithm, 0, e2ee.State("advanced"),
		eventA, second, []byte("ciphertext"), later)
	if err != nil {
		t.Fatalf("commit sealed: %v", err)
	}
	if sealed.CiphertextBase64 == "" {
		t.Fatal("the holding attempt could not seal")
	}
	// And sealing again spends no second message key.
	if _, err := journal.CommitSealed(session(0x11), algorithm, 1, e2ee.State("again"),
		eventA, second, []byte("second ciphertext"), later); !errors.Is(err, ErrAlreadySealed) {
		t.Fatalf("a delivery was sealed twice: %v", err)
	}
}

// An expired lease is not a held one, even when nobody else has taken over.
func TestAnExpiredAttemptCannotSeal(t *testing.T) {
	journal, _ := openJournal(t)
	now := time.Unix(1_800_000_000, 0)
	if _, _, err := journal.Enqueue(outbound(eventA)); err != nil {
		t.Fatalf("enqueue: %v", err)
	}
	attemptID := "send_" + strings.Repeat("a", 64)
	if _, err := journal.ClaimForSend(eventA, attemptID, now, time.Minute); err != nil {
		t.Fatalf("claim: %v", err)
	}
	if _, err := journal.CommitSealed(session(0x11), algorithm, 0, e2ee.State("advanced"),
		eventA, attemptID, []byte("late ciphertext"), now.Add(2*time.Minute)); !errors.Is(err, ErrLeaseMismatch) {
		t.Fatalf("an expired attempt sealed anyway: %v", err)
	}
}
