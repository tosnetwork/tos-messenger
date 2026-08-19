package dispatch

import (
	"context"
	"encoding/binary"
	"errors"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/tosnetwork/tos-messenger/pkg/e2ee"
	"github.com/tosnetwork/tos-messenger/pkg/envelope"
	"github.com/tosnetwork/tos-messenger/pkg/eventlog"
	"github.com/tosnetwork/tos-messenger/pkg/fault"
	"github.com/tosnetwork/tos-messenger/pkg/payload"
	nativev1 "github.com/tosnetwork/tos-service-protocol/gen/tos/service/v1"
)

const (
	baseUnix   = uint64(1_800_000_000)
	algorithm  = "tos.messaging.e2ee.test-double.v1"
	senderID   = "agent_" + "2222222222222222222222222222222222222222222222222222222222222222"
	peerID     = "agent_" + "5555555555555555555555555555555555555555555555555555555555555555"
	senderMEP  = "mep_" + "3333333333333333333333333333333333333333333333333333333333333333"
	peerMEP    = "mep_" + "6666666666666666666666666666666666666666666666666666666666666666"
	senderDev  = "dev_" + "4444444444444444444444444444444444444444444444444444444444444444"
	peerDev    = "dev_" + "7777777777777777777777777777777777777777777777777777777777777777"
	convoID    = "conv_" + "1111111111111111111111111111111111111111111111111111111111111111"
	sessionID  = "ses_" + "8888888888888888888888888888888888888888888888888888888888888888"
	otherSuite = "tos.messaging.e2ee.other-suite.v1"
)

// countingSuite is NOT cryptography. It exists so a test can tell how many
// times a message was sealed, which is the property this package is about.
type countingSuite struct{ seals *int }

// textBody is a real typed body. A test that queued arbitrary bytes would be
// exercising a path the dispatcher no longer has.
func textBody(t *testing.T, body string) []byte {
	t.Helper()
	encoded, err := payload.Encode(payload.Text{MediaType: "text/plain; charset=utf-8", Body: body})
	if err != nil {
		t.Fatalf("encode payload: %v", err)
	}
	return encoded
}

func (c countingSuite) AlgorithmID() string { return algorithm }

func (c countingSuite) NewPrekeyMaterial() ([]byte, []byte, error) {
	return []byte("public"), []byte("private"), nil
}

func (c countingSuite) Initiate([]byte, []byte) (e2ee.State, []byte, error) {
	return e2ee.State(make([]byte, 8)), []byte("initial"), nil
}

func (c countingSuite) Accept([]byte, []byte, []byte) (e2ee.State, error) {
	return e2ee.State(make([]byte, 8)), nil
}

func (c countingSuite) KeyMaterial(state e2ee.State) (e2ee.State, error) { return state, nil }

func (c countingSuite) Seal(state e2ee.State, plaintext, binding []byte) ([]byte, e2ee.State, error) {
	if len(state) != 8 {
		return nil, nil, e2ee.ErrStateUnusable
	}
	*c.seals++
	counter := binary.BigEndian.Uint64(state)
	ciphertext := make([]byte, 8, 8+len(plaintext))
	binary.BigEndian.PutUint64(ciphertext, counter)
	ciphertext = append(ciphertext, plaintext...)
	next := make([]byte, 8)
	binary.BigEndian.PutUint64(next, counter+1)
	return ciphertext, next, nil
}

func (c countingSuite) Open(state e2ee.State, ciphertext, binding []byte) ([]byte, e2ee.State, error) {
	return nil, nil, e2ee.ErrNotAuthentic
}

type fakeSender struct {
	sent []Message
	fail error
}

func (f *fakeSender) Send(_ context.Context, message Message) error {
	if f.fail != nil {
		return f.fail
	}
	f.sent = append(f.sent, message)
	return nil
}

type bindings struct{}

func (bindings) BindingFor(delivery eventlog.Delivery) (e2ee.Binding, error) {
	return e2ee.Binding{
		Network: &nativev1.NetworkDomain{
			NetworkId:       "tos-local",
			GenesisRootHash: strings.Repeat("a", 64),
			GenesisFileHash: strings.Repeat("b", 64),
		},
		AlgorithmID:         algorithm,
		ConversationID:      delivery.ConversationID,
		SenderAgentID:       senderID,
		SenderEndpointID:    senderMEP,
		SenderDeviceID:      senderDev,
		RecipientAgentID:    peerID,
		RecipientEndpointID: delivery.RecipientEndpointID,
		RecipientDeviceID:   peerDev,
	}, nil
}

type harness struct {
	dispatcher *Dispatcher
	journal    *eventlog.Journal
	sender     *fakeSender
	seals      int
	clock      time.Time
}

func newHarness(t *testing.T) *harness {
	t.Helper()
	journal, err := eventlog.Open(filepath.Join(t.TempDir(), "state"))
	if err != nil {
		t.Fatalf("journal: %v", err)
	}
	t.Cleanup(func() { _ = journal.Close() })

	instance := &harness{journal: journal, sender: &fakeSender{}, clock: time.Unix(int64(baseUnix), 0)}
	dispatcher, err := New(Config{
		Journal:  journal,
		Suite:    countingSuite{seals: &instance.seals},
		Sender:   instance.sender,
		Bindings: bindings{},
		Now:      func() time.Time { return instance.clock },
		Identity: testIdentity(),
	})
	if err != nil {
		t.Fatalf("dispatcher: %v", err)
	}
	instance.dispatcher = dispatcher
	if err := journal.PutSessionState(sessionID, algorithm, e2ee.State(make([]byte, 8)), instance.clock); err != nil {
		t.Fatalf("session: %v", err)
	}
	return instance
}

func (h *harness) event(t *testing.T, body string) envelope.Event {
	t.Helper()
	event, err := envelope.NewEvent(envelope.Event{
		Network: &nativev1.NetworkDomain{
			NetworkId:       "tos-local",
			GenesisRootHash: strings.Repeat("a", 64),
			GenesisFileHash: strings.Repeat("b", 64),
		},
		ConversationID:   convoID,
		SenderAgentID:    senderID,
		SenderEndpointID: senderMEP,
		SenderDeviceID:   senderDev,
		CreatedAtUnix:    baseUnix + 1,
		Kind:             "text",
		Content:          textBody(t, body),
	})
	if err != nil {
		t.Fatalf("event: %v", err)
	}
	return event
}

func (h *harness) sessionCounter(t *testing.T) uint64 {
	t.Helper()
	record, found, err := h.journal.SessionState(sessionID)
	if err != nil || !found {
		t.Fatalf("session state: found=%v err=%v", found, err)
	}
	state, err := record.State()
	if err != nil {
		t.Fatalf("state: %v", err)
	}
	return binary.BigEndian.Uint64(state)
}

func TestQueuedEventIsSealedOnceAndSent(t *testing.T) {
	h := newHarness(t)
	event := h.event(t, "hello")
	if _, _, err := h.dispatcher.Queue(event, sessionID, peerMEP, baseUnix+3600); err != nil {
		t.Fatalf("queue: %v", err)
	}
	summary, err := h.dispatcher.Sweep(context.Background(), 0)
	if err != nil {
		t.Fatalf("sweep: %v", err)
	}
	if summary.Sent != 1 || summary.Sealed != 1 {
		t.Fatalf("unexpected summary: %+v", summary)
	}
	if len(h.sender.sent) != 1 || h.sender.sent[0].EventID != event.EventID {
		t.Fatalf("unexpected send: %+v", h.sender.sent)
	}
	if h.sessionCounter(t) != 1 {
		t.Fatalf("the session did not advance exactly once: %d", h.sessionCounter(t))
	}
	// A settled delivery is not swept again.
	summary, err = h.dispatcher.Sweep(context.Background(), 0)
	if err != nil {
		t.Fatalf("sweep: %v", err)
	}
	if summary.Sent != 0 || summary.Sealed != 0 {
		t.Fatalf("a delivered message was attempted again: %+v", summary)
	}
}

// The rule this package exists for: a retry sends the message that was already
// sealed. Sealing again per attempt would consume a message key per lost
// packet.
func TestRetryReusesTheSealedMessage(t *testing.T) {
	h := newHarness(t)
	event := h.event(t, "hello")
	if _, _, err := h.dispatcher.Queue(event, sessionID, peerMEP, baseUnix+86_400); err != nil {
		t.Fatalf("queue: %v", err)
	}

	h.sender.fail = fault.New(fault.CodeUnreachable, "peer is down")
	summary, err := h.dispatcher.Sweep(context.Background(), 0)
	if err != nil {
		t.Fatalf("sweep: %v", err)
	}
	if summary.Retried != 1 || summary.Sealed != 1 || summary.Sent != 0 {
		t.Fatalf("unexpected first attempt: %+v", summary)
	}
	if h.sessionCounter(t) != 1 {
		t.Fatalf("the session advanced %d times on one seal", h.sessionCounter(t))
	}

	// Before the backoff elapses nothing is due.
	summary, err = h.dispatcher.Sweep(context.Background(), 0)
	if err != nil {
		t.Fatalf("sweep: %v", err)
	}
	if summary.Retried != 0 || summary.Sealed != 0 {
		t.Fatalf("a backed-off delivery was attempted early: %+v", summary)
	}

	h.clock = h.clock.Add(time.Hour)
	h.sender.fail = nil
	summary, err = h.dispatcher.Sweep(context.Background(), 0)
	if err != nil {
		t.Fatalf("sweep: %v", err)
	}
	if summary.Sent != 1 {
		t.Fatalf("the retry did not deliver: %+v", summary)
	}
	if summary.Sealed != 0 {
		t.Fatal("the retry sealed a second message")
	}
	if h.sessionCounter(t) != 1 {
		t.Fatalf("the session advanced on a retry: %d", h.sessionCounter(t))
	}
	// The sealed bytes are the ones that were committed, carrying the queued
	// event rather than a freshly encoded one.
	if !strings.Contains(string(h.sender.sent[0].Ciphertext), event.EventID) {
		t.Fatal("the retry sent something other than the committed message")
	}
}

func TestPermanentFailureAbandonsTheDelivery(t *testing.T) {
	h := newHarness(t)
	event := h.event(t, "hello")
	if _, _, err := h.dispatcher.Queue(event, sessionID, peerMEP, baseUnix+3600); err != nil {
		t.Fatalf("queue: %v", err)
	}
	h.sender.fail = fault.New(fault.CodeOversized, "too large for the peer")
	summary, err := h.dispatcher.Sweep(context.Background(), 0)
	if err != nil {
		t.Fatalf("sweep: %v", err)
	}
	if summary.Abandoned != 1 || summary.Retried != 0 {
		t.Fatalf("a permanent failure was retried: %+v", summary)
	}
	delivery, found, err := h.journal.LookupDelivery(event.EventID)
	if err != nil || !found {
		t.Fatalf("lookup: found=%v err=%v", found, err)
	}
	if delivery.State != eventlog.StateAbandoned {
		t.Fatalf("unexpected state: %+v", delivery)
	}
}

// An approval hold leaves the timer. Sweeping it again would ask the same
// person the same question on every pass.
func TestApprovalHoldLeavesTheSweep(t *testing.T) {
	h := newHarness(t)
	event := h.event(t, "hello")
	if _, _, err := h.dispatcher.Queue(event, sessionID, peerMEP, baseUnix+86_400); err != nil {
		t.Fatalf("queue: %v", err)
	}
	h.sender.fail = fault.New(fault.CodeApprovalRequired, "waiting on the owner")
	summary, err := h.dispatcher.Sweep(context.Background(), 0)
	if err != nil {
		t.Fatalf("sweep: %v", err)
	}
	if summary.Held != 1 {
		t.Fatalf("unexpected summary: %+v", summary)
	}
	h.clock = h.clock.Add(6 * time.Hour)
	h.sender.fail = nil
	summary, err = h.dispatcher.Sweep(context.Background(), 0)
	if err != nil {
		t.Fatalf("sweep: %v", err)
	}
	if summary.Sent != 0 {
		t.Fatal("a held delivery was swept by a timer")
	}
	if _, err := h.journal.Resume(event.EventID, h.clock); err != nil {
		t.Fatalf("resume: %v", err)
	}
	summary, err = h.dispatcher.Sweep(context.Background(), 0)
	if err != nil {
		t.Fatalf("sweep: %v", err)
	}
	if summary.Sent != 1 {
		t.Fatalf("a resumed delivery was not sent: %+v", summary)
	}
}

// An unreachable peer must not block every message to everyone else.
func TestOneFailureDoesNotBlockTheRest(t *testing.T) {
	h := newHarness(t)
	first := h.event(t, "first")
	second := h.event(t, "second")
	for _, event := range []envelope.Event{first, second} {
		if _, _, err := h.dispatcher.Queue(event, sessionID, peerMEP, baseUnix+86_400); err != nil {
			t.Fatalf("queue: %v", err)
		}
	}
	h.sender.fail = fault.New(fault.CodeUnreachable, "down")
	summary, err := h.dispatcher.Sweep(context.Background(), 0)
	if err != nil {
		t.Fatalf("sweep: %v", err)
	}
	if summary.Retried != 2 {
		t.Fatalf("expected both to be retried, got %+v", summary)
	}
	if summary.Sealed != 2 {
		t.Fatalf("expected both to be sealed once, got %+v", summary)
	}
	if h.sessionCounter(t) != 2 {
		t.Fatalf("unexpected session advance: %d", h.sessionCounter(t))
	}
}

// A session established under another suite cannot be continued by this one,
// and guessing would produce ciphertext nobody can open.
func TestSuiteMismatchIsRefused(t *testing.T) {
	h := newHarness(t)
	if err := h.journal.PutSessionState(sessionID, otherSuite, e2ee.State(make([]byte, 8)), h.clock); err != nil {
		t.Fatalf("session: %v", err)
	}
	event := h.event(t, "hello")
	if _, _, err := h.dispatcher.Queue(event, sessionID, peerMEP, baseUnix+3600); err != nil {
		t.Fatalf("queue: %v", err)
	}
	summary, err := h.dispatcher.Sweep(context.Background(), 0)
	if err != nil {
		t.Fatalf("sweep: %v", err)
	}
	if summary.Sent != 0 || summary.Abandoned != 1 {
		t.Fatalf("a mismatched suite was used: %+v", summary)
	}
	if len(h.sender.sent) != 0 {
		t.Fatal("a message was sent under the wrong suite")
	}
}

func TestMissingSessionIsRetriedNotSent(t *testing.T) {
	h := newHarness(t)
	event := h.event(t, "hello")
	if _, _, err := h.dispatcher.Queue(event, "ses_"+strings.Repeat("9", 64), peerMEP, baseUnix+86_400); err != nil {
		t.Fatalf("queue: %v", err)
	}
	summary, err := h.dispatcher.Sweep(context.Background(), 0)
	if err != nil {
		t.Fatalf("sweep: %v", err)
	}
	if summary.Sent != 0 || summary.Retried != 1 {
		t.Fatalf("unexpected summary: %+v", summary)
	}
	if len(h.sender.sent) != 0 {
		t.Fatal("a message was sent without a session")
	}
}

func TestQueueRefusesUnusableInput(t *testing.T) {
	h := newHarness(t)
	event := h.event(t, "hello")

	forged := event
	forged.Content = []byte("substituted after the identifier was derived")
	if _, _, err := h.dispatcher.Queue(forged, sessionID, peerMEP, baseUnix+3600); err == nil {
		t.Fatal("an event whose identifier no longer matches its content was queued")
	}
	if _, _, err := h.dispatcher.Queue(event, "ses_bad", peerMEP, baseUnix+3600); err == nil {
		t.Fatal("an invalid session identifier was accepted")
	}
	if _, _, err := h.dispatcher.Queue(event, sessionID, "mep_bad", baseUnix+3600); err == nil {
		t.Fatal("an invalid recipient was accepted")
	}
	if _, _, err := h.dispatcher.Queue(event, sessionID, peerMEP, baseUnix-1); err == nil {
		t.Fatal("an expiry in the past was accepted")
	}
}

func TestDispatcherRequiresEveryDependency(t *testing.T) {
	journal, err := eventlog.Open(filepath.Join(t.TempDir(), "state"))
	if err != nil {
		t.Fatalf("journal: %v", err)
	}
	defer journal.Close()
	seals := 0
	complete := Config{Journal: journal, Suite: countingSuite{seals: &seals},
		Sender: &fakeSender{}, Bindings: bindings{}, Identity: testIdentity()}
	for name, mutate := range map[string]func(*Config){
		"no journal":           func(c *Config) { c.Journal = nil },
		"suite without sender": func(c *Config) { c.Sender = nil },
		"sender without suite": func(c *Config) { c.Suite = nil },
		"no bindings":          func(c *Config) { c.Bindings = nil },
	} {
		t.Run(name, func(t *testing.T) {
			config := complete
			mutate(&config)
			if _, err := New(config); err == nil {
				t.Fatalf("expected %q to be refused", name)
			}
		})
	}
	if _, err := New(complete); err != nil {
		t.Fatalf("a complete configuration was refused: %v", err)
	}
	var absent *Dispatcher
	if _, err := absent.Sweep(context.Background(), 0); err == nil {
		t.Fatal("a nil dispatcher swept")
	}
}

func TestSweepStopsOnACancelledContext(t *testing.T) {
	h := newHarness(t)
	if _, _, err := h.dispatcher.Queue(h.event(t, "hello"), sessionID, peerMEP, baseUnix+3600); err != nil {
		t.Fatalf("queue: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := h.dispatcher.Sweep(ctx, 0); !errors.Is(err, context.Canceled) {
		t.Fatalf("expected cancellation to stop the sweep, got %v", err)
	}
	if len(h.sender.sent) != 0 {
		t.Fatal("a cancelled sweep still sent")
	}
}

// An installation with no transport can queue safely and must not read as one
// that is delivering.
func TestQueueWithoutATransport(t *testing.T) {
	journal, err := eventlog.Open(filepath.Join(t.TempDir(), "state"))
	if err != nil {
		t.Fatalf("journal: %v", err)
	}
	defer journal.Close()
	clock := time.Unix(int64(baseUnix), 0)
	dispatcher, err := New(Config{Journal: journal, Identity: testIdentity(),
		Now: func() time.Time { return clock }})
	if err != nil {
		t.Fatalf("dispatcher: %v", err)
	}
	if dispatcher.CanSend() {
		t.Fatal("a dispatcher with no transport claims it can send")
	}

	event, err := envelope.NewEvent(envelope.Event{
		Network: &nativev1.NetworkDomain{NetworkId: "tos-local",
			GenesisRootHash: strings.Repeat("a", 64), GenesisFileHash: strings.Repeat("b", 64)},
		ConversationID: convoID, SenderAgentID: senderID, SenderEndpointID: senderMEP,
		SenderDeviceID: senderDev, CreatedAtUnix: baseUnix + 1, Kind: "text",
		Content: textBody(t, "queued"),
	})
	if err != nil {
		t.Fatalf("event: %v", err)
	}
	fresh, _, err := dispatcher.Queue(event, sessionID, peerMEP, baseUnix+3600)
	if err != nil || !fresh {
		t.Fatalf("queue: fresh=%v err=%v", fresh, err)
	}
	if _, err := dispatcher.Sweep(context.Background(), 0); !errors.Is(err, ErrNoTransport) {
		t.Fatalf("expected a sweep without a transport to say so, got %v", err)
	}
	// The event is still there, unsealed, waiting for a transport to exist.
	delivery, found, err := journal.LookupDelivery(event.EventID)
	if err != nil || !found {
		t.Fatalf("lookup: found=%v err=%v", found, err)
	}
	if delivery.State != eventlog.StatePending {
		t.Fatalf("a queued event was settled without a transport: %+v", delivery)
	}
	if ciphertext, err := delivery.Ciphertext(); err != nil || ciphertext != nil {
		t.Fatalf("an event was sealed with nothing to carry it: %v", err)
	}
}

func testIdentity() Identity {
	return Identity{AgentID: senderID, EndpointID: senderMEP, DeviceID: senderDev}
}

// A local-only kind carries authority granted here. Refusing to send it is
// what makes the invariant hold at both ends rather than only at the far one.
func TestLocalOnlyKindsCannotBeQueued(t *testing.T) {
	h := newHarness(t)
	for _, kind := range []string{"owner.approval.grant", "owner.approval.deny"} {
		t.Run(kind, func(t *testing.T) {
			event := h.event(t, "approved")
			event.Kind = kind
			event.PayloadSchema = ""
			completed, err := envelope.NewEvent(event)
			if err != nil {
				t.Fatalf("new event: %v", err)
			}
			if _, _, err := h.dispatcher.Queue(completed, sessionID, peerMEP, baseUnix+3600); err == nil {
				t.Fatalf("%q was queued for the network", kind)
			}
		})
	}
}

// A runtime does not get to choose who a message came from: the session it
// would be sealed under belongs to this installation.
func TestOutboundSenderMustBeThisInstallation(t *testing.T) {
	h := newHarness(t)
	for name, mutate := range map[string]func(*envelope.Event){
		"another Agent":    func(e *envelope.Event) { e.SenderAgentID = "agent_" + strings.Repeat("9", 64) },
		"another endpoint": func(e *envelope.Event) { e.SenderEndpointID = "mep_" + strings.Repeat("9", 64) },
		"another device":   func(e *envelope.Event) { e.SenderDeviceID = "dev_" + strings.Repeat("9", 64) },
	} {
		t.Run(name, func(t *testing.T) {
			event := h.event(t, "impersonation")
			mutate(&event)
			completed, err := envelope.NewEvent(event)
			if err != nil {
				t.Fatalf("new event: %v", err)
			}
			if _, _, err := h.dispatcher.Queue(completed, sessionID, peerMEP, baseUnix+3600); err == nil {
				t.Fatalf("an event from %q was queued", name)
			}
		})
	}
}
