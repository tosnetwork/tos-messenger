package localapi

import (
	"bufio"
	"context"
	"encoding/binary"
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/tosnetwork/tos-messenger/pkg/dispatch"
	"github.com/tosnetwork/tos-messenger/pkg/e2ee"
	"github.com/tosnetwork/tos-messenger/pkg/envelope"
	"github.com/tosnetwork/tos-messenger/pkg/eventlog"
	"github.com/tosnetwork/tos-messenger/pkg/fault"
	nativev1 "github.com/tosnetwork/tos-service-protocol/gen/tos/service/v1"
)

const (
	baseUnix  = uint64(1_800_000_000)
	algorithm = "tos.messaging.e2ee.test-double.v1"
	senderID  = "agent_" + "2222222222222222222222222222222222222222222222222222222222222222"
	senderMEP = "mep_" + "3333333333333333333333333333333333333333333333333333333333333333"
	peerMEP   = "mep_" + "6666666666666666666666666666666666666666666666666666666666666666"
	senderDev = "dev_" + "4444444444444444444444444444444444444444444444444444444444444444"
	convoID   = "conv_" + "1111111111111111111111111111111111111111111111111111111111111111"
	sessionID = "ses_" + "8888888888888888888888888888888888888888888888888888888888888888"
	leaseID   = "lease_" + "9999999999999999999999999999999999999999999999999999999999999999"
)

type stubSuite struct{}

func (stubSuite) AlgorithmID() string { return algorithm }
func (stubSuite) NewPrekeyMaterial() ([]byte, []byte, error) {
	return []byte("public"), []byte("private"), nil
}
func (stubSuite) Initiate([]byte, []byte) (e2ee.State, []byte, error) {
	return e2ee.State(make([]byte, 8)), []byte("initial"), nil
}
func (stubSuite) Accept([]byte, []byte, []byte) (e2ee.State, error) {
	return e2ee.State(make([]byte, 8)), nil
}
func (stubSuite) KeyMaterial(state e2ee.State) (e2ee.State, error) { return state, nil }
func (stubSuite) Seal(state e2ee.State, plaintext, _ []byte) ([]byte, e2ee.State, error) {
	next := make([]byte, 8)
	binary.BigEndian.PutUint64(next, binary.BigEndian.Uint64(state)+1)
	return append([]byte("sealed:"), plaintext...), next, nil
}
func (stubSuite) Open(e2ee.State, []byte, []byte) ([]byte, e2ee.State, error) {
	return nil, nil, e2ee.ErrNotAuthentic
}

type stubSender struct{ sent int }

func (s *stubSender) Send(context.Context, dispatch.Message) error { s.sent++; return nil }

type stubBindings struct{}

func (stubBindings) BindingFor(delivery eventlog.Delivery) (e2ee.Binding, error) {
	return e2ee.Binding{
		Network:             testNetwork(),
		AlgorithmID:         algorithm,
		ConversationID:      delivery.ConversationID,
		SenderAgentID:       senderID,
		SenderEndpointID:    senderMEP,
		SenderDeviceID:      senderDev,
		RecipientAgentID:    "agent_" + strings.Repeat("5", 64),
		RecipientEndpointID: delivery.RecipientEndpointID,
		RecipientDeviceID:   "dev_" + strings.Repeat("7", 64),
	}, nil
}

func testNetwork() *nativev1.NetworkDomain {
	return &nativev1.NetworkDomain{
		NetworkId:       "tos-local",
		GenesisRootHash: strings.Repeat("a", 64),
		GenesisFileHash: strings.Repeat("b", 64),
	}
}

type harness struct {
	server  *Server
	journal *eventlog.Journal
	sender  *stubSender
	clock   time.Time
}

func newHarness(t *testing.T) *harness {
	t.Helper()
	journal, err := eventlog.Open(filepath.Join(t.TempDir(), "state"))
	if err != nil {
		t.Fatalf("journal: %v", err)
	}
	t.Cleanup(func() { _ = journal.Close() })

	instance := &harness{journal: journal, sender: &stubSender{}, clock: time.Unix(int64(baseUnix), 0)}
	dispatcher, err := dispatch.New(dispatch.Config{
		Journal: journal, Suite: stubSuite{}, Sender: instance.sender,
		Bindings: stubBindings{}, Now: func() time.Time { return instance.clock },
	})
	if err != nil {
		t.Fatalf("dispatcher: %v", err)
	}
	server, err := NewServer(Config{
		Journal: journal, Dispatcher: dispatcher,
		Now: func() time.Time { return instance.clock },
	})
	if err != nil {
		t.Fatalf("server: %v", err)
	}
	instance.server = server
	if err := journal.PutSessionState(sessionID, algorithm, e2ee.State(make([]byte, 8)), instance.clock); err != nil {
		t.Fatalf("session: %v", err)
	}
	return instance
}

func (h *harness) event(t *testing.T, body string) envelope.Event {
	t.Helper()
	event, err := envelope.NewEvent(envelope.Event{
		Network: testNetwork(), ConversationID: convoID,
		SenderAgentID: senderID, SenderEndpointID: senderMEP, SenderDeviceID: senderDev,
		CreatedAtUnix: baseUnix + 1, Kind: "text", Content: []byte(body),
	})
	if err != nil {
		t.Fatalf("event: %v", err)
	}
	return event
}

func (h *harness) call(t *testing.T, request Request) Response {
	t.Helper()
	raw, err := EncodeRequest(request)
	if err != nil {
		t.Fatalf("encode request: %v", err)
	}
	response := h.server.Handle(context.Background(), raw)
	encoded, err := EncodeResponse(response)
	if err != nil {
		t.Fatalf("encode response: %v", err)
	}
	decoded, err := DecodeResponse(encoded)
	if err != nil {
		t.Fatalf("decode response: %v", err)
	}
	return decoded
}

func (h *harness) receive(t *testing.T, event envelope.Event) {
	t.Helper()
	payload, err := envelope.EncodeEventJSON(event)
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	if _, _, err := h.journal.Accept(eventlog.Entry{
		EventID: event.EventID, SenderEndpointID: event.SenderEndpointID,
		ConversationID: event.ConversationID, Payload: payload,
		ReceivedAtUnix: uint64(h.clock.Unix()),
	}); err != nil {
		t.Fatalf("accept: %v", err)
	}
}

// The runtime's half of the loop: see what is waiting, take one, finish it.
func TestRuntimeDrainsTheInbox(t *testing.T) {
	h := newHarness(t)
	event := h.event(t, "hello")
	h.receive(t, event)

	listing := h.call(t, Request{Op: OpPending})
	if !listing.OK || len(listing.Events) != 1 {
		t.Fatalf("unexpected listing: %+v", listing)
	}
	if listing.Events[0].EventID != event.EventID {
		t.Fatalf("unexpected event: %+v", listing.Events[0])
	}
	// The runtime receives the event itself, not a reference it has to resolve.
	decoded, err := envelope.DecodeEventJSON(listing.Events[0].Event)
	if err != nil {
		t.Fatalf("decode delivered event: %v", err)
	}
	if string(decoded.Content) != "hello" {
		t.Fatalf("unexpected content: %q", decoded.Content)
	}

	claimed := h.call(t, Request{Op: OpClaim, EventID: event.EventID, LeaseID: leaseID, LeaseSeconds: 60})
	if !claimed.OK || claimed.Event == nil {
		t.Fatalf("unexpected claim: %+v", claimed)
	}
	// While the lease is live the event is not offered again.
	if listing := h.call(t, Request{Op: OpPending}); len(listing.Events) != 0 {
		t.Fatalf("a leased event was offered again: %+v", listing)
	}
	if done := h.call(t, Request{Op: OpComplete, EventID: event.EventID, LeaseID: leaseID}); !done.OK {
		t.Fatalf("complete: %+v", done)
	}
	if listing := h.call(t, Request{Op: OpPending}); len(listing.Events) != 0 {
		t.Fatalf("an applied event was offered again: %+v", listing)
	}
}

func TestRejectedEventIsNotOfferedAgain(t *testing.T) {
	h := newHarness(t)
	event := h.event(t, "hello")
	h.receive(t, event)
	if claimed := h.call(t, Request{Op: OpClaim, EventID: event.EventID, LeaseID: leaseID, LeaseSeconds: 60}); !claimed.OK {
		t.Fatalf("claim: %+v", claimed)
	}
	refused := h.call(t, Request{Op: OpReject, EventID: event.EventID, LeaseID: leaseID,
		Code: fault.CodeContentTooLarge})
	if !refused.OK {
		t.Fatalf("reject: %+v", refused)
	}
	if listing := h.call(t, Request{Op: OpPending}); len(listing.Events) != 0 {
		t.Fatalf("a rejected event was offered again: %+v", listing)
	}
}

// A runtime holding no lease cannot finish somebody else's work.
func TestApplicationOutcomesNeedTheLease(t *testing.T) {
	h := newHarness(t)
	event := h.event(t, "hello")
	h.receive(t, event)
	if claimed := h.call(t, Request{Op: OpClaim, EventID: event.EventID, LeaseID: leaseID, LeaseSeconds: 60}); !claimed.OK {
		t.Fatalf("claim: %+v", claimed)
	}
	other := "lease_" + strings.Repeat("1", 64)
	if done := h.call(t, Request{Op: OpComplete, EventID: event.EventID, LeaseID: other}); done.OK {
		t.Fatal("a foreign lease completed the work")
	}
	unknown := h.call(t, Request{Op: OpComplete,
		EventID: "evt_" + strings.Repeat("0", 64), LeaseID: leaseID})
	if unknown.OK || unknown.Code != fault.CodeUnknownEventKind {
		t.Fatalf("unexpected outcome for an unknown event: %+v", unknown)
	}
}

func TestRuntimeSubmitsAnEvent(t *testing.T) {
	h := newHarness(t)
	event := h.event(t, "outbound")
	encoded, err := envelope.EncodeEventJSON(event)
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	response := h.call(t, Request{
		Op: OpQueue, Event: json.RawMessage(encoded), SessionID: sessionID,
		RecipientEndpointID: peerMEP, ExpiresAtUnix: baseUnix + 3600,
	})
	if !response.OK || !response.Fresh {
		t.Fatalf("unexpected submission: %+v", response)
	}
	delivery, found, err := h.journal.LookupDelivery(event.EventID)
	if err != nil || !found {
		t.Fatalf("lookup: found=%v err=%v", found, err)
	}
	if delivery.SessionID != sessionID {
		t.Fatalf("the submission lost its session: %+v", delivery)
	}

	// The daemon owns what goes on the wire, so a malformed submission is
	// refused here rather than sealed and sent.
	bad := h.call(t, Request{
		Op: OpQueue, Event: json.RawMessage(`{"schema":"tos.messaging.event.v1"}`),
		SessionID: sessionID, RecipientEndpointID: peerMEP, ExpiresAtUnix: baseUnix + 3600,
	})
	if bad.OK {
		t.Fatal("a malformed event was queued")
	}
}

// The owner decision exists on this socket and nowhere else.
func TestOwnerDecisionResumesAHeldDelivery(t *testing.T) {
	h := newHarness(t)
	event := h.event(t, "outbound")
	encoded, err := envelope.EncodeEventJSON(event)
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	if response := h.call(t, Request{Op: OpQueue, Event: json.RawMessage(encoded),
		SessionID: sessionID, RecipientEndpointID: peerMEP, ExpiresAtUnix: baseUnix + 86_400}); !response.OK {
		t.Fatalf("queue: %+v", response)
	}
	if _, err := h.journal.Failed(event.EventID, fault.CodeApprovalRequired, h.clock); err != nil {
		t.Fatalf("hold: %v", err)
	}

	approved := h.call(t, Request{Op: OpApprove, EventID: event.EventID})
	if !approved.OK {
		t.Fatalf("approve: %+v", approved)
	}
	delivery, _, err := h.journal.LookupDelivery(event.EventID)
	if err != nil {
		t.Fatalf("lookup: %v", err)
	}
	if delivery.State != eventlog.StatePending {
		t.Fatalf("an approved delivery did not return to the queue: %+v", delivery)
	}

	// And the owner can refuse instead.
	second := h.event(t, "second")
	secondEncoded, err := envelope.EncodeEventJSON(second)
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	if response := h.call(t, Request{Op: OpQueue, Event: json.RawMessage(secondEncoded),
		SessionID: sessionID, RecipientEndpointID: peerMEP, ExpiresAtUnix: baseUnix + 86_400}); !response.OK {
		t.Fatalf("queue: %+v", response)
	}
	if _, err := h.journal.Failed(second.EventID, fault.CodeApprovalRequired, h.clock); err != nil {
		t.Fatalf("hold: %v", err)
	}
	if denied := h.call(t, Request{Op: OpDeny, EventID: second.EventID}); !denied.OK {
		t.Fatalf("deny: %+v", denied)
	}
	delivery, _, err = h.journal.LookupDelivery(second.EventID)
	if err != nil {
		t.Fatalf("lookup: %v", err)
	}
	if delivery.State != eventlog.StateAbandoned {
		t.Fatalf("a denied delivery was not abandoned: %+v", delivery)
	}
}

// Every operation names exactly the fields it uses.
func TestRequestsCarryOnlyWhatTheyUse(t *testing.T) {
	cases := map[string]Request{
		"unknown op":          {Op: "inbox.everything"},
		"pending with lease":  {Op: OpPending, LeaseID: leaseID},
		"pending with event":  {Op: OpPending, EventID: "evt_" + strings.Repeat("0", 64)},
		"claim without lease": {Op: OpClaim, EventID: "evt_" + strings.Repeat("0", 64)},
		"claim without time": {Op: OpClaim, EventID: "evt_" + strings.Repeat("0", 64),
			LeaseID: leaseID},
		"reject with unknown code": {Op: OpReject, EventID: "evt_" + strings.Repeat("0", 64),
			LeaseID: leaseID, Code: "invented"},
		"queue without session": {Op: OpQueue, Event: json.RawMessage(`{}`),
			RecipientEndpointID: peerMEP, ExpiresAtUnix: baseUnix},
		"queue without recipient": {Op: OpQueue, Event: json.RawMessage(`{}`),
			SessionID: sessionID, ExpiresAtUnix: baseUnix},
		"approve with lease": {Op: OpApprove, EventID: "evt_" + strings.Repeat("0", 64),
			LeaseID: leaseID},
		"approve without event": {Op: OpApprove},
	}
	for name, request := range cases {
		t.Run(name, func(t *testing.T) {
			if err := ValidateRequest(request); err == nil {
				t.Fatalf("expected %q to be refused", name)
			}
			if _, err := EncodeRequest(request); err == nil {
				t.Fatalf("expected %q to be unencodable", name)
			}
		})
	}
}

func TestDecodeRejectsMalformedFrames(t *testing.T) {
	valid, err := EncodeRequest(Request{Op: OpPending})
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	line := strings.TrimSuffix(string(valid), "\n")
	for name, raw := range map[string][]byte{
		"unknown field": []byte(line[:len(line)-1] + `,"extra":1}`),
		"trailing json": []byte(line + "{}"),
		"wrong schema":  []byte(strings.Replace(line, RequestSchema, "other", 1)),
		"empty":         []byte(""),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := DecodeRequest(raw); err == nil {
				t.Fatalf("expected %q to be refused", name)
			}
		})
	}
}

// The socket is owner-private: a private directory, a narrowed socket file,
// and on Linux a check of who is calling.
func TestSocketIsOwnerPrivate(t *testing.T) {
	root := filepath.Join(t.TempDir(), "run")
	path := filepath.Join(root, "messenger.sock")
	listener, err := Listen(path)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer listener.Close()

	directory, err := os.Lstat(root)
	if err != nil {
		t.Fatalf("stat directory: %v", err)
	}
	if directory.Mode().Perm() != 0o700 {
		t.Fatalf("the socket directory is not private: %v", directory.Mode().Perm())
	}
	socket, err := os.Lstat(path)
	if err != nil {
		t.Fatalf("stat socket: %v", err)
	}
	if socket.Mode().Perm() != 0o600 {
		t.Fatalf("the socket is not private: %v", socket.Mode().Perm())
	}

	// A second daemon must not take the socket away from a live one.
	if _, err := Listen(path); err == nil {
		t.Fatal("a second listener took over a live socket")
	}

	for name, candidate := range map[string]string{
		"relative":  "run/messenger.sock",
		"empty":     "",
		"uncleaned": "/tmp/../tmp/messenger.sock",
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := Listen(candidate); err == nil {
				t.Fatalf("expected %q to be refused", name)
			}
		})
	}
}

// A widened directory is refused rather than served.
func TestSharedDirectoryIsRefused(t *testing.T) {
	root := filepath.Join(t.TempDir(), "shared")
	if err := os.MkdirAll(root, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if _, err := Listen(filepath.Join(root, "messenger.sock")); err == nil {
		t.Fatal("a world-readable socket directory was accepted")
	}
}

func TestServeOverTheSocket(t *testing.T) {
	h := newHarness(t)
	event := h.event(t, "hello")
	h.receive(t, event)

	path := filepath.Join(t.TempDir(), "run", "messenger.sock")
	listener, err := Listen(path)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer listener.Close()
	go func() { _ = h.server.Serve(context.Background(), listener) }()

	connection, err := net.Dial("unix", path)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer connection.Close()

	request, err := EncodeRequest(Request{Op: OpPending})
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	if _, err := connection.Write(request); err != nil {
		t.Fatalf("write: %v", err)
	}
	line, err := bufio.NewReader(connection).ReadBytes('\n')
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	response, err := DecodeResponse(line)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if !response.OK || len(response.Events) != 1 {
		t.Fatalf("unexpected response: %+v", response)
	}
}

func TestServerRequiresEveryDependency(t *testing.T) {
	h := newHarness(t)
	dispatcher, err := dispatch.New(dispatch.Config{
		Journal: h.journal, Suite: stubSuite{}, Sender: h.sender, Bindings: stubBindings{},
	})
	if err != nil {
		t.Fatalf("dispatcher: %v", err)
	}
	if _, err := NewServer(Config{Dispatcher: dispatcher}); err == nil {
		t.Fatal("a server without a journal was accepted")
	}
	if _, err := NewServer(Config{Journal: h.journal}); err == nil {
		t.Fatal("a server without a dispatcher was accepted")
	}
	if _, err := NewServer(Config{Journal: h.journal, Dispatcher: dispatcher, Timeout: -1}); err == nil {
		t.Fatal("a negative timeout was accepted")
	}
}
