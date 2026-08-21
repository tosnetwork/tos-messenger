package localapi

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/binary"
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/tosnetwork/tos-messenger/pkg/dispatch"
	"github.com/tosnetwork/tos-messenger/pkg/e2ee"
	"github.com/tosnetwork/tos-messenger/pkg/envelope"
	"github.com/tosnetwork/tos-messenger/pkg/eventlog"
	"github.com/tosnetwork/tos-messenger/pkg/fault"
	"github.com/tosnetwork/tos-messenger/pkg/firewall"
	"github.com/tosnetwork/tos-messenger/pkg/negotiation"
	"github.com/tosnetwork/tos-messenger/pkg/payload"
	nativev1 "github.com/tosnetwork/tos-service-protocol/gen/tos/service/v1"
	"google.golang.org/protobuf/proto"
)

const (
	baseUnix  = uint64(1_800_000_000)
	algorithm = "tos.messaging.e2ee.test-double.v1"
	senderID  = "agent_" + "2222222222222222222222222222222222222222222222222222222222222222"
	senderMEP = "mep_" + "3333333333333333333333333333333333333333333333333333333333333333"
	peerMEP   = "mep_" + "6666666666666666666666666666666666666666666666666666666666666666"
	senderDev = "dev_" + "4444444444444444444444444444444444444444444444444444444444444444"
	targetDev = "dev_" + "7777777777777777777777777777777777777777777777777777777777777777"
	convoID   = "conv_" + "1111111111111111111111111111111111111111111111111111111111111111"
	sessionID = "ses_" + "8888888888888888888888888888888888888888888888888888888888888888"
	leaseID   = "lease_" + "9999999999999999999999999999999999999999999999999999999999999999"
)

type stubSuite struct{}

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

func (stubSuite) AlgorithmID() string { return algorithm }
func (stubSuite) NewPrekeyMaterial() ([]byte, []byte, error) {
	return []byte("public"), []byte("private"), nil
}
func (stubSuite) Initiate([]byte, []byte, []byte) (e2ee.State, []byte, error) {
	return e2ee.State(make([]byte, 8)), []byte("initial"), nil
}
func (stubSuite) Accept([]byte, []byte, []byte, []byte) (e2ee.State, error) {
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

type fixedQuoteResolver struct {
	quote negotiation.VerifiedAcceptedQuote
	found bool
	err   error
}

func (r fixedQuoteResolver) ResolveAcceptedQuote(string) (negotiation.VerifiedAcceptedQuote, bool, error) {
	return r.quote, r.found, r.err
}

func (r fixedQuoteResolver) ResolveAcceptedQuoteAt(
	context.Context,
	string,
	string,
	string,
) (negotiation.VerifiedAcceptedQuote, bool, error) {
	return r.quote, r.found, r.err
}

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
	server     *Server
	journal    *eventlog.Journal
	sender     *stubSender
	dispatcher *dispatch.Dispatcher
	clock      time.Time
}

func newHarness(t *testing.T) *harness { return newHarnessWithPolicy(t, firewall.Default()) }

func newHarnessWithPolicy(t *testing.T, policy firewall.Policy) *harness {
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
		Identity: dispatch.Identity{AgentID: senderID, EndpointID: senderMEP, DeviceID: senderDev},
		Network:  testNetwork(),
	})
	if err != nil {
		t.Fatalf("dispatcher: %v", err)
	}
	server, err := NewServer(Config{
		Journal: journal, Dispatcher: dispatcher, Policy: policy,
		OwnerKey: testOwnerPublic(), LocalEndpointID: peerMEP,
		Now: func() time.Time { return instance.clock }, DeviceIDs: []string{senderDev, targetDev},
	})
	if err != nil {
		t.Fatalf("server: %v", err)
	}
	instance.server = server
	instance.dispatcher = dispatcher
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
		CreatedAtUnix: baseUnix + 1, Kind: "text", Content: textBody(t, body),
	})
	if err != nil {
		t.Fatalf("event: %v", err)
	}
	return event
}

func TestOwnerCreatesScopedOneTimeAdmissionInvite(t *testing.T) {
	h := newHarness(t)
	expires := baseUnix + 600
	created := h.owner(t, Request{
		Op: OpCreateAdmissionInvite, InvitedAgentID: senderID, InviteExpiresAtUnix: expires,
	})
	if !created.OK || created.AdmissionToken == "" {
		t.Fatalf("create invite: %+v", created)
	}
	eventID := "evt_" + strings.Repeat("a", 64)
	if fresh, err := h.journal.ClaimAdmissionInvite(
		created.AdmissionToken, peerMEP, senderID, eventID, h.clock.Add(time.Minute),
	); err != nil || !fresh {
		t.Fatalf("claim invite: fresh=%v err=%v", fresh, err)
	}
	if _, err := h.journal.ClaimAdmissionInvite(
		created.AdmissionToken, peerMEP, senderID, "evt_"+strings.Repeat("b", 64), h.clock.Add(2*time.Minute),
	); err == nil {
		t.Fatal("owner-created invite authorized two events")
	}
}

func (h *harness) call(t *testing.T, request Request) Response {
	t.Helper()
	return h.callAs(t, PrincipalRuntime, request)
}

// owner signs every decision, because the daemon no longer takes the socket's
// word for who is calling.
func (h *harness) owner(t *testing.T, request Request) Response {
	t.Helper()
	if !Deciding(request.Op) {
		return h.callAs(t, PrincipalOwner, request)
	}
	issued := h.callAs(t, PrincipalOwner, Request{Op: OpChallenge})
	if !issued.OK || issued.Challenge == "" {
		t.Fatalf("challenge: %+v", issued)
	}
	signature, err := SignDecision(request, issued.Challenge, testOwnerKey())
	if err != nil {
		t.Fatalf("sign decision: %v", err)
	}
	request.Challenge = issued.Challenge
	request.OwnerSignature = signature
	return h.callAs(t, PrincipalOwner, request)
}

// accept records one inbound event waiting for the owner.
func (h *harness) accept(t *testing.T, body string) envelope.Event {
	t.Helper()
	event := h.event(t, body)
	stored, err := envelope.EncodeEventJSON(event)
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	if _, _, err := h.journal.Accept(eventlog.Entry{
		EventID: event.EventID, SenderEndpointID: event.SenderEndpointID,
		ConversationID: event.ConversationID, Payload: stored,
		Admission: eventlog.AdmissionPending, ReceivedAtUnix: uint64(h.clock.Unix()),
	}); err != nil {
		t.Fatalf("accept: %v", err)
	}
	return event
}

// runtimeAttempt sends a request from the runtime socket, signed the way an
// owner tool would sign it. A runtime that had somehow obtained a signature
// still must not be able to use it here.
func (h *harness) runtimeAttempt(t *testing.T, request Request) Response {
	t.Helper()
	if Deciding(request.Op) {
		request.Challenge = strings.Repeat("a", 64)
		signature, err := SignDecision(request, request.Challenge, testOwnerKey())
		if err != nil {
			t.Fatalf("sign: %v", err)
		}
		request.OwnerSignature = signature
	}
	return h.callAs(t, PrincipalRuntime, request)
}

// The owner's key is the boundary, so the tests hold one rather than relying
// on which socket a call arrived on.
func testOwnerKey() ed25519.PrivateKey {
	return ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x6f}, ed25519.SeedSize))
}

func testOwnerPublic() ed25519.PublicKey {
	public, ok := testOwnerKey().Public().(ed25519.PublicKey)
	if !ok {
		panic("unexpected key type")
	}
	return public
}

func (h *harness) callAs(t *testing.T, principal Principal, request Request) Response {
	t.Helper()
	framed, err := EncodeRequest(request)
	if err != nil {
		t.Fatalf("encode request: %v", err)
	}
	body, err := ReadFrame(bytes.NewReader(framed))
	if err != nil {
		t.Fatalf("read frame: %v", err)
	}
	response := h.server.Handle(context.Background(), principal, body)
	encoded, err := EncodeResponse(response)
	if err != nil {
		t.Fatalf("encode response: %v", err)
	}
	responseBody, err := ReadFrame(bytes.NewReader(encoded))
	if err != nil {
		t.Fatalf("read response frame: %v", err)
	}
	decoded, err := DecodeResponse(responseBody)
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
		Admission:      eventlog.AdmissionAdmitted,
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
	// The runtime gets the typed body, and it is the same body that was sent.
	body, err := payload.Decode(decoded.Kind, decoded.Content)
	if err != nil {
		t.Fatalf("decode payload: %v", err)
	}
	if text, ok := body.(payload.Text); !ok || text.Body != "hello" {
		t.Fatalf("unexpected content: %+v", body)
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

func TestRuntimeCannotListOrClaimDaemonOwnedTypedAdapters(t *testing.T) {
	h := newHarness(t)
	packetBody, err := payload.Encode(payload.AgentPacketMessage{Foreign: payload.Foreign{
		Protocol: "agentpacket", Version: "1", Body: []byte("{}"),
	}})
	if err != nil {
		t.Fatal(err)
	}
	packetEvent, err := envelope.NewEvent(envelope.Event{
		Network: testNetwork(), ConversationID: convoID,
		SenderAgentID: senderID, SenderEndpointID: senderMEP, SenderDeviceID: senderDev,
		CreatedAtUnix: baseUnix, Kind: "agent.packet", Content: packetBody,
	})
	if err != nil {
		t.Fatal(err)
	}
	h.receive(t, packetEvent)
	historical := h.event(t, "historical")
	historicalRaw, err := envelope.EncodeEventJSON(historical)
	if err != nil {
		t.Fatal(err)
	}
	historyBody, err := payload.Encode(payload.DeviceHistorySegment{
		SourceDeviceID: senderDev, TargetDeviceID: "dev_" + strings.Repeat("9", 64),
		ConversationID: convoID, Sequence: 1, Events: [][]byte{historicalRaw},
	})
	if err != nil {
		t.Fatal(err)
	}
	historyEvent, err := envelope.NewEvent(envelope.Event{
		Network: testNetwork(), ConversationID: convoID,
		SenderAgentID: senderID, SenderEndpointID: senderMEP, SenderDeviceID: senderDev,
		CreatedAtUnix: baseUnix + 1, Kind: "device.history.segment", Content: historyBody,
	})
	if err != nil {
		t.Fatal(err)
	}
	h.receive(t, historyEvent)
	textEvent := h.event(t, "still visible")
	h.receive(t, textEvent)

	listing := h.call(t, Request{Op: OpPending, Limit: 1})
	if !listing.OK || len(listing.Events) != 1 || listing.Events[0].EventID != textEvent.EventID {
		t.Fatalf("typed packet hid or entered the runtime listing: %+v", listing)
	}
	claimed := h.call(t, Request{Op: OpClaim, EventID: packetEvent.EventID,
		LeaseID: leaseID, LeaseSeconds: 60})
	if claimed.OK || claimed.Code != fault.CodeClassNotDelegated {
		t.Fatalf("runtime claimed daemon-owned Agent Packet: %+v", claimed)
	}
	claimed = h.call(t, Request{Op: OpClaim, EventID: historyEvent.EventID,
		LeaseID: "lease_" + strings.Repeat("7", 64), LeaseSeconds: 60})
	if claimed.OK || claimed.Code != fault.CodeClassNotDelegated {
		t.Fatalf("runtime claimed daemon-owned history segment: %+v", claimed)
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

func TestRuntimeComposesDaemonOwnedEventWithStableRetry(t *testing.T) {
	h := newHarness(t)
	request := Request{Op: OpCompose, ConversationID: convoID, MediaType: "text/plain; charset=utf-8",
		Body: "daemon owns this envelope", IdempotencyKey: "idem_" + strings.Repeat("a", 64),
		SessionID: sessionID, RecipientEndpointID: peerMEP, ExpiresAtUnix: baseUnix + 3600}
	first := h.call(t, request)
	if !first.OK || !first.Fresh || first.EventID == "" {
		t.Fatalf("first compose: %+v", first)
	}
	h.clock = h.clock.Add(30 * time.Second)
	retry := h.call(t, request)
	if !retry.OK || retry.Fresh || retry.EventID != first.EventID {
		t.Fatalf("retry changed the durable event: first=%+v retry=%+v", first, retry)
	}
	delivery, found, err := h.journal.LookupDelivery(first.EventID)
	if err != nil || !found {
		t.Fatalf("lookup composed delivery: found=%v err=%v", found, err)
	}
	raw, err := delivery.Payload()
	if err != nil {
		t.Fatal(err)
	}
	event, err := envelope.DecodeEventJSON(raw)
	if err != nil {
		t.Fatal(err)
	}
	if event.SenderAgentID != senderID || event.SenderEndpointID != senderMEP ||
		event.SenderDeviceID != senderDev || event.Network.NetworkId != testNetwork().NetworkId {
		t.Fatalf("event escaped daemon authority: %+v", event)
	}

	substitution := request
	substitution.Body = "replace it"
	if response := h.call(t, substitution); response.OK {
		t.Fatal("one idempotency key accepted different content")
	}
	substitution = request
	substitution.RecipientEndpointID = "mep_" + strings.Repeat("9", 64)
	if response := h.call(t, substitution); response.OK {
		t.Fatal("one idempotency key accepted a different recipient")
	}
}

func TestRuntimeComposesBoundRoomMessage(t *testing.T) {
	h := newHarness(t)
	roomID := "room_" + strings.Repeat("b", 64)
	response := h.call(t, Request{Op: OpCompose, ConversationID: convoID, RoomID: roomID,
		MembershipEpoch: 7, MediaType: "text/plain; charset=utf-8", Body: "room hello",
		IdempotencyKey: "idem_" + strings.Repeat("c", 64), SessionID: sessionID,
		RecipientEndpointID: peerMEP, ExpiresAtUnix: baseUnix + 3600})
	if !response.OK {
		t.Fatalf("compose room message: %+v", response)
	}
	delivery, _, err := h.journal.LookupDelivery(response.EventID)
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := delivery.Payload()
	event, err := envelope.DecodeEventJSON(raw)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := payload.Decode(event.Kind, event.Content)
	if err != nil {
		t.Fatal(err)
	}
	message, ok := decoded.(payload.RoomMessage)
	if !ok || event.RoomID != roomID || message.RoomID != roomID || message.Epoch != 7 {
		t.Fatalf("room binding was lost: event=%+v payload=%+v", event, decoded)
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
	if _, err := h.journal.Failed(event.EventID, sendAttempt(t, h, event.EventID, 0x40), fault.CodeApprovalRequired, h.clock); err != nil {
		t.Fatalf("hold: %v", err)
	}

	approved := h.owner(t, Request{Op: OpApprove, EventID: event.EventID})
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
	if _, err := h.journal.Failed(second.EventID, sendAttempt(t, h, second.EventID, 0x41), fault.CodeApprovalRequired, h.clock); err != nil {
		t.Fatalf("hold: %v", err)
	}
	if denied := h.owner(t, Request{Op: OpDeny, EventID: second.EventID}); !denied.OK {
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
	framed, err := EncodeRequest(Request{Op: OpPending})
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	body, err := ReadFrame(bytes.NewReader(framed))
	if err != nil {
		t.Fatalf("read frame: %v", err)
	}
	line := string(body)
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
	go func() { _ = h.server.Serve(context.Background(), listener, PrincipalRuntime) }()

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
	body, err := ReadFrame(bufio.NewReader(connection))
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	response, err := DecodeResponse(body)
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
		Identity: dispatch.Identity{AgentID: senderID, EndpointID: senderMEP, DeviceID: senderDev},
	})
	if err != nil {
		t.Fatalf("dispatcher: %v", err)
	}
	complete := Config{
		Journal: h.journal, Dispatcher: dispatcher, Policy: firewall.Default(),
		OwnerKey: testOwnerPublic(),
	}
	missing := map[string]func(*Config){
		"no journal":     func(c *Config) { c.Journal = nil },
		"no dispatcher":  func(c *Config) { c.Dispatcher = nil },
		"no policy":      func(c *Config) { c.Policy = firewall.Policy{} },
		"no owner key":   func(c *Config) { c.OwnerKey = nil },
		"zero owner key": func(c *Config) { c.OwnerKey = make(ed25519.PublicKey, ed25519.PublicKeySize) },
		"bad timeout":    func(c *Config) { c.Timeout = -1 },
	}
	for name, mutate := range missing {
		config := complete
		mutate(&config)
		if _, err := NewServer(config); err == nil {
			t.Fatalf("expected %q to be refused", name)
		}
	}
}

// The invariant the separation exists for: the party that asks for an approval
// must not be able to grant it.
func TestRuntimeCannotApproveAnything(t *testing.T) {
	h := newHarness(t)
	for _, operation := range []Operation{OpApprove, OpDeny, OpAdmit, OpRefuse, OpAwaitingAdmission} {
		t.Run(string(operation), func(t *testing.T) {
			if Permits(PrincipalRuntime, operation) {
				t.Fatalf("the runtime principal permits %q", operation)
			}
			request := Request{Op: operation, EventID: "evt_" + strings.Repeat("0", 64)}
			if operation == OpAwaitingAdmission {
				request = Request{Op: operation}
			}
			if operation == OpRefuse {
				request.Code = fault.CodeRejected
			}
			if Deciding(operation) {
				// Signed properly, and still refused: the runtime is not the
				// owner however well-formed its request is.
				request.Challenge = strings.Repeat("a", 64)
				signature, err := SignDecision(request, request.Challenge, testOwnerKey())
				if err != nil {
					t.Fatalf("sign: %v", err)
				}
				request.OwnerSignature = signature
			}
			response := h.callAs(t, PrincipalRuntime, request)
			if response.OK {
				t.Fatalf("the runtime performed %q", operation)
			}
		})
	}
	// And the owner does no Agent work.
	for _, operation := range []Operation{OpPending, OpClaim, OpComplete, OpReject, OpQueue} {
		if Permits(PrincipalOwner, operation) {
			t.Fatalf("the owner principal permits %q", operation)
		}
	}
	if Permits("someone-else", OpPending) {
		t.Fatal("an unknown principal was permitted")
	}
}

func TestOwnerHistoryExportIsBoundedAndRetryStable(t *testing.T) {
	h := newHarness(t)
	composed := h.call(t, Request{Op: OpCompose, ConversationID: convoID, SessionID: sessionID,
		RecipientEndpointID: peerMEP, ExpiresAtUnix: baseUnix + 3600,
		MediaType: "text/plain; charset=utf-8", Body: "durable history",
		IdempotencyKey: "idem_" + strings.Repeat("1", 64)})
	if !composed.OK {
		t.Fatalf("compose history source: %+v", composed)
	}
	if summary, err := h.dispatcher.Sweep(context.Background(), 0); err != nil || summary.Sent != 1 {
		t.Fatalf("deliver history source: %+v err=%v", summary, err)
	}
	request := Request{Op: OpExportDeviceHistory, TargetDeviceID: targetDev, ConversationID: convoID,
		HistorySequence: 1, Limit: 1, IdempotencyKey: "idem_" + strings.Repeat("2", 64),
		ExpiresAtUnix: baseUnix + 3600}
	first := h.owner(t, request)
	if !first.OK || !first.Fresh || first.EventID == "" || first.HistorySegmentDigest == "" ||
		first.LastEventID != composed.EventID || first.LastEventCreatedAt == 0 {
		t.Fatalf("export first history page: %+v", first)
	}

	// Arrival of more eligible history cannot change a page already bound to
	// this idempotency intent.
	h.clock = h.clock.Add(time.Second)
	secondSource := h.call(t, Request{Op: OpCompose, ConversationID: convoID, SessionID: sessionID,
		RecipientEndpointID: peerMEP, ExpiresAtUnix: baseUnix + 3600,
		MediaType: "text/plain; charset=utf-8", Body: "newer history",
		IdempotencyKey: "idem_" + strings.Repeat("3", 64)})
	if !secondSource.OK {
		t.Fatalf("compose newer source: %+v", secondSource)
	}
	if summary, err := h.dispatcher.Sweep(context.Background(), 0); err != nil || summary.Sent != 1 {
		t.Fatalf("deliver newer source: %+v err=%v", summary, err)
	}
	retry := h.owner(t, request)
	if !retry.OK || retry.Fresh || retry.EventID != first.EventID ||
		retry.HistorySegmentDigest != first.HistorySegmentDigest || retry.LastEventID != first.LastEventID {
		t.Fatalf("history retry changed the committed page: first=%+v retry=%+v", first, retry)
	}
}

func TestHistoryExportNeedsOwnerAndSignatureCoversTerms(t *testing.T) {
	h := newHarness(t)
	base := Request{Op: OpExportDeviceHistory, TargetDeviceID: targetDev, ConversationID: convoID,
		HistorySequence: 2, PreviousSegmentDigest: "sha256:" + strings.Repeat("a", 64),
		AfterCreatedAtUnix: baseUnix, AfterEventID: "evt_" + strings.Repeat("b", 64), Limit: 1,
		IdempotencyKey: "idem_" + strings.Repeat("c", 64), ExpiresAtUnix: baseUnix + 3600}
	if Permits(PrincipalRuntime, OpExportDeviceHistory) || !Permits(PrincipalOwner, OpExportDeviceHistory) ||
		!Deciding(OpExportDeviceHistory) {
		t.Fatal("history export is not confined to an owner decision")
	}
	if response := h.runtimeAttempt(t, base); response.OK || response.Code != fault.CodeClassNotDelegated {
		t.Fatalf("runtime exported history: %+v", response)
	}
	challenge := h.callAs(t, PrincipalOwner, Request{Op: OpChallenge}).Challenge
	signature, err := SignDecision(base, challenge, testOwnerKey())
	if err != nil {
		t.Fatal(err)
	}
	substituted := base
	substituted.TargetDeviceID = "dev_" + strings.Repeat("8", 64)
	substituted.Challenge, substituted.OwnerSignature = challenge, signature
	if response := h.callAs(t, PrincipalOwner, substituted); response.OK || response.Code != fault.CodeNotAuthentic {
		t.Fatalf("target substitution used an owner signature: %+v", response)
	}

	original, err := DecisionBytes(base, strings.Repeat("d", 64))
	if err != nil {
		t.Fatal(err)
	}
	mutations := map[string]func(*Request){
		"target":         func(r *Request) { r.TargetDeviceID = "dev_" + strings.Repeat("8", 64) },
		"conversation":   func(r *Request) { r.ConversationID = "conv_" + strings.Repeat("9", 64) },
		"sequence":       func(r *Request) { r.HistorySequence++ },
		"predecessor":    func(r *Request) { r.PreviousSegmentDigest = "sha256:" + strings.Repeat("e", 64) },
		"created cursor": func(r *Request) { r.AfterCreatedAtUnix++ },
		"event cursor":   func(r *Request) { r.AfterEventID = "evt_" + strings.Repeat("f", 64) },
		"limit":          func(r *Request) { r.Limit++ },
		"idempotency":    func(r *Request) { r.IdempotencyKey = "idem_" + strings.Repeat("0", 64) },
		"expiry":         func(r *Request) { r.ExpiresAtUnix++ },
	}
	for name, mutate := range mutations {
		t.Run(name, func(t *testing.T) {
			changed := base
			mutate(&changed)
			encoded, err := DecisionBytes(changed, strings.Repeat("d", 64))
			if err != nil || bytes.Equal(encoded, original) {
				t.Fatalf("term is not committed: err=%v", err)
			}
		})
	}
}

// The owner's half of the loop: see what is waiting, decide, and only then
// does the runtime see it.
func TestOwnerAdmitsAnInboundEvent(t *testing.T) {
	h := newHarness(t)
	event := h.event(t, "from a stranger")
	payload, err := envelope.EncodeEventJSON(event)
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	if _, _, err := h.journal.Accept(eventlog.Entry{
		EventID: event.EventID, SenderEndpointID: event.SenderEndpointID,
		ConversationID: event.ConversationID, Payload: payload,
		Admission: eventlog.AdmissionPending, ReceivedAtUnix: uint64(h.clock.Unix()),
	}); err != nil {
		t.Fatalf("accept: %v", err)
	}

	if listing := h.call(t, Request{Op: OpPending}); len(listing.Events) != 0 {
		t.Fatalf("a waiting event was offered to the runtime: %+v", listing)
	}
	waiting := h.owner(t, Request{Op: OpAwaitingAdmission})
	if !waiting.OK || len(waiting.Events) != 1 {
		t.Fatalf("the owner sees nothing waiting: %+v", waiting)
	}
	if admitted := h.owner(t, Request{Op: OpAdmit, EventID: event.EventID}); !admitted.OK {
		t.Fatalf("admit: %+v", admitted)
	}
	if listing := h.call(t, Request{Op: OpPending}); len(listing.Events) != 1 {
		t.Fatalf("an admitted event did not reach the runtime: %+v", listing)
	}
}

func TestOwnerRefusesAnInboundEvent(t *testing.T) {
	h := newHarness(t)
	event := h.event(t, "from a stranger")
	payload, err := envelope.EncodeEventJSON(event)
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	if _, _, err := h.journal.Accept(eventlog.Entry{
		EventID: event.EventID, SenderEndpointID: event.SenderEndpointID,
		ConversationID: event.ConversationID, Payload: payload,
		Admission: eventlog.AdmissionPending, ReceivedAtUnix: uint64(h.clock.Unix()),
	}); err != nil {
		t.Fatalf("accept: %v", err)
	}
	if refused := h.owner(t, Request{Op: OpRefuse, EventID: event.EventID,
		Code: fault.CodeAdmissionRequired}); !refused.OK {
		t.Fatalf("refuse: %+v", refused)
	}
	if listing := h.call(t, Request{Op: OpPending}); len(listing.Events) != 0 {
		t.Fatalf("a refused event reached the runtime: %+v", listing)
	}
	if waiting := h.owner(t, Request{Op: OpAwaitingAdmission}); len(waiting.Events) != 0 {
		t.Fatalf("a decided event is still waiting: %+v", waiting)
	}
	// The decision is made once.
	if again := h.owner(t, Request{Op: OpAdmit, EventID: event.EventID}); again.OK {
		t.Fatal("a refused event was admitted afterwards")
	}
}

// The frame bound has to be the bound, not whatever buffer the reader happened
// to allocate. A 4 KiB reader silently made every larger message unsendable.
func TestLargeFramesTravelOverTheSocket(t *testing.T) {
	h := newHarness(t)
	path := filepath.Join(t.TempDir(), "run", "runtime.sock")
	listener, err := Listen(path)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer listener.Close()
	go func() { _ = h.server.Serve(context.Background(), listener, PrincipalRuntime) }()

	for _, size := range []int{4 << 10, 64 << 10, 100 << 10} {
		t.Run(strconv.Itoa(size), func(t *testing.T) {
			event := h.event(t, strings.Repeat("x", size))
			encoded, err := envelope.EncodeEventJSON(event)
			if err != nil {
				t.Fatalf("encode: %v", err)
			}
			request, err := EncodeRequest(Request{
				Op: OpQueue, Event: json.RawMessage(encoded), SessionID: sessionID,
				RecipientEndpointID: peerMEP, ExpiresAtUnix: baseUnix + 3600,
			})
			if err != nil {
				t.Fatalf("encode request: %v", err)
			}
			if len(request) <= size {
				t.Fatalf("the request did not carry its content: %d bytes", len(request))
			}

			connection, err := net.Dial("unix", path)
			if err != nil {
				t.Fatalf("dial: %v", err)
			}
			defer connection.Close()
			if _, err := connection.Write(request); err != nil {
				t.Fatalf("write: %v", err)
			}
			body, err := ReadFrame(bufio.NewReader(connection))
			if err != nil {
				t.Fatalf("read: %v", err)
			}
			response, err := DecodeResponse(body)
			if err != nil {
				t.Fatalf("decode: %v", err)
			}
			if !response.OK {
				t.Fatalf("a %d byte event was refused: %+v", size, response)
			}
		})
	}
}

// A frame past the bound costs four bytes, not the size it claimed.
func TestOversizedFrameIsRefusedBeforeAllocation(t *testing.T) {
	var header [4]byte
	binary.BigEndian.PutUint32(header[:], uint32(MaxFrameBytes+1))
	if _, err := ReadFrame(bytes.NewReader(header[:])); err == nil {
		t.Fatal("an oversized frame was accepted")
	}
	binary.BigEndian.PutUint32(header[:], 0)
	if _, err := ReadFrame(bytes.NewReader(header[:])); err == nil {
		t.Fatal("an empty frame was accepted")
	}
	// A frame whose declared length exceeds what follows fails rather than
	// returning a short body.
	binary.BigEndian.PutUint32(header[:], 16)
	if _, err := ReadFrame(bytes.NewReader(append(header[:], []byte("short")...))); err == nil {
		t.Fatal("a truncated frame was accepted")
	}
}

func sendAttempt(t *testing.T, h *harness, eventID string, seed byte) string {
	t.Helper()
	id, err := eventlog.NewAttemptID(bytes.Repeat([]byte{seed}, 32))
	if err != nil {
		t.Fatalf("attempt id: %v", err)
	}
	if _, err := h.journal.ClaimForSend(eventID, id, h.clock, time.Minute); err != nil {
		t.Fatalf("claim for send: %v", err)
	}
	return id
}

func testAssetIdentity() AssetIdentity {
	return AssetIdentity{
		NetworkID:       "tos-local",
		GenesisRootHash: strings.Repeat("1", 64),
		GenesisFileHash: strings.Repeat("2", 64),
		Workchain:       0,
		AccountID:       strings.Repeat("a", 64),
		MasterCodeHash:  "tvm-cell-sha256:" + strings.Repeat("b", 64),
		WalletCodeHash:  "tvm-cell-sha256:" + strings.Repeat("c", 64),
		Decimals:        2,
	}
}

func testPurchase(units uint64) *PurchaseTerms {
	return &PurchaseTerms{
		CapabilityID:           "cap_" + strings.Repeat("9", 64),
		CapabilityVersion:      "1.0.0",
		CapabilityClass:        "transcription.audio",
		ProviderAgentID:        senderID,
		ManifestDigest:         "sha256:" + strings.Repeat("4", 64),
		TransportBindingDigest: "sha256:" + strings.Repeat("5", 64),
		Asset:                  testAssetIdentity(),
		PriceAtomic:            strconv.FormatUint(units, 10),
		EscrowTermsDigest:      "sha256:" + strings.Repeat("6", 64),
		DisputePolicyDigest:    "sha256:" + strings.Repeat("7", 64),
		NotAfterUnix:           baseUnix + 600,
	}
}

// The owner places a standing authorisation. The runtime never supplies one.
func (h *harness) placeMandate(t *testing.T) string {
	t.Helper()
	return h.placeMandateWithTotal(t, "1000", "500")
}

func TestOwnerRecordsFundedEscrowLocationCrashSafely(t *testing.T) {
	h := newHarness(t)
	commitment := "tvm-cell-sha256:" + strings.Repeat("a", 64)
	address := "0:" + strings.Repeat("b", 64)
	request := Request{Op: OpRecordEscrowLocation, QuoteCommitment: commitment,
		EscrowAddress: address, CapabilityClass: "software.audit"}
	first := h.owner(t, request)
	if !first.OK || !first.Fresh {
		t.Fatalf("record escrow location: %+v", first)
	}
	storedAddress, class, found, err := h.journal.LocateEscrow(commitment)
	if err != nil || !found || storedAddress != address || class != "software.audit" {
		t.Fatalf("stored escrow location: address=%q class=%q found=%v err=%v", storedAddress, class, found, err)
	}
	if retry := h.owner(t, request); !retry.OK || retry.Fresh {
		t.Fatalf("exact owner retry was not idempotent: %+v", retry)
	}
	redirect := request
	redirect.EscrowAddress = "0:" + strings.Repeat("c", 64)
	if response := h.owner(t, redirect); response.OK {
		t.Fatal("owner retry redirected one Quote commitment to another escrow")
	}
	if response := h.runtimeAttempt(t, request); response.OK {
		t.Fatal("runtime wrote the owner/wallet escrow locator")
	}
}

func TestRuntimeVerifiesExactFinalizedQuoteWithoutReceivingAuthority(t *testing.T) {
	h := newHarness(t)
	commitment := "tvm-cell-sha256:" + strings.Repeat("a", 64)
	expected := testPurchase(200)
	expected.Asset.NetworkID = testNetwork().NetworkId
	expected.Asset.GenesisRootHash = testNetwork().GenesisRootHash
	expected.Asset.GenesisFileHash = testNetwork().GenesisFileHash
	quote := negotiation.VerifiedAcceptedQuote{
		Commitment: commitment, Terms: *toTerms(expected), Network: testNetwork(),
		Reference: &nativev1.ChainReference{
			Account: "0:" + strings.Repeat("b", 64), TransactionHash: "sha256:" + strings.Repeat("c", 64),
			ContractCodeHash: "tvm-cell-sha256:" + strings.Repeat("d", 64), FinalizedCheckpoint: 99,
		},
		FinalizedAtUnix: baseUnix,
	}
	h.server.config.QuoteResolver = fixedQuoteResolver{quote: quote, found: true}
	h.server.config.Network = testNetwork()
	request := Request{Op: OpVerifyAcceptedQuote, QuoteCommitment: commitment,
		EscrowAddress: quote.Reference.Account, CapabilityClass: expected.CapabilityClass,
		ExpectedQuoteTerms: expected}
	verified := h.call(t, request)
	if !verified.OK || verified.Authorised || verified.FinalizedQuote == nil ||
		verified.FinalizedQuote.Commitment != commitment || verified.FinalizedQuote.FinalizedCheckpoint != 99 ||
		verified.FinalizedQuote.EscrowAccount != quote.Reference.Account {
		t.Fatalf("finalized Quote verification: %+v", verified)
	}
	if _, _, found, err := h.journal.LocateEscrow(commitment); err != nil || found {
		t.Fatalf("read-only verification created an escrow locator: found=%v err=%v", found, err)
	}
	wrongAccount := quote
	wrongReference := proto.Clone(quote.Reference).(*nativev1.ChainReference)
	wrongReference.Account = "0:" + strings.Repeat("f", 64)
	wrongAccount.Reference = wrongReference
	h.server.config.QuoteResolver = fixedQuoteResolver{quote: wrongAccount, found: true}
	if response := h.call(t, request); response.OK {
		t.Fatal("finalized evidence for another escrow account matched the candidate address")
	}
	h.server.config.QuoteResolver = fixedQuoteResolver{quote: quote, found: true}

	substituted := *expected
	substituted.ProviderAgentID = "agent_" + strings.Repeat("e", 64)
	request.ExpectedQuoteTerms = &substituted
	if response := h.call(t, request); response.OK {
		t.Fatal("finalized Quote with another provider matched expected terms")
	}

	foreign := *expected
	foreign.Asset.NetworkID = "tos-foreign"
	foreignQuote := quote
	foreignQuote.Terms = *toTerms(&foreign)
	foreignQuote.Network = &nativev1.NetworkDomain{NetworkId: foreign.Asset.NetworkID,
		GenesisRootHash: foreign.Asset.GenesisRootHash, GenesisFileHash: foreign.Asset.GenesisFileHash}
	h.server.config.QuoteResolver = fixedQuoteResolver{quote: foreignQuote, found: true}
	request.ExpectedQuoteTerms = &foreign
	if response := h.call(t, request); response.OK {
		t.Fatal("a self-consistent Quote from another network matched the daemon")
	}

	h.server.config.QuoteResolver = nil
	h.server.config.Network = nil
	request.ExpectedQuoteTerms = expected
	if response := h.call(t, request); response.OK || response.Code != fault.CodeClassNotDelegated {
		t.Fatalf("unconfigured Quote verification did not fail closed: %+v", response)
	}
	if response := h.callAs(t, PrincipalOwner, request); response.OK {
		t.Fatal("owner interface performed runtime Quote verification")
	}
}

// placeMandateWithTotal places a mandate with a chosen ceiling, so a test can
// make the sum of a few purchases cross MaxTotal without needing large amounts.
func (h *harness) placeMandateWithTotal(t *testing.T, maxTotal, approvalAbove string) string {
	t.Helper()
	return h.placeMandateNamed(t, "buy transcription", maxTotal, approvalAbove)
}

// placeMandateNamed places a mandate under a chosen objective, so two calls
// produce two distinct mandate identifiers rather than the same one.
func (h *harness) placeMandateNamed(t *testing.T, objective, maxTotal, approvalAbove string) string {
	t.Helper()
	placed := h.owner(t, Request{Op: OpPlaceMandate, Mandate: &MandateTerms{
		Objective: objective, Authority: "commit",
		CapabilityClass: "transcription.audio", Asset: testAssetIdentity(),
		MaxTotalAtomic: maxTotal, ApprovalAboveAtomic: approvalAbove, MaxCounteroffers: 4,
		ExpiresAtUnix: baseUnix + 86_400,
	}})
	if !placed.OK || placed.MandateID == "" {
		t.Fatalf("place mandate: %+v", placed)
	}
	return placed.MandateID
}

// testPurchaseCap builds a purchase whose capability identifier is distinct, so
// two calls describe two different economic executions even at the same price.
func testPurchaseCap(capSeed string, units uint64) *PurchaseTerms {
	terms := testPurchase(units)
	terms.CapabilityID = "cap_" + strings.Repeat(capSeed, 64)
	return terms
}

func testProposal(effect string, origins ...ActionOrigin) *ProposedAction {
	proposal := &ProposedAction{Effect: effect, Summary: "call the payments tool", Derived: origins}
	if effect == "tool-call" {
		proposal.IdempotencyKey = "idem_" + strings.Repeat("a", 64)
	}
	return proposal
}

func testActionOrigin() ActionOrigin {
	return ActionOrigin{
		AgentID:        senderID,
		EndpointID:     senderMEP,
		DeviceID:       senderDev,
		EventID:        "evt_" + strings.Repeat("7", 64),
		ConversationID: convoID,
		Kind:           "text",
		ReceivedAtUnix: baseUnix,
	}
}

// An action a stranger's message led to stops, waits for a person, and
// proceeds exactly once when that person says yes.
func TestActionDerivedFromReceivedContentWaitsForTheOwner(t *testing.T) {
	h := newHarness(t)

	asked := h.call(t, Request{Op: OpRequestAction, Action: testProposal("tool-call", testActionOrigin())})
	if !asked.OK || asked.Decision != "require-owner-approval" {
		t.Fatalf("a tool call a stranger's message drove ran unattended: %+v", asked)
	}
	if asked.ActionID == "" || asked.Authorised {
		t.Fatalf("the runtime was told it could proceed: %+v", asked)
	}

	// The runtime may look, and looking consumes nothing.
	status := h.call(t, Request{Op: OpActionStatus, ActionID: asked.ActionID})
	if status.State != "pending" {
		t.Fatalf("unexpected state before a decision: %+v", status)
	}
	if claimed := h.call(t, Request{Op: OpClaimAction, ActionID: asked.ActionID}); claimed.Authorised {
		t.Fatal("an undecided action was performed")
	}

	// The owner sees the question, and what caused it.
	waiting := h.owner(t, Request{Op: OpPendingActions})
	if len(waiting.Actions) != 1 || waiting.Actions[0].ActionID != asked.ActionID {
		t.Fatalf("the owner was not asked: %+v", waiting)
	}
	if len(waiting.Actions[0].Origins) != 1 ||
		waiting.Actions[0].Origins[0].EventID != testActionOrigin().EventID {
		t.Fatalf("the owner would not know what caused it: %+v", waiting.Actions[0])
	}
	if waiting.Actions[0].IdempotencyKey != askedKey(t, asked.ActionID, testProposal("tool-call", testActionOrigin())) {
		t.Fatal("the owner was not shown the tool invocation idempotency key")
	}

	if granted := h.owner(t, Request{Op: OpGrantAction, ActionID: asked.ActionID}); !granted.OK {
		t.Fatalf("grant: %+v", granted)
	}
	first := h.call(t, Request{Op: OpClaimAction, ActionID: asked.ActionID})
	if !first.Authorised {
		t.Fatalf("a granted action could not proceed: %+v", first)
	}
	second := h.call(t, Request{Op: OpClaimAction, ActionID: asked.ActionID})
	if second.Authorised {
		t.Fatal("one decision authorised the same action twice")
	}
}

func askedKey(t *testing.T, actionID string, proposal *ProposedAction) string {
	t.Helper()
	action, err := toAction(*proposal)
	if err != nil {
		t.Fatalf("action: %v", err)
	}
	derived, err := firewall.ActionID(action)
	if err != nil || derived != actionID {
		t.Fatalf("proposal did not reproduce action id: %s %v", derived, err)
	}
	return proposal.IdempotencyKey
}

func TestPolicyAllowedToolCallIsClaimedOncePerIdempotencyKey(t *testing.T) {
	h := newHarness(t)
	first := testProposal("tool-call")
	allowed := h.call(t, Request{Op: OpRequestAction, Action: first})
	if !allowed.OK || allowed.Decision != "allow" || allowed.Authorised || allowed.State != "granted" {
		t.Fatalf("tool call did not become a one-shot grant: %+v", allowed)
	}
	if claimed := h.call(t, Request{Op: OpClaimAction, ActionID: allowed.ActionID}); !claimed.Authorised {
		t.Fatalf("tool call grant could not be claimed: %+v", claimed)
	}
	replayed := h.call(t, Request{Op: OpRequestAction, Action: first})
	if replayed.ActionID != allowed.ActionID || replayed.State != "spent" {
		t.Fatalf("same idempotency key minted another grant: %+v", replayed)
	}
	if claimed := h.call(t, Request{Op: OpClaimAction, ActionID: replayed.ActionID}); claimed.Authorised {
		t.Fatal("same tool invocation was authorised twice")
	}
	reworded := *first
	reworded.Summary = "same invocation, gentler description"
	conflict := h.call(t, Request{Op: OpRequestAction, Action: &reworded})
	if conflict.Decision != "refuse" || conflict.ActionID == allowed.ActionID {
		t.Fatalf("re-described invocation reused one key: %+v", conflict)
	}

	second := testProposal("tool-call")
	second.IdempotencyKey = "idem_" + strings.Repeat("b", 64)
	distinct := h.call(t, Request{Op: OpRequestAction, Action: second})
	if distinct.ActionID == allowed.ActionID || distinct.State != "granted" {
		t.Fatalf("distinct tool invocation was collapsed into a replay: %+v", distinct)
	}
}

func TestToolCallRequiresCanonicalIdempotencyKey(t *testing.T) {
	for name, key := range map[string]string{"missing": "", "malformed": "idem_not-hex"} {
		t.Run(name, func(t *testing.T) {
			request := Request{Op: OpRequestAction, Action: &ProposedAction{
				Effect: "tool-call", Summary: "invoke tool", IdempotencyKey: key,
			}}
			if _, err := EncodeRequest(request); err == nil {
				t.Fatalf("tool call idempotency key %q was accepted", key)
			}
		})
	}
}

// One purchase is authorised once even when it is re-described. The economic
// one-shot is keyed on the mandate and the terms, not on the action identifier
// that a changed summary would move, so a second, gentler-worded attempt at the
// same purchase is refused rather than granted a second auto-authorisation.
func TestReDescribedPurchaseIsNotAuthorisedTwice(t *testing.T) {
	h := newHarnessWithPolicy(t, firewall.Policy{
		UnattendedCeiling: firewall.EffectSpend, OwnInitiativeCeiling: firewall.EffectSpend,
	})
	mandateID := h.placeMandate(t)

	first := &ProposedAction{Effect: "spend", Summary: "pay 100 for transcription", Terms: testPurchase(100)}
	a := h.call(t, Request{Op: OpRequestAction, Action: first, MandateID: mandateID})
	if a.Decision != string(firewall.Allow) {
		t.Fatalf("the first spend was not auto-authorised: %+v", a)
	}

	// The same purchase -- same mandate, same terms -- described more gently.
	// A different action identifier, the same economic execution.
	second := &ProposedAction{Effect: "spend", Summary: "start the transcription", Terms: testPurchase(100)}
	b := h.call(t, Request{Op: OpRequestAction, Action: second, MandateID: mandateID})
	if b.ActionID == a.ActionID {
		t.Fatal("two descriptions of one purchase shared an action identifier")
	}
	if b.Decision != string(firewall.Refuse) {
		t.Fatalf("a re-described purchase was authorised a second time: %+v", b)
	}
}

// Distinct purchases under one mandate are auto-authorised until their running
// sum would cross the mandate's MaxTotal, at which point the next is sent to the
// owner rather than auto-authorised. The per-spend ceiling alone would let three
// 90s through under a 250 ceiling; the durable per-mandate budget does not.
func TestDistinctPurchasesAreBoundedByTheMandateTotal(t *testing.T) {
	h := newHarnessWithPolicy(t, firewall.Policy{
		UnattendedCeiling: firewall.EffectSpend, OwnInitiativeCeiling: firewall.EffectSpend,
	})
	mandateID := h.placeMandateWithTotal(t, "250", "250")

	// 90 fits (90 <= 250).
	first := &ProposedAction{Effect: "spend", Summary: "first transcription", Terms: testPurchaseCap("1", 90)}
	a := h.call(t, Request{Op: OpRequestAction, Action: first, MandateID: mandateID})
	if a.Decision != string(firewall.Allow) {
		t.Fatalf("the first purchase was not auto-authorised: %+v", a)
	}

	// 90 + 90 = 180 still fits.
	second := &ProposedAction{Effect: "spend", Summary: "second transcription", Terms: testPurchaseCap("2", 90)}
	b := h.call(t, Request{Op: OpRequestAction, Action: second, MandateID: mandateID})
	if b.Decision != string(firewall.Allow) {
		t.Fatalf("the second purchase was not auto-authorised: %+v", b)
	}
	if b.ActionID == a.ActionID {
		t.Fatal("two distinct purchases shared an action identifier")
	}

	// 180 + 90 = 270 crosses the 250 ceiling: the owner has to decide.
	third := &ProposedAction{Effect: "spend", Summary: "third transcription", Terms: testPurchaseCap("3", 90)}
	c := h.call(t, Request{Op: OpRequestAction, Action: third, MandateID: mandateID})
	if c.Decision != string(firewall.RequireOwnerApproval) {
		t.Fatalf("a purchase past the mandate's total was auto-authorised: %+v", c)
	}
	if c.State != "pending" {
		t.Fatalf("the escalated purchase was not put to the owner: %+v", c)
	}
	// It cannot be claimed unattended -- it is waiting for a person.
	if claimed := h.call(t, Request{Op: OpClaimAction, ActionID: c.ActionID}); claimed.Authorised {
		t.Fatal("a purchase past the mandate's total was executed without the owner")
	}
	// The owner is the one holding the question.
	waiting := h.owner(t, Request{Op: OpPendingActions})
	if len(waiting.Actions) != 1 || waiting.Actions[0].ActionID != c.ActionID {
		t.Fatalf("the owner was not asked about the over-budget purchase: %+v", waiting)
	}

	// A second mandate over the same asset has its own untouched budget: the
	// first mandate's spending did not draw it down.
	other := h.placeMandateNamed(t, "a separate objective", "250", "250")
	fresh := &ProposedAction{Effect: "spend", Summary: "under a fresh mandate", Terms: testPurchaseCap("1", 90)}
	d := h.call(t, Request{Op: OpRequestAction, Action: fresh, MandateID: other})
	if d.Decision != string(firewall.Allow) {
		t.Fatalf("a fresh mandate's budget was drawn down by another mandate: %+v", d)
	}
}

// mandateBudget reopens one mandate's durable budget so a test can see what a
// spend is holding. The total is the ceiling the mandate was placed with; the
// asset is the one every purchase in these tests names.
func (h *harness) mandateBudget(t *testing.T, mandateID, total string) *negotiation.Budget {
	t.Helper()
	ledger, err := h.journal.OpenMandateBudgetLedger(mandateID, toAsset(testAssetIdentity()))
	if err != nil {
		t.Fatalf("open mandate budget ledger: %v", err)
	}
	budget, err := negotiation.OpenBudget(
		negotiation.Money{Asset: toAsset(testAssetIdentity()), Atomic: total}, ledger)
	if err != nil {
		t.Fatalf("open mandate budget: %v", err)
	}
	return budget
}

func executionOf(t *testing.T, mandateID string, terms *PurchaseTerms) string {
	t.Helper()
	id, err := negotiation.ExecutionID(mandateID, *toTerms(terms))
	if err != nil {
		t.Fatalf("execution id: %v", err)
	}
	return id
}

func remainingAtomic(t *testing.T, budget *negotiation.Budget) string {
	t.Helper()
	remaining, err := budget.Remaining()
	if err != nil {
		t.Fatalf("remaining: %v", err)
	}
	return remaining.Atomic
}

// A spend the owner refuses frees the budget it was holding, so the mandate can
// spend that amount on something the owner does approve.
func TestDeniedSpendReleasesItsMandateHold(t *testing.T) {
	h := newHarness(t)
	mandateID := h.placeMandateWithTotal(t, "250", "250")
	purchase := testPurchase(200)
	spend := testProposal("spend")
	spend.Terms = purchase

	asked := h.call(t, Request{Op: OpRequestAction, Action: spend, MandateID: mandateID})
	if asked.Decision != string(firewall.RequireOwnerApproval) || asked.State != "pending" {
		t.Fatalf("a spend inside the mandate did not wait for the owner: %+v", asked)
	}
	// The pending spend holds its slice of the budget while it waits.
	if amount, held := h.mandateBudget(t, mandateID, "250").Reserved(executionOf(t, mandateID, purchase)); !held || amount.Atomic != "200" {
		t.Fatalf("a pending spend did not hold its budget: held=%v amount=%+v", held, amount)
	}
	if left := remainingAtomic(t, h.mandateBudget(t, mandateID, "250")); left != "50" {
		t.Fatalf("the hold was not counted against the mandate: remaining=%s", left)
	}

	// The owner refuses it, and the hold is freed.
	if denied := h.owner(t, Request{Op: OpDenyAction, ActionID: asked.ActionID, Reason: "not this one"}); !denied.OK {
		t.Fatalf("deny: %+v", denied)
	}
	if _, held := h.mandateBudget(t, mandateID, "250").Reserved(executionOf(t, mandateID, purchase)); held {
		t.Fatal("a denied spend kept its hold")
	}
	if left := remainingAtomic(t, h.mandateBudget(t, mandateID, "250")); left != "250" {
		t.Fatalf("the mandate's full ceiling did not return: remaining=%s", left)
	}

	// The freed amount is available again: a distinct purchase of the same size
	// now fits where the mandate's ceiling would otherwise have been spent.
	againTerms := testPurchaseCap("8", 200)
	again := &ProposedAction{Effect: "spend", Summary: "a different purchase", Terms: againTerms}
	retry := h.call(t, Request{Op: OpRequestAction, Action: again, MandateID: mandateID})
	if retry.Decision != string(firewall.RequireOwnerApproval) {
		t.Fatalf("the freed budget could not be reserved again: %+v", retry)
	}
	if left := remainingAtomic(t, h.mandateBudget(t, mandateID, "250")); left != "50" {
		t.Fatalf("re-reserving the freed amount did not take: remaining=%s", left)
	}
}

// A spend the owner grants and the runtime claims turns its standing hold into a
// committed amount, so the mandate records it as spent rather than a reservation
// that could still be released.
func TestClaimedSpendCommitsItsMandateHold(t *testing.T) {
	h := newHarness(t)
	mandateID := h.placeMandateWithTotal(t, "250", "250")
	purchase := testPurchase(200)
	spend := testProposal("spend")
	spend.Terms = purchase

	asked := h.call(t, Request{Op: OpRequestAction, Action: spend, MandateID: mandateID})
	if asked.Decision != string(firewall.RequireOwnerApproval) {
		t.Fatalf("unexpected decision: %+v", asked)
	}
	if granted := h.owner(t, Request{Op: OpGrantAction, ActionID: asked.ActionID}); !granted.OK {
		t.Fatalf("grant: %+v", granted)
	}
	claimed := h.call(t, Request{Op: OpClaimAction, ActionID: asked.ActionID})
	if !claimed.Authorised {
		t.Fatalf("a granted spend could not proceed: %+v", claimed)
	}

	budget := h.mandateBudget(t, mandateID, "250")
	// The hold is gone -- it became a spend.
	if _, held := budget.Reserved(executionOf(t, mandateID, purchase)); held {
		t.Fatal("a committed spend was still a standing hold")
	}
	if budget.Spent().Atomic != "200" {
		t.Fatalf("the spend was not committed: spent=%+v", budget.Spent())
	}
	if left := remainingAtomic(t, budget); left != "50" {
		t.Fatalf("the committed spend was not counted: remaining=%s", left)
	}
}

// A spend nobody decides within the window is retired, and its hold is freed
// rather than consuming the mandate's ceiling forever.
func TestExpiredSpendReleasesItsMandateHold(t *testing.T) {
	h := newHarness(t)
	mandateID := h.placeMandateWithTotal(t, "250", "250")
	purchase := testPurchase(200)
	spend := testProposal("spend")
	spend.Terms = purchase

	asked := h.call(t, Request{Op: OpRequestAction, Action: spend, MandateID: mandateID})
	if asked.State != "pending" {
		t.Fatalf("the spend did not wait for the owner: %+v", asked)
	}
	if _, held := h.mandateBudget(t, mandateID, "250").Reserved(executionOf(t, mandateID, purchase)); !held {
		t.Fatal("a pending spend held no budget")
	}

	later := h.clock.Add(eventlog.DefaultMaxPendingAge + time.Hour)
	if count, err := h.journal.ExpirePendingApprovals(later); err != nil || count != 1 {
		t.Fatalf("expire: count=%d err=%v", count, err)
	}
	if _, held := h.mandateBudget(t, mandateID, "250").Reserved(executionOf(t, mandateID, purchase)); held {
		t.Fatal("an expired spend kept its hold")
	}
	if left := remainingAtomic(t, h.mandateBudget(t, mandateID, "250")); left != "250" {
		t.Fatalf("the expired hold was not freed: remaining=%s", left)
	}
	status := h.call(t, Request{Op: OpActionStatus, ActionID: asked.ActionID})
	if status.State != string(eventlog.ApprovalDenied) {
		t.Fatalf("the expired request was not retired: %+v", status)
	}
}

// MaxTotal is enforced across the owner-approval path: a within-budget spend
// awaiting the owner holds its slice, and a second spend that would cross the
// ceiling while the first is pending takes no hold until budget is freed.
func TestMandateTotalEnforcedAcrossTheOwnerApprovalPath(t *testing.T) {
	h := newHarness(t)
	mandateID := h.placeMandateWithTotal(t, "250", "250")

	firstTerms := testPurchaseCap("1", 200)
	first := &ProposedAction{Effect: "spend", Summary: "first", Terms: firstTerms}
	a := h.call(t, Request{Op: OpRequestAction, Action: first, MandateID: mandateID})
	if a.Decision != string(firewall.RequireOwnerApproval) {
		t.Fatalf("the first spend did not wait for the owner: %+v", a)
	}
	if _, held := h.mandateBudget(t, mandateID, "250").Reserved(executionOf(t, mandateID, firstTerms)); !held {
		t.Fatal("a within-budget pending spend held no budget")
	}

	// 200 + 100 > 250, so the second spend is put to the owner without a hold
	// while the first is still pending.
	secondTerms := testPurchaseCap("2", 100)
	second := &ProposedAction{Effect: "spend", Summary: "second", Terms: secondTerms}
	b := h.call(t, Request{Op: OpRequestAction, Action: second, MandateID: mandateID})
	if b.Decision != string(firewall.RequireOwnerApproval) {
		t.Fatalf("the second spend was not put to the owner: %+v", b)
	}
	if _, held := h.mandateBudget(t, mandateID, "250").Reserved(executionOf(t, mandateID, secondTerms)); held {
		t.Fatal("an over-budget pending spend took a hold it should not have")
	}
	if left := remainingAtomic(t, h.mandateBudget(t, mandateID, "250")); left != "50" {
		t.Fatalf("only the first spend should be held: remaining=%s", left)
	}

	// Refusing the first frees its 200, and the second's 100 fits once re-asked.
	if denied := h.owner(t, Request{Op: OpDenyAction, ActionID: a.ActionID, Reason: "no"}); !denied.OK {
		t.Fatalf("deny: %+v", denied)
	}
	if left := remainingAtomic(t, h.mandateBudget(t, mandateID, "250")); left != "250" {
		t.Fatalf("the first hold was not freed: remaining=%s", left)
	}
	third := &ProposedAction{Effect: "spend", Summary: "second again", Terms: testPurchaseCap("2", 100)}
	c := h.call(t, Request{Op: OpRequestAction, Action: third, MandateID: mandateID})
	if c.Decision != string(firewall.RequireOwnerApproval) {
		t.Fatalf("the freed budget could not admit the second spend: %+v", c)
	}
	if left := remainingAtomic(t, h.mandateBudget(t, mandateID, "250")); left != "150" {
		t.Fatalf("the second spend's hold did not take after the first was freed: remaining=%s", left)
	}
}

// The identifier is derived from the action, so an approval cannot be spent on
// a different one.
func TestApprovalCannotBeSpentOnAnotherAction(t *testing.T) {
	h := newHarness(t)
	origin := testActionOrigin()

	harmless := h.call(t, Request{Op: OpRequestAction, Action: testProposal("tool-call", origin)})
	if harmless.ActionID == "" {
		t.Fatalf("request: %+v", harmless)
	}
	if granted := h.owner(t, Request{Op: OpGrantAction, ActionID: harmless.ActionID}); !granted.OK {
		t.Fatalf("grant: %+v", granted)
	}

	// The same words, a stronger effect. A different action, and so a
	// different identifier with no approval behind it.
	mandateID := h.placeMandate(t)
	spend := testProposal("spend", origin)
	spend.Terms = testPurchase(200)
	stronger := h.call(t, Request{Op: OpRequestAction, Action: spend, MandateID: mandateID})
	if stronger.ActionID == harmless.ActionID {
		t.Fatal("two different actions shared one identifier")
	}
	if claimed := h.call(t, Request{Op: OpClaimAction, ActionID: stronger.ActionID}); claimed.Authorised {
		t.Fatal("an approval for one action authorised another")
	}
}

// The party that asks for an approval must not be able to grant it, and the
// party that grants does no Agent work.
func TestNeitherSideCanPlayTheOtherOnActions(t *testing.T) {
	h := newHarness(t)
	asked := h.call(t, Request{Op: OpRequestAction, Action: testProposal("tool-call", testActionOrigin())})
	if asked.ActionID == "" {
		t.Fatalf("request: %+v", asked)
	}
	for _, operation := range []Operation{OpGrantAction, OpDenyAction, OpPendingActions} {
		request := Request{Op: operation, ActionID: asked.ActionID}
		if operation == OpDenyAction {
			request.Reason = "no"
		}
		if operation == OpPendingActions {
			request.ActionID = ""
		}
		if response := h.runtimeAttempt(t, request); response.OK {
			t.Fatalf("the runtime performed %q", operation)
		}
	}
	for _, operation := range []Operation{OpRequestAction, OpActionStatus, OpClaimAction} {
		request := Request{Op: operation, ActionID: asked.ActionID}
		if operation == OpRequestAction {
			request.ActionID = ""
			request.Action = testProposal("tool-call", testActionOrigin())
		}
		if response := h.owner(t, request); response.OK {
			t.Fatalf("the owner performed %q", operation)
		}
	}
}

// Replying is ordinary Agent work and does not stop for a person.
func TestOrdinaryWorkNeedsNoDecision(t *testing.T) {
	h := newHarness(t)
	reply := h.call(t, Request{Op: OpRequestAction, Action: &ProposedAction{
		Effect: "message", Summary: "answer the message", Derived: []ActionOrigin{testActionOrigin()},
	}})
	if !reply.OK || !reply.Authorised || reply.Decision != "allow" {
		t.Fatalf("answering a message required a person: %+v", reply)
	}
	// Nothing was written down, because nothing was asked.
	if waiting := h.owner(t, Request{Op: OpPendingActions}); len(waiting.Actions) != 0 {
		t.Fatalf("an allowed action was put to the owner: %+v", waiting)
	}
}

// A malformed proposal is refused as a result rather than escalated: no owner
// decision makes it coherent.
func TestMalformedProposalIsRefusedNotAsked(t *testing.T) {
	h := newHarness(t)
	response := h.call(t, Request{Op: OpRequestAction, Action: testProposal("delete-everything")})
	if !response.OK || response.Decision != "refuse" {
		t.Fatalf("an unknown effect was not refused: %+v", response)
	}
	if waiting := h.owner(t, Request{Op: OpPendingActions}); len(waiting.Actions) != 0 {
		t.Fatalf("a malformed proposal was put to the owner: %+v", waiting)
	}
}

// The mandate is the owner's. A runtime that could supply the mandate it is
// judged against would be setting its own ceiling.
func TestSpendIsJudgedAgainstTheOwnersMandate(t *testing.T) {
	h := newHarness(t)
	mandateID := h.placeMandate(t)

	// Inside the mandate, but received content drove it, and the default
	// ceiling does not let received content reach a spend.
	prompted := testProposal("spend", testActionOrigin())
	prompted.Terms = testPurchase(200)
	driven := h.call(t, Request{Op: OpRequestAction, Action: prompted, MandateID: mandateID})
	if driven.Decision != "require-owner-approval" {
		t.Fatalf("a stranger's message reached a payment: %+v", driven)
	}

	// The Agent's own initiative, inside the mandate, still stops: the default
	// own-initiative ceiling is a tool call.
	own := testProposal("spend")
	own.Terms = testPurchase(200)
	unprompted := h.call(t, Request{Op: OpRequestAction, Action: own, MandateID: mandateID})
	if unprompted.Decision != "require-owner-approval" {
		t.Fatalf("a payment ran unattended under the default ceiling: %+v", unprompted)
	}

	// A mandate nobody placed authorises nothing.
	unknown := h.call(t, Request{Op: OpRequestAction, Action: own,
		MandateID: "mdt_" + strings.Repeat("e", 64)})
	if unknown.OK {
		t.Fatalf("a spend was judged against a mandate nobody placed: %+v", unknown)
	}

	// Withdrawing it stops further spends under it, and the record survives.
	if revoked := h.owner(t, Request{Op: OpRevokeMandate, MandateID: mandateID}); !revoked.OK {
		t.Fatalf("revoke: %+v", revoked)
	}
	after := h.call(t, Request{Op: OpRequestAction, Action: own, MandateID: mandateID})
	if after.OK {
		t.Fatalf("a withdrawn mandate still authorised a spend: %+v", after)
	}
	held := h.owner(t, Request{Op: OpListMandates})
	if len(held.Mandates) != 1 || held.Mandates[0].RevokedAtUnix == 0 {
		t.Fatalf("the withdrawal did not survive as a record: %+v", held)
	}
}

// Only the owner writes mandates. Both sides may read them, because an Agent
// has to know what it may spend before it negotiates.
func TestOnlyTheOwnerWritesMandates(t *testing.T) {
	h := newHarness(t)
	h.placeMandate(t)

	writes := []Request{
		{Op: OpPlaceMandate, Mandate: &MandateTerms{
			Objective: "spend freely", Authority: "commit", CapabilityClass: "anything",
			Asset: testAssetIdentity(), MaxTotalAtomic: "1", ApprovalAboveAtomic: "1",
			MaxCounteroffers: 1, ExpiresAtUnix: baseUnix + 10,
		}},
		{Op: OpRevokeMandate, MandateID: "mdt_" + strings.Repeat("a", 64)},
	}
	for _, request := range writes {
		if response := h.runtimeAttempt(t, request); response.OK {
			t.Fatalf("the runtime performed %q", request.Op)
		}
	}
	if listing := h.call(t, Request{Op: OpListMandates}); !listing.OK || len(listing.Mandates) != 1 {
		t.Fatalf("the runtime could not read what it may spend: %+v", listing)
	}
}

// A spend that names no mandate, and a non-spend that carries terms, are both
// refused before anything is judged.
func TestSpendShapeIsEnforced(t *testing.T) {
	spend := testProposal("spend", testActionOrigin())
	spend.Terms = testPurchase(200)
	if _, err := EncodeRequest(Request{Op: OpRequestAction, Action: spend}); err == nil {
		t.Fatal("a spend with no mandate was accepted")
	}
	noTerms := testProposal("spend", testActionOrigin())
	if _, err := EncodeRequest(Request{Op: OpRequestAction, Action: noTerms,
		MandateID: "mdt_" + strings.Repeat("a", 64)}); err == nil {
		t.Fatal("a spend with no terms was accepted")
	}
	message := testProposal("message", testActionOrigin())
	message.Terms = testPurchase(200)
	if _, err := EncodeRequest(Request{Op: OpRequestAction, Action: message}); err == nil {
		t.Fatal("a message carried purchase terms")
	}
}

// Peer credentials establish which Unix user is calling, and the Agent runtime
// commonly is that user. What separates the owner is a key the runtime does
// not have, so an unsigned or wrongly signed decision is refused however it
// arrived.
func TestOwnerDecisionsNeedTheOwnersKey(t *testing.T) {
	h := newHarness(t)
	event := h.accept(t, "hello")
	held := Request{Op: OpAdmit, EventID: event.EventID}

	issued := h.callAs(t, PrincipalOwner, Request{Op: OpChallenge})
	if !issued.OK || issued.Challenge == "" {
		t.Fatalf("challenge: %+v", issued)
	}

	// Someone else's key does not do.
	stranger := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x99}, ed25519.SeedSize))
	forged, err := SignDecision(held, issued.Challenge, stranger)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	attempt := held
	attempt.Challenge = issued.Challenge
	attempt.OwnerSignature = forged
	if response := h.callAs(t, PrincipalOwner, attempt); response.OK {
		t.Fatal("a decision signed by a stranger was accepted")
	}

	// A signature for one decision is not a signature for another.
	other := Request{Op: OpRefuse, EventID: event.EventID, Code: fault.CodeRejected}
	genuine, err := SignDecision(held, issued.Challenge, testOwnerKey())
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	other.Challenge = issued.Challenge
	other.OwnerSignature = genuine
	if response := h.callAs(t, PrincipalOwner, other); response.OK {
		t.Fatal("a signature for one decision authorised another")
	}

	// The genuine one works, once.
	attempt.OwnerSignature = genuine
	if response := h.callAs(t, PrincipalOwner, attempt); !response.OK {
		t.Fatalf("the owner's own decision was refused: %+v", response)
	}
	if response := h.callAs(t, PrincipalOwner, attempt); response.OK {
		t.Fatal("a decision was replayed")
	}
}

// A challenge is single use and does not outlive its window.
func TestChallengesExpireAndDoNotRepeat(t *testing.T) {
	h := newHarness(t)
	first := h.callAs(t, PrincipalOwner, Request{Op: OpChallenge})
	second := h.callAs(t, PrincipalOwner, Request{Op: OpChallenge})
	if first.Challenge == second.Challenge {
		t.Fatal("two challenges were the same")
	}

	event := h.accept(t, "hello")
	request := Request{Op: OpAdmit, EventID: event.EventID}
	signature, err := SignDecision(request, first.Challenge, testOwnerKey())
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	request.Challenge = first.Challenge
	request.OwnerSignature = signature

	h.clock = h.clock.Add(DefaultChallengeLifetime + time.Second)
	if response := h.callAs(t, PrincipalOwner, request); response.OK {
		t.Fatal("an expired challenge was accepted")
	}
}

// A wrong signature must not burn a challenge the owner is about to use.
func TestAFailedAttemptDoesNotConsumeTheChallenge(t *testing.T) {
	h := newHarness(t)
	event := h.accept(t, "hello")
	issued := h.callAs(t, PrincipalOwner, Request{Op: OpChallenge})

	request := Request{Op: OpAdmit, EventID: event.EventID, Challenge: issued.Challenge}
	stranger := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x99}, ed25519.SeedSize))
	forged, err := SignDecision(request, issued.Challenge, stranger)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	request.OwnerSignature = forged
	if response := h.callAs(t, PrincipalOwner, request); response.OK {
		t.Fatal("a forged decision was accepted")
	}

	genuine, err := SignDecision(Request{Op: OpAdmit, EventID: event.EventID}, issued.Challenge, testOwnerKey())
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	request.OwnerSignature = genuine
	if response := h.callAs(t, PrincipalOwner, request); !response.OK {
		t.Fatalf("a failed attempt consumed the challenge: %+v", response)
	}
}

// A spend the policy allows is authorised once. One decision -- the owner's or
// the policy's -- backs one execution, and the second occurrence of the same
// purchase finds its grant already spent.
func TestAllowedSpendIsAuthorisedOnce(t *testing.T) {
	h := newHarnessWithPolicy(t, firewall.Policy{
		UnattendedCeiling:    firewall.EffectSpend,
		OwnInitiativeCeiling: firewall.EffectSpend,
	})
	mandateID := h.placeMandate(t)
	spend := testProposal("spend", testActionOrigin())
	spend.Terms = testPurchase(200)

	asked := h.call(t, Request{Op: OpRequestAction, Action: spend, MandateID: mandateID})
	if !asked.OK || asked.Decision != "allow" {
		t.Fatalf("a spend inside the mandate was not allowed: %+v", asked)
	}
	// Allowed is not yet authorised: the grant has to be claimed.
	if asked.Authorised {
		t.Fatalf("an allowed spend was authorised without a claim: %+v", asked)
	}
	if asked.State != "granted" {
		t.Fatalf("the policy's grant was not recorded: %+v", asked)
	}

	first := h.call(t, Request{Op: OpClaimAction, ActionID: asked.ActionID})
	if !first.Authorised {
		t.Fatalf("a granted spend could not proceed: %+v", first)
	}
	second := h.call(t, Request{Op: OpClaimAction, ActionID: asked.ActionID})
	if second.Authorised {
		t.Fatal("one policy decision backed two executions")
	}
	// Asking again does not mint a second execution either.
	again := h.call(t, Request{Op: OpRequestAction, Action: spend, MandateID: mandateID})
	if again.State != "spent" {
		t.Fatalf("re-asking reopened a spent grant: %+v", again)
	}
	if claimed := h.call(t, Request{Op: OpClaimAction, ActionID: again.ActionID}); claimed.Authorised {
		t.Fatal("a replayed purchase was executed")
	}

	// A reply stays inline: the machinery is spent where the damage is.
	reply := h.call(t, Request{Op: OpRequestAction, Action: &ProposedAction{
		Effect: "message", Summary: "answer", Derived: []ActionOrigin{testActionOrigin()},
	}})
	if !reply.Authorised {
		t.Fatalf("a reply needed a claim: %+v", reply)
	}
}
