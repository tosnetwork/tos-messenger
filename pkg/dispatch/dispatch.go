// Package dispatch sends queued events and decides what to do when a send
// fails.
//
// It is the outbound half of what the admission gate does inbound, and it owns
// one rule that is easy to get wrong: a retry sends the message that was
// already sealed, not a newly sealed one. Sealing again for every network
// retry would consume a message key per attempt, and a ratchet that advances
// once per lost packet is a ratchet that runs away from the peer.
//
// Nothing here chooses a route. The transport is frozen only after the
// reachability study, so a Sender is supplied and this package never learns
// how the bytes travel.
package dispatch

import (
	"bytes"
	"context"
	"crypto/rand"
	"errors"
	"strings"
	"time"

	"github.com/tosnetwork/tos-messenger/internal/canon"
	"github.com/tosnetwork/tos-messenger/internal/ids"
	"github.com/tosnetwork/tos-messenger/pkg/e2ee"
	"github.com/tosnetwork/tos-messenger/pkg/envelope"
	"github.com/tosnetwork/tos-messenger/pkg/eventlog"
	"github.com/tosnetwork/tos-messenger/pkg/fault"
	"github.com/tosnetwork/tos-messenger/pkg/payload"
	nativev1 "github.com/tosnetwork/tos-service-protocol/gen/tos/service/v1"
)

// Message is one sealed event handed to a transport.
type Message struct {
	EventID             string
	SessionID           string
	RecipientEndpointID string
	RecipientDeviceID   string
	ConversationID      string
	// Bootstrap is present on an initiator's first-contact retries and contains
	// only signed public prekey evidence and suite initial bytes.
	Bootstrap      []byte
	AdmissionToken string
	Ciphertext     []byte
	ExpiresAtUnix  uint64
}

// Sender delivers a sealed message.
//
// It returns nil once a recipient device has durably accepted the message, and
// otherwise an error whose fault code says what to do next. Returning nil for
// "handed to the network" would turn every lost packet into a delivered
// message.
type Sender interface {
	Send(context.Context, Message) error
}

// BindingResolver supplies the associated data one delivery is bound to.
//
// This package cannot construct it: the binding names both devices, and which
// device of a multi-device recipient a message is for is a routing decision
// made above.
type BindingResolver interface {
	BindingFor(eventlog.Delivery) (e2ee.Binding, error)
}

// Config wires one dispatcher.
//
// The journal is required and the sending half is not. Queueing an event needs
// somewhere durable to put it; sealing and sending need a frozen suite and a
// chosen route, and neither exists yet. An installation without them can
// accumulate outbound events safely and cannot pretend to deliver them, which
// is exactly the state this project is in.
type Config struct {
	Journal  *eventlog.Journal
	Suite    e2ee.Suite
	Sender   Sender
	Bindings BindingResolver
	Now      func() time.Time
	// Identity is who this installation is. Outbound events must say they came
	// from it, because a runtime that could set the sender fields freely could
	// send as somebody else from this daemon's own sessions.
	Identity Identity
	// Network is fixed by daemon configuration. It is deliberately not a
	// compose-call argument: a runtime may choose words, not their chain domain.
	Network *nativev1.NetworkDomain
	// AllowedEventClasses is the outbound authority granted by the live
	// endpoint delegation. Nil leaves the dispatcher reusable for callers that
	// enforce authority at a higher boundary; daemon startup always supplies
	// the finalized delegation's non-empty list.
	AllowedEventClasses []string
	// AttemptLease bounds how long one sweep may hold a delivery. A lease that
	// never expires strands an event when the sweep holding it dies.
	AttemptLease time.Duration
}

// ComposeRequest is the semantic subset an Agent runtime may choose.
type ComposeRequest struct {
	ConversationID, RoomID, ReplyToEventID string
	MembershipEpoch                        uint64
	MediaType, Body, IdempotencyKey        string
	SessionID, RecipientEndpointID         string
	RecipientAgentID                       string
	ExpiresAtUnix                          uint64
}

// ProtocolResultRequest is the narrow runtime-selected meaning of a reply.
// Identity, network, clock, schema and Event ID remain daemon-owned.
type ProtocolResultRequest struct {
	ConversationID, ReplyToEventID string
	Kind, Protocol, Version        string
	Body                           []byte
	IdempotencyKey                 string
	SessionID, RecipientEndpointID string
	ExpiresAtUnix                  uint64
}

// AttachmentRequest is assembled only by the daemon-owned attachment
// emitter after it has encrypted the complete plaintext and obtained exact
// Endpoint-signed storage grants. An Agent runtime never supplies Reference,
// capability, locator, sender, network, clock, kind, or Event ID fields.
type AttachmentRequest struct {
	ConversationID, RoomID, ReplyToEventID string
	IdempotencyKey, IntentDigest           string
	SessionID, RecipientEndpointID         string
	ExpiresAtUnix                          uint64
	Attachment                             payload.EncryptedAttachment
}

// HistoryRequest is one owner-authorized direct-history page. The dispatcher
// derives the source identity, recipient endpoint, device session, network,
// Event kind, and Event ID; none is supplied by the caller.
type HistoryRequest struct {
	TargetDeviceID, ConversationID string
	Sequence                       uint64
	PreviousSegmentDigest          string
	AfterCreatedAtUnix             uint64
	AfterEventID, IdempotencyKey   string
	Limit                          int
	ExpiresAtUnix                  uint64
}

// DefaultAttemptLease is how long one sweep holds a delivery by default.
const DefaultAttemptLease = 2 * time.Minute

// Identity is the Agent, endpoint, and device this installation speaks for.
type Identity struct {
	AgentID    string
	EndpointID string
	DeviceID   string
}

// Validate enforces a complete local identity.
func (i Identity) Validate() error {
	if !ids.Agent.MatchString(i.AgentID) {
		return errors.New("invalid local Agent identifier")
	}
	if !ids.Endpoint.MatchString(i.EndpointID) {
		return errors.New("invalid local endpoint identifier")
	}
	if !ids.Device.MatchString(i.DeviceID) {
		return errors.New("invalid local device identifier")
	}
	return nil
}

// Dispatcher sends what the journal says is due.
type Dispatcher struct {
	config  Config
	allowed map[string]struct{}
}

// Summary is what one sweep did.
type Summary struct {
	// Sent counts messages a recipient durably accepted.
	Sent int
	// Sealed counts messages sealed during this sweep. It is lower than Sent
	// whenever a retry reused a committed ciphertext, which is the point.
	Sealed int
	// Retried counts failures that will be attempted again.
	Retried int
	// Held counts messages waiting on an owner decision rather than on time.
	Held int
	// Abandoned counts messages no further attempt can deliver.
	Abandoned int
}

// ErrNoTransport reports a dispatcher that can queue but not send.
var ErrNoTransport = errors.New("no transport is configured")

// New builds a dispatcher.
//
// The sending half is all or nothing: a dispatcher with a suite but no sender
// would seal messages nothing can carry, advancing a ratchet for nothing.
func New(config Config) (*Dispatcher, error) {
	if config.Journal == nil {
		return nil, errors.New("dispatch requires a durable journal")
	}
	if err := config.Identity.Validate(); err != nil {
		return nil, err
	}
	present := 0
	for _, dependency := range []bool{config.Suite != nil, config.Sender != nil, config.Bindings != nil} {
		if dependency {
			present++
		}
	}
	if present != 0 && present != 3 {
		return nil, errors.New("a sending dispatcher needs a suite, a sender, and a binding resolver")
	}
	if config.Now == nil {
		config.Now = time.Now
	}
	if config.AttemptLease == 0 {
		config.AttemptLease = DefaultAttemptLease
	}
	if config.AttemptLease < time.Second {
		return nil, errors.New("the send attempt lease is below its floor")
	}
	var allowed map[string]struct{}
	if config.AllowedEventClasses != nil {
		allowed = make(map[string]struct{}, len(config.AllowedEventClasses))
		for _, class := range config.AllowedEventClasses {
			if class == "" {
				return nil, errors.New("dispatch event authority contains an empty class")
			}
			if _, duplicate := allowed[class]; duplicate {
				return nil, errors.New("dispatch event authority contains a duplicate class")
			}
			allowed[class] = struct{}{}
		}
		if len(allowed) == 0 {
			return nil, errors.New("dispatch event authority is empty")
		}
	}
	return &Dispatcher{config: config, allowed: allowed}, nil
}

// CanSend reports whether this dispatcher has a transport.
func (d *Dispatcher) CanSend() bool {
	return d != nil && d.config.Suite != nil && d.config.Sender != nil && d.config.Bindings != nil
}

// ConfigureTransport installs the complete carrier tuple during daemon
// assembly. Partial installation and replacement are refused; callers must do
// this before serving or sweeping.
func (d *Dispatcher) ConfigureTransport(suite e2ee.Suite, sender Sender, bindings BindingResolver) error {
	if d == nil || suite == nil || sender == nil || bindings == nil {
		return errors.New("a sending dispatcher needs a suite, a sender, and a binding resolver")
	}
	if d.CanSend() {
		return errors.New("dispatcher transport is already configured")
	}
	d.config.Suite, d.config.Sender, d.config.Bindings = suite, sender, bindings
	return nil
}

// LocalIdentity returns the daemon-owned identity used for every composition.
func (d *Dispatcher) LocalIdentity() Identity {
	if d == nil {
		return Identity{}
	}
	return d.config.Identity
}

// Network returns a defensive copy of the daemon-owned chain domain. It is
// exposed for daemon subsystems that must repeat the exact Event domain in an
// independently signed authority object; runtimes cannot set it.
func (d *Dispatcher) Network() *nativev1.NetworkDomain {
	if d == nil || d.config.Network == nil {
		return nil
	}
	return &nativev1.NetworkDomain{NetworkId: d.config.Network.NetworkId,
		GenesisRootHash: d.config.Network.GenesisRootHash, GenesisFileHash: d.config.Network.GenesisFileHash}
}

// Queue records an event for delivery.
//
// The plaintext is stored before anything is sealed, so a crash between
// advancing the session and committing the ciphertext leaves something to seal
// again.
func (d *Dispatcher) Queue(event envelope.Event, sessionID, recipientEndpointID string, expiresAtUnix uint64) (bool, eventlog.Delivery, error) {
	stored, now, err := d.prepareQueue(event)
	if err != nil {
		return false, eventlog.Delivery{}, err
	}
	return d.config.Journal.Enqueue(eventlog.Outbound{
		EventID: event.EventID, SessionID: sessionID, RecipientEndpointID: recipientEndpointID,
		ConversationID: event.ConversationID, Payload: stored, CreatedAtUnix: uint64(now.Unix()),
		ExpiresAtUnix: expiresAtUnix,
	})
}

// CopyTarget is one daemon-selected device destination for a logical Event.
type CopyTarget struct {
	SessionID, RecipientEndpointID, RecipientDeviceID string
}

// QueueCopies records one independently sealed delivery per verified device.
// Every copy carries the same Event bytes and EventID; only the journal key and
// cryptographic device session differ.
func (d *Dispatcher) QueueCopies(event envelope.Event, targets []CopyTarget,
	expiresAtUnix uint64) ([]eventlog.Delivery, error) {
	stored, now, err := d.prepareQueue(event)
	if err != nil {
		return nil, err
	}
	if len(targets) == 0 || len(targets) > e2ee.MaxDevicesPerSet*2-1 {
		return nil, errors.New("invalid delivery fan-out size")
	}
	deliveries := make([]eventlog.Delivery, 0, len(targets))
	for _, target := range targets {
		copyID, err := eventlog.NewDeliveryCopyID(event.EventID, target.RecipientEndpointID, target.RecipientDeviceID)
		if err != nil {
			return nil, err
		}
		_, delivery, err := d.config.Journal.Enqueue(eventlog.Outbound{DeliveryID: copyID,
			EventID: event.EventID, SessionID: target.SessionID,
			RecipientEndpointID: target.RecipientEndpointID, RecipientDeviceID: target.RecipientDeviceID,
			ConversationID: event.ConversationID, Payload: stored, CreatedAtUnix: uint64(now.Unix()),
			ExpiresAtUnix: expiresAtUnix})
		if err != nil {
			return nil, err
		}
		deliveries = append(deliveries, delivery)
	}
	return deliveries, nil
}

func (d *Dispatcher) prepareQueue(event envelope.Event) ([]byte, time.Time, error) {
	if d == nil {
		return nil, time.Time{}, errors.New("no dispatcher")
	}
	if err := envelope.ValidateEvent(event); err != nil {
		return nil, time.Time{}, err
	}
	if !d.authorizedKind(event.Kind) {
		return nil, time.Time{}, errors.New("event class is not authorized by the endpoint delegation")
	}
	// A local-only kind carries authority granted here. The receiving side
	// refuses it on every route, and refusing to send it is what makes the
	// invariant hold at both ends rather than only at the far one.
	if envelope.LocalOnly(event.Kind) {
		return nil, time.Time{}, errors.New("this event kind exists only on the owner's own interface")
	}
	// The sender fields say who this came from, and a runtime does not get to
	// choose that: the session it would be sealed under belongs to this
	// installation.
	if event.SenderAgentID != d.config.Identity.AgentID ||
		event.SenderEndpointID != d.config.Identity.EndpointID ||
		event.SenderDeviceID != d.config.Identity.DeviceID {
		return nil, time.Time{}, errors.New("event does not come from this installation")
	}
	// A body that does not meet its own kind's contract must not leave here.
	// The recipient will refuse it, and queueing it would spend the sender's
	// delivery attempts on a message that was never going to be interpreted.
	if err := payload.Validate(event.Kind, event.Content); err != nil {
		return nil, time.Time{}, err
	}
	stored, err := envelope.EncodeEventJSON(event)
	if err != nil {
		return nil, time.Time{}, err
	}
	now := d.config.Now()
	if now.IsZero() || now.Unix() < 0 {
		return nil, time.Time{}, errors.New("invalid dispatch time")
	}
	return stored, now, nil
}

// ComposeAndQueue constructs the canonical event under daemon-owned identity,
// network, clock and kind, then durably binds it to the runtime's idempotency
// key before queueing it. A process crash at either boundary is retry-safe.
func (d *Dispatcher) ComposeAndQueue(request ComposeRequest) (envelope.Event, bool, error) {
	if d == nil || d.config.Network == nil {
		return envelope.Event{}, false, errors.New("dispatch composition has no network")
	}
	now := d.config.Now()
	if request.RecipientAgentID != "" && !ids.Agent.MatchString(request.RecipientAgentID) {
		return envelope.Event{}, false, errors.New("invalid expected recipient Agent identifier")
	}
	if request.RecipientAgentID != "" && d.CanSend() {
		binding, err := d.config.Bindings.BindingFor(eventlog.Delivery{
			SessionID: request.SessionID, RecipientEndpointID: request.RecipientEndpointID,
			ConversationID: request.ConversationID,
		})
		if err != nil || binding.RecipientAgentID != request.RecipientAgentID ||
			binding.RecipientEndpointID != request.RecipientEndpointID || binding.ConversationID != request.ConversationID {
			return envelope.Event{}, false, errors.New("outbound route is not bound to the expected recipient Agent")
		}
	}
	if now.IsZero() || now.Unix() < 0 || request.ExpiresAtUnix <= uint64(now.Unix()) {
		return envelope.Event{}, false, errors.New("invalid outbound lifetime")
	}
	kind := "text"
	var body payload.Payload = payload.Text{MediaType: request.MediaType, Body: request.Body, ReplyToEventID: request.ReplyToEventID}
	if request.RoomID != "" {
		kind = "room.message"
		body = payload.RoomMessage{RoomID: request.RoomID, Epoch: request.MembershipEpoch, MediaType: request.MediaType, Body: request.Body}
	}
	if !d.authorizedKind(kind) {
		return envelope.Event{}, false, errors.New("event class is not authorized by the endpoint delegation")
	}
	content, err := payload.Encode(body)
	if err != nil {
		return envelope.Event{}, false, err
	}
	event, err := envelope.NewEvent(envelope.Event{Network: d.config.Network,
		ConversationID: request.ConversationID, SenderAgentID: d.config.Identity.AgentID,
		SenderEndpointID: d.config.Identity.EndpointID, SenderDeviceID: d.config.Identity.DeviceID,
		RoomID: request.RoomID, ReplyToEventID: request.ReplyToEventID,
		CreatedAtUnix: uint64(now.Unix()), ExpiresAtUnix: request.ExpiresAtUnix,
		Kind: kind, IdempotencyKey: strings.TrimPrefix(request.IdempotencyKey, "idem_"), Content: content})
	if err != nil {
		return envelope.Event{}, false, err
	}
	encoded, err := envelope.EncodeEventJSON(event)
	if err != nil {
		return envelope.Event{}, false, err
	}
	intent := bytes.NewBufferString(canon.DomainOutboundIntent)
	for _, value := range []string{d.config.Network.NetworkId, d.config.Network.GenesisRootHash,
		d.config.Network.GenesisFileHash, d.config.Identity.AgentID, d.config.Identity.EndpointID,
		d.config.Identity.DeviceID, request.ConversationID, request.RoomID, request.ReplyToEventID, request.MediaType,
		request.Body, request.IdempotencyKey, request.SessionID, request.RecipientEndpointID, request.RecipientAgentID} {
		canon.Text(intent, value)
	}
	canon.Uint64(intent, request.MembershipEpoch)
	canon.Uint64(intent, request.ExpiresAtUnix)
	chosen, compositionFresh, err := d.config.Journal.ClaimOutboundComposition(request.IdempotencyKey, canon.Digest(intent.Bytes()), eventlog.Outbound{
		EventID: event.EventID, SessionID: request.SessionID, RecipientEndpointID: request.RecipientEndpointID,
		ConversationID: request.ConversationID, Payload: encoded, CreatedAtUnix: uint64(now.Unix()), ExpiresAtUnix: request.ExpiresAtUnix})
	if err != nil {
		return envelope.Event{}, false, err
	}
	if !compositionFresh {
		event, err = envelope.DecodeEventJSON(chosen.Payload)
		if err != nil {
			return envelope.Event{}, false, err
		}
	}
	fresh, _, err := d.config.Journal.Enqueue(chosen)
	return event, fresh, err
}

// ComposeProtocolResultAndQueue constructs only A2A responses and MCP results.
// Calls cannot be synthesized through this result-only boundary.
func (d *Dispatcher) ComposeProtocolResultAndQueue(request ProtocolResultRequest) (envelope.Event, bool, error) {
	if d == nil || d.config.Network == nil {
		return envelope.Event{}, false, errors.New("protocol result composition has no network")
	}
	now := d.config.Now()
	if now.IsZero() || now.Unix() < 0 || request.ExpiresAtUnix <= uint64(now.Unix()) ||
		request.Protocol == "" || request.Version != "1" || len(request.Body) == 0 {
		return envelope.Event{}, false, errors.New("invalid outbound protocol result")
	}
	foreign := payload.Foreign{Protocol: request.Protocol, Version: request.Version, Body: append([]byte(nil), request.Body...)}
	var body payload.Payload
	switch request.Kind {
	case "a2a.message":
		body = payload.A2AMessage{Foreign: foreign}
	case "mcp.result":
		body = payload.MCPResult{Foreign: foreign}
	default:
		return envelope.Event{}, false, errors.New("kind is not an outbound protocol result")
	}
	if !d.authorizedKind(request.Kind) {
		return envelope.Event{}, false, errors.New("event class is not authorized by the endpoint delegation")
	}
	content, err := payload.Encode(body)
	if err != nil {
		return envelope.Event{}, false, err
	}
	event, err := envelope.NewEvent(envelope.Event{Network: d.config.Network,
		ConversationID: request.ConversationID, SenderAgentID: d.config.Identity.AgentID,
		SenderEndpointID: d.config.Identity.EndpointID, SenderDeviceID: d.config.Identity.DeviceID,
		ReplyToEventID: request.ReplyToEventID, CreatedAtUnix: uint64(now.Unix()), ExpiresAtUnix: request.ExpiresAtUnix,
		Kind: request.Kind, IdempotencyKey: strings.TrimPrefix(request.IdempotencyKey, "idem_"), Content: content})
	if err != nil {
		return envelope.Event{}, false, err
	}
	encoded, err := envelope.EncodeEventJSON(event)
	if err != nil {
		return envelope.Event{}, false, err
	}
	intent := bytes.NewBufferString(canon.DomainOutboundIntent)
	for _, value := range []string{d.config.Network.NetworkId, d.config.Network.GenesisRootHash,
		d.config.Network.GenesisFileHash, d.config.Identity.AgentID, d.config.Identity.EndpointID,
		d.config.Identity.DeviceID, request.ConversationID, request.ReplyToEventID, request.Kind,
		request.Protocol, request.Version, request.IdempotencyKey, request.SessionID, request.RecipientEndpointID} {
		canon.Text(intent, value)
	}
	canon.Bytes(intent, request.Body)
	canon.Uint64(intent, request.ExpiresAtUnix)
	chosen, compositionFresh, err := d.config.Journal.ClaimOutboundComposition(request.IdempotencyKey, canon.Digest(intent.Bytes()), eventlog.Outbound{
		EventID: event.EventID, SessionID: request.SessionID, RecipientEndpointID: request.RecipientEndpointID,
		ConversationID: request.ConversationID, Payload: encoded, CreatedAtUnix: uint64(now.Unix()), ExpiresAtUnix: request.ExpiresAtUnix})
	if err != nil {
		return envelope.Event{}, false, err
	}
	if !compositionFresh {
		event, err = envelope.DecodeEventJSON(chosen.Payload)
		if err != nil {
			return envelope.Event{}, false, err
		}
	}
	fresh, _, err := d.config.Journal.Enqueue(chosen)
	return event, fresh, err
}

// LookupComposition returns a previously committed Event for an exact daemon
// intent. It is used before attachment encryption/upload so a completed retry
// performs no new external side effect.
func (d *Dispatcher) LookupComposition(idempotencyKey, intentDigest string) (envelope.Event, bool, error) {
	if d == nil {
		return envelope.Event{}, false, errors.New("no dispatcher")
	}
	chosen, found, err := d.config.Journal.OutboundComposition(idempotencyKey, intentDigest)
	if err != nil || !found {
		return envelope.Event{}, found, err
	}
	event, err := envelope.DecodeEventJSON(chosen.Payload)
	if err != nil || event.EventID != chosen.EventID || event.ConversationID != chosen.ConversationID {
		return envelope.Event{}, false, errors.New("stored outbound composition conflicts with its Event")
	}
	return event, true, nil
}

// LookupQueuedComposition returns a composition only after its exact delivery
// record is durable. Attachment emission deliberately commits a composition
// before contacting storage, so composition existence alone is not completion
// evidence: a crash may leave a prepared Event whose ciphertext lease was
// never acknowledged and whose delivery was never queued.
func (d *Dispatcher) LookupQueuedComposition(idempotencyKey, intentDigest string) (envelope.Event, bool, error) {
	event, found, err := d.LookupComposition(idempotencyKey, intentDigest)
	if err != nil || !found {
		return envelope.Event{}, found, err
	}
	delivery, queued, err := d.config.Journal.LookupDelivery(event.EventID)
	if err != nil {
		return envelope.Event{}, false, err
	}
	if !queued {
		return envelope.Event{}, false, errors.New("outbound composition is prepared but not queued")
	}
	payload, err := delivery.Payload()
	if err != nil {
		return envelope.Event{}, false, err
	}
	encoded, err := envelope.EncodeEventJSON(event)
	if err != nil || delivery.EventID != event.EventID || delivery.ConversationID != event.ConversationID ||
		!bytes.Equal(payload, encoded) {
		return envelope.Event{}, false, errors.New("queued outbound composition conflicts with its delivery")
	}
	return event, true, nil
}

// PrepareEncryptedAttachment durably binds the first complete, daemon-built
// Event to its idempotency intent without queueing it. The caller must obtain
// and verify the storage StoredAck before QueuePreparedAttachment; therefore a
// recipient can never receive an Event whose exact ciphertext lease was not
// acknowledged first.
func (d *Dispatcher) PrepareEncryptedAttachment(request AttachmentRequest) (envelope.Event, bool, error) {
	if d == nil || d.config.Network == nil {
		return envelope.Event{}, false, errors.New("attachment composition has no network")
	}
	if !d.authorizedKind("artifact.encrypted") {
		return envelope.Event{}, false, errors.New("event class is not authorized by the endpoint delegation")
	}
	now := d.config.Now()
	if now.IsZero() || now.Unix() < 0 || request.ExpiresAtUnix <= uint64(now.Unix()) {
		return envelope.Event{}, false, errors.New("invalid outbound attachment lifetime")
	}
	content, err := payload.Encode(request.Attachment)
	if err != nil {
		return envelope.Event{}, false, err
	}
	event, err := envelope.NewEvent(envelope.Event{Network: d.config.Network,
		ConversationID: request.ConversationID, SenderAgentID: d.config.Identity.AgentID,
		SenderEndpointID: d.config.Identity.EndpointID, SenderDeviceID: d.config.Identity.DeviceID,
		RoomID: request.RoomID, ReplyToEventID: request.ReplyToEventID,
		CreatedAtUnix: uint64(now.Unix()), ExpiresAtUnix: request.ExpiresAtUnix,
		Kind: "artifact.encrypted", IdempotencyKey: strings.TrimPrefix(request.IdempotencyKey, "idem_"),
		Content: content, AttachmentReferences: []string{request.Attachment.ManifestDigest}})
	if err != nil {
		return envelope.Event{}, false, err
	}
	encoded, err := envelope.EncodeEventJSON(event)
	if err != nil {
		return envelope.Event{}, false, err
	}
	chosen, fresh, err := d.config.Journal.ClaimOutboundComposition(request.IdempotencyKey, request.IntentDigest, eventlog.Outbound{
		EventID: event.EventID, SessionID: request.SessionID, RecipientEndpointID: request.RecipientEndpointID,
		ConversationID: request.ConversationID, Payload: encoded, CreatedAtUnix: uint64(now.Unix()),
		ExpiresAtUnix: request.ExpiresAtUnix})
	if err != nil {
		return envelope.Event{}, false, err
	}
	if !fresh {
		event, err = envelope.DecodeEventJSON(chosen.Payload)
		if err != nil {
			return envelope.Event{}, false, err
		}
	}
	return event, fresh, nil
}

// QueuePreparedAttachment queues the exact previously prepared Event after a
// verified StoredAck. Queue is idempotent, including a crash after enqueue and
// before the attachment transaction is removed.
func (d *Dispatcher) QueuePreparedAttachment(event envelope.Event, sessionID, recipientEndpointID string, expiresAtUnix uint64) (bool, error) {
	fresh, _, err := d.Queue(event, sessionID, recipientEndpointID, expiresAtUnix)
	return fresh, err
}

// ComposeHistoryAndQueue builds a stable page from durable applied/delivered
// Events and queues it to another device of this Endpoint. The idempotency
// intent describes the requested page, not the current journal contents, so a
// retry returns the first committed Event even if newer messages arrived.
func (d *Dispatcher) ComposeHistoryAndQueue(request HistoryRequest) (envelope.Event, payload.DeviceHistorySegment, bool, error) {
	if d == nil || d.config.Network == nil {
		return envelope.Event{}, payload.DeviceHistorySegment{}, false, errors.New("history composition has no network")
	}
	if !d.authorizedKind("device.history.segment") {
		return envelope.Event{}, payload.DeviceHistorySegment{}, false,
			errors.New("event class is not authorized by the endpoint delegation")
	}
	now := d.config.Now()
	if now.IsZero() || now.Unix() < 0 || request.ExpiresAtUnix <= uint64(now.Unix()) {
		return envelope.Event{}, payload.DeviceHistorySegment{}, false, errors.New("invalid history lifetime")
	}
	sessionID, err := e2ee.DeviceSessionID(d.config.Identity.DeviceID, request.TargetDeviceID)
	if err != nil {
		return envelope.Event{}, payload.DeviceHistorySegment{}, false, err
	}
	segment, err := d.config.Journal.BuildHistorySegment(d.config.Identity.DeviceID, request.TargetDeviceID,
		request.ConversationID, request.Sequence, request.PreviousSegmentDigest,
		request.AfterCreatedAtUnix, request.AfterEventID, request.Limit)
	if err != nil {
		return envelope.Event{}, payload.DeviceHistorySegment{}, false, err
	}
	content, err := payload.Encode(segment)
	if err != nil {
		return envelope.Event{}, payload.DeviceHistorySegment{}, false, err
	}
	event, err := envelope.NewEvent(envelope.Event{Network: d.config.Network,
		ConversationID: request.ConversationID, SenderAgentID: d.config.Identity.AgentID,
		SenderEndpointID: d.config.Identity.EndpointID, SenderDeviceID: d.config.Identity.DeviceID,
		CreatedAtUnix: uint64(now.Unix()), ExpiresAtUnix: request.ExpiresAtUnix,
		Kind: "device.history.segment", IdempotencyKey: strings.TrimPrefix(request.IdempotencyKey, "idem_"), Content: content})
	if err != nil {
		return envelope.Event{}, payload.DeviceHistorySegment{}, false, err
	}
	encoded, err := envelope.EncodeEventJSON(event)
	if err != nil {
		return envelope.Event{}, payload.DeviceHistorySegment{}, false, err
	}
	intent := bytes.NewBufferString(canon.DomainOutboundIntent)
	for _, value := range []string{d.config.Network.NetworkId, d.config.Network.GenesisRootHash,
		d.config.Network.GenesisFileHash, d.config.Identity.AgentID, d.config.Identity.EndpointID,
		d.config.Identity.DeviceID, request.TargetDeviceID, request.ConversationID,
		request.PreviousSegmentDigest, request.AfterEventID, request.IdempotencyKey, sessionID} {
		canon.Text(intent, value)
	}
	canon.Uint64(intent, request.Sequence)
	canon.Uint64(intent, request.AfterCreatedAtUnix)
	canon.Uint32(intent, uint32(request.Limit))
	canon.Uint64(intent, request.ExpiresAtUnix)
	chosen, _, err := d.config.Journal.ClaimOutboundComposition(request.IdempotencyKey,
		canon.Digest(intent.Bytes()), eventlog.Outbound{EventID: event.EventID, SessionID: sessionID,
			RecipientEndpointID: d.config.Identity.EndpointID, ConversationID: request.ConversationID,
			Payload: encoded, CreatedAtUnix: uint64(now.Unix()), ExpiresAtUnix: request.ExpiresAtUnix})
	if err != nil {
		return envelope.Event{}, payload.DeviceHistorySegment{}, false, err
	}
	if chosen.EventID != event.EventID {
		event, err = envelope.DecodeEventJSON(chosen.Payload)
		if err != nil {
			return envelope.Event{}, payload.DeviceHistorySegment{}, false, err
		}
		decoded, decodeErr := payload.Decode(event.Kind, event.Content)
		var ok bool
		segment, ok = decoded.(payload.DeviceHistorySegment)
		if decodeErr != nil || !ok {
			return envelope.Event{}, payload.DeviceHistorySegment{}, false, errors.New("invalid committed history composition")
		}
	}
	fresh, _, err := d.config.Journal.Enqueue(chosen)
	return event, segment, fresh, err
}

func (d *Dispatcher) authorizedKind(kind string) bool {
	class, known := envelope.ClassOf(kind)
	if !known {
		return false
	}
	if d.allowed == nil {
		return true
	}
	_, authorized := d.allowed[class]
	return authorized
}

// Sweep attempts every delivery whose next attempt has arrived.
//
// One failing delivery does not stop the others: a peer that is unreachable
// would otherwise block every message to everyone else.
func (d *Dispatcher) Sweep(ctx context.Context, limit int) (Summary, error) {
	if d == nil {
		return Summary{}, errors.New("no dispatcher")
	}
	if !d.CanSend() {
		// Queued events stay queued. Reporting an error here rather than
		// sweeping nothing keeps an operator from reading a quiet daemon as a
		// working one.
		return Summary{}, ErrNoTransport
	}
	now := d.config.Now()
	if now.IsZero() || now.Unix() < 0 {
		return Summary{}, errors.New("invalid dispatch time")
	}
	due, err := d.config.Journal.Due(now)
	if err != nil {
		return Summary{}, err
	}
	if limit > 0 && len(due) > limit {
		due = due[:limit]
	}
	summary := Summary{}
	for _, delivery := range due {
		if err := ctx.Err(); err != nil {
			return summary, err
		}
		attemptID, err := newAttemptID()
		if err != nil {
			return summary, err
		}
		// One sweep at a time owns a delivery. Two sweeps reading the same due
		// list would otherwise both send it; the session conflict check stops
		// the second ratchet advance but not the second message.
		// The claim returns the delivery as it now stands, and that is the one
		// the attempt works from. Carrying on with the copy read before the
		// claim would mean acting on state the claim may have changed.
		claimed, err := d.config.Journal.ClaimForSend(delivery.Key(), attemptID, now, d.config.AttemptLease)
		if err != nil {
			continue
		}
		sealed, err := d.attempt(ctx, claimed, attemptID, now)
		if sealed {
			summary.Sealed++
		}
		if err == nil {
			summary.Sent++
			continue
		}
		settled, failErr := d.config.Journal.Failed(delivery.Key(), attemptID, fault.CodeOf(err), d.config.Now())
		if failErr != nil {
			return summary, failErr
		}
		switch settled.State {
		case eventlog.StateHeld:
			summary.Held++
		case eventlog.StateAbandoned:
			summary.Abandoned++
		default:
			summary.Retried++
		}
	}
	return summary, nil
}

// attempt seals if necessary and sends. It reports whether it sealed.
func (d *Dispatcher) attempt(ctx context.Context, delivery eventlog.Delivery, attemptID string, now time.Time) (bool, error) {
	ciphertext, err := delivery.Ciphertext()
	if err != nil {
		return false, fault.Wrap(fault.CodeInternal, err)
	}
	sealed := false
	if ciphertext == nil {
		ciphertext, err = d.seal(delivery, attemptID, now)
		if err != nil {
			return false, err
		}
		sealed = true
	}
	record, found, err := d.config.Journal.SessionState(delivery.SessionID)
	if err != nil || !found {
		return sealed, fault.New(fault.CodeInternal, "no session bootstrap state")
	}
	var bootstrap []byte
	if record.BootstrapBase64 != "" {
		value, present, bootstrapErr := record.Bootstrap()
		if bootstrapErr != nil || !present {
			return sealed, fault.Wrap(fault.CodeInternal, bootstrapErr)
		}
		bootstrap, bootstrapErr = e2ee.EncodeFirstContactJSON(value)
		if bootstrapErr != nil {
			return sealed, fault.Wrap(fault.CodeInternal, bootstrapErr)
		}
	}
	message := Message{
		EventID:             delivery.EventID,
		SessionID:           delivery.SessionID,
		RecipientEndpointID: delivery.RecipientEndpointID,
		RecipientDeviceID:   delivery.RecipientDeviceID,
		ConversationID:      delivery.ConversationID,
		Bootstrap:           bootstrap,
		Ciphertext:          ciphertext,
		ExpiresAtUnix:       delivery.ExpiresAtUnix,
	}
	if err := d.config.Sender.Send(ctx, message); err != nil {
		return sealed, err
	}
	if _, err := d.config.Journal.Delivered(delivery.Key(), attemptID, d.config.Now()); err != nil {
		return sealed, fault.Wrap(fault.CodeInternal, err)
	}
	return sealed, nil
}

// seal advances the session and commits the ciphertext, in that order.
//
// A crash between the two loses the ciphertext and keeps the advance, so the
// next sweep seals again under a fresh key. The other order would leave a
// ciphertext that may already be on the wire while the state rolled back, and
// the next seal would reuse a message key.
func (d *Dispatcher) seal(delivery eventlog.Delivery, attemptID string, now time.Time) ([]byte, error) {
	record, found, err := d.config.Journal.SessionState(delivery.SessionID)
	if err != nil {
		return nil, fault.Wrap(fault.CodeInternal, err)
	}
	if !found {
		return nil, fault.New(fault.CodeInternal, "no session state for "+delivery.SessionID)
	}
	state, err := record.State()
	if err != nil {
		return nil, fault.Wrap(fault.CodeInternal, err)
	}
	if record.AlgorithmID != d.config.Suite.AlgorithmID() {
		// A session established under another suite cannot be continued by
		// this one, and guessing would produce ciphertext nobody can open.
		return nil, fault.New(fault.CodeSuiteUnsupported, record.AlgorithmID)
	}
	payload, err := delivery.Payload()
	if err != nil {
		return nil, fault.Wrap(fault.CodeInternal, err)
	}
	binding, err := d.config.Bindings.BindingFor(delivery)
	if err != nil {
		return nil, fault.Wrap(fault.CodeInternal, err)
	}
	associated, err := binding.Bytes()
	if err != nil {
		return nil, fault.Wrap(fault.CodeInternal, err)
	}
	ciphertext, next, err := d.config.Suite.Seal(state, payload, associated)
	if err != nil {
		return nil, fault.Wrap(fault.CodeInternal, err)
	}
	// The generation read before the transition is presented with it. If the
	// session moved while this seal was being prepared, the commit is refused
	// and this attempt's ciphertext is discarded rather than sent under a key
	// somebody else already used.
	if _, err := d.config.Journal.CommitSealed(delivery.SessionID, record.AlgorithmID,
		record.Generation, next, delivery.Key(), attemptID, ciphertext, now); err != nil {
		return nil, fault.Wrap(fault.CodeInternal, err)
	}
	return ciphertext, nil
}

func newAttemptID() (string, error) {
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return "", errors.New("generate send attempt identifier")
	}
	return eventlog.NewAttemptID(raw)
}
