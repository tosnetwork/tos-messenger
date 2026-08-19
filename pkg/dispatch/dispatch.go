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
	"context"
	"crypto/rand"
	"errors"
	"time"

	"github.com/tosnetwork/tos-messenger/internal/ids"
	"github.com/tosnetwork/tos-messenger/pkg/e2ee"
	"github.com/tosnetwork/tos-messenger/pkg/envelope"
	"github.com/tosnetwork/tos-messenger/pkg/eventlog"
	"github.com/tosnetwork/tos-messenger/pkg/fault"
)

// Message is one sealed event handed to a transport.
type Message struct {
	EventID             string
	SessionID           string
	RecipientEndpointID string
	ConversationID      string
	Ciphertext          []byte
	ExpiresAtUnix       uint64
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
	// AttemptLease bounds how long one sweep may hold a delivery. A lease that
	// never expires strands an event when the sweep holding it dies.
	AttemptLease time.Duration
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
	config Config
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
	return &Dispatcher{config: config}, nil
}

// CanSend reports whether this dispatcher has a transport.
func (d *Dispatcher) CanSend() bool {
	return d != nil && d.config.Suite != nil && d.config.Sender != nil && d.config.Bindings != nil
}

// Queue records an event for delivery.
//
// The plaintext is stored before anything is sealed, so a crash between
// advancing the session and committing the ciphertext leaves something to seal
// again.
func (d *Dispatcher) Queue(event envelope.Event, sessionID, recipientEndpointID string, expiresAtUnix uint64) (bool, eventlog.Delivery, error) {
	if d == nil {
		return false, eventlog.Delivery{}, errors.New("no dispatcher")
	}
	if err := envelope.ValidateEvent(event); err != nil {
		return false, eventlog.Delivery{}, err
	}
	// A local-only kind carries authority granted here. The receiving side
	// refuses it on every route, and refusing to send it is what makes the
	// invariant hold at both ends rather than only at the far one.
	if envelope.LocalOnly(event.Kind) {
		return false, eventlog.Delivery{}, errors.New("this event kind exists only on the owner's own interface")
	}
	// The sender fields say who this came from, and a runtime does not get to
	// choose that: the session it would be sealed under belongs to this
	// installation.
	if event.SenderAgentID != d.config.Identity.AgentID ||
		event.SenderEndpointID != d.config.Identity.EndpointID ||
		event.SenderDeviceID != d.config.Identity.DeviceID {
		return false, eventlog.Delivery{}, errors.New("event does not come from this installation")
	}
	payload, err := envelope.EncodeEventJSON(event)
	if err != nil {
		return false, eventlog.Delivery{}, err
	}
	now := d.config.Now()
	if now.IsZero() || now.Unix() < 0 {
		return false, eventlog.Delivery{}, errors.New("invalid dispatch time")
	}
	return d.config.Journal.Enqueue(eventlog.Outbound{
		EventID:             event.EventID,
		SessionID:           sessionID,
		RecipientEndpointID: recipientEndpointID,
		ConversationID:      event.ConversationID,
		Payload:             payload,
		CreatedAtUnix:       uint64(now.Unix()),
		ExpiresAtUnix:       expiresAtUnix,
	})
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
		if _, err := d.config.Journal.ClaimForSend(delivery.EventID, attemptID, now, d.config.AttemptLease); err != nil {
			continue
		}
		sealed, err := d.attempt(ctx, delivery, attemptID, now)
		if sealed {
			summary.Sealed++
		}
		if err == nil {
			summary.Sent++
			continue
		}
		settled, failErr := d.config.Journal.Failed(delivery.EventID, attemptID, fault.CodeOf(err), d.config.Now())
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
		ciphertext, err = d.seal(delivery, now)
		if err != nil {
			return false, err
		}
		sealed = true
	}
	message := Message{
		EventID:             delivery.EventID,
		SessionID:           delivery.SessionID,
		RecipientEndpointID: delivery.RecipientEndpointID,
		ConversationID:      delivery.ConversationID,
		Ciphertext:          ciphertext,
		ExpiresAtUnix:       delivery.ExpiresAtUnix,
	}
	if err := d.config.Sender.Send(ctx, message); err != nil {
		return sealed, err
	}
	if _, err := d.config.Journal.Delivered(delivery.EventID, attemptID, d.config.Now()); err != nil {
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
func (d *Dispatcher) seal(delivery eventlog.Delivery, now time.Time) ([]byte, error) {
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
		record.Generation, next, delivery.EventID, ciphertext, now); err != nil {
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
