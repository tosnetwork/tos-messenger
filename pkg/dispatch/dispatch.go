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
	"errors"
	"time"

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
type Config struct {
	Journal  *eventlog.Journal
	Suite    e2ee.Suite
	Sender   Sender
	Bindings BindingResolver
	Now      func() time.Time
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

// New builds a dispatcher. Every dependency is required: a dispatcher without
// a suite would have nothing to seal with, and one without a binding resolver
// would have to invent the context a ciphertext is bound to.
func New(config Config) (*Dispatcher, error) {
	if config.Journal == nil {
		return nil, errors.New("dispatch requires a durable journal")
	}
	if config.Suite == nil {
		return nil, errors.New("dispatch requires an encryption suite")
	}
	if config.Sender == nil {
		return nil, errors.New("dispatch requires a sender")
	}
	if config.Bindings == nil {
		return nil, errors.New("dispatch requires a binding resolver")
	}
	if config.Now == nil {
		config.Now = time.Now
	}
	return &Dispatcher{config: config}, nil
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
		sealed, err := d.attempt(ctx, delivery, now)
		if sealed {
			summary.Sealed++
		}
		if err == nil {
			summary.Sent++
			continue
		}
		settled, failErr := d.config.Journal.Failed(delivery.EventID, fault.CodeOf(err), d.config.Now())
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
func (d *Dispatcher) attempt(ctx context.Context, delivery eventlog.Delivery, now time.Time) (bool, error) {
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
	if _, err := d.config.Journal.Delivered(delivery.EventID, d.config.Now()); err != nil {
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
	if _, err := d.config.Journal.CommitSealed(delivery.SessionID, record.AlgorithmID,
		next, delivery.EventID, ciphertext, now); err != nil {
		return nil, fault.Wrap(fault.CodeInternal, err)
	}
	return ciphertext, nil
}
