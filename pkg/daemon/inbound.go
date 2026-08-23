package daemon

import (
	"bytes"
	"context"
	"errors"
	"time"

	"github.com/tosnetwork/tos-messenger/pkg/admission"
	"github.com/tosnetwork/tos-messenger/pkg/dispatch"
	"github.com/tosnetwork/tos-messenger/pkg/e2ee"
	"github.com/tosnetwork/tos-messenger/pkg/envelope"
	"github.com/tosnetwork/tos-messenger/pkg/eventlog"
	"github.com/tosnetwork/tos-messenger/pkg/fault"
	"github.com/tosnetwork/tos-messenger/pkg/identity"
	nativev1 "github.com/tosnetwork/tos-service-protocol/gen/tos/service/v1"
)

type ReceiveResult struct {
	Outcome admission.Outcome
	Code    fault.Code
	EventID string
}

// ReceiveSealed authenticates, opens, admits and durably commits one device
// copy. The arrival route grants no identity or admission authority.
func (d *Daemon) ReceiveSealed(ctx context.Context, message dispatch.Message,
	route admission.Route) (ReceiveResult, error) {
	if d == nil || d.journal == nil || d.discovery == nil || d.discovery.contacts == nil ||
		d.prekeys == nil || d.prekeys.devices == nil || d.admission == nil {
		return ReceiveResult{}, errors.New("inbound encrypted messaging is not configured")
	}
	if ctx == nil || message.EventID == "" || message.SessionID == "" || len(message.Ciphertext) == 0 ||
		message.RecipientEndpointID != d.config.EndpointID || message.RecipientDeviceID != d.config.DeviceID {
		return ReceiveResult{}, errors.New("sealed message targets another device")
	}
	now := time.Now()
	if d.now != nil {
		now = d.now()
	}
	record, found, err := d.journal.SessionState(message.SessionID)
	if err != nil {
		return ReceiveResult{}, err
	}
	if found && record.LastInboundEventID == message.EventID {
		return ReceiveResult{Outcome: admission.Duplicate, EventID: message.EventID}, nil
	}
	if !found {
		return d.receiveFirstContact(ctx, message, route, now)
	}
	return d.receiveEstablished(ctx, message, record, route, now)
}

func (d *Daemon) receiveFirstContact(ctx context.Context, message dispatch.Message,
	route admission.Route, now time.Time) (ReceiveResult, error) {
	bootstrap, err := e2ee.DecodeFirstContactJSON(message.Bootstrap)
	if err != nil {
		return ReceiveResult{}, err
	}
	binding := bootstrap.Binding
	if binding.RecipientAgentID != d.config.AgentID || binding.RecipientEndpointID != d.config.EndpointID ||
		binding.RecipientDeviceID != d.config.DeviceID || binding.ConversationID != message.ConversationID ||
		binding.AlgorithmID != d.prekeys.suite.AlgorithmID() || !sameMessengerNetwork(binding.Network, d.config.Network()) {
		return ReceiveResult{}, errors.New("first-contact binding targets another authority")
	}
	expected, err := e2ee.DeviceSessionID(binding.SenderDeviceID, binding.RecipientDeviceID)
	if err != nil || expected != message.SessionID {
		return ReceiveResult{}, errors.New("first-contact session identity mismatch")
	}
	resolved, err := d.discovery.contacts.Ensure(ctx, binding.SenderAgentID)
	if err != nil {
		return ReceiveResult{}, errors.New("verify first-contact sender directory: " + err.Error())
	}
	if resolved.Delegation.AgentID != binding.SenderAgentID ||
		resolved.Descriptor.EndpointID != binding.SenderEndpointID ||
		!containsExactBundle(resolved.Bundles, bootstrap.SenderBundle) {
		return ReceiveResult{}, errors.New("first-contact sender bundle is not verified directory evidence")
	}
	private, err := d.prekeys.devices.DevicePrekeyPrivate(d.config.EndpointID, d.config.DeviceID,
		bootstrap.RecipientBundleDigest, now)
	if err != nil {
		return ReceiveResult{}, err
	}
	defer clearSecret(private)
	associated, err := binding.Bytes()
	if err != nil {
		return ReceiveResult{}, err
	}
	state, err := d.prekeys.suite.Accept(private, bootstrap.SenderBundle.Material, bootstrap.Initial, associated)
	if err != nil {
		return ReceiveResult{}, err
	}
	plaintext, next, err := d.prekeys.suite.Open(state, message.Ciphertext, associated)
	if err != nil {
		return ReceiveResult{}, err
	}
	event, err := validateOpenedMessage(plaintext, message, binding)
	if err != nil {
		return ReceiveResult{}, err
	}
	if envelope.RequiresEstablishedDirect(event.Kind) {
		return ReceiveResult{}, errors.New("Agent Gift events are forbidden during first contact")
	}
	delegationJSON, err := identity.EncodeJSON(resolved.Delegation)
	if err != nil {
		return ReceiveResult{}, err
	}
	decision, err := d.admission.AdmitWithCommit(admission.Inbound{Event: event,
		DelegationJSON: delegationJSON, AdmissionToken: message.AdmissionToken,
		Route: route, ReceivedAtUnix: uint64(now.Unix())}, func(entry eventlog.Entry) (bool, error) {
		fresh, _, commitErr := d.journal.CommitInboundFirstContact(message.SessionID,
			binding.AlgorithmID, next, entry, bootstrap, now)
		return fresh, commitErr
	})
	if err != nil {
		return ReceiveResult{}, err
	}
	return ReceiveResult{Outcome: decision.Outcome, Code: decision.Code, EventID: event.EventID}, nil
}

func (d *Daemon) receiveEstablished(ctx context.Context, message dispatch.Message, record eventlog.SessionRecord,
	route admission.Route, now time.Time) (ReceiveResult, error) {
	if record.Authority == nil || record.AlgorithmID != d.prekeys.suite.AlgorithmID() {
		return ReceiveResult{}, errors.New("session has no supported verified authority")
	}
	a := record.Authority
	if a.LocalAgentID != d.config.AgentID || a.LocalEndpointID != d.config.EndpointID ||
		a.LocalDeviceID != d.config.DeviceID {
		return ReceiveResult{}, errors.New("session belongs to another local identity")
	}
	binding := e2ee.Binding{Network: d.config.Network(), AlgorithmID: record.AlgorithmID,
		ConversationID: message.ConversationID, SenderAgentID: a.PeerAgentID,
		SenderEndpointID: a.PeerEndpointID, SenderDeviceID: a.PeerDeviceID,
		RecipientAgentID: a.LocalAgentID, RecipientEndpointID: a.LocalEndpointID,
		RecipientDeviceID: a.LocalDeviceID}
	if len(message.Bootstrap) != 0 {
		bootstrap, err := e2ee.DecodeFirstContactJSON(message.Bootstrap)
		if err != nil || bootstrap.Binding.SenderAgentID != a.PeerAgentID ||
			bootstrap.Binding.SenderEndpointID != a.PeerEndpointID ||
			bootstrap.Binding.SenderDeviceID != a.PeerDeviceID {
			return ReceiveResult{}, errors.New("session bootstrap attempts authority substitution")
		}
	}
	state, err := record.State()
	if err != nil {
		return ReceiveResult{}, err
	}
	associated, err := binding.Bytes()
	if err != nil {
		return ReceiveResult{}, err
	}
	plaintext, next, err := d.prekeys.suite.Open(state, message.Ciphertext, associated)
	if err != nil {
		return ReceiveResult{}, err
	}
	event, err := validateOpenedMessage(plaintext, message, binding)
	if err != nil {
		return ReceiveResult{}, err
	}
	resolved, err := d.discovery.contacts.Ensure(ctx, a.PeerAgentID)
	if err != nil || resolved.Delegation.AgentID != a.PeerAgentID ||
		resolved.Descriptor.EndpointID != a.PeerEndpointID {
		return ReceiveResult{}, errors.New("established sender no longer has verified Endpoint authority")
	}
	delegationJSON, err := identity.EncodeJSON(resolved.Delegation)
	if err != nil {
		return ReceiveResult{}, err
	}
	decision, err := d.admission.AdmitWithCommit(admission.Inbound{Event: event,
		DelegationJSON: delegationJSON, AdmissionToken: message.AdmissionToken,
		Route: route, ReceivedAtUnix: uint64(now.Unix())}, func(entry eventlog.Entry) (bool, error) {
		fresh, _, commitErr := d.journal.CommitInbound(message.SessionID, record.AlgorithmID,
			record.Generation, next, entry, now)
		return fresh, commitErr
	})
	if err != nil {
		return ReceiveResult{}, err
	}
	return ReceiveResult{Outcome: decision.Outcome, Code: decision.Code, EventID: event.EventID}, nil
}

func validateOpenedMessage(raw []byte, message dispatch.Message, binding e2ee.Binding) (envelope.Event, error) {
	event, err := envelope.DecodeEventJSON(raw)
	if err != nil {
		return envelope.Event{}, err
	}
	if event.EventID != message.EventID || event.ConversationID != message.ConversationID ||
		event.SenderAgentID != binding.SenderAgentID || event.SenderEndpointID != binding.SenderEndpointID ||
		event.SenderDeviceID != binding.SenderDeviceID || !sameMessengerNetwork(event.Network, binding.Network) {
		return envelope.Event{}, errors.New("opened Event conflicts with session binding")
	}
	return event, nil
}

func containsExactBundle(values []e2ee.Bundle, wanted e2ee.Bundle) bool {
	wire, err := e2ee.EncodeBundleJSON(wanted)
	if err != nil {
		return false
	}
	for _, value := range values {
		candidate, err := e2ee.EncodeBundleJSON(value)
		if err == nil && bytes.Equal(candidate, wire) {
			return true
		}
	}
	return false
}

func clearSecret(value []byte) {
	for index := range value {
		value[index] = 0
	}
}

func sameMessengerNetwork(first, second *nativev1.NetworkDomain) bool {
	return first != nil && second != nil && first.NetworkId == second.NetworkId &&
		first.GenesisRootHash == second.GenesisRootHash && first.GenesisFileHash == second.GenesisFileHash
}
