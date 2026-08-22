package dispatch

import (
	"errors"

	"github.com/tosnetwork/tos-messenger/pkg/e2ee"
	"github.com/tosnetwork/tos-messenger/pkg/eventlog"
	nativev1 "github.com/tosnetwork/tos-service-protocol/gen/tos/service/v1"
)

// SessionBindings derives outbound AEAD authority solely from the durable
// first-contact session and daemon configuration. Network messages and Agent
// runtimes cannot substitute any identity or route field.
type SessionBindings struct {
	Journal  *eventlog.Journal
	Identity Identity
	Network  *nativev1.NetworkDomain
}

func (r SessionBindings) BindingFor(delivery eventlog.Delivery) (e2ee.Binding, error) {
	if r.Journal == nil || r.Network == nil {
		return e2ee.Binding{}, errors.New("session binding resolver is incomplete")
	}
	record, found, err := r.Journal.SessionState(delivery.SessionID)
	if err != nil || !found || record.Authority == nil {
		return e2ee.Binding{}, errors.New("delivery session has no verified authority")
	}
	authority := record.Authority
	if authority.LocalAgentID != r.Identity.AgentID || authority.LocalEndpointID != r.Identity.EndpointID ||
		authority.LocalDeviceID != r.Identity.DeviceID {
		return e2ee.Binding{}, errors.New("delivery session belongs to another local identity")
	}
	if delivery.RecipientEndpointID != authority.PeerEndpointID ||
		delivery.RecipientDeviceID != authority.PeerDeviceID {
		return e2ee.Binding{}, errors.New("delivery target conflicts with session authority")
	}
	binding := e2ee.Binding{Network: r.Network, AlgorithmID: record.AlgorithmID,
		ConversationID: delivery.ConversationID, SenderAgentID: authority.LocalAgentID,
		SenderEndpointID: authority.LocalEndpointID, SenderDeviceID: authority.LocalDeviceID,
		RecipientAgentID: authority.PeerAgentID, RecipientEndpointID: authority.PeerEndpointID,
		RecipientDeviceID: authority.PeerDeviceID}
	if _, err := binding.Bytes(); err != nil {
		return e2ee.Binding{}, err
	}
	return binding, nil
}
