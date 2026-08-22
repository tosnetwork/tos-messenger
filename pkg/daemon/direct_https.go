package daemon

import (
	"context"
	"crypto/ed25519"
	"errors"
	"net/http"
	"time"

	"github.com/tosnetwork/tos-messenger/internal/safehttps"
	"github.com/tosnetwork/tos-messenger/pkg/admission"
	"github.com/tosnetwork/tos-messenger/pkg/directhttps"
	"github.com/tosnetwork/tos-messenger/pkg/dispatch"
)

type daemonHTTPSReceiver struct{ daemon *Daemon }

func (r daemonHTTPSReceiver) ReceiveHTTPS(ctx context.Context, message dispatch.Message) (directhttps.ReceiveResult, error) {
	result, err := r.daemon.ReceiveSealed(ctx, message, admission.RouteHTTPS)
	return directhttps.ReceiveResult{Outcome: string(result.Outcome), Code: result.Code}, err
}

type daemonHTTPSTargets struct{ daemon *Daemon }

func (r daemonHTTPSTargets) ResolveHTTPS(ctx context.Context, sessionID string) (directhttps.Target, error) {
	record, found, err := r.daemon.journal.SessionState(sessionID)
	if err != nil || !found || record.Authority == nil {
		return directhttps.Target{}, errors.New("HTTPS delivery session has no verified authority")
	}
	authority := record.Authority
	resolved, err := r.daemon.discovery.contacts.Ensure(ctx, authority.PeerAgentID)
	if err != nil {
		return directhttps.Target{}, err
	}
	if resolved.Delegation.AgentID != authority.PeerAgentID ||
		resolved.Delegation.EndpointID != authority.PeerEndpointID ||
		resolved.Descriptor.EndpointID != authority.PeerEndpointID {
		return directhttps.Target{}, errors.New("HTTPS target Endpoint authority changed")
	}
	deviceCurrent := false
	for _, bundle := range resolved.Bundles {
		if bundle.DeviceID == authority.PeerDeviceID {
			deviceCurrent = true
			break
		}
	}
	if !deviceCurrent {
		return directhttps.Target{}, errors.New("HTTPS target device is no longer current")
	}
	parsed, err := safehttps.ParseURL(resolved.Descriptor.HTTPSEndpoint)
	if err != nil || parsed.Path != directhttps.IngressPath {
		return directhttps.Target{}, errors.New("descriptor has no canonical HTTPS Messenger ingress")
	}
	public := append(ed25519.PublicKey(nil), resolved.Delegation.IdentityPublicKey...)
	if len(public) != ed25519.PublicKeySize {
		return directhttps.Target{}, errors.New("HTTPS target has no Ed25519 Endpoint authority")
	}
	return directhttps.Target{URL: parsed.String(), EndpointPublicKey: public}, nil
}

func (d *Daemon) configureHTTPSBootstrap() error {
	if d == nil || d.dispatch == nil || d.discovery == nil || d.discovery.contacts == nil ||
		d.prekeys == nil || d.prekeys.signer == nil || d.admission == nil {
		return errors.New("HTTPS bootstrap transport dependencies are incomplete")
	}
	client, err := safehttps.NewClient(safehttps.Config{RequestTimeout: 20 * time.Second,
		ConnectTimeout: 10 * time.Second, MaxIdleConns: 32, MaxPerHost: 4,
		RedirectError: "Messenger HTTPS redirects are refused"})
	if err != nil {
		return err
	}
	return d.dispatch.ConfigureTransport(d.prekeys.suite,
		directhttps.Sender{Client: client, Targets: daemonHTTPSTargets{daemon: d}},
		dispatch.SessionBindings{Journal: d.journal, Identity: d.config.Identity(), Network: d.config.Network()})
}

// HTTPSHandler returns the bounded encrypted-message ingress for mounting at
// the exact descriptor URL behind an operator-managed TLS listener/proxy.
func (d *Daemon) HTTPSHandler() (http.Handler, error) {
	if d == nil || d.config.Transport != TransportHTTPSBootstrap || d.prekeys == nil {
		return nil, errors.New("HTTPS bootstrap transport is not enabled")
	}
	return directhttps.NewHandler(directhttps.HandlerConfig{Receiver: daemonHTTPSReceiver{daemon: d},
		Signer: d.prekeys.signer, EndpointID: d.config.EndpointID, DeviceID: d.config.DeviceID, Now: d.now})
}
