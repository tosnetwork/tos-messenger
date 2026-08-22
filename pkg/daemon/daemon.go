package daemon

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/tosnetwork/tos-messenger/pkg/agentpacketbridge"
	"github.com/tosnetwork/tos-messenger/pkg/attachmentadmission"
	"github.com/tosnetwork/tos-messenger/pkg/attachmentops"
	"github.com/tosnetwork/tos-messenger/pkg/chainquote"
	"github.com/tosnetwork/tos-messenger/pkg/contact"
	"github.com/tosnetwork/tos-messenger/pkg/directory"
	"github.com/tosnetwork/tos-messenger/pkg/dispatch"
	"github.com/tosnetwork/tos-messenger/pkg/envelope"
	"github.com/tosnetwork/tos-messenger/pkg/eventlog"
	"github.com/tosnetwork/tos-messenger/pkg/fault"
	"github.com/tosnetwork/tos-messenger/pkg/localapi"
	"github.com/tosnetwork/tos-messenger/pkg/negotiation"
	"github.com/tosnetwork/tos-messenger/pkg/payload"
	"github.com/tosnetwork/tos-messenger/pkg/prekeyapi"
	"github.com/tosnetwork/tos-messenger/pkg/protocolbridge"
	"github.com/tosnetwork/tos-service-protocol/pkg/nativeclient"
)

const (
	// SaltFile holds the per-install value that keeps decision records from
	// correlating across installations.
	SaltFile = "install.salt"
	// SaltBytes is its length.
	SaltBytes = 32
)

// Observer receives what the daemon did. It exists so a caller can watch
// without the daemon deciding how logs are formatted or where they go.
type Observer interface {
	Swept(dispatch.Summary)
	Maintained(expired int, report eventlog.PruneReport)
	Failed(stage string, err error)
}

type protocolEventReceiver interface {
	Receive(context.Context, envelope.Event) error
}

// Daemon is one running installation.
type Daemon struct {
	config        Config
	journal       *eventlog.Journal
	dispatch      *dispatch.Dispatcher
	server        *localapi.Server
	listener      net.Listener
	owner         net.Listener
	salt          []byte
	observer      Observer
	discovery     *discoveryRuntime
	prekeys       *prekeyRuntime
	agentPackets  *agentpacketbridge.Bridge
	a2aReceiver   protocolEventReceiver
	mcpReceiver   protocolEventReceiver
	quoteResolver negotiation.QuoteResolver
	contactDNS    *nativeclient.Client
	now           func() time.Time

	closeOnce sync.Once
}

type contactResolveFunc func(context.Context, string) (contact.Result, error)

func (f contactResolveFunc) Resolve(ctx context.Context, input string) (contact.Result, error) {
	return f(ctx, input)
}

// ResolveContact accepts a human contact input at the daemon boundary. A .tos
// name is reduced to a quorum-finalized Agent identifier and immediately run
// through the same delegation, DHT, Contact Descriptor, and prekey verification
// chain as an explicit Agent ID. The returned CanonicalName is display metadata;
// callers must persist and authorize only Result.AgentID.
//
// DNS transport credentials are operator-owned. The service-protocol
// nativeclient.Client satisfies the interface. Discovery must be enabled
// because there is no safe contact result without the existing directory chain.
func (d *Daemon) ResolveContact(ctx context.Context, input string, dns contact.DNSAliasClient) (contact.Result, error) {
	if d == nil || d.discovery == nil || d.discovery.contacts == nil {
		return contact.Result{}, errors.New("contact discovery is not enabled")
	}
	now := time.Now
	if d.now != nil {
		now = d.now
	}
	resolver := &contact.Resolver{
		DNS: dns, Directory: d.discovery.contacts, Network: d.config.Network(),
		Chain: d.discovery.chain, CallerID: d.config.AgentID, Now: now,
	}
	return resolver.Resolve(ctx, input)
}

// Open assembles a daemon and takes ownership of its state.
//
// Ownership is taken before anything else: the journal's directory lock is
// what makes a second daemon on the same state fail immediately rather than
// two of them interleaving writes for a while first.
func Open(config Config, observer Observer) (*Daemon, error) {
	return openWithDiscoveryAndPublisher(config, observer, finalizedVerifier{}, productionDiscoveryBuilder{}, nil, nil)
}

// OpenWithGenerationPublisher assembles the daemon with an externally
// custodied Endpoint signer and explicit public sinks. The daemon never
// accepts private-key bytes through this boundary.
func OpenWithGenerationPublisher(config Config, observer Observer, publisher *directory.GenerationPublisher) (*Daemon, error) {
	if publisher == nil {
		return nil, errors.New("no public generation publisher")
	}
	return openWithDiscoveryAndPublisher(config, observer, finalizedVerifier{}, productionDiscoveryBuilder{}, publisher, nil)
}

// OpenWithOperatorResources assembles optional public-generation and outbound
// attachment resources after the command has pinned them to live finalized
// authority. Private Endpoint key bytes cross neither boundary.
func OpenWithOperatorResources(config Config, observer Observer, publisher *directory.GenerationPublisher,
	attachment *attachmentops.Resources) (*Daemon, error) {
	if publisher == nil && attachment == nil {
		return nil, errors.New("no operator resources")
	}
	return openWithDiscoveryAndPublisher(config, observer, finalizedVerifier{}, productionDiscoveryBuilder{}, publisher, attachment)
}

func open(config Config, observer Observer, verifier delegationVerifier) (*Daemon, error) {
	return openWithDiscoveryAndPublisher(config, observer, verifier, productionDiscoveryBuilder{}, nil, nil)
}

func openWithDiscovery(config Config, observer Observer, verifier delegationVerifier, builder discoveryBuilder) (*Daemon, error) {
	return openWithDiscoveryAndPublisher(config, observer, verifier, builder, nil, nil)
}

func openWithDiscoveryAndPublisher(config Config, observer Observer, verifier delegationVerifier,
	builder discoveryBuilder, publisher *directory.GenerationPublisher, attachmentResources *attachmentops.Resources) (*Daemon, error) {
	if err := config.Validate(); err != nil {
		return nil, err
	}
	config.Publication.DeviceIDs = append([]string(nil), config.Publication.DeviceIDs...)
	if verifier == nil {
		return nil, errors.New("no finalized delegation verifier")
	}
	if builder == nil {
		return nil, errors.New("no directory discovery builder")
	}
	journal, err := eventlog.Open(config.StateDir)
	if err != nil {
		return nil, err
	}
	instance := &Daemon{config: config, journal: journal, observer: observer, now: time.Now}
	assembled := false
	defer func() {
		if !assembled && instance.contactDNS != nil {
			_ = instance.contactDNS.Close()
		}
	}()
	delegation, err := verifier.Verify(config, time.Now())
	if err != nil {
		_ = journal.Close()
		return nil, errors.New("verify finalized endpoint delegation: " + err.Error())
	}
	if delegation.AgentID != config.AgentID || delegation.EndpointID != config.EndpointID {
		_ = journal.Close()
		return nil, errors.New("finalized delegation does not authorize the configured endpoint")
	}
	policy, err := config.AdmissionPolicy()
	if err != nil {
		_ = journal.Close()
		return nil, err
	}
	if delegation.InboxAdmissionPolicyDigest != policy.Digest() {
		_ = journal.Close()
		return nil, errors.New("finalized delegation commits another inbox admission policy")
	}

	salt, err := loadOrCreateSalt(filepath.Join(config.StateDir, SaltFile))
	if err != nil {
		_ = journal.Close()
		return nil, err
	}
	instance.salt = salt

	// With no transport the dispatcher can queue and not send, which is what
	// this installation can honestly do.
	dispatcher, err := dispatch.New(dispatch.Config{
		Journal: journal, Identity: config.Identity(),
		Network:             config.Network(),
		AllowedEventClasses: append([]string(nil), delegation.AllowedOutboundEventClasses...),
	})
	if err != nil {
		_ = journal.Close()
		return nil, err
	}
	instance.dispatch = dispatcher

	ownerKey, err := config.OwnerKey()
	if err != nil {
		_ = journal.Close()
		return nil, err
	}
	var quoteResolver *chainquote.Resolver
	if config.EscrowCodeHash != "" {
		adapter, adapterErr := config.ChainAdapter()
		if adapterErr != nil {
			_ = journal.Close()
			return nil, errors.New("build Quote chain adapter: " + adapterErr.Error())
		}
		resolved, resolverErr := chainquote.NewFromChain(adapter, config.Network(), config.EscrowCodeHash,
			config.EscrowCheckpointPath, journal)
		if resolverErr != nil {
			_ = journal.Close()
			return nil, errors.New("build finalized Quote resolver: " + resolverErr.Error())
		}
		quoteResolver = resolved
	}
	serverConfig := localapi.Config{
		Policy: config.FirewallPolicy(), OwnerKey: ownerKey,
		Journal: journal, Dispatcher: dispatcher, LocalEndpointID: config.EndpointID,
		DeviceIDs: append([]string(nil), config.Publication.DeviceIDs...),
	}
	if attachmentResources != nil {
		emitter, emitterErr := attachmentResources.NewEmitter(config.StateDir, dispatcher)
		if emitterErr != nil {
			_ = journal.Close()
			return nil, errors.New("build outbound attachment emitter: " + emitterErr.Error())
		}
		serverConfig.AttachmentEmitter = emitter
	}
	if config.AttachmentAdmission != nil {
		openPolicy, contentPolicy, httpsConfig, policyErr := config.AttachmentAdmission.Policies()
		if policyErr != nil {
			_ = journal.Close()
			return nil, policyErr
		}
		admitter, admissionErr := attachmentadmission.New(attachmentadmission.Config{
			OpenPolicy: openPolicy, ContentPolicy: contentPolicy, HTTPS: httpsConfig, Now: instance.now,
		})
		if admissionErr != nil {
			_ = journal.Close()
			return nil, errors.New("build attachment admission: " + admissionErr.Error())
		}
		serverConfig.AttachmentAdmitter = admitter
	}
	if quoteResolver != nil {
		serverConfig.QuoteResolver = quoteResolver
		serverConfig.Network = config.Network()
	}
	var contactDNS contact.DNSAliasClient
	if config.ContactDNS != nil {
		client, clientErr := config.ContactDNS.Client()
		if clientErr != nil {
			_ = journal.Close()
			return nil, clientErr
		}
		instance.contactDNS = client
		contactDNS = client
	}
	serverConfig.ContactResolver = contactResolveFunc(func(ctx context.Context, input string) (contact.Result, error) {
		return instance.ResolveContact(ctx, input, contactDNS)
	})
	server, err := localapi.NewServer(serverConfig)
	if err != nil {
		_ = journal.Close()
		return nil, err
	}
	instance.server = server
	instance.quoteResolver = quoteResolver
	if config.AgentPacketReceiverSocket != "" {
		resolver, resolverErr := newFinalizedPacketResolver(config)
		if resolverErr != nil {
			_ = journal.Close()
			return nil, errors.New("build Agent Packet resolver: " + resolverErr.Error())
		}
		receiver, receiverErr := agentpacketbridge.NewUnixReceiver(
			config.AgentPacketReceiverSocket, config.AgentPacketReceiverTimeout())
		if receiverErr != nil {
			_ = journal.Close()
			return nil, receiverErr
		}
		bridge, bridgeErr := agentpacketbridge.New(agentpacketbridge.Config{
			Resolver: resolver, Journal: journal, Receiver: receiver, RecipientAgentID: config.AgentID,
		})
		if bridgeErr != nil {
			_ = journal.Close()
			return nil, bridgeErr
		}
		instance.agentPackets = bridge
	}
	if config.A2AReceiverSocket != "" {
		receiver, receiverErr := protocolbridge.NewUnixReceiver(
			config.A2AReceiverSocket, protocolbridge.ProfileA2A, config.ProtocolReceiverTimeout())
		if receiverErr != nil {
			_ = journal.Close()
			return nil, receiverErr
		}
		instance.a2aReceiver = receiver
	}
	if config.MCPReceiverSocket != "" {
		receiver, receiverErr := protocolbridge.NewUnixReceiver(
			config.MCPReceiverSocket, protocolbridge.ProfileMCP, config.ProtocolReceiverTimeout())
		if receiverErr != nil {
			_ = journal.Close()
			return nil, receiverErr
		}
		instance.mcpReceiver = receiver
	}
	discovery, err := builder.Build(config, journal, observer)
	if err != nil {
		_ = journal.Close()
		return nil, errors.New("build peer discovery: " + err.Error())
	}
	instance.discovery = discovery
	prekeys, err := newPrekeyRuntime(config, delegation, journal, time.Now)
	if err != nil {
		_ = discovery.Close()
		_ = journal.Close()
		return nil, err
	}
	if publisher != nil {
		if prekeys == nil {
			_ = discovery.Close()
			_ = journal.Close()
			return nil, errors.New("public generation publisher requires prekey publication mode")
		}
		owned := *publisher
		owned.Delegation = delegation
		if err := owned.Validate(); err != nil {
			_ = discovery.Close()
			_ = journal.Close()
			return nil, errors.New("configure public generation publisher: " + err.Error())
		}
		prekeys.publisher = &owned
	}
	instance.prekeys = prekeys

	listener, err := localapi.Listen(config.SocketPath)
	if err != nil {
		_ = discovery.Close()
		_ = journal.Close()
		return nil, err
	}
	instance.listener = listener

	owner, err := localapi.Listen(config.OwnerSocketPath)
	if err != nil {
		_ = listener.Close()
		_ = os.Remove(config.SocketPath)
		_ = discovery.Close()
		_ = journal.Close()
		return nil, err
	}
	instance.owner = owner
	if prekeys != nil {
		device, err := prekeyapi.Listen(config.Publication.DeviceSocketPath)
		if err != nil {
			_ = owner.Close()
			_ = listener.Close()
			_ = os.Remove(config.OwnerSocketPath)
			_ = os.Remove(config.SocketPath)
			_ = discovery.Close()
			_ = journal.Close()
			return nil, err
		}
		prekeys.listener = device
	}
	assembled = true
	return instance, nil
}

// InstallSalt returns the per-install value used for decision records.
func (d *Daemon) InstallSalt() []byte {
	if d == nil {
		return nil
	}
	return append([]byte(nil), d.salt...)
}

// SocketPath returns where the Agent runtime connects.
func (d *Daemon) SocketPath() string {
	if d == nil {
		return ""
	}
	return d.config.SocketPath
}

// OwnerSocketPath returns where the owner decides.
func (d *Daemon) OwnerSocketPath() string {
	if d == nil {
		return ""
	}
	return d.config.OwnerSocketPath
}

// PrekeySocketPath returns the public-only device contribution socket, or an
// empty string when publication is disabled.
func (d *Daemon) PrekeySocketPath() string {
	if d == nil || d.prekeys == nil {
		return ""
	}
	return d.config.Publication.DeviceSocketPath
}

// Run serves the local API and keeps the schedule until the context ends.
//
// It returns when everything has stopped, so a caller that waits on Run knows
// the state directory is released rather than merely no longer in use.
func (d *Daemon) Run(ctx context.Context) error {
	if d == nil {
		return errors.New("no daemon")
	}
	var group sync.WaitGroup
	if d.discovery != nil {
		group.Add(1)
		go func() {
			defer group.Done()
			if err := d.discovery.runner.Run(ctx, d.discovery.peers, d.config.Discovery.RefreshInterval()); err != nil && ctx.Err() == nil {
				d.report("directory", err)
			}
		}()
	}
	for _, endpoint := range []struct {
		listener  net.Listener
		principal localapi.Principal
	}{
		{d.listener, localapi.PrincipalRuntime},
		{d.owner, localapi.PrincipalOwner},
	} {
		group.Add(1)
		go func(listener net.Listener, principal localapi.Principal) {
			defer group.Done()
			if err := d.server.Serve(ctx, listener, principal); err != nil && !isClosed(err) {
				d.report("serve", err)
			}
		}(endpoint.listener, endpoint.principal)
	}
	if d.prekeys != nil {
		group.Add(2)
		go func() {
			defer group.Done()
			if err := d.prekeys.server.Serve(ctx, d.prekeys.listener); err != nil && !isClosed(err) {
				d.report("serve prekey devices", err)
			}
		}()
		go func() {
			defer group.Done()
			d.prekeys.planner.Run(ctx, func(err error) { d.report("plan prekeys", err) })
		}()
		if d.prekeys.publisher != nil {
			group.Add(1)
			go func() {
				defer group.Done()
				d.prekeys.runPublisher(ctx, func(err error) { d.report("publish prekeys", err) })
			}()
		}
	}
	if d.agentPackets != nil {
		group.Add(1)
		go func() {
			defer group.Done()
			d.runAgentPackets(ctx)
		}()
	}
	if d.a2aReceiver != nil || d.mcpReceiver != nil {
		group.Add(1)
		go func() {
			defer group.Done()
			d.runProtocolEvents(ctx)
		}()
	}
	group.Add(1)
	go func() {
		defer group.Done()
		d.runHistorySync(ctx)
	}()

	group.Add(1)
	go func() {
		defer group.Done()
		d.schedule(ctx)
	}()

	<-ctx.Done()
	// Closing the listeners is what unblocks Accept; the schedule stops on the
	// same context.
	_ = d.listener.Close()
	_ = d.owner.Close()
	if d.prekeys != nil {
		_ = d.prekeys.listener.Close()
	}
	group.Wait()
	return d.Close()
}

func (d *Daemon) runHistorySync(ctx context.Context) {
	ticker := time.NewTicker(d.config.SweepInterval())
	defer ticker.Stop()
	for {
		d.sweepHistorySync(ctx)
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

func (d *Daemon) sweepHistorySync(ctx context.Context) {
	nowFn := d.now
	if nowFn == nil {
		nowFn = time.Now
	}
	records, err := d.journal.ListPending(nowFn(), 0)
	if err != nil {
		d.report("list device history", err)
		return
	}
	for _, record := range records {
		if ctx.Err() != nil {
			return
		}
		raw, err := record.Payload()
		if err != nil {
			continue
		}
		event, err := envelope.DecodeEventJSON(raw)
		if err != nil || event.Kind != "device.history.segment" {
			continue
		}
		decoded, err := payload.Decode(event.Kind, event.Content)
		segment, ok := decoded.(payload.DeviceHistorySegment)
		if err != nil || !ok {
			d.report("decode device history", errors.New("invalid admitted device history payload"))
			continue
		}
		var entropy [32]byte
		if _, err := rand.Read(entropy[:]); err != nil {
			d.report("claim device history", err)
			return
		}
		leaseID, err := eventlog.NewLeaseID(entropy[:])
		if err != nil {
			d.report("claim device history", err)
			return
		}
		now := nowFn()
		if _, err := d.journal.ClaimForApplicationKind(record.EventID, leaseID, now, time.Minute, "device.history.segment"); err != nil {
			if !errors.Is(err, eventlog.ErrLeaseMismatch) && !errors.Is(err, eventlog.ErrNotPending) {
				d.report("claim device history", err)
			}
			continue
		}
		_, applyErr := d.journal.ApplyHistorySegment(event, segment, d.config.AgentID, d.config.EndpointID,
			d.config.DeviceID, d.config.Publication.DeviceIDs, now)
		if applyErr == nil {
			if _, err := d.journal.CompleteApplication(record.EventID, leaseID, nowFn()); err != nil {
				d.report("complete device history", err)
			}
			continue
		}
		if errors.Is(applyErr, eventlog.ErrHistorySequence) {
			d.report("await prior device history", applyErr)
			continue
		}
		code := fault.CodePayloadMalformed
		if errors.Is(applyErr, eventlog.ErrHistoryDevice) {
			code = fault.CodeDeviceRevoked
		}
		if errors.Is(applyErr, eventlog.ErrHistoryContent) || errors.Is(applyErr, eventlog.ErrHistoryRoute) ||
			errors.Is(applyErr, eventlog.ErrHistoryDevice) {
			if _, err := d.journal.RejectApplication(record.EventID, leaseID, code, nowFn()); err != nil {
				d.report("reject device history", err)
			}
			continue
		}
		d.report("apply device history", applyErr)
	}
}

func (d *Daemon) runAgentPackets(ctx context.Context) {
	ticker := time.NewTicker(d.config.SweepInterval())
	defer ticker.Stop()
	for {
		d.sweepAgentPackets(ctx)
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

// sweepAgentPackets consumes only the typed daemon-owned application class.
// The kind check and lease acquisition are one journal operation, so a stale
// listing cannot make this adapter take ordinary runtime work.
func (d *Daemon) sweepAgentPackets(ctx context.Context) {
	nowFn := d.now
	if nowFn == nil {
		nowFn = time.Now
	}
	records, err := d.journal.ListPending(nowFn(), 0)
	if err != nil {
		d.report("list Agent Packets", err)
		return
	}
	for _, record := range records {
		if ctx.Err() != nil {
			return
		}
		raw, err := record.Payload()
		if err != nil {
			continue
		}
		event, err := envelope.DecodeEventJSON(raw)
		if err != nil || event.Kind != "agent.packet" {
			continue
		}
		decoded, err := payload.Decode(event.Kind, event.Content)
		body, ok := decoded.(payload.AgentPacketMessage)
		if err != nil || !ok {
			d.report("decode Agent Packet", errors.New("invalid admitted Agent Packet payload"))
			continue
		}
		var entropy [32]byte
		if _, err := rand.Read(entropy[:]); err != nil {
			d.report("claim Agent Packet", err)
			return
		}
		leaseID, err := eventlog.NewLeaseID(entropy[:])
		if err != nil {
			d.report("claim Agent Packet", err)
			return
		}
		now := nowFn()
		lease := d.config.AgentPacketReceiverTimeout() + 5*time.Second
		if _, err := d.journal.ClaimForApplicationKind(record.EventID, leaseID, now, lease, "agent.packet"); err != nil {
			if !errors.Is(err, eventlog.ErrLeaseMismatch) && !errors.Is(err, eventlog.ErrNotPending) {
				d.report("claim Agent Packet", err)
			}
			continue
		}
		if err := d.agentPackets.Handle(ctx, event.SenderAgentID, body, now); err != nil {
			d.report("deliver Agent Packet", err)
			continue
		}
		if _, err := d.journal.CompleteApplication(record.EventID, leaseID, nowFn()); err != nil {
			d.report("complete Agent Packet", err)
		}
	}
}

func (d *Daemon) runProtocolEvents(ctx context.Context) {
	ticker := time.NewTicker(d.config.SweepInterval())
	defer ticker.Stop()
	for {
		d.sweepProtocolEvents(ctx)
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

// sweepProtocolEvents owns A2A and MCP application leases. These events are
// reserved even when no receiver is configured, so they can never silently
// degrade into untrusted model text.
func (d *Daemon) sweepProtocolEvents(ctx context.Context) {
	nowFn := d.now
	if nowFn == nil {
		nowFn = time.Now
	}
	records, err := d.journal.ListPending(nowFn(), 0)
	if err != nil {
		d.report("list protocol events", err)
		return
	}
	for _, record := range records {
		if ctx.Err() != nil {
			return
		}
		raw, err := record.Payload()
		if err != nil {
			continue
		}
		event, err := envelope.DecodeEventJSON(raw)
		if err != nil {
			continue
		}
		receiver := d.protocolReceiver(event.Kind)
		if receiver == nil {
			continue
		}
		if _, err := payload.Decode(event.Kind, event.Content); err != nil {
			d.report("decode protocol event", err)
			continue
		}
		var entropy [32]byte
		if _, err := rand.Read(entropy[:]); err != nil {
			d.report("claim protocol event", err)
			return
		}
		leaseID, err := eventlog.NewLeaseID(entropy[:])
		if err != nil {
			d.report("claim protocol event", err)
			return
		}
		now := nowFn()
		lease := d.config.ProtocolReceiverTimeout() + 5*time.Second
		if _, err := d.journal.ClaimForApplicationKind(record.EventID, leaseID, now, lease, event.Kind); err != nil {
			if !errors.Is(err, eventlog.ErrLeaseMismatch) && !errors.Is(err, eventlog.ErrNotPending) {
				d.report("claim protocol event", err)
			}
			continue
		}
		if err := receiver.Receive(ctx, event); err != nil {
			d.report("deliver protocol event", err)
			continue
		}
		if _, err := d.journal.CompleteApplication(record.EventID, leaseID, nowFn()); err != nil {
			d.report("complete protocol event", err)
		}
	}
}

func (d *Daemon) protocolReceiver(kind string) protocolEventReceiver {
	switch kind {
	case "a2a.message":
		return d.a2aReceiver
	case "mcp.call", "mcp.result":
		return d.mcpReceiver
	default:
		return nil
	}
}

// Close releases the state directory and removes the socket.
func (d *Daemon) Close() error {
	if d == nil {
		return nil
	}
	var err error
	d.closeOnce.Do(func() {
		_ = d.listener.Close()
		_ = d.owner.Close()
		if d.prekeys != nil && d.prekeys.listener != nil {
			_ = d.prekeys.listener.Close()
		}
		// The sockets are removed only by the daemon that created them, and
		// only once it is done with the state it was serving.
		_ = os.Remove(d.config.SocketPath)
		_ = os.Remove(d.config.OwnerSocketPath)
		if d.prekeys != nil {
			_ = os.Remove(d.config.Publication.DeviceSocketPath)
		}
		_ = d.discovery.Close()
		if d.contactDNS != nil {
			_ = d.contactDNS.Close()
		}
		err = d.journal.Close()
	})
	return err
}

func (d *Daemon) schedule(ctx context.Context) {
	sweep := time.NewTicker(d.config.SweepInterval())
	defer sweep.Stop()
	maintenance := time.NewTicker(d.config.MaintenanceInterval())
	defer maintenance.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-sweep.C:
			d.Sweep(ctx)
		case <-maintenance.C:
			d.Maintain()
		}
	}
}

// Sweep attempts every due delivery. With no transport it does nothing and
// says so once rather than reporting an empty success on every tick.
func (d *Daemon) Sweep(ctx context.Context) {
	if !d.dispatch.CanSend() {
		return
	}
	summary, err := d.dispatch.Sweep(ctx, 0)
	if err != nil {
		d.report("sweep", err)
		return
	}
	if d.observer != nil {
		d.observer.Swept(summary)
	}
}

// Maintain settles what has expired and removes what is finished.
//
// Expiry runs before pruning, because an event that has just expired is
// finished work and the sweep that removes finished work should see it in the
// same pass rather than a maintenance interval later.
func (d *Daemon) Maintain() {
	now := time.Now()
	expired, err := d.journal.ExpireDeliveries(now)
	if err != nil {
		d.report("expire", err)
		return
	}
	// Questions nobody answered are retired in the same pass. A queue only a
	// person can drain would otherwise grow until the disk decided for them.
	undecided, err := d.journal.ExpirePendingAdmissions(now)
	if err != nil {
		d.report("expire admissions", err)
		return
	}
	unanswered, err := d.journal.ExpirePendingApprovals(now)
	if err != nil {
		d.report("expire approvals", err)
		return
	}
	expired += undecided + unanswered
	report, err := d.journal.Prune(now, d.config.Retention())
	if err != nil {
		d.report("prune", err)
		return
	}
	if d.observer != nil {
		d.observer.Maintained(expired, report)
	}
}

func (d *Daemon) report(stage string, err error) {
	if d.observer != nil {
		d.observer.Failed(stage, err)
	}
}

// loadOrCreateSalt keeps decision records correlatable within one install and
// meaningless outside it. A salt regenerated on every start would make a
// node's own logs uncorrelatable with themselves.
func loadOrCreateSalt(path string) ([]byte, error) {
	raw, err := os.ReadFile(path)
	if err == nil {
		decoded, err := hex.DecodeString(strings.TrimSpace(string(raw)))
		if err != nil || len(decoded) < SaltBytes {
			return nil, errors.New("install salt file is unusable")
		}
		return decoded, nil
	}
	if !os.IsNotExist(err) {
		return nil, errors.New("read install salt")
	}
	salt := make([]byte, SaltBytes)
	if _, err := rand.Read(salt); err != nil {
		return nil, errors.New("generate install salt")
	}
	if err := os.WriteFile(path, []byte(hex.EncodeToString(salt)+"\n"), 0o600); err != nil {
		return nil, errors.New("write install salt")
	}
	return salt, nil
}

func isClosed(err error) bool {
	return errors.Is(err, net.ErrClosed) || errors.Is(err, context.Canceled)
}
