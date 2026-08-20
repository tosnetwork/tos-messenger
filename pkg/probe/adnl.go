package probe

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"net"
	"net/netip"
	"strconv"
	"sync"
	"time"

	"github.com/xssnick/tonutils-go/adnl"
	"github.com/xssnick/tonutils-go/adnl/address"

	"github.com/tosnetwork/tos-messenger/pkg/reachability"
)

var silenceADNLLogs sync.Once

const (
	// keepalivePingTimeout bounds one keepalive or reconnect round trip. It is
	// the bound the establishment pings already use, so "the session answered"
	// means the same thing in every phase.
	keepalivePingTimeout = 2 * time.Second
	// keepaliveDeathLimit is how many consecutive failed keepalives judge the
	// session dead. One lost datagram is UDP behaving normally; several in a
	// row, each given a full round-trip timeout, is the session gone. The death
	// time recorded is the last successful ping, not the moment of the verdict,
	// because the verdict's lateness is this tool's, not the network's.
	keepaliveDeathLimit = 3
	// doneSignalGrace pads the done-signal wait past the last phase a peer can
	// legitimately still be in, covering the signalling round trips themselves.
	doneSignalGrace = 2 * time.Second
)

// arrival is one usable session, with the address it exists over.
type arrival struct {
	addr netip.AddrPort
	peer adnl.Peer
}

// RunADNL measures one endpoint of one ADNL establishment attempt.
//
// The UDP probe answers whether datagrams pass at all. This one answers the
// question the route decision actually turns on: whether a full ADNL session
// -- handshake, channel, and a round trip over it -- comes up on that path.
// The two can differ, because a handshake is several packets in both
// directions with sizes and timing a NAT or a middlebox may treat differently
// from a single probe datagram, and freezing a transport on datagram evidence
// alone would be measuring the wrong protocol.
//
// Establishment alone is still not the route decision's whole question. A NAT
// that admits a handshake and then forgets the mapping under keepalives kills
// the session minutes later, and a session that cannot be re-established after
// a drop is a different deployment reality than one that can. When a hold
// window is configured, both ends therefore keep the confirmed session alive
// with paced pings and record how long it survived, and the initiator can
// additionally drop its channel state on purpose and time the reconnect.
//
// When a tunnel relay is configured and the direct phase ends without a
// session, a fallback phase establishes the same ADNL session through the
// relay instead. That is what gives the study's tunnel-first route a
// collection path: without it, "direct failed" and "direct failed but a
// tunnel works" would be indistinguishable, and the route decision needs the
// difference.
//
// The flow reuses the coordinator rendezvous, then hands the socket's port to
// a real ADNL gateway. The roles are deliberately asymmetric from there, and
// the asymmetry is the design: if both sides dialled, their handshakes would
// cross, and a crossed handshake leaves the two ends holding different
// channel states -- each side's packets may pass in one direction and silently
// fail in the other, and which side suffers is a race. So exactly one ADNL
// session ever exists. The initiator dials, with retries. The responder never
// dials: its half of the NAT punch is a burst of raw datagrams sent from the
// rendezvous socket before the gateway takes the port, which opens its
// mapping without starting a second handshake, and its establishment is
// measured over the inbound session, because a session has no preferred
// direction.
//
// The transport key is ephemeral and never the evidence key. A transport key
// that doubled as the trial-signing identity would tie every session a network
// observer sees to the operator's published evidence.
func RunADNL(ctx context.Context, config Config) (Result, error) {
	if err := validateConfig(&config); err != nil {
		return Result{}, err
	}
	if config.Probe != reachability.ProbeADNL {
		return Result{}, errors.New("this runner measures the adnl probe; use Run for udp")
	}

	transportPublic, transportPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return Result{}, errors.New("generate transport key")
	}

	connection, err := net.ListenPacket("udp", config.ListenAddr)
	if err != nil {
		return Result{}, errors.New("open probe socket")
	}

	instance := &runner{
		config:          config,
		transportKeyHex: hex.EncodeToString(transportPublic),
		connection:      connection,
	}
	instance.result.Mapping = reachability.NATUndetermined
	instance.result.Failure = reachability.FailureInternal

	if err := instance.discover(ctx); err != nil {
		_ = connection.Close()
		return instance.result, nil
	}
	peers, err := instance.exchange(ctx)
	if err != nil {
		_ = connection.Close()
		return instance.result, nil
	}
	peerKey, err := hex.DecodeString(instance.result.PeerTransportKey)
	if err != nil || len(peerKey) != ed25519.PublicKeySize {
		// The peer paired without a usable transport key, so no handshake
		// toward it can even be built. That is the peer failing to show up
		// for this probe, not a network result.
		instance.result.Failure = reachability.FailurePeerUnreachable
		_ = connection.Close()
		return instance.result, nil
	}

	// The responder's half of the punch happens here, while the socket is
	// still a plain socket: raw datagrams toward every peer candidate open
	// this side's NAT mapping on exactly the 5-tuples the initiator's
	// handshakes will arrive on. The initiator needs no burst -- its
	// handshakes are their own punch.
	if config.Role == RoleB {
		instance.punchBurst(peers)
	}

	// The port the rendezvous ran on is the port the peer's NAT mapping
	// points at, so the gateway has to live on exactly that port.
	local, ok := connection.LocalAddr().(*net.UDPAddr)
	if !ok {
		_ = connection.Close()
		return instance.result, nil
	}
	if err := connection.Close(); err != nil {
		return instance.result, nil
	}

	instance.establishADNL(ctx, transportPrivate, ed25519.PublicKey(peerKey), local, peers)

	// The tunnel is a fallback, never a second chance for a session that
	// already exists: it runs only when the direct phase ended without one.
	// The failure class the direct phase produced is what the resulting trial
	// keeps either way, because a proxy-fallback outcome is defined by what it
	// fell back from.
	if !instance.result.Established && config.TunnelAddr != "" && ctx.Err() == nil {
		instance.tunnelEstablish(ctx, transportPrivate, ed25519.PublicKey(peerKey))
	}
	return instance.result, nil
}

// tunnelEstablish runs the fallback phase through the relay, inside its own
// bounded window.
//
// The phase gets a fresh socket rather than the rendezvous port: the peer's
// NAT mapping toward this endpoint no longer matters, because both sides now
// speak only to the relay, at whatever tuple each proved it can receive at
// during registration. The registration runs over exactly the socket the
// gateway then takes over, so the tuple the relay learned is the tuple the
// session's packets use. The role asymmetry is kept -- the initiator dials the
// relay's address as its sole candidate, the responder awaits the inbound
// session arriving from the relay -- for the same reason as the direct phase:
// exactly one session must ever exist.
//
// Survival and reconnect are never measured here. They are direct-session
// properties and the trial schema forbids them off a direct outcome; a relay
// session's lifetime would be measuring the relay, not the path.
func (r *runner) tunnelEstablish(ctx context.Context, transportKey ed25519.PrivateKey,
	peerKey ed25519.PublicKey) {
	directFailure := r.result.Failure
	if directFailure == reachability.FailureNone {
		// A fallback with nothing to fall back from would produce a trial the
		// schema rightly refuses.
		return
	}
	started := time.Now()
	deadline := started.Add(r.config.PunchTimeout)

	connection, err := net.ListenPacket("udp", freshPort(r.config.ListenAddr))
	if err != nil {
		return
	}
	relayAddr, err := registerWithTunnel(ctx, connection, r.config.TunnelAddr,
		r.config.SessionID, r.config.Role, deadline)
	if err != nil {
		_ = connection.Close()
		return
	}
	local, ok := connection.LocalAddr().(*net.UDPAddr)
	if !ok {
		_ = connection.Close()
		return
	}
	if err := connection.Close(); err != nil {
		return
	}
	bind, err := wildcardBind(local)
	if err != nil {
		return
	}

	gateway := adnl.NewGateway(transportKey)
	// The relay's address is the one place the peer can reach this endpoint,
	// so it is the only address worth advertising. The ADNL address list is
	// IPv4-only on the wire, so an IPv6 relay simply goes unadvertised;
	// establishment turns on the explicit dial and the answered packet source,
	// not on the list.
	if ip := relayAddr.Addr().Unmap(); ip.Is4() {
		gateway.SetAddressList([]*address.UDP{{IP: ip.AsSlice(), Port: int32(relayAddr.Port())}})
	}
	established := make(chan arrival, 4)
	gateway.SetConnectionHandler(confirmInbound(ctx, deadline, established))
	if err := gateway.StartServer(bind); err != nil {
		return
	}
	defer gateway.Close()

	var confirmed adnl.Peer
	if r.config.Role == RoleA {
		confirmed = r.dial(ctx, gateway, peerKey, []netip.AddrPort{relayAddr}, established, started, deadline)
	} else {
		confirmed = r.awaitInbound(ctx, established, started, deadline)
	}
	// Whatever the loops above wrote, the failure class stays the direct
	// phase's: a successful fallback files as proxy fallback carrying what it
	// fell back from, and a failed fallback leaves the trial failed for the
	// reason the direct path failed -- the schema has no slot for the tunnel's
	// own failure, and inventing one here would grow the study's vocabulary
	// from inside a collector.
	r.result.Failure = directFailure
	if confirmed == nil {
		return
	}
	r.result.TunneledEstablish = true

	// The same teardown discipline as the direct phase: hold the gateway open
	// until the peer reports done through the coordinator, so the teardown
	// bias never lands on the slower side.
	r.awaitPeerDone(ctx, deadline.Add(doneSignalGrace))
}

// freshPort strips a configured listen address to its host and a kernel-chosen
// port. The rendezvous port stayed with the direct phase; the relay learns
// whatever tuple the registration arrives from, so the tunnel phase needs no
// particular one.
func freshPort(listen string) string {
	host, _, err := net.SplitHostPort(listen)
	if err != nil {
		return ":0"
	}
	return net.JoinHostPort(host, "0")
}

// punchBurst opens this side's NAT mapping toward every candidate.
//
// The datagrams are probe punch messages, not ADNL; the peer's gateway drops
// them silently, which is all they are for. A short burst suffices: filter
// state outlives it by far longer than the establishment window.
func (r *runner) punchBurst(peers []netip.AddrPort) {
	for round := 0; round < 3; round++ {
		nonce, err := newNonce()
		if err != nil {
			return
		}
		message, err := Encode(Message{
			Kind: KindPunch, SessionID: r.config.SessionID, Role: r.config.Role,
			Nonce: nonce, Sequence: uint32(round), Commit: r.config.Commit,
			ManifestDigest: r.config.ManifestDigest,
		})
		if err != nil {
			return
		}
		for _, candidate := range peers {
			r.send(message, net.UDPAddrFromAddrPort(candidate))
		}
		time.Sleep(100 * time.Millisecond)
	}
}

// wildcardBind returns the address the gateway binds to: the rendezvous port on
// a wildcard host of the family the socket already runs over.
//
// The bound socket is where the peer's mapping points, so its family is the one
// in use, and the wildcard has to match it -- a hardcoded IPv4 wildcard could
// never receive the IPv6 half of the reachability policy. tonutils' StartServer
// splits the listen address on ":" and rejects anything that is not host:port,
// so the IPv6 wildcard is given as ":port" (which net.ListenPacket binds
// dual-family) rather than "[::]:port", a form that parser cannot accept. The
// port is validated so a malformed socket address fails closed instead of
// producing an unbindable string.
func wildcardBind(local *net.UDPAddr) (string, error) {
	if local == nil {
		return "", errors.New("no local address to bind the gateway")
	}
	if local.Port <= 0 || local.Port > 65535 {
		return "", errors.New("local address has no usable port")
	}
	port := strconv.Itoa(local.Port)
	if local.IP.To4() != nil {
		// Unchanged IPv4 path: an explicit IPv4 wildcard.
		return net.JoinHostPort("0.0.0.0", port), nil
	}
	// Empty host binds the wildcard across families, which covers the IPv6
	// endpoints; JoinHostPort renders it as ":port", the only IPv6-capable form
	// StartServer's ":"-split accepts.
	return net.JoinHostPort("", port), nil
}

// establishADNL runs the gateway phase.
//
// local is the socket the rendezvous ran over. Its port is the one the peer's
// mapping points at, so the gateway has to reclaim exactly it, and its address
// family is the family the session runs over, so the wildcard the gateway binds
// follows it rather than a hardcoded IPv4.
func (r *runner) establishADNL(ctx context.Context, transportKey ed25519.PrivateKey,
	peerKey ed25519.PublicKey, local *net.UDPAddr, peers []netip.AddrPort) {
	if local == nil {
		r.result.Failure = reachability.FailureInternal
		return
	}
	bind, err := wildcardBind(local)
	if err != nil {
		r.result.Failure = reachability.FailureInternal
		return
	}
	port := local.Port

	silenceADNLLogs.Do(func() {
		// The responder's punch datagrams are not ADNL, and the peer's gateway
		// drops them; the drop must not spam whatever process embeds this.
		adnl.Logger = func(...any) {}
	})

	gateway := adnl.NewGateway(transportKey)
	// The gateway advertises the address the coordinator observed for this
	// endpoint, so the peer's NAT mapping -- which the endpoint cannot know
	// locally and the coordinator just told it -- is what the address list names.
	// The ADNL address list is IPv4-only on the wire (its UDP address type
	// serializes a 4-byte IP), so an IPv6 observation cannot travel in it and is
	// dropped from the list; that is not a loss here, because establishment turns
	// on the initiator dialling an explicit candidate and the responder answering
	// the packet's source, not on the advertised list, which stays empty for an
	// IPv6 session. Listening still happens on the wildcard of the family in use.
	advertised := make([]*address.UDP, 0, len(r.result.Observed))
	for _, observed := range r.result.Observed {
		ip := observed.Addr().Unmap()
		if !ip.Is4() {
			continue
		}
		advertised = append(advertised, &address.UDP{
			IP:   ip.AsSlice(),
			Port: int32(observed.Port()),
		})
	}
	if len(advertised) == 0 && local.IP.To4() != nil {
		advertised = append(advertised, &address.UDP{IP: net.IPv4(127, 0, 0, 1), Port: int32(port)})
	}
	gateway.SetAddressList(advertised)

	started := time.Now()
	deadline := started.Add(r.config.PunchTimeout)
	established := make(chan arrival, 4)
	gateway.SetConnectionHandler(confirmInbound(ctx, deadline, established))
	if err := gateway.StartServer(bind); err != nil {
		r.result.Failure = reachability.FailureInternal
		return
	}
	defer gateway.Close()

	if directPeersForTest != nil {
		peers = directPeersForTest(peers)
	}
	if len(peers) == 0 {
		r.result.Failure = reachability.FailureNoCandidate
		return
	}
	r.result.Failure = reachability.FailureHandshake

	var confirmed adnl.Peer
	if r.config.Role == RoleA {
		confirmed = r.dial(ctx, gateway, peerKey, peers, established, started, deadline)
	} else {
		confirmed = r.awaitInbound(ctx, established, started, deadline)
	}
	if confirmed == nil {
		return
	}

	if r.config.HoldWindow > 0 {
		alive := r.holdSession(ctx, confirmed)
		// Reconnect is measured only on the initiating side, and only over a
		// session the hold phase showed was still alive: re-establishing a
		// session the network had already killed would time the network's
		// recovery, not the deliberate drop this phase performs. The responder
		// leaves the field zero, and pair joining takes the max of the two
		// halves, so the pair still carries one number.
		if alive && r.config.MeasureReconnect && r.config.Role == RoleA {
			r.measureReconnect(ctx, confirmed)
		}
	}

	// The gateway has to outlive this endpoint's own success: closing the
	// moment the session came up would pull it out from under a peer that is
	// still measuring, and that error is not random -- it lands on whichever
	// endpoint is slower, which is exactly the bias a success rate must not
	// carry. The wait is therefore budgeted for every phase the peer may still
	// be in, not only for establishment. The done signal travels through the
	// coordinator, not over the session under test, because a layer must not
	// carry its own test's control plane: "the session failed" and "the
	// signalling failed" have to stay distinguishable.
	r.awaitPeerDone(ctx, deadline.Add(measurementBudget(r.config)))
}

// measurementBudget is how long past the shared establishment deadline the
// peer may legitimately still be measuring. Its hold phase starts at its own
// establishment, which can land as late as the deadline itself; its last
// keepalive can still be in flight at the window's edge; and its reconnect
// phase is bounded by the punch timeout. The reconnect share is budgeted on
// both sides even though only the initiator reconnects, because an endpoint
// cannot see its peer's flags -- and the done signal ends the wait early, so
// the surplus is only ever paid when the peer actually uses it.
func measurementBudget(config Config) time.Duration {
	if config.HoldWindow <= 0 {
		return 0
	}
	return config.HoldWindow + keepalivePingTimeout + config.PunchTimeout + doneSignalGrace
}

// holdSession keeps the confirmed session alive with paced pings until the
// hold window elapses or the session is judged dead, and records the survival
// span. It reports whether the session was still alive when the phase ended.
//
// Both roles run this: a session exists only while both ends have it, and the
// aggregation takes the shorter half, so a side that did not measure would
// silently remove its pair from the survival percentile.
func (r *runner) holdSession(ctx context.Context, peer adnl.Peer) bool {
	holdUntil := r.establishedAt.Add(r.config.HoldWindow)
	lastAlive := r.establishedAt
	failures := 0
	ticker := time.NewTicker(r.config.KeepaliveInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			// A torn-down run is tooling, not the network. Recording the span
			// measured so far would understate sessions that were still alive,
			// so the field keeps its unmeasured zero.
			return false
		case <-ticker.C:
		}
		if !time.Now().Before(holdUntil) {
			// Death is only ever judged at the failure limit, so a window that
			// ends with fewer misses than the limit counts as survived to its
			// end: at the keepalive's granularity that is what was observed.
			r.result.SurvivalSeconds = clampedSeconds(r.config.HoldWindow)
			return true
		}
		attempt, cancel := context.WithTimeout(ctx, keepalivePingTimeout)
		_, err := peer.Ping(attempt)
		cancel()
		if err == nil {
			lastAlive = time.Now()
			failures = 0
			continue
		}
		failures++
		if failures >= keepaliveDeathLimit {
			r.result.SurvivalSeconds = clampedSeconds(lastAlive.Sub(r.establishedAt))
			return false
		}
	}
}

// clampedSeconds converts a measured span to whole seconds with a floor of
// one, because zero already means "not measured" in the trial schema and a
// session that was measured and died at once has to stay distinguishable from
// one that was never measured at all.
func clampedSeconds(span time.Duration) uint64 {
	if span < time.Second {
		return 1
	}
	return uint64(span / time.Second)
}

// measureReconnect deliberately drops the initiator's channel state and times
// the re-establishment against the address that carried the session, using
// fresh ping round trips -- the same act that defined establishment, so the
// two latencies are comparable.
//
// A reconnect that fails inside its window leaves the field at zero, which
// the schema reads as "not measured". That is honest but lossy: a failed
// reconnect is currently indistinguishable from an unmeasured one, because
// the trial record has no slot for a reconnect failure, and inventing one by
// changing the trial's direct outcome would misfile a session that was
// genuinely established and genuinely survived.
func (r *runner) measureReconnect(ctx context.Context, peer adnl.Peer) {
	dropped := time.Now()
	deadline := dropped.Add(r.config.PunchTimeout)
	peer.Reinit()
	failures := 0
	for time.Now().Before(deadline) {
		if ctx.Err() != nil {
			return
		}
		attempt, cancel := context.WithTimeout(ctx, keepalivePingTimeout)
		_, err := peer.Ping(attempt)
		cancel()
		if err == nil {
			elapsed := time.Since(dropped).Milliseconds()
			if elapsed < 1 {
				elapsed = 1
			}
			r.result.ReconnectMillis = uint64(elapsed)
			return
		}
		failures++
		if failures%2 == 0 {
			peer.Reinit()
		}
		time.Sleep(200 * time.Millisecond)
	}
}

// directPeersForTest lets a test replace the direct phase's candidate set --
// forcing a deterministic direct failure so the tunnel fallback can be
// exercised on loopback -- without the production path reading anything but
// nil. It is written only by tests, before their runners start, and never by
// production code.
var directPeersForTest func([]netip.AddrPort) []netip.AddrPort

// confirmInbound is the gateway connection handler every phase shares: the
// responder's only path, the initiator's safety net. A completed ping round
// trip over the inbound session is what establishment means, and it is
// retried because losing the measurement to one dropped packet would
// understate the path.
func confirmInbound(ctx context.Context, deadline time.Time, established chan<- arrival) func(adnl.Peer) error {
	return func(client adnl.Peer) error {
		go func() {
			for time.Now().Before(deadline) {
				attempt, cancel := context.WithTimeout(ctx, keepalivePingTimeout)
				_, err := client.Ping(attempt)
				cancel()
				if err != nil {
					if ctx.Err() != nil {
						return
					}
					time.Sleep(200 * time.Millisecond)
					continue
				}
				if addr, parseErr := netip.ParseAddrPort(client.RemoteAddr()); parseErr == nil {
					select {
					case established <- arrival{addr: addr, peer: client}:
					default:
					}
				}
				return
			}
		}()
		return nil
	}
}

// dial is the initiator's loop: try every candidate until one carries a
// session, reinitialising a peer whose pings keep failing rather than
// retrying into silence.
func (r *runner) dial(ctx context.Context, gateway *adnl.Gateway, peerKey ed25519.PublicKey,
	peers []netip.AddrPort, established <-chan arrival, started, deadline time.Time) adnl.Peer {
	dialled := make(map[string]adnl.Peer, len(peers))
	failures := make(map[string]int, len(peers))
	timer := time.NewTimer(0)
	defer timer.Stop()
	for {
		select {
		case <-ctx.Done():
			r.result.Failure = reachability.FailureInternal
			return nil
		case arrived := <-established:
			r.record(started, arrived.addr)
			return arrived.peer
		case <-timer.C:
		}
		if !time.Now().Before(deadline) {
			return nil
		}
		for _, candidate := range peers {
			name := candidate.String()
			peer, held := dialled[name]
			if !held {
				registered, err := gateway.RegisterClient(name, peerKey)
				if err != nil {
					continue
				}
				dialled[name] = registered
				peer = registered
			}
			attempt, cancel := context.WithTimeout(ctx, 2*time.Second)
			_, err := peer.Ping(attempt)
			cancel()
			if err != nil {
				failures[name]++
				if failures[name]%2 == 0 {
					peer.Reinit()
				}
				continue
			}
			r.record(started, candidate)
			return peer
		}
		timer.Reset(300 * time.Millisecond)
	}
}

// awaitInbound is the responder's wait: the initiator dials, and the session
// that arrives is the measurement.
func (r *runner) awaitInbound(ctx context.Context, established <-chan arrival,
	started, deadline time.Time) adnl.Peer {
	timer := time.NewTimer(time.Until(deadline))
	defer timer.Stop()
	select {
	case <-ctx.Done():
		r.result.Failure = reachability.FailureInternal
		return nil
	case arrived := <-established:
		r.record(started, arrived.addr)
		return arrived.peer
	case <-timer.C:
		return nil
	}
}

// record marks the establishment and anchors the hold window to it.
func (r *runner) record(started time.Time, peer netip.AddrPort) {
	r.result.Established = true
	r.result.Failure = reachability.FailureNone
	r.result.PeerAddress = peer
	r.establishedAt = time.Now()
	r.result.EstablishMillis = uint64(r.establishedAt.Sub(started).Milliseconds())
	if r.result.EstablishMillis == 0 {
		r.result.EstablishMillis = 1
	}
}

// awaitPeerDone reports this endpoint done and holds the gateway open until
// the peer reports the same, or the shared deadline passes.
//
// It speaks to the coordinator over a fresh socket: the measured port belongs
// to the gateway now, and an outbound flow to a public host needs no punching.
func (r *runner) awaitPeerDone(ctx context.Context, deadline time.Time) {
	connection, err := net.Dial("udp", r.config.Coordinators[0])
	if err != nil {
		return
	}
	defer connection.Close()
	for time.Now().Before(deadline) {
		if ctx.Err() != nil {
			return
		}
		nonce, err := newNonce()
		if err != nil {
			return
		}
		request, err := EncodeRequest(Message{
			Kind: KindDone, SessionID: r.config.SessionID, Role: r.config.Role, Nonce: nonce,
		})
		if err != nil {
			return
		}
		if _, err := connection.Write(request); err != nil {
			return
		}
		_ = connection.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
		buffer := make([]byte, 2048)
		read, err := connection.Read(buffer)
		if err == nil {
			reply, decodeErr := Decode(buffer[:read])
			if decodeErr == nil && reply.Kind == KindDoneOK && reply.Nonce == nonce && reply.PeerDone {
				return
			}
		}
		time.Sleep(400 * time.Millisecond)
	}
}
