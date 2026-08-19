package probe

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"sync"
	"time"

	"github.com/xssnick/tonutils-go/adnl"
	"github.com/xssnick/tonutils-go/adnl/address"

	"github.com/tosnetwork/tos-messenger/pkg/reachability"
)

var silenceADNLLogs sync.Once

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

	instance.establishADNL(ctx, transportPrivate, ed25519.PublicKey(peerKey), local.Port, peers)
	return instance.result, nil
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

// establishADNL runs the gateway phase.
func (r *runner) establishADNL(ctx context.Context, transportKey ed25519.PrivateKey,
	peerKey ed25519.PublicKey, port int, peers []netip.AddrPort) {
	silenceADNLLogs.Do(func() {
		// The responder's punch datagrams are not ADNL, and the peer's gateway
		// drops them; the drop must not spam whatever process embeds this.
		adnl.Logger = func(...any) {}
	})

	gateway := adnl.NewGateway(transportKey)
	// The gateway advertises the address the coordinator observed for this
	// endpoint. Listening happens on the wildcard, because the socket has to
	// receive on whatever interface the rendezvous ran over; the advertised
	// address is the one the peer's NAT mapping actually points at, which the
	// endpoint cannot know locally and the coordinator just told it.
	advertised := make([]*address.UDP, 0, len(r.result.Observed))
	for _, observed := range r.result.Observed {
		advertised = append(advertised, &address.UDP{
			IP:   observed.Addr().AsSlice(),
			Port: int32(observed.Port()),
		})
	}
	if len(advertised) == 0 {
		advertised = append(advertised, &address.UDP{IP: net.IPv4(127, 0, 0, 1), Port: int32(port)})
	}
	gateway.SetAddressList(advertised)

	started := time.Now()
	deadline := started.Add(r.config.PunchTimeout)
	established := make(chan arrival, 4)
	// The inbound path: the responder's only path, the initiator's safety
	// net. The confirming ping is retried, because losing the measurement to
	// one dropped packet would understate the path.
	gateway.SetConnectionHandler(func(client adnl.Peer) error {
		go func() {
			for time.Now().Before(deadline) {
				attempt, cancel := context.WithTimeout(ctx, 2*time.Second)
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
	})
	if err := gateway.StartServer(fmt.Sprintf("0.0.0.0:%d", port)); err != nil {
		r.result.Failure = reachability.FailureInternal
		return
	}
	defer gateway.Close()

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

	// The gateway has to outlive this endpoint's own success: closing the
	// moment the session came up would pull it out from under a peer that is
	// still measuring, and that error is not random -- it lands on whichever
	// endpoint is slower, which is exactly the bias a success rate must not
	// carry. The done signal travels through the coordinator, not over the
	// session under test, because a layer must not carry its own test's
	// control plane: "the session failed" and "the signalling failed" have to
	// stay distinguishable.
	r.awaitPeerDone(ctx, deadline)
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

// record marks the establishment.
func (r *runner) record(started time.Time, peer netip.AddrPort) {
	r.result.Established = true
	r.result.Failure = reachability.FailureNone
	r.result.PeerAddress = peer
	r.result.EstablishMillis = uint64(time.Since(started).Milliseconds())
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
