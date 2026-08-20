package probe

import (
	"bytes"
	"context"
	"crypto/rand"
	"errors"
	"net"
	"net/netip"
	"sync"
	"time"
)

// The tunnel relay is the measurement counterpart of the study's tunnel-first
// route: a minimal double-registration UDP forwarder. Both endpoints of one
// probe session register with it, and once both have proven they can receive
// at the addresses they registered from, it forwards each side's datagrams to
// the other, verbatim. It carries the fallback phase of the ADNL probe and
// nothing else: it is measurement infrastructure, never a Messenger transport,
// and it must not be presented as the Relay milestone, which has its own
// acceptance this tool does not touch.
//
// Its control protocol deliberately does not reuse the coordinator's wire
// format. The coordinator's messages are rendezvous signalling; these frames
// share a socket with forwarded session payload, so they need a shape the
// relay can separate from that payload by prefix alone. The framing is its
// own eight-byte magic plus a fixed binary layout, and after a source 5-tuple
// completes its registration, everything arriving from that tuple is treated
// as payload -- with one deliberate exception, the endpoint's own re-sent echo,
// so a lost answer can be re-polled (see fromRegisteredLocked).
//
// The amplification rules mirror the coordinator's: client control requests
// are padded to a floor, a control response larger than the request that
// produced it is never sent, and anything that cannot be answered inside that
// rule is dropped silently. Forwarding adds its own rules: a registration is
// completed only by echoing a random token the relay sent to the claimed
// source address, so a spoofed source never becomes a forwarding target;
// forwarded traffic is byte-for-byte the size of what arrived, so the relay
// amplifies nothing; and each session's forwarding is capped by bytes and by
// a lifetime, so a registered pair cannot turn the relay into unmetered
// transit.

const (
	// tunnelMagic opens every tunnel control frame. Forwarded payload is
	// whatever the session's endpoints exchange, so the prefix is what lets a
	// relay hold control traffic and payload apart on one socket.
	tunnelMagic = "tostun01"
	// tunnelSessionIDBytes is the fixed length of a probe session identifier.
	tunnelSessionIDBytes = 36
	// tunnelHeaderBytes is the fixed control frame layout: magic, kind, session
	// identifier, role, token, flag.
	tunnelHeaderBytes = 8 + 1 + tunnelSessionIDBytes + 1 + tunnelTokenBytes + 1
	// tunnelTokenBytes sizes the registration token.
	tunnelTokenBytes = 16
	// TunnelRequestFloor is the exact size of every client control request.
	// Padding requests up to it is what makes every control response strictly
	// smaller than the request that produced it, and requiring the exact size
	// keeps the relay's parser away from anything in between.
	TunnelRequestFloor = 128
	// MaxTunnelDatagramBytes bounds one forwarded datagram. Anything larger is
	// dropped rather than truncated, because a silently truncated datagram
	// would corrupt the session under measurement instead of merely losing one
	// packet, which UDP already permits.
	MaxTunnelDatagramBytes = 1500

	// DefaultTunnelSessionTTL bounds how long one tunnel session lives. The
	// fallback phase establishes and confirms within the punch timeout; the
	// TTL only has to outlive that plus the done-signal wait.
	DefaultTunnelSessionTTL = 2 * time.Minute
	// DefaultTunnelMaxSessions bounds relay memory.
	DefaultTunnelMaxSessions = 4096
	// DefaultTunnelSessionBytes caps the bytes forwarded per session, both
	// directions counted together. An establishment plus its confirming pings
	// is a few kilobytes; the cap is generous headroom, not a throughput
	// grant.
	DefaultTunnelSessionBytes = uint64(1) << 20
)

// Tunnel control frame kinds. The client sends register and echo; the relay
// answers with challenge and status. Nothing else exists, so nothing else
// parses.
const (
	tunnelKindRegister  byte = 1
	tunnelKindChallenge byte = 2
	tunnelKindEcho      byte = 3
	tunnelKindStatus    byte = 4
)

// tunnelFrame is one parsed control frame.
type tunnelFrame struct {
	kind      byte
	sessionID string
	role      Role
	token     [tunnelTokenBytes]byte
	peerReady bool
}

// encodeTunnelFrame renders one control frame, padded with zeros up to floor
// when a floor is given. Client requests pass TunnelRequestFloor; relay
// responses pass zero and stay at the bare header, which is what keeps every
// response smaller than the padded request it answers.
func encodeTunnelFrame(frame tunnelFrame, floor int) ([]byte, error) {
	if frame.kind < tunnelKindRegister || frame.kind > tunnelKindStatus {
		return nil, errors.New("invalid tunnel frame kind")
	}
	if !sessionPattern.MatchString(frame.sessionID) {
		return nil, errors.New("invalid tunnel session identifier")
	}
	if frame.role != RoleA && frame.role != RoleB {
		return nil, errors.New("invalid tunnel role")
	}
	size := tunnelHeaderBytes
	if floor > size {
		size = floor
	}
	raw := make([]byte, size)
	copy(raw[0:8], tunnelMagic)
	raw[8] = frame.kind
	copy(raw[9:9+tunnelSessionIDBytes], frame.sessionID)
	raw[45] = frame.role[0]
	copy(raw[46:46+tunnelTokenBytes], frame.token[:])
	if frame.peerReady {
		raw[62] = 1
	}
	return raw, nil
}

// decodeTunnelFrame parses and validates one control frame. Every structural
// rule fails closed: a frame that is not exactly well-formed is not a frame.
func decodeTunnelFrame(raw []byte) (tunnelFrame, error) {
	if len(raw) < tunnelHeaderBytes || len(raw) > TunnelRequestFloor {
		return tunnelFrame{}, errors.New("tunnel frame is outside its bound")
	}
	if !bytes.Equal(raw[0:8], []byte(tunnelMagic)) {
		return tunnelFrame{}, errors.New("not a tunnel control frame")
	}
	frame := tunnelFrame{kind: raw[8]}
	if frame.kind < tunnelKindRegister || frame.kind > tunnelKindStatus {
		return tunnelFrame{}, errors.New("invalid tunnel frame kind")
	}
	frame.sessionID = string(raw[9 : 9+tunnelSessionIDBytes])
	if !sessionPattern.MatchString(frame.sessionID) {
		return tunnelFrame{}, errors.New("invalid tunnel session identifier")
	}
	switch raw[45] {
	case 'a':
		frame.role = RoleA
	case 'b':
		frame.role = RoleB
	default:
		return tunnelFrame{}, errors.New("invalid tunnel role")
	}
	copy(frame.token[:], raw[46:46+tunnelTokenBytes])
	switch raw[62] {
	case 0:
	case 1:
		frame.peerReady = true
	default:
		return tunnelFrame{}, errors.New("invalid tunnel flag")
	}
	for _, pad := range raw[tunnelHeaderBytes:] {
		if pad != 0 {
			return tunnelFrame{}, errors.New("invalid tunnel padding")
		}
	}
	return frame, nil
}

// TunnelRelayOptions configures a relay.
type TunnelRelayOptions struct {
	SessionTTL time.Duration
	// MaxSessions bounds relay memory.
	MaxSessions int
	// SessionByteBudget caps forwarded bytes per session, both directions
	// counted together.
	SessionByteBudget uint64
	RequestsPerWindow int
	RateWindow        time.Duration
	MaxSources        int
	Now               func() time.Time
}

// TunnelRelay is the double-registration forwarder. It holds no state beyond
// the live sessions, learns nothing about the forwarded payload, and never
// looks inside it.
type TunnelRelay struct {
	ttl      time.Duration
	capacity int
	budget   uint64
	limiter  *rateLimiter
	now      func() time.Time

	mutex    sync.Mutex
	sessions map[string]*tunnelSession
	byTuple  map[netip.AddrPort]tunnelBinding
}

type tunnelBinding struct {
	sessionID string
	role      Role
}

type tunnelEndpoint struct {
	tuple      netip.AddrPort
	token      [tunnelTokenBytes]byte
	registered bool
}

type tunnelSession struct {
	endpoints map[Role]*tunnelEndpoint
	forwarded uint64
	touchedAt time.Time
}

// NewTunnelRelay builds a relay. An invalid option is an error rather than a
// silent default, for the same reason the coordinator refuses one: a
// measurement service that quietly changed its own limits would make the
// resulting matrix unreproducible.
func NewTunnelRelay(options TunnelRelayOptions) (*TunnelRelay, error) {
	ttl := options.SessionTTL
	if ttl == 0 {
		ttl = DefaultTunnelSessionTTL
	}
	capacity := options.MaxSessions
	if capacity == 0 {
		capacity = DefaultTunnelMaxSessions
	}
	budget := options.SessionByteBudget
	if budget == 0 {
		budget = DefaultTunnelSessionBytes
	}
	perWindow := options.RequestsPerWindow
	if perWindow == 0 {
		perWindow = DefaultRequestsPerWindow
	}
	window := options.RateWindow
	if window == 0 {
		window = DefaultRateWindow
	}
	sources := options.MaxSources
	if sources == 0 {
		sources = DefaultMaxSources
	}
	clock := options.Now
	if clock == nil {
		clock = time.Now
	}
	if ttl <= 0 || capacity <= 0 || perWindow <= 0 || window <= 0 || sources <= 0 {
		return nil, errors.New("invalid tunnel relay limits")
	}
	return &TunnelRelay{
		ttl:      ttl,
		capacity: capacity,
		budget:   budget,
		limiter:  newRateLimiter(perWindow, window, sources),
		now:      clock,
		sessions: make(map[string]*tunnelSession),
		byTuple:  make(map[netip.AddrPort]tunnelBinding),
	}, nil
}

// Handle answers one datagram. It returns the datagram to send and where to
// send it; nil bytes mean the input is dropped without a word, which is the
// correct response to anything that cannot be answered without amplifying it,
// or forwarded without both endpoints having proven their addresses.
func (t *TunnelRelay) Handle(raw []byte, from netip.AddrPort) ([]byte, netip.AddrPort) {
	if len(raw) == 0 || len(raw) > MaxTunnelDatagramBytes || !from.IsValid() {
		return nil, netip.AddrPort{}
	}
	t.mutex.Lock()
	defer t.mutex.Unlock()
	now := t.now()
	t.expireLocked(now)

	if binding, bound := t.byTuple[from]; bound {
		return t.fromRegisteredLocked(raw, from, binding, now)
	}
	// Everything from an unregistered tuple has to be a well-formed control
	// request at exactly the padding floor. Anything else -- payload from a
	// stranger, a spoofed probe, a malformed frame -- is dropped silently,
	// because answering it would either amplify it or acknowledge it.
	if len(raw) != TunnelRequestFloor {
		return nil, netip.AddrPort{}
	}
	frame, err := decodeTunnelFrame(raw)
	if err != nil {
		return nil, netip.AddrPort{}
	}
	if !t.limiter.allow(from.Addr(), now) {
		return nil, netip.AddrPort{}
	}
	switch frame.kind {
	case tunnelKindRegister:
		return t.registerLocked(frame, from, now)
	case tunnelKindEcho:
		return t.echoLocked(frame, from, now)
	default:
		return nil, netip.AddrPort{}
	}
}

// fromRegisteredLocked handles a datagram from a tuple that completed its
// registration. One control shape stays recognisable -- the endpoint's own
// echo, byte-exact down to its token, so a status answer lost in flight can
// be re-polled instead of stranding the client -- and everything else is the
// session's payload, forwarded verbatim to the other registered endpoint.
// A payload datagram being misread as that echo would need the peer's session
// to emit our exact 128-byte frame including the secret token, which is not a
// collision, it is the token having leaked.
func (t *TunnelRelay) fromRegisteredLocked(raw []byte, from netip.AddrPort,
	binding tunnelBinding, now time.Time) ([]byte, netip.AddrPort) {
	session, live := t.sessions[binding.sessionID]
	if !live {
		delete(t.byTuple, from)
		return nil, netip.AddrPort{}
	}
	self := session.endpoints[binding.role]
	if self == nil || !self.registered || self.tuple != from {
		return nil, netip.AddrPort{}
	}
	peer := session.endpoints[binding.role.Peer()]
	if len(raw) == TunnelRequestFloor {
		if frame, err := decodeTunnelFrame(raw); err == nil &&
			frame.kind == tunnelKindEcho && frame.sessionID == binding.sessionID &&
			frame.role == binding.role && frame.token == self.token {
			if !t.limiter.allow(from.Addr(), now) {
				return nil, netip.AddrPort{}
			}
			session.touchedAt = now
			return t.statusLocked(binding.sessionID, binding.role, self.token, peer, from, len(raw))
		}
	}
	if peer == nil || !peer.registered {
		return nil, netip.AddrPort{}
	}
	// Forwarding is capped by bytes per session as well as by the session's
	// lifetime, so two registered endpoints cannot turn the relay into
	// unmetered transit. The forwarded datagram is byte-for-byte what arrived,
	// so nothing here amplifies, and it only ever goes to an address that
	// proved it can receive by echoing its token.
	next := session.forwarded + uint64(len(raw))
	if next < session.forwarded || next > t.budget {
		return nil, netip.AddrPort{}
	}
	session.forwarded = next
	session.touchedAt = now
	return raw, peer.tuple
}

// registerLocked starts one endpoint's registration: it stores the claimed
// tuple with a fresh random token and answers with the challenge. The token
// travels only to the claimed source address, which is the whole anti-spoofing
// argument -- completing the registration requires having received there.
func (t *TunnelRelay) registerLocked(frame tunnelFrame, from netip.AddrPort, now time.Time) ([]byte, netip.AddrPort) {
	session, found := t.sessions[frame.sessionID]
	if !found {
		if len(t.sessions) >= t.capacity {
			return nil, netip.AddrPort{}
		}
		session = &tunnelSession{endpoints: make(map[Role]*tunnelEndpoint, 2)}
		t.sessions[frame.sessionID] = session
	}
	endpoint := session.endpoints[frame.role]
	if endpoint != nil && endpoint.registered {
		// A completed registration is locked. Answering a late register would
		// let anyone who learned the session identifier evict a proven
		// endpoint and take its place in the forwarding pair.
		return nil, netip.AddrPort{}
	}
	var token [tunnelTokenBytes]byte
	if _, err := rand.Read(token[:]); err != nil {
		return nil, netip.AddrPort{}
	}
	session.touchedAt = now
	// A pending (unproven) slot is overwritten rather than locked: the honest
	// client retries after a lost challenge, possibly from a rebound socket,
	// and only the tuple that receives this new token can complete.
	session.endpoints[frame.role] = &tunnelEndpoint{tuple: from, token: token}
	answer, err := encodeTunnelFrame(tunnelFrame{
		kind: tunnelKindChallenge, sessionID: frame.sessionID, role: frame.role, token: token,
	}, 0)
	if err != nil || len(answer) > TunnelRequestFloor {
		return nil, netip.AddrPort{}
	}
	return answer, from
}

// echoLocked completes one endpoint's registration. The echo has to arrive
// from exactly the tuple the challenge was sent to, carrying exactly the token
// it carried: anything else is a spoofed source that never saw the token, or a
// bystander guessing, and both are dropped without a word.
func (t *TunnelRelay) echoLocked(frame tunnelFrame, from netip.AddrPort, now time.Time) ([]byte, netip.AddrPort) {
	session, found := t.sessions[frame.sessionID]
	if !found {
		return nil, netip.AddrPort{}
	}
	endpoint := session.endpoints[frame.role]
	if endpoint == nil || endpoint.tuple != from || endpoint.token != frame.token {
		return nil, netip.AddrPort{}
	}
	if !endpoint.registered {
		endpoint.registered = true
		t.byTuple[from] = tunnelBinding{sessionID: frame.sessionID, role: frame.role}
	}
	session.touchedAt = now
	return t.statusLocked(frame.sessionID, frame.role, endpoint.token,
		session.endpoints[frame.role.Peer()], from, TunnelRequestFloor)
}

// statusLocked builds the answer that tells an endpoint whether its peer has
// registered too, addressed back to the tuple that asked. The client keeps
// re-echoing until this says yes, and only then hands its socket to the
// gateway, so no payload is ever sent into a half-registered session on
// purpose. The answer is refused rather than sent if it could not stay within
// the size of the request that produced it.
func (t *TunnelRelay) statusLocked(sessionID string, role Role, token [tunnelTokenBytes]byte,
	peer *tunnelEndpoint, to netip.AddrPort, requestBytes int) ([]byte, netip.AddrPort) {
	ready := peer != nil && peer.registered
	answer, err := encodeTunnelFrame(tunnelFrame{
		kind: tunnelKindStatus, sessionID: sessionID, role: role, token: token, peerReady: ready,
	}, 0)
	if err != nil || len(answer) > requestBytes {
		return nil, netip.AddrPort{}
	}
	return answer, to
}

// expireLocked sweeps sessions past their lifetime, together with the tuple
// bindings that would otherwise keep forwarding for a session that no longer
// exists.
func (t *TunnelRelay) expireLocked(now time.Time) {
	for id, session := range t.sessions {
		if now.Sub(session.touchedAt) <= t.ttl {
			continue
		}
		for _, endpoint := range session.endpoints {
			if endpoint.registered {
				delete(t.byTuple, endpoint.tuple)
			}
		}
		delete(t.sessions, id)
	}
}

// Sessions reports the number of live tunnel sessions.
func (t *TunnelRelay) Sessions() int {
	t.mutex.Lock()
	defer t.mutex.Unlock()
	t.expireLocked(t.now())
	return len(t.sessions)
}

// Serve reads datagrams until the connection is closed. The read buffer is
// one byte larger than the datagram bound so an oversized datagram is seen as
// oversized and dropped, rather than silently truncated and forwarded as a
// corrupted packet.
func (t *TunnelRelay) Serve(connection net.PacketConn) error {
	buffer := make([]byte, MaxTunnelDatagramBytes+1)
	for {
		count, from, err := connection.ReadFrom(buffer)
		if err != nil {
			return err
		}
		source, ok := addrPort(from)
		if !ok {
			continue
		}
		answer, destination := t.Handle(buffer[:count], source)
		if answer == nil || !destination.IsValid() {
			continue
		}
		if _, err := connection.WriteTo(answer, net.UDPAddrFromAddrPort(destination)); err != nil {
			return err
		}
	}
}

// registerWithTunnel performs this endpoint's half of the double registration,
// over exactly the socket the ADNL gateway will take over afterwards, so the
// 5-tuple the relay proved is the 5-tuple the session's packets will use. It
// registers, echoes the token the relay sent back to this address, then keeps
// re-echoing until the relay reports the peer registered too or the deadline
// passes, and returns the relay's address -- which is, to both gateways, where
// the peer lives.
func registerWithTunnel(ctx context.Context, connection net.PacketConn, relay string,
	sessionID string, role Role, deadline time.Time) (netip.AddrPort, error) {
	if connection == nil {
		return netip.AddrPort{}, errors.New("no socket to register over")
	}
	target, err := net.ResolveUDPAddr("udp", relay)
	if err != nil {
		return netip.AddrPort{}, errors.New("resolve tunnel relay")
	}
	relayAddr, ok := addrPort(target)
	if !ok || relayAddr.Port() == 0 || relayAddr.Addr().IsUnspecified() {
		return netip.AddrPort{}, errors.New("unusable tunnel relay address")
	}
	register, err := encodeTunnelFrame(tunnelFrame{
		kind: tunnelKindRegister, sessionID: sessionID, role: role,
	}, TunnelRequestFloor)
	if err != nil {
		return netip.AddrPort{}, err
	}
	var token [tunnelTokenBytes]byte
	haveToken := false
	buffer := make([]byte, MaxTunnelDatagramBytes+1)
	for time.Now().Before(deadline) {
		if err := ctx.Err(); err != nil {
			return netip.AddrPort{}, err
		}
		request := register
		if haveToken {
			echo, err := encodeTunnelFrame(tunnelFrame{
				kind: tunnelKindEcho, sessionID: sessionID, role: role, token: token,
			}, TunnelRequestFloor)
			if err != nil {
				return netip.AddrPort{}, err
			}
			request = echo
		}
		if _, err := connection.WriteTo(request, target); err != nil {
			return netip.AddrPort{}, errors.New("send to tunnel relay")
		}
		window := minTime(deadline, time.Now().Add(300*time.Millisecond))
	reads:
		for time.Now().Before(window) {
			if err := connection.SetReadDeadline(window); err != nil {
				return netip.AddrPort{}, errors.New("arm tunnel read deadline")
			}
			count, from, err := connection.ReadFrom(buffer)
			if err != nil {
				break
			}
			source, valid := addrPort(from)
			if !valid || source != relayAddr {
				continue
			}
			frame, decodeErr := decodeTunnelFrame(buffer[:count])
			if decodeErr != nil {
				// The peer's first payload can already be flowing through the
				// relay while this endpoint is still polling. Dropping it here
				// loses one datagram of a protocol that retries; answering it
				// is the gateway's job, and the gateway takes this socket over
				// next.
				continue
			}
			if frame.sessionID != sessionID || frame.role != role {
				continue
			}
			switch frame.kind {
			case tunnelKindChallenge:
				token = frame.token
				haveToken = true
				// Echo immediately rather than at the next resend interval.
				break reads
			case tunnelKindStatus:
				if haveToken && frame.token == token && frame.peerReady {
					return relayAddr, nil
				}
			}
		}
	}
	return netip.AddrPort{}, errors.New("tunnel registration never completed")
}
