package probe

import (
	"errors"
	"net"
	"net/netip"
	"sync"
	"time"
)

const (
	// DefaultSessionTTL bounds how long a pairing is remembered.
	DefaultSessionTTL = 5 * time.Minute
	// DefaultMaxSessions bounds coordinator memory.
	DefaultMaxSessions = 4096
	// DefaultRequestsPerWindow bounds one source address per window.
	//
	// Two endpoints behind one carrier-grade NAT share a source address, and
	// each polls for the length of its pairing timeout. A budget that only fits
	// one endpoint would throttle precisely the network class the study exists
	// to measure, so the default carries several full sessions.
	DefaultRequestsPerWindow = 600
	// DefaultRateWindow is the rate-limit window.
	DefaultRateWindow = time.Minute
	// DefaultMaxSources bounds the rate-limit table.
	DefaultMaxSources = 16384
)

// Coordinator is the rendezvous service: it reports the source address it
// observes and exchanges candidate sets between the two endpoints of a
// session.
//
// It holds no long-lived state, learns nothing about the conversation that a
// later Messenger session would carry, and is not part of the Messenger. It
// exists so that a measurement can be run at all.
type Coordinator struct {
	serverID string
	ttl      time.Duration
	capacity int
	limiter  *rateLimiter
	now      func() time.Time

	mutex    sync.Mutex
	sessions map[string]*pairing
}

type pairing struct {
	endpoints map[Role]*endpointState
	touchedAt time.Time
}

type endpointState struct {
	observed   netip.AddrPort
	candidates []string
	commit     string
}

// CoordinatorOptions configures a coordinator.
type CoordinatorOptions struct {
	ServerID          string
	SessionTTL        time.Duration
	MaxSessions       int
	RequestsPerWindow int
	RateWindow        time.Duration
	MaxSources        int
	Now               func() time.Time
}

// NewCoordinator builds a coordinator. An invalid option is an error rather
// than a silent default, because a measurement service that quietly changed
// its own limits would make the resulting matrix unreproducible.
func NewCoordinator(options CoordinatorOptions) (*Coordinator, error) {
	if !serverPattern.MatchString(options.ServerID) {
		return nil, errors.New("invalid coordinator server identifier")
	}
	ttl := options.SessionTTL
	if ttl == 0 {
		ttl = DefaultSessionTTL
	}
	capacity := options.MaxSessions
	if capacity == 0 {
		capacity = DefaultMaxSessions
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
		return nil, errors.New("invalid coordinator limits")
	}
	return &Coordinator{
		serverID: options.ServerID,
		ttl:      ttl,
		capacity: capacity,
		limiter:  newRateLimiter(perWindow, window, sources),
		now:      clock,
		sessions: make(map[string]*pairing),
	}, nil
}

// Handle answers one request. It returns nil bytes when the datagram must be
// dropped without a reply, which is the correct response to anything that
// cannot be answered without amplifying it.
func (c *Coordinator) Handle(request []byte, from netip.AddrPort) []byte {
	if len(request) < MinRequestBytes || len(request) > MaxMessageBytes || !from.IsValid() {
		return nil
	}
	if !c.limiter.allow(from.Addr(), c.now()) {
		return nil
	}
	message, err := Decode(request)
	if err != nil {
		return nil
	}
	var response Message
	switch message.Kind {
	case KindBind:
		response = Message{
			Kind: KindBindOK, SessionID: message.SessionID, Role: message.Role,
			Nonce: message.Nonce, Observed: from.String(), ServerID: c.serverID,
		}
	case KindPair:
		peer, peerPublic, peerCommit, reason := c.pair(message, from)
		if reason != "" {
			response = Message{
				Kind: KindError, SessionID: message.SessionID, Role: message.Role,
				Nonce: message.Nonce, ServerID: c.serverID, Reason: reason,
			}
			break
		}
		response = Message{
			Kind: KindPairOK, SessionID: message.SessionID, Role: message.Role,
			Nonce: message.Nonce, Observed: from.String(), ServerID: c.serverID,
			Candidates: peer, PeerPublic: peerPublic, PeerCommit: peerCommit,
		}
	default:
		// Punch traffic belongs between peers. A coordinator that answered it
		// would become a relay, which is not what is being measured.
		return nil
	}
	encoded, err := Encode(response)
	if err != nil {
		return nil
	}
	if err := CheckNoAmplification(request, encoded); err != nil {
		return nil
	}
	return encoded
}

// pair records one endpoint and returns the peer's candidate set along with
// whether the peer is publicly addressable.
//
// Only the coordinator sees both sides, so only the coordinator can answer the
// second question. An endpoint that had to guess it would be labelling its own
// stratum from an assumption, and the stratum is what the decision is computed
// over.
func (c *Coordinator) pair(message Message, from netip.AddrPort) ([]string, string, string, string) {
	c.mutex.Lock()
	defer c.mutex.Unlock()
	now := c.now()
	c.expireLocked(now)

	session, found := c.sessions[message.SessionID]
	if !found {
		if len(c.sessions) >= c.capacity {
			return nil, "", "", "coordinator is at capacity"
		}
		session = &pairing{endpoints: make(map[Role]*endpointState, 2)}
		c.sessions[message.SessionID] = session
	}
	session.touchedAt = now
	session.endpoints[message.Role] = &endpointState{observed: from, candidates: message.Candidates, commit: message.Commit}

	peer, present := session.endpoints[message.Role.Peer()]
	if !present {
		return nil, "", "", ""
	}
	peerPublic := PeerPublicNo
	for _, candidate := range peer.candidates {
		if candidate == peer.observed.String() {
			peerPublic = PeerPublicYes
			break
		}
	}
	candidates := make([]string, 0, MaxCandidates)
	seen := make(map[string]struct{}, MaxCandidates)
	for _, candidate := range append([]string{peer.observed.String()}, peer.candidates...) {
		if _, duplicate := seen[candidate]; duplicate {
			continue
		}
		seen[candidate] = struct{}{}
		candidates = append(candidates, candidate)
		if len(candidates) == MaxCandidates {
			break
		}
	}
	return candidates, peerPublic, peer.commit, ""
}

func (c *Coordinator) expireLocked(now time.Time) {
	for id, session := range c.sessions {
		if now.Sub(session.touchedAt) > c.ttl {
			delete(c.sessions, id)
		}
	}
}

// Sessions reports the number of live pairings.
func (c *Coordinator) Sessions() int {
	c.mutex.Lock()
	defer c.mutex.Unlock()
	c.expireLocked(c.now())
	return len(c.sessions)
}

// Serve reads datagrams until the connection is closed.
func (c *Coordinator) Serve(connection net.PacketConn) error {
	buffer := make([]byte, MaxMessageBytes)
	for {
		count, from, err := connection.ReadFrom(buffer)
		if err != nil {
			return err
		}
		source, ok := addrPort(from)
		if !ok {
			continue
		}
		response := c.Handle(buffer[:count], source)
		if response == nil {
			continue
		}
		if _, err := connection.WriteTo(response, from); err != nil {
			return err
		}
	}
}

func addrPort(address net.Addr) (netip.AddrPort, bool) {
	udp, ok := address.(*net.UDPAddr)
	if !ok {
		return netip.AddrPort{}, false
	}
	parsed, ok := netip.AddrFromSlice(udp.IP)
	if !ok {
		return netip.AddrPort{}, false
	}
	return netip.AddrPortFrom(parsed.Unmap(), uint16(udp.Port)), true
}

// rateLimiter is a fixed-window counter with a bounded table. The table is
// cleared rather than grown without limit: forgetting counters is a fairness
// cost, while an unbounded table is a memory-exhaustion path.
type rateLimiter struct {
	perWindow int
	window    time.Duration
	maxSource int

	mutex    sync.Mutex
	windowAt time.Time
	observed map[netip.Addr]int
}

func newRateLimiter(perWindow int, window time.Duration, maxSource int) *rateLimiter {
	return &rateLimiter{
		perWindow: perWindow,
		window:    window,
		maxSource: maxSource,
		observed:  make(map[netip.Addr]int),
	}
}

func (r *rateLimiter) allow(source netip.Addr, now time.Time) bool {
	r.mutex.Lock()
	defer r.mutex.Unlock()
	if r.windowAt.IsZero() || now.Sub(r.windowAt) >= r.window {
		r.windowAt = now
		r.observed = make(map[netip.Addr]int)
	}
	count, tracked := r.observed[source]
	if !tracked && len(r.observed) >= r.maxSource {
		return false
	}
	if count >= r.perWindow {
		return false
	}
	r.observed[source] = count + 1
	return true
}
