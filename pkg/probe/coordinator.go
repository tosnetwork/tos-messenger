package probe

import (
	"crypto/ed25519"
	"errors"
	"net"
	"net/netip"
	"sync"
	"time"

	"github.com/tosnetwork/tos-messenger/pkg/reachability"
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
	key      ed25519.PrivateKey
	ttl      time.Duration
	capacity int
	limiter  *rateLimiter
	now      func() time.Time

	mutex    sync.Mutex
	sessions map[string]*pairing
	// filterSources are the cold sockets filter probes are sent from, one per
	// source kind. They are write-only: a cold source that answered anything
	// would stop being cold.
	filterSources map[reachability.FilterSourceKind]net.PacketConn
	// filterGrants holds the outstanding receipt tokens, each redeemable only
	// over the flow its probe was sent to.
	filterGrants map[string]*filterGrant
}

// filterGrant is one outstanding cold-source probe: the token it carried and
// the flow it may be redeemed over.
type filterGrant struct {
	sessionID   string
	role        Role
	endpointKey string
	probe       string
	observed    netip.AddrPort
	source      reachability.FilterSourceKind
	issuedAt    time.Time
}

type pairing struct {
	endpoints map[Role]*endpointState
	done      map[Role]bool
	touchedAt time.Time
}

type endpointState struct {
	observed     netip.AddrPort
	candidates   []string
	commit       string
	probe        string
	transportKey string
}

// CoordinatorOptions configures a coordinator.
type CoordinatorOptions struct {
	// PrivateKey signs what the coordinator observed. The identifier is
	// derived from it rather than chosen, so a coordinator cannot present
	// itself under a name it does not hold the key for.
	PrivateKey        ed25519.PrivateKey
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
	if len(options.PrivateKey) != ed25519.PrivateKeySize {
		return nil, errors.New("a coordinator needs a signing key")
	}
	public, ok := options.PrivateKey.Public().(ed25519.PublicKey)
	if !ok {
		return nil, errors.New("invalid coordinator signing key")
	}
	serverID, err := reachability.CoordinatorID(public)
	if err != nil {
		return nil, err
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
		serverID:      serverID,
		key:           options.PrivateKey,
		ttl:           ttl,
		capacity:      capacity,
		limiter:       newRateLimiter(perWindow, window, sources),
		now:           clock,
		sessions:      make(map[string]*pairing),
		filterSources: make(map[reachability.FilterSourceKind]net.PacketConn),
		filterGrants:  make(map[string]*filterGrant),
	}, nil
}

// AttachFilterSource gives the coordinator one cold socket to send filter
// probes from: a second port on the coordinator's own address, or a socket on
// a secondary address it also holds. The kind is what the coordinator will
// attest, so it has to be configured truthfully -- the endpoint never states
// it and cannot check it, which is the same trust the policy already places in
// a predeclared coordinator's signatures. At most one source per kind: a
// second socket under one kind could not be told apart in the evidence.
func (c *Coordinator) AttachFilterSource(kind reachability.FilterSourceKind, connection net.PacketConn) error {
	if kind != reachability.FilterSourceOtherPort && kind != reachability.FilterSourceOtherAddress {
		return errors.New("unknown filter source kind")
	}
	if connection == nil {
		return errors.New("a filter source needs a socket")
	}
	c.mutex.Lock()
	defer c.mutex.Unlock()
	if _, taken := c.filterSources[kind]; taken {
		return errors.New("this filter source kind is already attached")
	}
	c.filterSources[kind] = connection
	return nil
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
		// The address a coordinator reflects at bind, attested per coordinator,
		// is what lets the NAT mapping class be derived from signed evidence
		// across several coordinators rather than from the endpoint's own
		// declaration. A bind request that names the endpoint key and probe
		// gets a signed reflection; an older one that omits them still gets its
		// address, unsigned.
		if message.EndpointKey != "" && message.Probe != "" {
			attested, err := c.attestBind(message, from)
			if err != nil {
				return nil
			}
			response.ObservedAt = attested.AtUnix
			response.SignerKey = attested.PublicKeyHex
			response.Signature = attested.SignatureHex
		}
	case KindPair:
		peer, peerPublic, peerCommit, peerTransportKey, reason := c.pair(message, from)
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
			PeerTransportKey: peerTransportKey,
		}
		// The address observed here and whether the peer is publicly
		// addressable are the two facts that place a trial in its stratum, and
		// an endpoint cannot check either about itself. Attesting to them is
		// what stops a stratum label from being the operator's own claim.
		if peerPublic != "" {
			attested, err := c.attest(message, from, peerPublic)
			if err != nil {
				return nil
			}
			response.ObservedAt = attested.AtUnix
			response.SignerKey = attested.PublicKeyHex
			response.Signature = attested.SignatureHex
		}
	case KindDone:
		peerDone := c.markDone(message)
		response = Message{
			Kind: KindDoneOK, SessionID: message.SessionID, Role: message.Role,
			Nonce: message.Nonce, ServerID: c.serverID, PeerDone: peerDone,
		}
	case KindFilter:
		// The answer to a filter request is the cold-source probes themselves,
		// paid for by the request's own padding. Nothing goes back on the
		// primary flow, so the whole exchange stays inside the request's
		// amplification budget, and a request that cannot be honoured within it
		// is silence.
		c.sendFilterProbes(message, from, len(request))
		return nil
	case KindFilterEcho:
		observation, ok := c.redeemFilterToken(message, from)
		if !ok {
			return nil
		}
		response = Message{
			Kind: KindFilterOK, SessionID: message.SessionID, Role: message.Role,
			Nonce: message.Nonce, ServerID: c.serverID, Token: message.Token,
			FilterSource: string(observation.Source), Observed: observation.Observed,
			ObservedAt: observation.AtUnix, SignerKey: observation.PublicKeyHex,
			Signature: observation.SignatureHex,
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

// attest signs what the coordinator saw.
//
// The address observed here and whether the peer is publicly addressable are
// the two facts that place a trial in its stratum, and an endpoint cannot
// check either about itself. Attesting to them is what stops a stratum label
// from being the operator's own claim about which cell their result counts
// towards.
func (c *Coordinator) attest(message Message, from netip.AddrPort, peerPublic string) (reachability.Observation, error) {
	return reachability.SignObservation(reachability.Observation{
		SessionID: message.SessionID,
		Role:      string(message.Role),
		// The attestation names the party as well as the session. A bystander
		// who copied it would be presenting a statement about somebody else's
		// key, which is not a statement they can wear.
		EndpointPublicKeyHex: message.EndpointKey,
		Probe:                message.Probe,
		Observed:             from.String(),
		PeerPublic:           peerPublic,
		AtUnix:               uint64(c.now().Unix()),
	}, c.key)
}

// attestBind signs the external address a coordinator reflected at bind.
//
// Each coordinator attests only to what it reflected, for the named endpoint
// and probe. The set of these across several coordinators is what the NAT
// mapping class is derived from, so no single coordinator decides it and the
// endpoint cannot declare it for itself.
func (c *Coordinator) attestBind(message Message, from netip.AddrPort) (reachability.BindObservation, error) {
	return reachability.SignBindObservation(reachability.BindObservation{
		SessionID:            message.SessionID,
		Role:                 string(message.Role),
		EndpointPublicKeyHex: message.EndpointKey,
		Probe:                message.Probe,
		Observed:             from.String(),
		AtUnix:               uint64(c.now().Unix()),
	}, c.key)
}

// pair records one endpoint and returns the peer's candidate set along with
// whether the peer is publicly addressable.
//
// Only the coordinator sees both sides, so only the coordinator can answer the
// second question. An endpoint that had to guess it would be labelling its own
// stratum from an assumption, and the stratum is what the decision is computed
// over.
func (c *Coordinator) pair(message Message, from netip.AddrPort) ([]string, string, string, string, string) {
	c.mutex.Lock()
	defer c.mutex.Unlock()
	now := c.now()
	c.expireLocked(now)

	session, found := c.sessions[message.SessionID]
	if !found {
		if len(c.sessions) >= c.capacity {
			return nil, "", "", "", "coordinator is at capacity"
		}
		session = &pairing{endpoints: make(map[Role]*endpointState, 2), done: make(map[Role]bool, 2)}
		c.sessions[message.SessionID] = session
	}
	session.touchedAt = now
	session.endpoints[message.Role] = &endpointState{
		observed: from, candidates: message.Candidates, commit: message.Commit,
		probe: message.Probe, transportKey: message.TransportKey,
	}

	peer, present := session.endpoints[message.Role.Peer()]
	if !present {
		return nil, "", "", "", ""
	}
	// Two halves measuring different probes are not one measurement, and the
	// aggregation would discard the pair anyway. Refusing here tells the
	// operators at pairing time rather than at report time.
	if peer.probe != message.Probe {
		return nil, "", "", "", "the two endpoints are measuring different probes"
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
	return candidates, peerPublic, peer.commit, peer.transportKey, ""
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

// sendFilterProbes answers a filter request by probing the requester's
// observed address from every attached cold source.
//
// The discipline is the coordinator's usual one, applied across sockets: the
// probes go only to the observed source address of the requesting flow, never
// to an address the request names, so a spoofed request can only ever direct
// traffic at the spoofed host's own reflection of itself; and the probes sent
// for one request together never exceed the request's own padded size, so the
// cold sockets cannot amplify. Each probe carries a fresh random token, and
// the token is the entire proof: it travels only through the path whose
// filtering is under test.
func (c *Coordinator) sendFilterProbes(message Message, from netip.AddrPort, budget int) {
	// Deterministic order, so which source wins a tight budget is not
	// map-iteration luck.
	order := []reachability.FilterSourceKind{
		reachability.FilterSourceOtherPort,
		reachability.FilterSourceOtherAddress,
	}
	now := c.now()
	c.mutex.Lock()
	defer c.mutex.Unlock()
	c.expireFilterGrantsLocked(now)
	spent := 0
	for _, kind := range order {
		connection, attached := c.filterSources[kind]
		if !attached {
			continue
		}
		// The grant table is bounded by the pairing capacity: two cold sources
		// per session is what an honest load produces, and past that the probe
		// is not sent rather than the table growing without limit.
		if len(c.filterGrants) >= c.capacity*len(order) {
			return
		}
		token, err := randomHex16()
		if err != nil {
			return
		}
		probe, err := Encode(Message{
			Kind: KindFilterProbe, SessionID: message.SessionID, Role: message.Role,
			Nonce: message.Nonce, Token: token, ServerID: c.serverID,
		})
		if err != nil {
			continue
		}
		if spent+len(probe) > budget {
			continue
		}
		if _, err := connection.WriteTo(probe, net.UDPAddrFromAddrPort(from)); err != nil {
			continue
		}
		spent += len(probe)
		c.filterGrants[token] = &filterGrant{
			sessionID: message.SessionID, role: message.Role,
			endpointKey: message.EndpointKey, probe: message.Probe,
			observed: from, source: kind, issuedAt: now,
		}
	}
}

// redeemFilterToken turns an echoed token into a signed filtering observation.
//
// The echo must arrive over the same flow the probe was sent to, and must name
// the same session, role, endpoint key, and probe the grant was issued for:
// anything else is somebody trying to wear a receipt that is not theirs, and
// is dropped silently. The grant survives redemption until it expires, so an
// echo whose answer was lost can be retried.
func (c *Coordinator) redeemFilterToken(message Message, from netip.AddrPort) (reachability.FilteringObservation, bool) {
	c.mutex.Lock()
	defer c.mutex.Unlock()
	now := c.now()
	c.expireFilterGrantsLocked(now)
	grant, found := c.filterGrants[message.Token]
	if !found {
		return reachability.FilteringObservation{}, false
	}
	if grant.sessionID != message.SessionID || grant.role != message.Role ||
		grant.endpointKey != message.EndpointKey || grant.probe != message.Probe ||
		grant.observed != from {
		return reachability.FilteringObservation{}, false
	}
	observation, err := reachability.SignFilteringObservation(reachability.FilteringObservation{
		SessionID:            grant.sessionID,
		Role:                 string(grant.role),
		EndpointPublicKeyHex: grant.endpointKey,
		Probe:                grant.probe,
		Observed:             grant.observed.String(),
		Source:               grant.source,
		AtUnix:               uint64(now.Unix()),
	}, c.key)
	if err != nil {
		return reachability.FilteringObservation{}, false
	}
	return observation, true
}

func (c *Coordinator) expireFilterGrantsLocked(now time.Time) {
	for token, grant := range c.filterGrants {
		if now.Sub(grant.issuedAt) > c.ttl {
			delete(c.filterGrants, token)
		}
	}
}

// markDone records that one endpoint finished measuring and reports whether
// the other has. It is the lifetime half of the rendezvous: each endpoint
// holds its gateway open until the peer is done or the window ends, and the
// signal travels through the coordinator because the session under test must
// not carry its own test's control plane.
func (c *Coordinator) markDone(message Message) bool {
	c.mutex.Lock()
	defer c.mutex.Unlock()
	now := c.now()
	c.expireLocked(now)
	session, found := c.sessions[message.SessionID]
	if !found {
		// The pairing has expired; whatever the peer was doing is over.
		return true
	}
	session.touchedAt = now
	session.done[message.Role] = true
	return session.done[message.Role.Peer()]
}
