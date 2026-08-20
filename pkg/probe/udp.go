package probe

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"net"
	"net/netip"
	"time"

	"github.com/tosnetwork/tos-messenger/pkg/reachability"
)

const (
	// DefaultBindTimeout bounds reflexive address discovery.
	DefaultBindTimeout = 3 * time.Second
	// DefaultPairTimeout bounds waiting for the peer to arrive.
	DefaultPairTimeout = 30 * time.Second
	// DefaultPunchTimeout bounds the direct establishment attempt.
	DefaultPunchTimeout = 10 * time.Second
	// DefaultPollInterval paces coordinator polling and punch retries.
	DefaultPollInterval = 250 * time.Millisecond
	// DefaultLingerWindow is how long an endpoint keeps answering the peer
	// after its own path is established.
	DefaultLingerWindow = 2 * time.Second
)

// Config configures one measured endpoint.
type Config struct {
	Coordinators []string
	SessionID    string
	Role         Role
	ListenAddr   string
	BindTimeout  time.Duration
	PairTimeout  time.Duration
	PunchTimeout time.Duration
	PollInterval time.Duration
	LingerWindow time.Duration
	Commit       string
	// EndpointKeyHex is the public key this endpoint will sign its trial with.
	// It is presented to the coordinator so the attestation names a party, not
	// only a session.
	EndpointKeyHex string
	// Probe names what is being measured.
	Probe reachability.ProbeKind
}

// Result is what one endpoint measured.
type Result struct {
	Observed        []netip.AddrPort
	Mapping         reachability.NATBehavior
	Reachability    reachability.Reachability
	AddressFamily   reachability.AddressFamily
	Established     bool
	EstablishMillis uint64
	PeerAddress     netip.AddrPort
	Failure         reachability.FailureClass
	PeerCommit      string
	// PeerTransportKey is the key the peer will run its measured transport
	// under, learned during pairing.
	PeerTransportKey string
	// Observation is the coordinator's signed account of what it saw. A result
	// without one cannot be filed under a stratum, because the two facts that
	// place it there would be the endpoint's own claim.
	Observation reachability.Observation
	TxBytes     uint64
	RxBytes     uint64
}

// NewSessionID returns a fresh session identifier for one measured pair.
func NewSessionID() (string, error) {
	raw := make([]byte, 16)
	if _, err := rand.Read(raw); err != nil {
		return "", errors.New("generate probe session identifier")
	}
	return "ses_" + hex.EncodeToString(raw), nil
}

// NewServerID returns a fresh coordinator identifier.
func NewServerID() (string, error) {
	raw := make([]byte, 8)
	if _, err := rand.Read(raw); err != nil {
		return "", errors.New("generate probe server identifier")
	}
	return "srv_" + hex.EncodeToString(raw), nil
}

func newNonce() (string, error) {
	raw := make([]byte, 16)
	if _, err := rand.Read(raw); err != nil {
		return "", errors.New("generate probe nonce")
	}
	return hex.EncodeToString(raw), nil
}

type runner struct {
	config Config
	// transportKeyHex is presented during pairing for probes whose handshake
	// needs the peer's key. Empty for a plain datagram probe.
	transportKeyHex string
	connection      net.PacketConn
	result          Result
	selfPublic      bool
	learned         []netip.AddrPort
}

// observe answers a peer probe that arrives while this endpoint is still
// binding or pairing.
//
// Waiting until the pairing completes would drop the peer's probes on the
// floor and lose a path that demonstrably works: the datagram arrived, which
// is the one thing no amount of candidate exchange can prove. Answering it
// also records the source as a verified candidate to punch back at.
func (r *runner) observe(message Message, from netip.AddrPort) {
	if message.SessionID != r.config.SessionID || message.Role == r.config.Role ||
		message.Kind != KindPunch {
		return
	}
	if r.result.PeerCommit == "" && message.Commit != "" {
		r.result.PeerCommit = message.Commit
	}
	acknowledgement, err := Encode(Message{
		Kind: KindPunchAck, SessionID: r.config.SessionID, Role: r.config.Role,
		Nonce: message.Nonce, Sequence: message.Sequence, Commit: r.config.Commit,
	})
	if err != nil {
		return
	}
	r.send(acknowledgement, net.UDPAddrFromAddrPort(from))
	for _, known := range r.learned {
		if known == from {
			return
		}
	}
	if len(r.learned) < MaxCandidates {
		r.learned = append(r.learned, from)
	}
}

// Run measures one endpoint of one pair: reflexive discovery, mapping
// behavior, candidate exchange, and a direct establishment attempt.
//
// Every failure is classified rather than collapsed into a boolean, because
// the study's decision depends on distinguishing a blocked network from a
// peer that never arrived.
func Run(ctx context.Context, config Config) (Result, error) {
	if err := validateConfig(&config); err != nil {
		return Result{}, err
	}
	// This runner measures raw datagrams. Running it under another probe's
	// name would have the coordinator attest to a measurement that never
	// happened: the attestation names the probe from the pairing request, and
	// the pairing request names whatever this config says.
	if config.Probe != reachability.ProbeUDP {
		return Result{}, errors.New("this runner measures the udp probe; use RunADNL for adnl")
	}
	connection, err := net.ListenPacket("udp", config.ListenAddr)
	if err != nil {
		return Result{}, errors.New("open probe socket")
	}
	defer connection.Close()

	instance := &runner{config: config, connection: connection}
	instance.result.Mapping = reachability.NATUndetermined
	instance.result.Failure = reachability.FailureInternal

	if err := instance.discover(ctx); err != nil {
		return instance.result, nil
	}
	peers, err := instance.exchange(ctx)
	if err != nil {
		return instance.result, nil
	}
	instance.punch(ctx, peers)
	return instance.result, nil
}

func validateConfig(config *Config) error {
	if len(config.Coordinators) == 0 || len(config.Coordinators) > 4 {
		return errors.New("a probe needs between one and four coordinators")
	}
	for _, coordinator := range config.Coordinators {
		if _, err := net.ResolveUDPAddr("udp", coordinator); err != nil {
			return errors.New("invalid coordinator address")
		}
	}
	if !sessionPattern.MatchString(config.SessionID) {
		return errors.New("invalid probe session identifier")
	}
	if config.Role != RoleA && config.Role != RoleB {
		return errors.New("invalid probe role")
	}
	// The coordinator attests to a party, so the party has to be named. A run
	// that could not say which key would sign its trial would be collecting an
	// attestation anybody could wear.
	if !endpointKeyPattern.MatchString(config.EndpointKeyHex) {
		return errors.New("a probe must present the endpoint key it will sign with")
	}
	if config.Probe != reachability.ProbeUDP && config.Probe != reachability.ProbeADNL {
		return errors.New("a probe must say what it is measuring")
	}
	if config.ListenAddr == "" {
		config.ListenAddr = ":0"
	}
	if config.BindTimeout == 0 {
		config.BindTimeout = DefaultBindTimeout
	}
	if config.PairTimeout == 0 {
		config.PairTimeout = DefaultPairTimeout
	}
	if config.PunchTimeout == 0 {
		config.PunchTimeout = DefaultPunchTimeout
	}
	if config.PollInterval == 0 {
		config.PollInterval = DefaultPollInterval
	}
	if config.LingerWindow == 0 {
		config.LingerWindow = DefaultLingerWindow
	}
	if config.LingerWindow < 0 {
		return errors.New("invalid probe linger window")
	}
	if config.Commit != "" && !commitPattern.MatchString(config.Commit) {
		return errors.New("invalid probe commit")
	}
	if config.BindTimeout < 0 || config.PairTimeout < 0 || config.PunchTimeout < 0 || config.PollInterval <= 0 {
		return errors.New("invalid probe timeouts")
	}
	return nil
}

// discover asks every coordinator what source address it observed, and
// classifies the mapping behavior from the answers.
func (r *runner) discover(ctx context.Context) error {
	for _, coordinator := range r.config.Coordinators {
		observed, err := r.bind(ctx, coordinator)
		if err != nil {
			r.result.Failure = reachability.FailureUDPBlocked
			return err
		}
		r.result.Observed = append(r.result.Observed, observed)
	}
	r.result.Mapping = classifyMapping(r.result.Observed, r.localPort(), hostAddrs())
	r.result.AddressFamily = classifyFamily(r.result.Observed)
	r.selfPublic = r.result.Mapping == reachability.NATNone
	return nil
}

// classifyFamily reports the family the reflexive observations actually used.
// It is measured rather than declared, because an operator's belief about
// which family a socket ended up on is not evidence.
func classifyFamily(observed []netip.AddrPort) reachability.AddressFamily {
	var four, six bool
	for _, address := range observed {
		if address.Addr().Is4() || address.Addr().Is4In6() {
			four = true
			continue
		}
		six = true
	}
	switch {
	case four && six:
		return reachability.FamilyDual
	case six:
		return reachability.FamilyIPv6
	default:
		return reachability.FamilyIPv4
	}
}

// recordObservation keeps the coordinator's attestation, and only if it
// verifies. An attestation that does not verify is worth no more than the
// claim it was supposed to replace, so it is dropped rather than carried
// forward to be discovered later.
func (r *runner) recordObservation(reply Message) {
	if reply.Signature == "" || reply.SignerKey == "" {
		return
	}
	identifier, err := reachability.CoordinatorID(mustKey(reply.SignerKey))
	if err != nil {
		return
	}
	// The endpoint key and the probe are this endpoint's own inputs to the
	// pairing, not something the reply echoes: the signature only verifies if
	// the coordinator signed exactly what was presented, so filling them in
	// locally is reconstruction, not trust.
	observation := reachability.Observation{
		CoordinatorID:        identifier,
		SessionID:            reply.SessionID,
		Role:                 string(reply.Role),
		EndpointPublicKeyHex: r.config.EndpointKeyHex,
		Probe:                string(r.config.Probe),
		Observed:             reply.Observed,
		PeerPublic:           reply.PeerPublic,
		AtUnix:               reply.ObservedAt,
		PublicKeyHex:         reply.SignerKey,
		SignatureHex:         reply.Signature,
	}
	if err := reachability.VerifyObservation(observation); err != nil {
		return
	}
	r.result.Observation = observation
}

func mustKey(encoded string) []byte {
	raw, err := hex.DecodeString(encoded)
	if err != nil {
		return nil
	}
	return raw
}

// classifySelf records what this endpoint measured about its own situation.
//
// It deliberately says nothing about the peer. Whether the far side was
// publicly addressable is the peer's own fact to report, and the joint label a
// route decision reads is derived when the two halves are paired. An endpoint
// that filled in its peer's side would be reporting a cell it cannot observe.
func (r *runner) classifySelf() {
	if r.selfPublic {
		r.result.Reachability = reachability.PublicAddress
		r.result.Mapping = reachability.NATNone
		return
	}
	r.result.Reachability = reachability.BehindNAT
	if r.result.Mapping == "" {
		r.result.Mapping = reachability.NATUndetermined
	}
}

// classifyMapping compares the addresses different coordinators observed.
//
// One coordinator cannot separate an endpoint-independent mapping from an
// address-dependent one, so a single observation is reported as undetermined
// rather than guessed. Deciding a route strategy on a guessed NAT class is the
// failure this study exists to prevent.
//
// An endpoint is unmapped only when the address a coordinator observed is the
// endpoint's own -- the same global IP on one of its interfaces, at the same
// port. Matching the port alone is not enough: a NAT that preserves the source
// port still translates the IP, and treating a port-preserving NAT as a public
// host would put a NATed endpoint into a cell it does not belong to.
func classifyMapping(observed []netip.AddrPort, localPort uint16, localAddrs []netip.Addr) reachability.NATBehavior {
	if len(observed) == 0 {
		return reachability.NATUndetermined
	}
	first := observed[0]
	if first.Port() == localPort && first.Addr().IsGlobalUnicast() && !isPrivate(first.Addr()) &&
		containsAddr(localAddrs, first.Addr()) {
		return reachability.NATNone
	}
	if len(observed) < 2 {
		return reachability.NATUndetermined
	}
	for _, candidate := range observed[1:] {
		if candidate != first {
			return reachability.NATAddressPortDependent
		}
	}
	return reachability.NATEndpointIndependent
}

func isPrivate(address netip.Addr) bool {
	return address.IsPrivate() || address.IsLoopback() || address.IsLinkLocalUnicast()
}

// containsAddr reports whether an address is one of the host's own, comparing
// canonicalised forms so an IPv4-in-IPv6 mapping does not hide a match.
func containsAddr(addrs []netip.Addr, target netip.Addr) bool {
	want := target.Unmap()
	for _, addr := range addrs {
		if addr.Unmap() == want {
			return true
		}
	}
	return false
}

// hostAddrs returns the host's own interface addresses. An endpoint is only
// unmapped if a coordinator observed one of these, so a NAT cannot be mistaken
// for a direct public address.
func hostAddrs() []netip.Addr {
	interfaces, err := net.InterfaceAddrs()
	if err != nil {
		return nil
	}
	addrs := make([]netip.Addr, 0, len(interfaces))
	for _, entry := range interfaces {
		network, ok := entry.(*net.IPNet)
		if !ok {
			continue
		}
		if addr, ok := netip.AddrFromSlice(network.IP); ok {
			addrs = append(addrs, addr.Unmap())
		}
	}
	return addrs
}

func (r *runner) bind(ctx context.Context, coordinator string) (netip.AddrPort, error) {
	nonce, err := newNonce()
	if err != nil {
		return netip.AddrPort{}, err
	}
	request, err := EncodeRequest(Message{
		Kind: KindBind, SessionID: r.config.SessionID, Role: r.config.Role, Nonce: nonce,
	})
	if err != nil {
		return netip.AddrPort{}, err
	}
	target, err := net.ResolveUDPAddr("udp", coordinator)
	if err != nil {
		return netip.AddrPort{}, errors.New("resolve coordinator")
	}
	deadline := time.Now().Add(r.config.BindTimeout)
	for time.Now().Before(deadline) {
		if err := ctx.Err(); err != nil {
			return netip.AddrPort{}, err
		}
		r.send(request, target)
		window := minTime(deadline, time.Now().Add(r.config.PollInterval))
		for time.Now().Before(window) {
			reply, from, err := r.receive(window)
			if err != nil {
				break
			}
			if reply.Kind == KindBindOK && reply.Nonce == nonce && reply.SessionID == r.config.SessionID {
				observed, parseErr := netip.ParseAddrPort(reply.Observed)
				if parseErr == nil {
					return observed, nil
				}
				continue
			}
			r.observe(reply, from)
		}
	}
	return netip.AddrPort{}, errors.New("coordinator did not answer")
}

// exchange publishes local candidates and waits for the peer's.
func (r *runner) exchange(ctx context.Context) ([]netip.AddrPort, error) {
	candidates := r.candidates()
	deadline := time.Now().Add(r.config.PairTimeout)
	target, err := net.ResolveUDPAddr("udp", r.config.Coordinators[0])
	if err != nil {
		return nil, errors.New("resolve coordinator")
	}
	for time.Now().Before(deadline) {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		nonce, err := newNonce()
		if err != nil {
			return nil, err
		}
		request, err := EncodeRequest(Message{
			Kind: KindPair, SessionID: r.config.SessionID, Role: r.config.Role,
			Nonce: nonce, Candidates: candidates, Commit: r.config.Commit,
			EndpointKey: r.config.EndpointKeyHex, Probe: string(r.config.Probe),
			TransportKey: r.transportKeyHex,
		})
		if err != nil {
			return nil, err
		}
		r.send(request, target)

		// One request per interval, then listen for the rest of it. An
		// immediate empty answer must not become a tight resend loop: that
		// floods the coordinator, and the shared per-address budget would then
		// throttle the peer behind the same NAT rather than the endpoint doing
		// the flooding.
		window := minTime(deadline, time.Now().Add(r.config.PollInterval))
		for time.Now().Before(window) {
			reply, from, err := r.receive(window)
			if err != nil {
				break
			}
			if reply.Kind == KindPairOK && reply.Nonce == nonce && len(reply.Candidates) > 0 {
				r.classifySelf()
				r.result.PeerCommit = reply.PeerCommit
				r.result.PeerTransportKey = reply.PeerTransportKey
				r.recordObservation(reply)
				peers := make([]netip.AddrPort, 0, len(reply.Candidates)+len(r.learned))
				for _, candidate := range reply.Candidates {
					address, parseErr := netip.ParseAddrPort(candidate)
					if parseErr != nil {
						continue
					}
					peers = append(peers, address)
				}
				peers = append(peers, r.learned...)
				if len(peers) > 0 {
					return peers, nil
				}
				continue
			}
			r.observe(reply, from)
		}
	}
	if len(r.learned) > 0 {
		// The coordinator never completed the pairing, but the peer reached us
		// directly. The path is real; the stratum labels simply are not
		// available, and the caller has to decide whether a record without
		// them is worth anything.
		return r.learned, nil
	}
	r.result.Failure = reachability.FailureNoCandidate
	return nil, errors.New("peer never published candidates")
}

// punch attempts a direct path to every peer candidate at once and answers
// the peer's own probes, which is what makes a simultaneous open possible.
//
// An endpoint keeps answering for a bounded window after its own path is
// established. Returning the instant the acknowledgement arrives would close
// the socket under a peer that is still probing, and the peer would record a
// handshake timeout for a path that demonstrably works. That error is not
// random: it lands on whichever endpoint is slower, so it would bias the
// success rate the route decision is computed from.
func (r *runner) punch(ctx context.Context, peers []netip.AddrPort) {
	nonce, err := newNonce()
	if err != nil {
		r.result.Failure = reachability.FailureInternal
		return
	}
	started := time.Now()
	deadline := started.Add(r.config.PunchTimeout)
	var settle time.Time
	var sequence uint32
	for time.Now().Before(deadline) {
		if !settle.IsZero() && !time.Now().Before(settle) {
			return
		}
		if err := ctx.Err(); err != nil {
			r.result.Failure = reachability.FailureInternal
			return
		}
		sequence++
		request, err := Encode(Message{
			Kind: KindPunch, SessionID: r.config.SessionID, Role: r.config.Role,
			Nonce: nonce, Sequence: sequence, Commit: r.config.Commit,
		})
		if err != nil {
			r.result.Failure = reachability.FailureInternal
			return
		}
		for _, peer := range peers {
			r.send(request, net.UDPAddrFromAddrPort(peer))
		}
		window := minTime(deadline, time.Now().Add(r.config.PollInterval))
		for time.Now().Before(window) {
			reply, from, err := r.receive(window)
			if err != nil {
				break
			}
			if reply.SessionID != r.config.SessionID || reply.Role == r.config.Role {
				continue
			}
			switch reply.Kind {
			case KindPunch:
				r.observe(reply, from)
			case KindPunchAck:
				if r.result.PeerCommit == "" && reply.Commit != "" {
					r.result.PeerCommit = reply.Commit
				}
				if reply.Nonce != nonce || r.result.Established {
					continue
				}
				r.result.Established = true
				r.result.PeerAddress = from
				r.result.Failure = reachability.FailureNone
				elapsed := time.Since(started).Milliseconds()
				if elapsed < 1 {
					elapsed = 1
				}
				r.result.EstablishMillis = uint64(elapsed)
				settle = minTime(deadline, time.Now().Add(r.config.LingerWindow))
			}
		}
	}
	if !r.result.Established {
		r.result.Failure = reachability.FailureHandshake
	}
}

// candidates lists the local addresses worth trying.
//
// A socket bound to one address can only ever send from that address, so
// advertising the machine's other interfaces would publish paths this endpoint
// cannot use. Only an unspecified bind enumerates interfaces.
func (r *runner) candidates() []string {
	port := r.localPort()
	if port == 0 {
		return nil
	}
	if bound, ok := r.connection.LocalAddr().(*net.UDPAddr); ok {
		if address, valid := netip.AddrFromSlice(bound.IP); valid {
			address = address.Unmap()
			if address.IsValid() && !address.IsUnspecified() {
				return []string{netip.AddrPortFrom(address, port).String()}
			}
		}
	}
	interfaces, err := net.InterfaceAddrs()
	if err != nil {
		return nil
	}
	var routable, local []string
	for _, entry := range interfaces {
		network, ok := entry.(*net.IPNet)
		if !ok {
			continue
		}
		address, ok := netip.AddrFromSlice(network.IP)
		if !ok {
			continue
		}
		address = address.Unmap()
		if !address.IsValid() || address.IsMulticast() || address.IsUnspecified() ||
			address.IsLinkLocalUnicast() || address.IsLinkLocalMulticast() {
			continue
		}
		formatted := netip.AddrPortFrom(address, port).String()
		if address.IsLoopback() {
			local = append(local, formatted)
			continue
		}
		routable = append(routable, formatted)
	}
	candidates := append(routable, local...)
	if len(candidates) > MaxCandidates {
		candidates = candidates[:MaxCandidates]
	}
	return candidates
}

func (r *runner) localPort() uint16 {
	address, ok := r.connection.LocalAddr().(*net.UDPAddr)
	if !ok {
		return 0
	}
	return uint16(address.Port)
}

func (r *runner) send(payload []byte, target net.Addr) {
	written, err := r.connection.WriteTo(payload, target)
	if err == nil {
		r.result.TxBytes += uint64(written)
	}
}

func (r *runner) receive(deadline time.Time) (Message, netip.AddrPort, error) {
	if err := r.connection.SetReadDeadline(deadline); err != nil {
		return Message{}, netip.AddrPort{}, err
	}
	buffer := make([]byte, MaxMessageBytes)
	count, from, err := r.connection.ReadFrom(buffer)
	if err != nil {
		return Message{}, netip.AddrPort{}, err
	}
	r.result.RxBytes += uint64(count)
	source, ok := addrPort(from)
	if !ok {
		return Message{}, netip.AddrPort{}, errors.New("unexpected source address")
	}
	message, err := Decode(buffer[:count])
	if err != nil {
		return Message{}, netip.AddrPort{}, err
	}
	return message, source, nil
}

func minTime(first, second time.Time) time.Time {
	if first.Before(second) {
		return first
	}
	return second
}
