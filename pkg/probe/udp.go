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
	// DefaultKeepaliveInterval paces the hold phase's keepalive pings. It only
	// matters when a hold window is configured.
	DefaultKeepaliveInterval = 2 * time.Second
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
	// HoldWindow is how long past a confirmed establishment the ADNL session is
	// kept alive and measured. Zero measures establishment only, which is the
	// default and the historical behavior. Establishment answers whether a
	// session comes up; the hold window answers whether it stays up, which is a
	// different property of the same middleboxes.
	HoldWindow time.Duration
	// KeepaliveInterval paces the hold phase's pings. It is meaningful only
	// when HoldWindow is set, and it must fit inside the window, because an
	// interval the window cannot contain would measure nothing while claiming
	// to.
	KeepaliveInterval time.Duration
	// MeasureReconnect asks the initiating side to deliberately drop its
	// channel state after the hold phase and time the re-establishment. It
	// requires a hold window: a reconnect measured against a session that was
	// never shown to still be alive would time an unknown baseline. It is also
	// refused on the responding role, which never dials and so has nothing to
	// re-establish: a responder run that accepted it would validate and then
	// silently measure nothing.
	MeasureReconnect bool
	// TunnelAddr names the relay the fallback phase registers with when the
	// direct phase ends without a session. Empty disables the fallback, which
	// is the default: a study cell that never attempts the tunnel is different
	// evidence from one where the tunnel also failed, and the operator chooses
	// which is being collected.
	TunnelAddr string
	// SidecarPath selects the native ADNL sidecar runner and names its binary.
	// Empty selects the in-process tosutils-go gateway, which is the default
	// and the historical behavior. The sidecar runner refuses the tunnel
	// fallback and IPv6 sockets, because the native transport supports
	// neither and a silent no-op would record "not measured" for something
	// the operator asked for.
	SidecarPath string
	// EchoSizes asks for one echo round trip per size after a confirmed
	// direct establishment: an ADNL query carrying that many random bytes,
	// answered with their sha256. The results are cross-check harness
	// evidence about payload transport between implementations, reported
	// beside the trial and never inside it. ADNL probe only.
	EchoSizes []int
	Commit    string
	// ManifestDigest is the digest of this endpoint's collector manifest,
	// presented to the peer wherever the commit is. The commit names a
	// repository revision; the manifest names the build that spoke on the wire,
	// which is the provenance a per-implementation study report is split by.
	ManifestDigest string
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
	// SurvivalSeconds is measured from establishment to the last successful
	// keepalive, floored at one second so a session that was measured and died
	// at once stays distinguishable from a session that was never measured:
	// zero is the schema's "not measured". Surviving the whole hold window
	// records the window's full length. It is a DIRECT-session measurement
	// only: the tunneled hold phase reports its booleans below and never this
	// number, because a relayed session's lifetime would be measuring the
	// relay.
	SurvivalSeconds uint64
	// ReconnectMillis is the initiating side's time from a deliberate channel
	// drop to the first confirming round trip. The responder leaves it zero;
	// pair joining takes the max of the two halves, so the pair still carries
	// one number.
	ReconnectMillis uint64
	// The phase-status booleans say which phases ran and how they ended,
	// because the zero measurements above are ambiguous on their own: a
	// reconnect that was never asked for and a reconnect that failed both leave
	// ReconnectMillis at zero. Attempted is set when the phase ran; completed
	// or succeeded reports what actually happened, so a failed phase is finally
	// attempted-and-not-completed rather than invisible.
	HoldAttempted bool
	// HoldCompleted reports the direct session surviving its FULL hold window;
	// a session that died mid-window leaves it false while SurvivalSeconds
	// still records the measured span.
	HoldCompleted      bool
	ReconnectAttempted bool
	ReconnectSucceeded bool
	// TunnelHoldAttempted and TunnelHoldCompleted are the tunneled session's
	// hold phase, run when a hold window is configured and the session came up
	// through the relay. They are the tunnel-survival evidence; SurvivalSeconds
	// stays direct-only.
	TunnelHoldAttempted bool
	TunnelHoldCompleted bool
	// TunneledEstablish reports that the session came up through the relay
	// after the direct phase failed. When it is set, Failure keeps the direct
	// phase's class rather than none, because a proxy-fallback trial is defined
	// by what it fell back from, and EstablishMillis counts from the start of
	// the tunnel phase.
	TunneledEstablish bool
	PeerAddress       netip.AddrPort
	Failure           reachability.FailureClass
	PeerCommit        string
	// PeerManifestDigest is the collector-manifest digest the peer presented,
	// learned during pairing exactly as PeerCommit is. A trial cannot be
	// emitted without it, because pair joining cross-checks what each side
	// claims the other ran.
	PeerManifestDigest string
	// PeerTransportKey is the key the peer will run its measured transport
	// under, learned during pairing.
	PeerTransportKey string
	// EchoResults is what each configured echo round trip did over the
	// confirmed direct session, in the order configured. It is cross-check
	// harness evidence, reported beside the trial and never inside it.
	EchoResults []EchoResult
	// Observation is the coordinator's signed account of what it saw. A result
	// without one cannot be filed under a stratum, because the two facts that
	// place it there would be the endpoint's own claim.
	Observation reachability.Observation
	// BindObservations are the per-coordinator signed reflections of this
	// endpoint's external address, one per coordinator that answered with a
	// verifiable attestation. The NAT mapping class is derived from them rather
	// than declared, so a trial that carries them lets a verifier check the
	// mapping against evidence instead of trusting the endpoint's own label.
	BindObservations []reachability.BindObservation
	// FilteringObservations are the coordinator-signed cold-source receipts
	// the filtering class is derived from; see reachability.DeriveFiltering.
	// They are collected during the bind phase over the same socket, because
	// the question is whether the NAT admits cold sources back to this
	// mapping.
	FilteringObservations []reachability.FilteringObservation
	TxBytes               uint64
	RxBytes               uint64
}

// EchoResult is one echo round trip's outcome: how many random bytes the
// query carried, whether their exact sha256 came back inside the window, and
// how long the round trip took (zero when it never completed, the schema's
// "not measured").
type EchoResult struct {
	Bytes  int
	OK     bool
	Millis uint64
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
	// establishedAt is the moment the confirming round trip completed; the hold
	// window and the survival measurement are both anchored to it.
	establishedAt time.Time
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
	if r.result.PeerManifestDigest == "" && message.ManifestDigest != "" {
		r.result.PeerManifestDigest = message.ManifestDigest
	}
	acknowledgement, err := Encode(Message{
		Kind: KindPunchAck, SessionID: r.config.SessionID, Role: r.config.Role,
		Nonce: message.Nonce, Sequence: message.Sequence, Commit: r.config.Commit,
		ManifestDigest: r.config.ManifestDigest,
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
	if config.HoldWindow < 0 || config.KeepaliveInterval < 0 {
		return errors.New("invalid probe hold windows")
	}
	if config.KeepaliveInterval == 0 {
		config.KeepaliveInterval = DefaultKeepaliveInterval
	}
	if config.HoldWindow > 0 && config.KeepaliveInterval > config.HoldWindow {
		return errors.New("the keepalive interval must fit inside the hold window")
	}
	if config.MeasureReconnect && config.HoldWindow == 0 {
		return errors.New("reconnect measurement requires a hold window")
	}
	// Reconnect is the initiator's measurement: the responder never dials, so
	// it has no channel to deliberately drop and re-dial. Accepting the flag on
	// the responding role would validate a run that then measures nothing --
	// "not measured" recorded for something the operator asked for -- so it is
	// refused, exactly as the udp probe refuses the phases it cannot measure.
	if config.MeasureReconnect && config.Role == RoleB {
		return errors.New("reconnect measurement belongs to the initiating role")
	}
	if config.TunnelAddr != "" {
		if _, err := net.ResolveUDPAddr("udp", config.TunnelAddr); err != nil {
			return errors.New("invalid tunnel relay address")
		}
	}
	// The datagram probe has no session to hold, reconnect, tunnel, or echo
	// over, and no sidecar speaks it. Ignoring the request would record "not
	// measured" for something the operator asked to measure, so it is refused
	// instead.
	if config.Probe == reachability.ProbeUDP &&
		(config.HoldWindow > 0 || config.MeasureReconnect || config.TunnelAddr != "" ||
			config.SidecarPath != "" || len(config.EchoSizes) > 0) {
		return errors.New("the udp probe measures datagram establishment only")
	}
	// The native sidecar has no tunnel path yet; that is a later production
	// gate. Accepting the flag and silently not tunneling would file "direct
	// failed" for runs the operator configured as "direct failed but a tunnel
	// works", which is exactly the distinction the tunnel-first route needs.
	if config.SidecarPath != "" && config.TunnelAddr != "" {
		return errors.New("the sidecar runner does not measure the tunnel fallback")
	}
	// An echo that cannot be sent must be refused where the operator can see
	// it: the native stack caps query payloads, and a size past the cap would
	// be recorded as a network failure it never was.
	for _, size := range config.EchoSizes {
		if size < 1 || size > MaxEchoBytes {
			return errors.New("echo sizes must be between 1 and 8176 bytes")
		}
	}
	if config.Commit != "" && !commitPattern.MatchString(config.Commit) {
		return errors.New("invalid probe commit")
	}
	if config.ManifestDigest != "" && !manifestPattern.MatchString(config.ManifestDigest) {
		return errors.New("invalid probe manifest digest")
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
		observed, attestation, err := r.bind(ctx, coordinator)
		if err != nil {
			r.result.Failure = reachability.FailureUDPBlocked
			return err
		}
		r.result.Observed = append(r.result.Observed, observed)
		// Only a reflection that verifies under the coordinator key it names is
		// carried forward. An unverifiable one is worth no more than the
		// endpoint's own claim about its mapping, so it is dropped here rather
		// than folded into a trial that would fail verification later.
		if reachability.VerifyBindObservation(attestation) == nil &&
			len(r.result.BindObservations) < reachability.MaxBindObservations {
			r.result.BindObservations = append(r.result.BindObservations, attestation)
		}
		// The filter exchange runs over the same established socket, and its
		// stray traffic (early peer punches) is fed back into the runner.
		filtering := MeasureFiltering(ctx, r.connection, coordinator, r.config, r.observe)
		r.result.TxBytes += filtering.TxBytes
		r.result.RxBytes += filtering.RxBytes
		r.result.FilteringObservations = append(r.result.FilteringObservations, filtering.Observations...)
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

func (r *runner) bind(ctx context.Context, coordinator string) (netip.AddrPort, reachability.BindObservation, error) {
	nonce, err := newNonce()
	if err != nil {
		return netip.AddrPort{}, reachability.BindObservation{}, err
	}
	// The endpoint key and probe are presented so the coordinator can attest to
	// a named party and probe rather than to a bare session, which is what makes
	// the reflection usable as mapping evidence.
	request, err := EncodeRequest(Message{
		Kind: KindBind, SessionID: r.config.SessionID, Role: r.config.Role, Nonce: nonce,
		EndpointKey: r.config.EndpointKeyHex, Probe: string(r.config.Probe),
	})
	if err != nil {
		return netip.AddrPort{}, reachability.BindObservation{}, err
	}
	target, err := net.ResolveUDPAddr("udp", coordinator)
	if err != nil {
		return netip.AddrPort{}, reachability.BindObservation{}, errors.New("resolve coordinator")
	}
	deadline := time.Now().Add(r.config.BindTimeout)
	for time.Now().Before(deadline) {
		if err := ctx.Err(); err != nil {
			return netip.AddrPort{}, reachability.BindObservation{}, err
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
					return observed, r.reflection(reply), nil
				}
				continue
			}
			r.observe(reply, from)
		}
	}
	return netip.AddrPort{}, reachability.BindObservation{}, errors.New("coordinator did not answer")
}

// reflection reconstructs the coordinator's signed bind observation from a bind
// answer. The endpoint key, probe, session, and role are this endpoint's own
// inputs, not something the reply echoes: the signature verifies only if the
// coordinator signed exactly what was presented, so filling them in locally is
// reconstruction, not trust. A reply without a signature yields a zero value
// the caller discards.
func (r *runner) reflection(reply Message) reachability.BindObservation {
	if reply.Signature == "" || reply.SignerKey == "" {
		return reachability.BindObservation{}
	}
	identifier, err := reachability.CoordinatorID(mustKey(reply.SignerKey))
	if err != nil {
		return reachability.BindObservation{}
	}
	return reachability.BindObservation{
		CoordinatorID:        identifier,
		SessionID:            r.config.SessionID,
		Role:                 string(r.config.Role),
		EndpointPublicKeyHex: r.config.EndpointKeyHex,
		Probe:                string(r.config.Probe),
		Observed:             reply.Observed,
		AtUnix:               reply.ObservedAt,
		PublicKeyHex:         reply.SignerKey,
		SignatureHex:         reply.Signature,
	}
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
			ManifestDigest: r.config.ManifestDigest,
			EndpointKey:    r.config.EndpointKeyHex, Probe: string(r.config.Probe),
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
				r.result.PeerManifestDigest = reply.PeerManifestDigest
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
			ManifestDigest: r.config.ManifestDigest,
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
				if r.result.PeerManifestDigest == "" && reply.ManifestDigest != "" {
					r.result.PeerManifestDigest = reply.ManifestDigest
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
