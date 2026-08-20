package probe

import (
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"time"

	"github.com/tosnetwork/tos-messenger/pkg/reachability"
)

// sidecarEchoAttempts bounds how many single-query echo attempts one
// configured size gets; the attempts share the size's overall window.
const sidecarEchoAttempts = 3

// RunADNLSidecar measures one endpoint of one ADNL establishment attempt with
// the native ADNL stack, driven as a subprocess, instead of the in-process
// tosutils-go gateway.
//
// The study's honest caveat about the gateway runner is that it speaks the
// TON lineage of ADNL through a reimplementation; a route decision frozen on
// its evidence needs cross-checking against the node's own stack. This runner
// is that cross-check's collection path: the same rendezvous, the same roles,
// the same phases, with the wire spoken by the audited native code.
//
// The flow keeps RunADNL's port-handoff design. The rendezvous runs on a
// plain Go socket -- the sidecar's transport key, asked for first, is what
// pairing presents -- and the responder's punch burst leaves from that same
// socket. Then the socket closes and the sidecar binds the SAME port (it
// retries a just-released port internally), so the NAT mapping the
// coordinator observed is the mapping the ADNL session runs over. The roles
// keep their asymmetry: the initiator dials, the responder only awaits, so
// exactly one session ever exists.
//
// What the native transport cannot do is refused rather than silently
// skipped: it binds IPv4 only, so a rendezvous socket that ended up on an
// IPv6-only family is an error (those study cells stay with the gateway
// runner), IPv6 candidates are filtered before they can reach the native
// stack (which cannot survive sending to one), and the tunnel fallback is
// refused at validation because no native tunnel path exists yet.
func RunADNLSidecar(ctx context.Context, config Config) (Result, error) {
	if err := validateConfig(&config); err != nil {
		return Result{}, err
	}
	if config.Probe != reachability.ProbeADNL {
		return Result{}, errors.New("this runner measures the adnl probe; use Run for udp")
	}
	if config.SidecarPath == "" {
		return Result{}, errors.New("the sidecar runner needs a sidecar binary path")
	}
	// The sidecar protocol freezes hard bounds on every window it accepts,
	// and it validates them before touching any session state -- an
	// out-of-range timeout answered after a channel reset would record a
	// control-plane mistake as a network failure. Refusing here keeps the
	// two implementations byte-for-byte agreed on the bounds and turns an
	// operator's oversized flag into a loud tooling error instead of a
	// protocol error mid-measurement.
	if config.PunchTimeout < time.Millisecond || config.PunchTimeout > sidecarMaxTimeout {
		return Result{}, errors.New("the sidecar protocol bounds timeouts to [1ms, 120s]")
	}
	if config.HoldWindow > sidecarMaxHoldWindow {
		return Result{}, errors.New("the sidecar protocol bounds the hold window to at most 600s")
	}
	if config.HoldWindow > 0 && config.KeepaliveInterval > sidecarMaxTimeout {
		return Result{}, errors.New("the sidecar protocol bounds the keepalive interval to at most 120s")
	}

	sidecar, err := StartSidecar(ctx, config.SidecarPath)
	if err != nil {
		return Result{}, err
	}
	// Whatever path this run takes, the subprocess must not outlive it.
	defer sidecar.Stop()

	// The transport identity is the sidecar's, generated before any socket
	// exists, because the peer needs this endpoint's transport key during
	// pairing -- exactly where the gateway runner presents its own ephemeral
	// key.
	transportKeyHex, err := sidecar.Identity()
	if err != nil {
		return Result{}, err
	}
	if raw, decodeErr := hex.DecodeString(transportKeyHex); decodeErr != nil || len(raw) != ed25519.PublicKeySize {
		return Result{}, errors.New("sidecar reported an unusable transport key")
	}

	connection, err := net.ListenPacket("udp", config.ListenAddr)
	if err != nil {
		return Result{}, errors.New("open probe socket")
	}
	local, ok := connection.LocalAddr().(*net.UDPAddr)
	if !ok {
		_ = connection.Close()
		return Result{}, errors.New("probe socket has no usable address")
	}
	// Fail closed before anything pairs: the native transport binds IPv4
	// only, so a session on an IPv6 socket cannot be measured here, and
	// running on anyway would strand a peer and file the network's cell under
	// a failure the tooling caused. The IPv6 cells stay with the gateway
	// runner.
	if !sidecarServableFamily(local) {
		_ = connection.Close()
		return Result{}, errors.New("the native sidecar transport is IPv4-only; measure IPv6 cells with the gateway runner")
	}

	instance := &runner{
		config:          config,
		transportKeyHex: transportKeyHex,
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

	// The responder's half of the punch happens here, from the still-plain
	// rendezvous socket, exactly as in the gateway runner: raw datagrams
	// toward every candidate open this side's mapping on the 5-tuples the
	// initiator's handshakes will arrive on. The initiator needs no burst --
	// its dial is its own punch.
	if config.Role == RoleB {
		instance.punchBurst(peers)
	}

	if err := connection.Close(); err != nil {
		return instance.result, nil
	}

	err = instance.establishSidecar(ctx, sidecar, instance.result.PeerTransportKey,
		local.Port, ipv4Candidates(peers))
	sidecar.Close()
	return instance.result, err
}

// sidecarServableFamily reports whether the sidecar's IPv4-only bind can
// serve the socket's family: an explicit IPv4 address, or an unspecified bind
// whose IPv4 half the sidecar covers. An explicitly IPv6 socket cannot be
// handed over.
func sidecarServableFamily(local *net.UDPAddr) bool {
	if len(local.IP) == 0 || local.IP.IsUnspecified() {
		return true
	}
	return local.IP.To4() != nil
}

// ipv4Candidates keeps the candidates the native stack can be given. Handing
// it an IPv6 address is not a failed dial, it is an aborted process -- the
// native send-error path does not survive -- so the filter is this runner's
// job, before anything crosses the protocol boundary.
func ipv4Candidates(peers []netip.AddrPort) []string {
	candidates := make([]string, 0, len(peers))
	for _, peer := range peers {
		ip := peer.Addr().Unmap()
		if !ip.Is4() {
			continue
		}
		candidates = append(candidates, netip.AddrPortFrom(ip, peer.Port()).String())
	}
	return candidates
}

// The sidecar protocol's frozen window bounds. They are protocol constants
// shared with the native implementation, not tunables: both sides validate
// against exactly these values, so a run that would be refused over there is
// refused here first, as a tooling error rather than a measurement.
const (
	sidecarMaxTimeout    = 120 * time.Second
	sidecarMaxHoldWindow = 600 * time.Second
)

// sidecarUnsupportedCandidate is the sidecar's distinct refusal for a
// candidate set that was non-empty but entirely outside what its
// implementation can serve (address family, port validity). It is a tooling
// vocabulary word, deliberately absent from the study's failure classes: a
// trial must never be filed from it.
const sidecarUnsupportedCandidate = "unsupported-candidate"

// sidecarFailureClass maps the sidecar's failure vocabulary onto the study's.
// The two match by construction; anything novel fails closed into the tooling
// class rather than inventing a network finding.
func sidecarFailureClass(class string) reachability.FailureClass {
	switch mapped := reachability.FailureClass(class); mapped {
	case reachability.FailureNoCandidate, reachability.FailureHandshake,
		reachability.FailureUDPBlocked, reachability.FailurePeerUnreachable,
		reachability.FailureInternal:
		return mapped
	default:
		return reachability.FailureInternal
	}
}

// establishSidecar runs the measured phases over the sidecar: bind handoff,
// establishment, hold, reconnect, echo, and the done-signal dance. The done
// signal still travels through the coordinator on a fresh Go socket -- it
// never touched the measured socket in the gateway runner and it does not
// start here, because a layer must not carry its own test's control plane.
func (r *runner) establishSidecar(ctx context.Context, sidecar *Sidecar,
	peerKeyHex string, port int, candidates []string) error {
	// The sidecar always binds the IPv4 wildcard; the bind address's role in
	// its protocol is family selection and the port. The port is the
	// rendezvous port, the one the peer's NAT mapping points at.
	_, boundKey, err := sidecar.Listen(fmt.Sprintf("0.0.0.0:%d", port))
	if err != nil {
		r.result.Failure = reachability.FailureInternal
		return nil
	}
	// The peer was told one transport key during pairing; a sidecar listening
	// under any other key measures a session the pairing never described.
	if boundKey != r.transportKeyHex {
		r.result.Failure = reachability.FailureInternal
		return nil
	}

	if directPeersForTest != nil {
		filtered := directPeersForTest(nil)
		candidates = make([]string, 0, len(filtered))
		for _, peer := range filtered {
			candidates = append(candidates, peer.String())
		}
	}
	if len(candidates) == 0 {
		r.result.Failure = reachability.FailureNoCandidate
		return nil
	}
	r.result.Failure = reachability.FailureHandshake

	started := time.Now()
	deadline := started.Add(r.config.PunchTimeout)

	var session SidecarSession
	if r.config.Role == RoleA {
		session, err = sidecar.Dial(peerKeyHex, candidates, r.config.PunchTimeout)
	} else {
		session, err = sidecar.Await(peerKeyHex, r.config.PunchTimeout)
	}
	if err != nil {
		// The sidecar broke protocol or died: tooling, never the network.
		r.result.Failure = reachability.FailureInternal
		return nil
	}
	if !session.Established {
		// The sidecar's distinct refusal for a candidate set its
		// implementation cannot serve is a statement about the tooling, not
		// the network. This runner filters unservable candidates before they
		// ever reach the sidecar, so seeing the class here means the two
		// sides disagree about what is servable -- a contract surprise that
		// must abort the run rather than be filed as a measured failure,
		// because a trial built from it would pollute a network cell with an
		// implementation limit.
		if session.FailureClass == sidecarUnsupportedCandidate {
			return errors.New("the sidecar refused every candidate as implementation-unsupported; no trial can be filed from an implementation limit")
		}
		r.result.Failure = sidecarFailureClass(session.FailureClass)
		return nil
	}
	peerAddr, err := netip.ParseAddrPort(session.PeerAddr)
	if err != nil {
		r.result.Failure = reachability.FailureInternal
		return nil
	}
	r.result.Established = true
	r.result.Failure = reachability.FailureNone
	r.result.PeerAddress = peerAddr
	r.establishedAt = time.Now()
	r.result.EstablishMillis = session.Millis
	if r.result.EstablishMillis == 0 {
		r.result.EstablishMillis = 1
	}

	holdAlive := false
	if r.config.HoldWindow > 0 {
		r.result.HoldAttempted = true
		survival, completed, holdErr := sidecar.Hold(r.config.HoldWindow, r.config.KeepaliveInterval)
		if holdErr == nil {
			// The sidecar floors a measured span at one second exactly as the
			// schema requires, so the numbers pass through untranslated.
			r.result.SurvivalSeconds = survival
			r.result.HoldCompleted = completed
			holdAlive = completed
		}
		// Reconnect only over a session the hold phase showed was still
		// alive, and only on the initiating side -- the same rules as the
		// gateway runner, for the same reasons.
		if holdAlive && r.config.MeasureReconnect && r.config.Role == RoleA {
			r.result.ReconnectAttempted = true
			millis, succeeded, reconnectErr := sidecar.Reconnect(r.config.PunchTimeout)
			if reconnectErr == nil && succeeded {
				r.result.ReconnectSucceeded = true
				r.result.ReconnectMillis = millis
				if r.result.ReconnectMillis == 0 {
					r.result.ReconnectMillis = 1
				}
			}
		}
	}

	// The echo cross-check runs last, after every phase the signed trial
	// carries, so an echo that ends the peer's process -- the native stack's
	// query-size limits make that a real possibility -- cannot destroy the
	// measured phases that preceded it. The sidecar's echo command is a
	// single query, and one datagram lost to UDP or to the peer's concurrent
	// channel rotation (its reconnect phase) would fail the verdict for a
	// path that transports the payload fine, so a failed echo is retried
	// inside the size's overall window; the gateway runner's own echo already
	// resends on the library's cadence.
	attemptWindow := r.config.PunchTimeout / sidecarEchoAttempts
	if attemptWindow <= 0 {
		attemptWindow = r.config.PunchTimeout
	}
	for _, size := range r.config.EchoSizes {
		if ctx.Err() != nil {
			break
		}
		var echoed EchoResult
		var echoErr error
		for attempt := 0; attempt < sidecarEchoAttempts; attempt++ {
			echoed, echoErr = sidecar.Echo(size, attemptWindow)
			if echoErr != nil || echoed.OK {
				break
			}
		}
		if echoErr != nil {
			// A dead or protocol-broken sidecar answers nothing more; record
			// the echo as failed rather than pretending it was never asked.
			r.result.EchoResults = append(r.result.EchoResults, EchoResult{Bytes: size})
			break
		}
		r.result.EchoResults = append(r.result.EchoResults, echoed)
	}

	// The session must outlive this endpoint's own success for the same
	// reason the gateway must in the direct runner: tearing down early
	// strands whichever peer is slower, a bias the success rate must not
	// carry. The sidecar keeps the session until told to close, and the wait
	// runs through the coordinator exactly as before.
	r.awaitPeerDone(ctx, deadline.Add(measurementBudget(r.config)))
	return nil
}
