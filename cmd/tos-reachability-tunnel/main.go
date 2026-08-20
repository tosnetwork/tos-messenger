// Command tos-reachability-tunnel runs the double-registration UDP forwarder
// the reachability study's proxy-fallback phase measures against.
//
// It is measurement infrastructure, not Messenger infrastructure: it forwards
// the datagrams of one probe session between its two registered endpoints,
// verbatim, capped by bytes and by a lifetime, and looks at none of them. It
// must not be presented as the Relay milestone, a production tunnel, or any
// part of the protocol -- the study needs a relay to exist so that a
// tunnel-first route decision can be measured at all, and that is the whole
// job.
package main

import (
	"flag"
	"fmt"
	"net"
	"os"
	"time"

	"github.com/tosnetwork/tos-messenger/pkg/probe"
)

func main() {
	listen := flag.String("listen", ":7692", "UDP address to serve on")
	sessionTTL := flag.Duration("session-ttl", probe.DefaultTunnelSessionTTL, "how long an idle tunnel session is kept")
	maxSessions := flag.Int("max-sessions", probe.DefaultTunnelMaxSessions, "concurrent tunnel sessions held")
	sessionBytes := flag.Uint64("session-bytes", probe.DefaultTunnelSessionBytes, "bytes forwarded per session before it is cut off")
	perWindow := flag.Int("requests-per-window", probe.DefaultRequestsPerWindow, "control requests admitted per source address per window")
	window := flag.Duration("rate-window", probe.DefaultRateWindow, "rate-limit window")
	flag.Parse()

	if err := run(*listen, *sessionTTL, *maxSessions, *sessionBytes, *perWindow, *window); err != nil {
		fmt.Fprintln(os.Stderr, "tos-reachability-tunnel:", err)
		os.Exit(1)
	}
}

func run(listen string, ttl time.Duration, maxSessions int, sessionBytes uint64,
	perWindow int, window time.Duration) error {
	relay, err := probe.NewTunnelRelay(probe.TunnelRelayOptions{
		SessionTTL:        ttl,
		MaxSessions:       maxSessions,
		SessionByteBudget: sessionBytes,
		RequestsPerWindow: perWindow,
		RateWindow:        window,
	})
	if err != nil {
		return err
	}
	connection, err := net.ListenPacket("udp", listen)
	if err != nil {
		return err
	}
	defer connection.Close()

	// Both endpoints of a pair are given this address out of band, the same
	// way they are given the coordinator's. The relay needs no identity key:
	// it attests to nothing, and a trial that went through it is recognisable
	// by its own outcome, not by anything the relay signs.
	fmt.Printf("listening=%s\n", connection.LocalAddr())
	return relay.Serve(connection)
}
