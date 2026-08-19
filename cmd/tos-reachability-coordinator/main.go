// Command tos-reachability-coordinator runs the rendezvous service used by the
// reachability study.
//
// It reports the source address it observes and exchanges candidate sets
// between the two endpoints of a session. It is measurement infrastructure,
// not Messenger infrastructure: it carries no application data and must not be
// presented as a relay, a gateway, or any part of the protocol.
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
	listen := flag.String("listen", ":7691", "UDP address to serve on")
	serverID := flag.String("server-id", "", "coordinator identifier, generated when empty")
	sessionTTL := flag.Duration("session-ttl", probe.DefaultSessionTTL, "how long a pairing is remembered")
	maxSessions := flag.Int("max-sessions", probe.DefaultMaxSessions, "concurrent pairings held")
	perWindow := flag.Int("requests-per-window", probe.DefaultRequestsPerWindow, "requests admitted per source address per window")
	window := flag.Duration("rate-window", probe.DefaultRateWindow, "rate-limit window")
	flag.Parse()

	if err := run(*listen, *serverID, *sessionTTL, *maxSessions, *perWindow, *window); err != nil {
		fmt.Fprintln(os.Stderr, "tos-reachability-coordinator:", err)
		os.Exit(1)
	}
}

func run(listen, serverID string, ttl time.Duration, maxSessions, perWindow int, window time.Duration) error {
	if serverID == "" {
		generated, err := probe.NewServerID()
		if err != nil {
			return err
		}
		serverID = generated
	}
	coordinator, err := probe.NewCoordinator(probe.CoordinatorOptions{
		ServerID:          serverID,
		SessionTTL:        ttl,
		MaxSessions:       maxSessions,
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

	fmt.Printf("server_id=%s listening=%s\n", serverID, connection.LocalAddr())
	return coordinator.Serve(connection)
}
