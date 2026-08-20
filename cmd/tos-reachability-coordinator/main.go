// Command tos-reachability-coordinator runs the rendezvous service used by the
// reachability study.
//
// It reports the source address it observes and exchanges candidate sets
// between the two endpoints of a session. It is measurement infrastructure,
// not Messenger infrastructure: it carries no application data and must not be
// presented as a relay, a gateway, or any part of the protocol.
package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"net"
	"os"
	"strings"
	"time"

	"github.com/tosnetwork/tos-messenger/pkg/probe"
	"github.com/tosnetwork/tos-messenger/pkg/reachability"
)

func main() {
	listen := flag.String("listen", ":7691", "UDP address to serve on")
	keyPath := flag.String("key", "", "coordinator signing key file, created when absent")
	sessionTTL := flag.Duration("session-ttl", probe.DefaultSessionTTL, "how long a pairing is remembered")
	maxSessions := flag.Int("max-sessions", probe.DefaultMaxSessions, "concurrent pairings held")
	perWindow := flag.Int("requests-per-window", probe.DefaultRequestsPerWindow, "requests admitted per source address per window")
	window := flag.Duration("rate-window", probe.DefaultRateWindow, "rate-limit window")
	filterListen := flag.String("filter-listen", ":0",
		"UDP address for the cold second-port filter source; it must share the primary address, defaults to an ephemeral port so filter probing is on, and empty disables it")
	filterSecondary := flag.String("filter-secondary-listen", "",
		"UDP address for a cold filter source on a secondary address this host also holds; the address must genuinely differ from the primary, because the coordinator attests the source kind and cannot check it")
	flag.Parse()

	if err := run(*listen, *keyPath, *sessionTTL, *maxSessions, *perWindow, *window,
		*filterListen, *filterSecondary); err != nil {
		fmt.Fprintln(os.Stderr, "tos-reachability-coordinator:", err)
		os.Exit(1)
	}
}

func run(listen, keyPath string, ttl time.Duration, maxSessions, perWindow int, window time.Duration,
	filterListen, filterSecondary string) error {
	key, err := loadOrCreateKey(keyPath)
	if err != nil {
		return err
	}
	public, ok := key.Public().(ed25519.PublicKey)
	if !ok {
		return errors.New("invalid coordinator signing key")
	}
	serverID, err := reachability.CoordinatorID(public)
	if err != nil {
		return err
	}
	coordinator, err := probe.NewCoordinator(probe.CoordinatorOptions{
		PrivateKey:        key,
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

	// The cold sockets are write-only: filter probes leave through them, and
	// nothing is ever read from or answered on them, because a cold source that
	// answered anything would stop being cold.
	filterSources := ""
	if filterListen != "" {
		cold, err := net.ListenPacket("udp", filterListen)
		if err != nil {
			return err
		}
		defer cold.Close()
		if err := coordinator.AttachFilterSource(reachability.FilterSourceOtherPort, cold); err != nil {
			return err
		}
		filterSources += " filter_port_source=" + cold.LocalAddr().String()
	}
	if filterSecondary != "" {
		cold, err := net.ListenPacket("udp", filterSecondary)
		if err != nil {
			return err
		}
		defer cold.Close()
		if err := coordinator.AttachFilterSource(reachability.FilterSourceOtherAddress, cold); err != nil {
			return err
		}
		filterSources += " filter_address_source=" + cold.LocalAddr().String()
	}

	// Operators put the identifier in their policy. A study only counts
	// attestations from coordinators it predeclared, so this line is what has
	// to travel out of band before any measurement is worth anything.
	fmt.Printf("coordinator_id=%s public_key=%s listening=%s%s\n",
		serverID, hex.EncodeToString(public), connection.LocalAddr(), filterSources)
	return coordinator.Serve(connection)
}

// loadOrCreateKey keeps the coordinator's identity stable across restarts. A
// coordinator that generated a fresh key on every start would fall out of
// every policy that predeclared it.
func loadOrCreateKey(path string) (ed25519.PrivateKey, error) {
	if path == "" {
		return nil, errors.New("a coordinator signing key file is required")
	}
	raw, err := os.ReadFile(path)
	if err == nil {
		decoded, err := hex.DecodeString(strings.TrimSpace(string(raw)))
		if err != nil || len(decoded) != ed25519.PrivateKeySize {
			return nil, errors.New("coordinator key file is not a signing key")
		}
		return ed25519.PrivateKey(decoded), nil
	}
	if !os.IsNotExist(err) {
		return nil, errors.New("read coordinator key")
	}
	_, generated, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, errors.New("generate coordinator key")
	}
	if err := os.WriteFile(path, []byte(hex.EncodeToString(generated)+"\n"), 0o600); err != nil {
		return nil, errors.New("write coordinator key")
	}
	return generated, nil
}
