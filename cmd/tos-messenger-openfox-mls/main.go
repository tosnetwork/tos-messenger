// Command tos-messenger-openfox-mls bootstraps private per-Agent OpenMLS state
// or serves one owner-private plaintext proxy in front of an opaque lab Relay.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/tosnetwork/tos-messenger/pkg/group"
	"github.com/tosnetwork/tos-messenger/pkg/mlslab"
)

type stringFlags []string

func (f *stringFlags) String() string         { return strings.Join(*f, ",") }
func (f *stringFlags) Set(value string) error { *f = append(*f, value); return nil }

func main() {
	mode := flag.String("mode", "", "bootstrap or serve")
	driverPath := flag.String("driver", "", "path to tos-openmls-driver")
	stateDir := flag.String("state-dir", "", "bootstrap output directory")
	statePath := flag.String("state", "", "private Agent state file")
	label := flag.String("label", "", "bootstrap room label")
	creator := flag.String("creator", "", "bootstrap creator Agent ID")
	agentID := flag.String("agent-id", "", "serving Agent ID")
	token := flag.String("token", "", "serving Agent Relay credential")
	socket := flag.String("socket", "", "owner-private OpenFox Unix socket")
	relaySocket := flag.String("relay-socket", "", "opaque Relay Unix socket")
	var members stringFlags
	flag.Var(&members, "member", "bootstrap Agent ID (repeat)")
	flag.Parse()
	if err := run(*mode, *driverPath, *stateDir, *statePath, *label, *creator, *agentID, *token, *socket, *relaySocket, members); err != nil {
		fmt.Fprintln(os.Stderr, "tos-messenger-openfox-mls:", err)
		os.Exit(1)
	}
}

func run(mode, driverPath, stateDir, statePath, label, creator, agentID, token, socket, relaySocket string, members []string) error {
	if driverPath == "" {
		return errors.New("-driver is required")
	}
	driver := &group.OpenMLSSidecar{Command: []string{driverPath}, Timeout: 10 * time.Second}
	switch mode {
	case "bootstrap":
		ordered, err := mlslab.OrderedMembers(creator, members)
		if err != nil {
			return err
		}
		room, err := mlslab.Bootstrap(stateDir, label, ordered, driver)
		if err != nil {
			return err
		}
		fmt.Printf("room_id=%s creator=%s members=%d mls_epoch=%d encryption=openmls-0.8.1-suite-0x0001\n", room.RoomID, creator, len(room.Members), len(room.Members)-1)
		return nil
	case "serve":
		if statePath == "" || agentID == "" || token == "" || socket == "" || relaySocket == "" {
			return errors.New("serve requires -state, -agent-id, -token, -socket, and -relay-socket")
		}
		transport := &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, "unix", relaySocket)
		}}
		proxy, err := mlslab.Open(statePath, agentID, token, driver, &http.Client{Transport: transport, Timeout: 15 * time.Second}, "http://unix")
		if err != nil {
			return err
		}
		return serve(socket, proxy.Handler(), agentID)
	default:
		return errors.New("-mode must be bootstrap or serve")
	}
}

func serve(socket string, handler http.Handler, agentID string) error {
	if err := os.MkdirAll(filepath.Dir(socket), 0o700); err != nil {
		return err
	}
	if info, err := os.Lstat(socket); err == nil {
		if info.Mode()&os.ModeSocket == 0 {
			return errors.New("socket path exists and is not a Unix socket")
		}
		if err := os.Remove(socket); err != nil {
			return err
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	listener, err := net.Listen("unix", socket)
	if err != nil {
		return err
	}
	defer func() { listener.Close(); os.Remove(socket) }()
	if err := os.Chmod(socket, 0o600); err != nil {
		return err
	}
	server := &http.Server{Handler: handler, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 20 * time.Second, WriteTimeout: 20 * time.Second, IdleTimeout: 30 * time.Second}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	go func() {
		<-ctx.Done()
		shutdown, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = server.Shutdown(shutdown)
	}()
	fmt.Printf("openfox_mls_socket=%s agent_id=%s transport=local-unix-openmls-ciphertext-relay\n", socket, agentID)
	err = server.Serve(listener)
	if errors.Is(err, http.ErrServerClosed) {
		return nil
	}
	return err
}
