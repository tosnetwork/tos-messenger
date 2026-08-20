// Command tos-messenger-lab-group runs the local-only group-chat acceptance
// carrier. It is not a production route and refuses TCP configuration.
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

	"github.com/tosnetwork/tos-messenger/pkg/labgroup"
)

type credentialFlags []string

func (f *credentialFlags) String() string         { return strings.Join(*f, ",") }
func (f *credentialFlags) Set(value string) error { *f = append(*f, value); return nil }

func main() {
	var credentials credentialFlags
	socket := flag.String("socket", "", "owner-private Unix socket path")
	state := flag.String("state", "", "durable lab state file")
	flag.Var(&credentials, "agent", "agent_id=token (repeat for every allowed Agent)")
	flag.Parse()
	if err := run(*socket, *state, credentials); err != nil {
		fmt.Fprintln(os.Stderr, "tos-messenger-lab-group:", err)
		os.Exit(1)
	}
}

func run(socket, state string, rawCredentials []string) error {
	if socket == "" || state == "" {
		return errors.New("-socket and -state are required")
	}
	credentials := make([]labgroup.Credential, 0, len(rawCredentials))
	for _, raw := range rawCredentials {
		agentID, token, found := strings.Cut(raw, "=")
		if !found {
			return errors.New("each -agent must be agent_id=token")
		}
		credentials = append(credentials, labgroup.Credential{AgentID: agentID, Token: token})
	}
	hub, err := labgroup.Open(state, credentials)
	if err != nil {
		return err
	}
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
	server := &http.Server{Handler: hub.Handler(), ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 15 * time.Second, WriteTimeout: 15 * time.Second, IdleTimeout: 30 * time.Second}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	go func() {
		<-ctx.Done()
		shutdown, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = server.Shutdown(shutdown)
	}()
	fmt.Printf("lab_group_socket=%s state=%s transport=local-unix-plaintext\n", socket, state)
	err = server.Serve(listener)
	if errors.Is(err, http.ErrServerClosed) {
		return nil
	}
	return err
}
