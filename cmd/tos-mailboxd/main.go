// Command tos-mailboxd runs the bounded authenticated Mailbox service over a
// private Unix carrier. The strict request protocol is transport-neutral; a
// public carrier remains gated on M0-R.
package main

import (
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/tosnetwork/tos-messenger/internal/ids"
	"github.com/tosnetwork/tos-messenger/internal/securefile"
	"github.com/tosnetwork/tos-messenger/pkg/daemon"
	"github.com/tosnetwork/tos-messenger/pkg/mailbox"
	"github.com/tosnetwork/tos-messenger/pkg/mailboxapi"
)

const maxRelayKeyBytes = 256

type delegationFlags []string

func (d *delegationFlags) String() string         { return strings.Join(*d, ",") }
func (d *delegationFlags) Set(value string) error { *d = append(*d, value); return nil }

type fileSource struct{ paths map[string]string }

func (s fileSource) Delegation(ctx context.Context, agentID string) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	path, ok := s.paths[agentID]
	if !ok {
		return nil, errors.New("Mailbox delegation is not provisioned")
	}
	return securefile.ReadBoundedRegular(path, 64<<10)
}

func main() {
	configPath := flag.String("authority-config", "", "validated tos-messengerd config supplying finalized-chain authority")
	state := flag.String("state", "", "private Relay state directory")
	socket := flag.String("socket", "", "private Unix socket")
	keyPath := flag.String("relay-key", "", "mode-0600 hex Ed25519 private-key file")
	check := flag.Bool("check", false, "validate configuration and exit")
	var delegations delegationFlags
	flag.Var(&delegations, "delegation", "agent_id=/absolute/delegation.json (repeat)")
	flag.Parse()
	if err := run(*configPath, *state, *socket, *keyPath, delegations, *check); err != nil {
		fmt.Fprintln(os.Stderr, "tos-mailboxd:", err)
		os.Exit(1)
	}
}

func run(configPath, state, socket, keyPath string, delegations []string, check bool) error {
	if configPath == "" || !filepath.IsAbs(state) || filepath.Clean(state) != state || !filepath.IsAbs(socket) || filepath.Clean(socket) != socket {
		return errors.New("authority-config, absolute state, and absolute socket are required")
	}
	config, err := daemon.LoadConfig(configPath)
	if err != nil {
		return err
	}
	resolver, policy, err := daemon.FinalizedAgentResolver(config)
	if err != nil {
		return err
	}
	paths := make(map[string]string, len(delegations))
	for _, entry := range delegations {
		agent, path, ok := strings.Cut(entry, "=")
		if !ok || !ids.Agent.MatchString(agent) || !filepath.IsAbs(path) || filepath.Clean(path) != path {
			return errors.New("invalid delegation mapping")
		}
		if _, duplicate := paths[agent]; duplicate {
			return errors.New("duplicate delegation mapping")
		}
		paths[agent] = path
	}
	if len(paths) == 0 || len(paths) > 4096 {
		return errors.New("invalid delegation mapping count")
	}
	authority, err := mailbox.NewFinalizedAuthority(resolver, config.Network(), policy, fileSource{paths: paths})
	if err != nil {
		return err
	}
	raw, err := securefile.ReadBoundedRegular(keyPath, maxRelayKeyBytes)
	if err != nil {
		return err
	}
	keyBytes, err := hex.DecodeString(strings.TrimSpace(string(raw)))
	if err != nil || len(keyBytes) != ed25519.PrivateKeySize {
		return errors.New("relay-key must contain one canonical 64-byte Ed25519 private key in hex")
	}
	key := ed25519.PrivateKey(keyBytes)
	if check {
		fmt.Printf("configuration is valid: state=%s socket=%s delegations=%d relay_public_key=%s\n", state, socket, len(paths), hex.EncodeToString(key.Public().(ed25519.PublicKey)))
		return nil
	}
	store, err := mailbox.Open(state, mailbox.DefaultQuota(), key)
	if err != nil {
		return err
	}
	defer store.Close()
	authenticated, err := mailbox.NewAuthenticatedStore(store, authority)
	if err != nil {
		return err
	}
	server, err := mailboxapi.NewServer(authenticated, nil, 0)
	if err != nil {
		return err
	}
	listener, err := mailboxapi.ListenUnix(socket)
	if err != nil {
		return err
	}
	defer listener.Close()
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	fmt.Printf("socket=%s state=%s relay_public_key=%s authority=finalized-chain carrier=private-unix\n", socket, state, hex.EncodeToString(key.Public().(ed25519.PublicKey)))
	return server.Serve(ctx, listener)
}
