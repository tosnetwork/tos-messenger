// Command tos-attachmentd runs authenticated opaque attachment storage over a
// private Unix carrier. The service frames are also exposed by the strict HTTPS
// handler; public TLS deployment and operator evidence remain separate gates.
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
	"github.com/tosnetwork/tos-messenger/pkg/attachmentapi"
	"github.com/tosnetwork/tos-messenger/pkg/attachments"
	"github.com/tosnetwork/tos-messenger/pkg/daemon"
)

const maxStorageKeyBytes = 256

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
		return nil, errors.New("attachment delegation is not provisioned")
	}
	return securefile.ReadBoundedRegular(path, 64<<10)
}

func main() {
	configPath := flag.String("authority-config", "", "validated tos-messengerd config supplying finalized-chain authority")
	state := flag.String("state", "", "private attachment storage state directory")
	socket := flag.String("socket", "", "private Unix socket")
	keyPath := flag.String("storage-key", "", "mode-0600 hex Ed25519 private-key file")
	check := flag.Bool("check", false, "validate configuration and exit")
	var delegations delegationFlags
	flag.Var(&delegations, "delegation", "agent_id=/absolute/delegation.json (repeat)")
	flag.Parse()
	if err := run(*configPath, *state, *socket, *keyPath, delegations, *check); err != nil {
		fmt.Fprintln(os.Stderr, "tos-attachmentd:", err)
		os.Exit(1)
	}
}

func run(configPath, state, socket, keyPath string, delegations []string, check bool) error {
	if configPath == "" || !filepath.IsAbs(state) || filepath.Clean(state) != state ||
		!filepath.IsAbs(socket) || filepath.Clean(socket) != socket || !filepath.IsAbs(keyPath) || filepath.Clean(keyPath) != keyPath {
		return errors.New("authority-config, absolute state, socket, and storage-key are required")
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
			return errors.New("invalid attachment delegation mapping")
		}
		if _, duplicate := paths[agent]; duplicate {
			return errors.New("duplicate attachment delegation mapping")
		}
		paths[agent] = path
	}
	if len(paths) == 0 || len(paths) > 4096 {
		return errors.New("invalid attachment delegation mapping count")
	}
	authority, err := attachments.NewFinalizedAuthority(resolver, config.Network(), policy, fileSource{paths: paths})
	if err != nil {
		return err
	}
	raw, err := securefile.ReadBoundedRegular(keyPath, maxStorageKeyBytes)
	if err != nil {
		return err
	}
	keyBytes, err := hex.DecodeString(strings.TrimSpace(string(raw)))
	if err != nil || len(keyBytes) != ed25519.PrivateKeySize || hex.EncodeToString(keyBytes) != strings.TrimSpace(string(raw)) {
		return errors.New("storage-key must contain one canonical 64-byte Ed25519 private key in lowercase hex")
	}
	key := ed25519.PrivateKey(keyBytes)
	if check {
		fmt.Printf("configuration is valid: state=%s socket=%s delegations=%d storage_public_key=%s\n",
			state, socket, len(paths), hex.EncodeToString(key.Public().(ed25519.PublicKey)))
		return nil
	}
	store, err := attachments.OpenStore(state, attachments.DefaultStoreQuota())
	if err != nil {
		return err
	}
	defer store.Close()
	authenticated, err := attachments.NewAuthenticatedStore(store, authority, key)
	if err != nil {
		return err
	}
	server, err := attachmentapi.NewServer(authenticated, nil, 0)
	if err != nil {
		return err
	}
	listener, err := attachmentapi.ListenUnix(socket)
	if err != nil {
		return err
	}
	defer listener.Close()
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	fmt.Printf("socket=%s state=%s storage_public_key=%s authority=finalized-chain carrier=private-unix\n",
		socket, state, hex.EncodeToString(key.Public().(ed25519.PublicKey)))
	return server.Serve(ctx, listener)
}
