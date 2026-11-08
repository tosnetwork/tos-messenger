// Command tos-intent-carrierd runs the Messenger public-channel Intent
// Carrier profile. It is intentionally a separate process and store from the
// service Gateway Carrier so operators can supply an independent discovery
// failure domain.
package main

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"errors"
	"flag"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"sort"
	"strings"
	"syscall"
	"time"

	"github.com/tosnetwork/tos-messenger/internal/securefile"
	"github.com/tosnetwork/tos-messenger/pkg/economicaction"
	"github.com/tosnetwork/tos-messenger/pkg/intentcarrier"
	"github.com/tosnetwork/tos-service-protocol/pkg/mldsa44"
)

// pinsFlag collects repeated --authority values; ParseAuthorityPins reads
// them at startup.
type pinsFlag []string

func (p *pinsFlag) String() string { return fmt.Sprintf("%d configured", len(*p)) }

func (p *pinsFlag) Set(value string) error {
	*p = append(*p, value)
	return nil
}

// helperFlags pins the verify-only tosctl helper for ML-DSA-44 signatures.
type helperFlags struct{ binary, sha256 string }

// pinnedAuthorities reads the pins and pins the verify-only helper. The
// helper is configured without a vault, so it cannot sign; the pin is never
// computed here.
func pinnedAuthorities(pins pinsFlag, helper helperFlags) (map[string]economicaction.PinnedAuthority, *mldsa44.Tosctl, error) {
	if helper.binary == "" || helper.sha256 == "" {
		return nil, nil, errors.New("--tosctl and --tosctl-sha256 (or TOS_SERVICE_TOSCTL and TOS_SERVICE_TOSCTL_SHA256) are required to verify ML-DSA-44 Action Authority signatures")
	}
	parsed, err := economicaction.ParseAuthorityPins(pins)
	if err != nil {
		return nil, nil, err
	}
	verifier, err := mldsa44.NewTosctl(mldsa44.TosctlConfig{Binary: helper.binary, SHA256: helper.sha256})
	if err != nil {
		return nil, nil, err
	}
	return parsed, verifier, nil
}

func describePins(pins map[string]economicaction.PinnedAuthority) string {
	entries := make([]string, 0, len(pins))
	for authorityID, pin := range pins {
		entries = append(entries, authorityID+"="+mldsa44.KeyIDText(pin.KeyID))
	}
	sort.Strings(entries)
	return strings.Join(entries, ",")
}

type tokenAuthorizer struct {
	readHash  [32]byte
	writeHash [32]byte
}

func (a tokenAuthorizer) Authorize(header string, write bool) error {
	if !strings.HasPrefix(header, "Bearer ") || len(header) > 8192 {
		return os.ErrPermission
	}
	digest := sha256.Sum256([]byte(strings.TrimPrefix(header, "Bearer ")))
	want := a.readHash
	if write {
		want = a.writeHash
	}
	if subtle.ConstantTimeCompare(digest[:], want[:]) != 1 {
		return os.ErrPermission
	}
	return nil
}

func main() {
	state := flag.String("state", "", "absolute private Carrier state directory")
	carrierID := flag.String("carrier-id", "", "source-local stable Carrier identifier")
	listen := flag.String("listen", "127.0.0.1:8092", "HTTP listen address")
	readToken := flag.String("read-token-file", "", "absolute mode-0600 bearer token file")
	writeToken := flag.String("write-token-file", "", "absolute mode-0600 relay token file")
	tlsCert := flag.String("tls-cert", "", "TLS certificate PEM (required outside loopback)")
	tlsKey := flag.String("tls-key", "", "TLS private key PEM (required outside loopback)")
	maxEntries := flag.Uint64("max-entries", 100000, "maximum retained operations")
	maxActorEntries := flag.Uint64("max-actor-entries", 1000, "maximum retained Intent publications per issuer")
	check := flag.Bool("check", false, "validate configuration and state without listening")
	pins := pinsFlag{}
	flag.Var(&pins, "authority", "pinned writer-fence authority AUTHORITY_ID=mldsa44:<key ID>@<key file> (repeat)")
	tosctl := flag.String("tosctl", os.Getenv("TOS_SERVICE_TOSCTL"), "absolute path of the verify-only tosctl helper")
	tosctlSHA256 := flag.String("tosctl-sha256", os.Getenv("TOS_SERVICE_TOSCTL_SHA256"), "lowercase hex SHA-256 of the tosctl helper")
	flag.Parse()
	if *maxEntries > 1_000_000 || *maxActorEntries > 1_000_000 {
		fmt.Fprintln(os.Stderr, "tos-intent-carrierd: retention limit is too large")
		os.Exit(1)
	}
	if err := run(*state, *carrierID, *listen, *readToken, *writeToken, *tlsCert, *tlsKey,
		uint32(*maxEntries), uint32(*maxActorEntries), pins, helperFlags{binary: *tosctl, sha256: *tosctlSHA256}, *check); err != nil {
		fmt.Fprintln(os.Stderr, "tos-intent-carrierd:", err)
		os.Exit(1)
	}
}

func run(state, carrierID, listen, readTokenPath, writeTokenPath, certPath, keyPath string,
	maxEntries, maxActorEntries uint32, pins pinsFlag, helper helperFlags, check bool) error {
	if !filepath.IsAbs(state) || carrierID == "" || len(pins) == 0 || maxEntries == 0 || maxActorEntries == 0 {
		return errors.New("incomplete Carrier configuration")
	}
	authorities, verifier, err := pinnedAuthorities(pins, helper)
	if err != nil {
		return err
	}
	readToken, err := loadToken(readTokenPath)
	if err != nil {
		return fmt.Errorf("read token: %w", err)
	}
	defer zero(readToken)
	writeToken, err := loadToken(writeTokenPath)
	if err != nil {
		return fmt.Errorf("write token: %w", err)
	}
	defer zero(writeToken)
	if string(readToken) == string(writeToken) {
		return errors.New("read and write bearer tokens must be distinct")
	}
	host, _, err := net.SplitHostPort(listen)
	if err != nil {
		return errors.New("listen address is invalid")
	}
	loopback := strings.EqualFold(host, "localhost") || net.ParseIP(host) != nil && net.ParseIP(host).IsLoopback()
	if !loopback && (certPath == "" || keyPath == "") {
		return errors.New("TLS is mandatory outside loopback")
	}
	store, err := intentcarrier.Open(state, carrierID, maxEntries, maxActorEntries, authorities, verifier)
	if err != nil {
		return err
	}
	defer store.Close()
	if check {
		fmt.Printf("configuration_valid=true carrier_id=%s independent_store=messenger-append-journal authority_pins=%s\n",
			carrierID, describePins(authorities))
		return nil
	}
	authorizer := tokenAuthorizer{readHash: sha256.Sum256(readToken), writeHash: sha256.Sum256(writeToken)}
	server := &http.Server{Addr: listen, Handler: intentcarrier.Handler(store, authorizer), ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout: 35 * time.Second, WriteTimeout: 35 * time.Second, IdleTimeout: 60 * time.Second, MaxHeaderBytes: 32 << 10,
		TLSConfig: &tls.Config{MinVersion: tls.VersionTLS13}}
	listener, err := net.Listen("tcp", listen)
	if err != nil {
		return err
	}
	defer listener.Close()
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	done := make(chan error, 1)
	go func() {
		if certPath != "" {
			done <- server.ServeTLS(listener, certPath, keyPath)
		} else {
			done <- server.Serve(listener)
		}
	}()
	fmt.Printf("ready=true carrier_id=%s listen=%s profile=messenger-public-channel independent_store=true\n", carrierID, listen)
	select {
	case <-ctx.Done():
		shutdown, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_ = server.Shutdown(shutdown)
		err = <-done
	case err = <-done:
	}
	if errors.Is(err, http.ErrServerClosed) {
		return nil
	}
	return err
}

func loadToken(path string) ([]byte, error) {
	if !filepath.IsAbs(path) {
		return nil, errors.New("token path must be absolute")
	}
	raw, err := securefile.ReadBoundedRegular(path, 8192)
	if err != nil {
		return nil, err
	}
	info, err := os.Lstat(path)
	if err != nil || info.Mode().Perm() != 0o600 {
		return nil, errors.New("token file must have mode 0600")
	}
	raw = []byte(strings.TrimSpace(string(raw)))
	if len(raw) < 32 {
		return nil, errors.New("bearer token must contain at least 32 bytes")
	}
	return raw, nil
}

func zero(value []byte) {
	for i := range value {
		value[i] = 0
	}
}
