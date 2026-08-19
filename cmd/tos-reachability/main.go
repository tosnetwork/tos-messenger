// Command tos-reachability runs one endpoint of one measured pair and appends
// a trial record to a study log.
//
// The tool measures what can be measured and asks the operator only for what
// cannot: the address family, the pair's public reachability, the NAT
// behavior, and the commits of both endpoints come from the measurement and
// are not accepted as flags. An operator can misdescribe their access network;
// they should not be able to misdescribe the result.
//
// It records one trial, UDP or ADNL. A UDP study answers whether a datagram
// path exists,
// which is an input to a route decision and never a route decision itself.
package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"os"
	"runtime/debug"
	"strings"
	"time"

	"github.com/tosnetwork/tos-messenger/pkg/probe"
	"github.com/tosnetwork/tos-messenger/pkg/reachability"
)

type declared struct {
	carrier    string
	udpPolicy  string
	mobility   string
	class      string
	assistance string
	operator   string
	site       string
}

func main() {
	coordinators := flag.String("coordinators", "", "comma-separated coordinator addresses, two or more to classify NAT mapping")
	session := flag.String("session", "", "shared session identifier for this pair")
	role := flag.String("role", "", "a or b")
	out := flag.String("out", "", "study log to append to, stdout when empty")
	commit := flag.String("commit", "", "commit of this build, taken from build information when empty")
	identity := flag.String("identity", "", "endpoint signing key file, created when absent")
	listen := flag.String("listen", ":0", "local UDP address to bind")
	probeKind := flag.String("probe", string(reachability.ProbeUDP),
		"udp for datagram feasibility, adnl for the session establishment a route decision needs")
	pairTimeout := flag.Duration("pair-timeout", probe.DefaultPairTimeout, "how long to wait for the peer")
	punchTimeout := flag.Duration("punch-timeout", probe.DefaultPunchTimeout, "how long to attempt a direct path")

	var labels declared
	flag.StringVar(&labels.operator, "operator", "", "operator name, hashed into an opaque identifier")
	flag.StringVar(&labels.site, "site", "", "name of the network this endpoint runs on, hashed into an opaque identifier")
	flag.StringVar(&labels.carrier, "carrier", "", "datacenter, consumer-isp, carrier-grade-nat, or mobile-carrier")
	flag.StringVar(&labels.udpPolicy, "udp-policy", string(reachability.UDPAllowed), "allowed, rate-limited, or blocked")
	flag.StringVar(&labels.mobility, "mobility", string(reachability.MobilityStationary), "stationary, wifi-to-mobile, mobile-to-wifi, address-change, or sleep-wake")
	flag.StringVar(&labels.class, "endpoint-class", "", "server, desktop, edge-arm, edge-riscv, or mobile")
	flag.StringVar(&labels.assistance, "mapping-assistance", string(reachability.AssistanceNone), "none, static-port-mapping, or discovery-assisted")
	flag.Parse()

	trial, err := measure(context.Background(), *coordinators, *session, *role, *listen, *commit, *identity,
		reachability.ProbeKind(*probeKind), *pairTimeout, *punchTimeout, labels)
	if err != nil {
		fmt.Fprintln(os.Stderr, "tos-reachability:", err)
		os.Exit(1)
	}
	encoded, err := reachability.EncodeTrialJSON(trial)
	if err != nil {
		fmt.Fprintln(os.Stderr, "tos-reachability:", err)
		os.Exit(1)
	}
	if err := emit(*out, encoded); err != nil {
		fmt.Fprintln(os.Stderr, "tos-reachability:", err)
		os.Exit(1)
	}
	fmt.Fprintf(os.Stderr, "outcome=%s failure=%s establish_ms=%d\n", trial.Outcome, trial.Failure, trial.EstablishMillis)
}

func measure(ctx context.Context, coordinators, session, role, listen, commit, identity string,
	probeKind reachability.ProbeKind, pairTimeout, punchTimeout time.Duration, labels declared) (reachability.Trial, error) {
	addresses := splitAddresses(coordinators)
	if len(addresses) == 0 {
		return reachability.Trial{}, errors.New("at least one coordinator is required")
	}
	if commit == "" {
		commit = buildCommit()
	}
	if commit == "" {
		return reachability.Trial{}, errors.New("the exact commit is required and could not be read from build information")
	}
	operator, err := reachability.OperatorID(labels.operator)
	if err != nil {
		return reachability.Trial{}, err
	}
	site, err := reachability.SiteID(labels.site)
	if err != nil {
		return reachability.Trial{}, err
	}
	// Both endpoints of one attempt derive the same pair identifier from the
	// session they shared, so the two halves are recognisable as one
	// measurement rather than two independent successes.
	pair, err := reachability.PairID(session)
	if err != nil {
		return reachability.Trial{}, err
	}
	endpointKey, err := loadOrCreateKey(identity)
	if err != nil {
		return reachability.Trial{}, err
	}
	endpointPublic, ok := endpointKey.Public().(ed25519.PublicKey)
	if !ok {
		return reachability.Trial{}, errors.New("unexpected endpoint key type")
	}
	endpointPublicHex := hex.EncodeToString(endpointPublic)
	configuration := probe.Config{
		Coordinators:   addresses,
		SessionID:      session,
		Role:           probe.Role(role),
		ListenAddr:     listen,
		PairTimeout:    pairTimeout,
		PunchTimeout:   punchTimeout,
		Commit:         commit,
		EndpointKeyHex: endpointPublicHex,
		Probe:          probeKind,
	}
	// The two runners measure different questions. The UDP one answers
	// whether datagrams pass; the ADNL one answers whether the session a
	// route decision is actually about comes up. Each refuses the other's
	// name, so the attestation always describes what happened.
	var result probe.Result
	switch probeKind {
	case reachability.ProbeUDP:
		result, err = probe.Run(ctx, configuration)
	case reachability.ProbeADNL:
		result, err = probe.RunADNL(ctx, configuration)
	default:
		return reachability.Trial{}, errors.New("probe must be udp or adnl")
	}
	if err != nil {
		return reachability.Trial{}, err
	}
	if result.PeerCommit == "" {
		return reachability.Trial{}, errors.New("the peer's commit was never learned, so the trial cannot name what it measured")
	}
	if result.Reachability == "" {
		return reachability.Trial{}, errors.New("this endpoint's own public reachability was never established")
	}
	// Without a verified attestation the endpoint's declared situation would be
	// its own unchecked claim about where its result counts, so no record is
	// written.
	if result.Observation.SignatureHex == "" {
		return reachability.Trial{}, errors.New("no coordinator attested to this measurement")
	}

	trial := reachability.Trial{
		// Only this endpoint's own situation. The peer describes its own, and
		// the cell is the ordered pair of the two.
		Local: reachability.EndpointStratum{
			Family:        result.AddressFamily,
			Reachability:  result.Reachability,
			NATBehavior:   result.Mapping,
			Carrier:       reachability.Carrier(labels.carrier),
			UDPPolicy:     reachability.UDPPolicy(labels.udpPolicy),
			Mobility:      reachability.Mobility(labels.mobility),
			EndpointClass: reachability.EndpointClass(labels.class),
			Assistance:    reachability.Assistance(labels.assistance),
		},
		PairID:          pair,
		SiteID:          site,
		OperatorID:      operator,
		SessionID:       session,
		Role:            reachability.Role(role),
		Observation:     result.Observation,
		Probe:           probeKind,
		StartedAtUnix:   uint64(time.Now().Unix()),
		LocalCommit:     commit,
		PeerCommit:      result.PeerCommit,
		TxBytes:         result.TxBytes,
		RxBytes:         result.RxBytes,
		EstablishMillis: result.EstablishMillis,
	}
	if result.Established {
		trial.Outcome = reachability.OutcomeDirect
		trial.Failure = reachability.FailureNone
	} else {
		// This probe measures the direct path only. It cannot claim a proxy,
		// Relay, or HTTPS fallback it never attempted, so a trial without a
		// direct session is recorded as a failure with its cause.
		trial.Outcome = reachability.OutcomeFailed
		trial.Failure = result.Failure
		trial.EstablishMillis = 0
	}
	signed, err := reachability.SignTrial(trial, endpointKey)
	if err != nil {
		return reachability.Trial{}, err
	}
	if err := signed.Validate(); err != nil {
		return reachability.Trial{}, err
	}
	return signed, nil
}

// loadOrCreateKey keeps one host's endpoint identity stable. A key that
// changed every run would make a single host indistinguishable from many, which
// is the counting the operator minimum exists to prevent.
func loadOrCreateKey(path string) (ed25519.PrivateKey, error) {
	if path == "" {
		return nil, errors.New("an endpoint signing key file is required")
	}
	raw, err := os.ReadFile(path)
	if err == nil {
		decoded, err := hex.DecodeString(strings.TrimSpace(string(raw)))
		if err != nil || len(decoded) != ed25519.PrivateKeySize {
			return nil, errors.New("identity file is not a signing key")
		}
		return ed25519.PrivateKey(decoded), nil
	}
	if !os.IsNotExist(err) {
		return nil, errors.New("read identity file")
	}
	_, generated, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, errors.New("generate endpoint key")
	}
	if err := os.WriteFile(path, []byte(hex.EncodeToString(generated)+"\n"), 0o600); err != nil {
		return nil, errors.New("write identity file")
	}
	return generated, nil
}

func splitAddresses(value string) []string {
	var addresses []string
	for _, part := range strings.Split(value, ",") {
		trimmed := strings.TrimSpace(part)
		if trimmed != "" {
			addresses = append(addresses, trimmed)
		}
	}
	return addresses
}

// buildCommit reads the revision Go records at build time, so a record names
// the binary that produced it without an operator having to type it.
func buildCommit() string {
	info, available := debug.ReadBuildInfo()
	if !available {
		return ""
	}
	for _, setting := range info.Settings {
		if setting.Key == "vcs.revision" {
			return setting.Value
		}
	}
	return ""
}

func emit(path string, line []byte) error {
	if path == "" {
		_, err := os.Stdout.Write(append(line, '\n'))
		return err
	}
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0o600)
	if err != nil {
		return errors.New("open study log")
	}
	defer file.Close()
	if _, err := file.Write(append(line, '\n')); err != nil {
		return errors.New("append to study log")
	}
	return file.Sync()
}
