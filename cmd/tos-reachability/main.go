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
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"os"
	"runtime"
	"runtime/debug"
	"strings"
	"time"

	"github.com/tosnetwork/tos-messenger/pkg/probe"
	"github.com/tosnetwork/tos-messenger/pkg/reachability"
)

const (
	// orchestratorRepository is what this binary is: the process that runs the
	// rendezvous, drives the ADNL implementation, and signs the trial.
	orchestratorRepository = "github.com/tosnetwork/tos-messenger"
	// adnlModulePath is the module that actually speaks ADNL on the wire for
	// this collector. The manifest pins its resolved version, because two
	// binaries at one orchestrator commit can still have compiled different
	// implementation code.
	adnlModulePath = "github.com/xssnick/tonutils-go"
	// wireProfile names the ADNL lineage this collector speaks, so its
	// evidence cannot be silently pooled with a dialect it never exercised.
	wireProfile = "ton-adnl"
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
	manifestOut := flag.String("manifest-out", "", "also write this collector's manifest JSON to a file; the evidence bundle needs the document, not only its digest")

	var phases sessionPhases
	flag.DurationVar(&phases.hold, "hold", 0, "how long past establishment to keep the adnl session alive and measure survival, 0 for establishment only")
	flag.DurationVar(&phases.keepalive, "keepalive", 0, "keepalive ping interval of the hold phase, defaulted when 0")
	flag.BoolVar(&phases.reconnect, "reconnect", false, "deliberately drop and re-establish the session after the hold phase (requires -hold; role a only, refused on role b, which never dials)")
	flag.StringVar(&phases.tunnel, "tunnel", "", "tunnel relay address for the fallback phase after a failed direct attempt, empty for none")

	var labels declared
	flag.StringVar(&labels.operator, "operator", "", "operator name, hashed into an opaque identifier")
	flag.StringVar(&labels.site, "site", "", "name of the network this endpoint runs on, hashed into an opaque identifier")
	flag.StringVar(&labels.carrier, "carrier", "", "datacenter, consumer-isp, carrier-grade-nat, or mobile-carrier")
	flag.StringVar(&labels.udpPolicy, "udp-policy", string(reachability.UDPAllowed), "allowed, rate-limited, or blocked")
	flag.StringVar(&labels.mobility, "mobility", string(reachability.MobilityStationary), "stationary, wifi-to-mobile, mobile-to-wifi, address-change, or sleep-wake")
	flag.StringVar(&labels.class, "endpoint-class", "", "server, desktop, edge-arm, edge-riscv, or mobile")
	flag.StringVar(&labels.assistance, "mapping-assistance", string(reachability.AssistanceNone), "none, static-port-mapping, or discovery-assisted")
	flag.Parse()

	trial, manifest, err := measure(context.Background(), *coordinators, *session, *role, *listen, *commit, *identity,
		reachability.ProbeKind(*probeKind), *pairTimeout, *punchTimeout, phases, labels)
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
	if *manifestOut != "" {
		if err := writeManifest(*manifestOut, manifest); err != nil {
			fmt.Fprintln(os.Stderr, "tos-reachability:", err)
			os.Exit(1)
		}
	}
	fmt.Fprintf(os.Stderr, "outcome=%s failure=%s establish_ms=%d survival_s=%d reconnect_ms=%d manifest=%s\n",
		trial.Outcome, trial.Failure, trial.EstablishMillis, trial.SurvivalSeconds, trial.ReconnectMillis,
		trial.LocalManifestDigest)
}

// writeManifest writes the manifest document the trial's local digest names.
func writeManifest(path string, manifest reachability.CollectorManifest) error {
	encoded, err := reachability.EncodeManifestJSON(manifest)
	if err != nil {
		return err
	}
	if err := os.WriteFile(path, append(encoded, '\n'), 0o600); err != nil {
		return errors.New("write manifest file")
	}
	return nil
}

// sessionPhases carries the measurement phases that run beyond the direct
// establishment attempt. They are collected in one place because they travel
// together: reconnect requires a hold window, and all of them are refused for
// the udp probe, which has no session to hold, reconnect, or tunnel.
type sessionPhases struct {
	hold      time.Duration
	keepalive time.Duration
	reconnect bool
	tunnel    string
}

func measure(ctx context.Context, coordinators, session, role, listen, commit, identity string,
	probeKind reachability.ProbeKind, pairTimeout, punchTimeout time.Duration,
	phases sessionPhases, labels declared) (reachability.Trial, reachability.CollectorManifest, error) {
	addresses := splitAddresses(coordinators)
	if len(addresses) == 0 {
		return reachability.Trial{}, reachability.CollectorManifest{}, errors.New("at least one coordinator is required")
	}
	if commit == "" {
		commit = buildCommit()
	}
	if commit == "" {
		return reachability.Trial{}, reachability.CollectorManifest{}, errors.New("the exact commit is required and could not be read from build information")
	}
	// The manifest describes the build that is about to measure, so it is
	// constructed before anything runs and fails closed: a record whose
	// provenance cannot be stated is a record that must not be written.
	manifest, err := collectorManifest(commit)
	if err != nil {
		return reachability.Trial{}, reachability.CollectorManifest{}, err
	}
	manifestDigest, err := manifest.Digest()
	if err != nil {
		return reachability.Trial{}, reachability.CollectorManifest{}, err
	}
	operator, err := reachability.OperatorID(labels.operator)
	if err != nil {
		return reachability.Trial{}, manifest, err
	}
	site, err := reachability.SiteID(labels.site)
	if err != nil {
		return reachability.Trial{}, manifest, err
	}
	// Both endpoints of one attempt derive the same pair identifier from the
	// session they shared, so the two halves are recognisable as one
	// measurement rather than two independent successes.
	pair, err := reachability.PairID(session)
	if err != nil {
		return reachability.Trial{}, manifest, err
	}
	endpointKey, err := loadOrCreateKey(identity)
	if err != nil {
		return reachability.Trial{}, manifest, err
	}
	endpointPublic, ok := endpointKey.Public().(ed25519.PublicKey)
	if !ok {
		return reachability.Trial{}, manifest, errors.New("unexpected endpoint key type")
	}
	endpointPublicHex := hex.EncodeToString(endpointPublic)
	configuration := probe.Config{
		Coordinators:      addresses,
		SessionID:         session,
		Role:              probe.Role(role),
		ListenAddr:        listen,
		PairTimeout:       pairTimeout,
		PunchTimeout:      punchTimeout,
		HoldWindow:        phases.hold,
		KeepaliveInterval: phases.keepalive,
		MeasureReconnect:  phases.reconnect,
		TunnelAddr:        phases.tunnel,
		Commit:            commit,
		ManifestDigest:    manifestDigest,
		EndpointKeyHex:    endpointPublicHex,
		Probe:             probeKind,
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
		return reachability.Trial{}, manifest, errors.New("probe must be udp or adnl")
	}
	if err != nil {
		return reachability.Trial{}, manifest, err
	}
	if result.PeerCommit == "" {
		return reachability.Trial{}, manifest, errors.New("the peer's commit was never learned, so the trial cannot name what it measured")
	}
	// The peer's manifest digest is learned during pairing exactly as its
	// commit is, and a trial without it cannot say which collector build the
	// far side ran -- which is the provenance a per-implementation report is
	// split by, so no record is written.
	if result.PeerManifestDigest == "" {
		return reachability.Trial{}, manifest, errors.New("the peer's collector manifest was never learned, so the trial cannot name what it measured against")
	}
	if result.Reachability == "" {
		return reachability.Trial{}, manifest, errors.New("this endpoint's own public reachability was never established")
	}
	// Without a verified attestation the endpoint's declared situation would be
	// its own unchecked claim about where its result counts, so no record is
	// written.
	if result.Observation.SignatureHex == "" {
		return reachability.Trial{}, manifest, errors.New("no coordinator attested to this measurement")
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
		PairID:      pair,
		SiteID:      site,
		OperatorID:  operator,
		SessionID:   session,
		Role:        reachability.Role(role),
		Observation: result.Observation,
		// The signed per-coordinator reflections the verifier derives the NAT
		// mapping class from, rather than trusting the declared one above.
		BindObservations:      result.BindObservations,
		FilteringObservations: result.FilteringObservations,
		Probe:                 probeKind,
		StartedAtUnix:         uint64(time.Now().Unix()),
		LocalCommit:           commit,
		PeerCommit:            result.PeerCommit,
		LocalManifestDigest:   manifestDigest,
		PeerManifestDigest:    result.PeerManifestDigest,
		TxBytes:               result.TxBytes,
		RxBytes:               result.RxBytes,
		EstablishMillis:       result.EstablishMillis,
	}
	if err := classify(&trial, result); err != nil {
		return reachability.Trial{}, manifest, err
	}
	signed, err := reachability.SignTrial(trial, endpointKey)
	if err != nil {
		return reachability.Trial{}, manifest, err
	}
	if err := signed.Validate(); err != nil {
		return reachability.Trial{}, manifest, err
	}
	return signed, manifest, nil
}

// collectorManifest describes this build: which orchestrator at which commit,
// driving which ADNL implementation at which resolved version, compiled by
// which toolchain for which target, hashed as the exact binary that ran. Every
// field fails closed, because a manifest that guessed any of them would be
// provenance the evidence bundle cannot check.
func collectorManifest(commit string) (reachability.CollectorManifest, error) {
	version, err := adnlModuleVersion()
	if err != nil {
		return reachability.CollectorManifest{}, err
	}
	binaryHash, err := executableSHA256()
	if err != nil {
		return reachability.CollectorManifest{}, err
	}
	return reachability.CollectorManifest{
		OrchestratorRepository: orchestratorRepository,
		OrchestratorCommit:     commit,
		ADNLImplementation:     "tonutils-go",
		// The module version is both the implementation pin and the dependency
		// version for a collector whose ADNL code arrives as a Go module: the
		// version is the identity the build actually resolved.
		ADNLImplementationCommit: version,
		DependencyVersion:        version,
		BinarySHA256:             binaryHash,
		Target:                   runtime.GOOS + "/" + runtime.GOARCH,
		Toolchain:                runtime.Version(),
		WireProfile:              wireProfile,
	}, nil
}

// adnlModuleVersion reads the resolved version of the ADNL module from build
// information, honouring a replace directive because the replacement is what
// was compiled.
func adnlModuleVersion() (string, error) {
	info, available := debug.ReadBuildInfo()
	if !available {
		return "", errors.New("build information is unavailable, so the adnl implementation version cannot be stated")
	}
	for _, dependency := range info.Deps {
		if dependency.Path != adnlModulePath {
			continue
		}
		if dependency.Replace != nil {
			dependency = dependency.Replace
		}
		if dependency.Version == "" {
			break
		}
		return dependency.Version, nil
	}
	return "", errors.New("the adnl implementation does not appear in build information")
}

// executableSHA256 hashes the running binary, failing closed if it cannot be
// read: a manifest is about the build that ran, and a hash of anything else
// would be a checkable-looking field that checks nothing.
func executableSHA256() (string, error) {
	path, err := os.Executable()
	if err != nil {
		return "", errors.New("the running binary could not be located for hashing")
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return "", errors.New("the running binary could not be read for hashing")
	}
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:]), nil
}

// classify translates what the probe measured into the trial's outcome
// vocabulary.
//
// A direct session carries its survival and reconnect measurements. A session
// established through the relay files as a proxy fallback carrying the
// failure class of the direct phase it fell back from -- exactly the pairing
// the schema requires of that outcome -- and never a survival or reconnect,
// which are direct-session properties. A trial with neither session is a
// classified failure: this collector cannot claim a Relay or HTTPS fallback
// it never attempted, so the failure keeps its cause, and zeroing the
// establishment latency is what the schema requires of a failed trial.
func classify(trial *reachability.Trial, result probe.Result) error {
	if !result.Established {
		trial.Outcome = reachability.OutcomeFailed
		trial.Failure = result.Failure
		trial.EstablishMillis = 0
		return nil
	}
	if result.TunneledEstablish {
		if result.Failure == reachability.FailureNone {
			return errors.New("a tunneled establishment must carry the failure class of the direct phase it fell back from")
		}
		trial.Outcome = reachability.OutcomeProxyFallback
		trial.Failure = result.Failure
		return nil
	}
	trial.Outcome = reachability.OutcomeDirect
	trial.Failure = reachability.FailureNone
	trial.SurvivalSeconds = result.SurvivalSeconds
	trial.ReconnectMillis = result.ReconnectMillis
	return nil
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
