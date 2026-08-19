// Command tos-reachability-report aggregates a study log against a predeclared
// policy and prints the matrix and the route decision.
//
// It exits non-zero when the study does not meet its own predeclared minimums.
// That is the point of the tool: a study that has not covered its required
// strata produces no finding, and a build pipeline should be able to tell the
// difference without reading prose.
//
// A UDP study never produces a route decision, whatever its success rate. It
// measures whether a datagram path exists, which an ADNL handshake, channel,
// keepalive, and recovery still have to survive.
package main

import (
	"errors"
	"flag"
	"fmt"
	"os"

	"github.com/tosnetwork/tos-messenger/pkg/reachability"
)

func main() {
	policyPath := flag.String("policy", "", "predeclared acceptance policy")
	logPath := flag.String("log", "", "study log of trial records")
	probeKind := flag.String("probe", string(reachability.ProbeUDP), "probe to aggregate, udp or adnl")
	flag.Parse()

	report, err := build(*policyPath, *logPath, *probeKind)
	if err != nil {
		fmt.Fprintln(os.Stderr, "tos-reachability-report:", err)
		os.Exit(2)
	}
	encoded, err := reachability.EncodeReportJSON(report)
	if err != nil {
		fmt.Fprintln(os.Stderr, "tos-reachability-report:", err)
		os.Exit(2)
	}
	fmt.Println(string(encoded))
	if report.Finding == reachability.FindingInsufficient {
		fmt.Fprintln(os.Stderr, "tos-reachability-report: the study does not meet its own predeclared minimums")
		os.Exit(1)
	}
	if !report.SupportsRouteDecision() {
		// Said plainly, because the finding alone reads like an answer.
		fmt.Fprintf(os.Stderr,
			"tos-reachability-report: %s evidence yields %q, which is network feasibility and not a route decision; freezing a transport needs an %s study\n",
			report.Probe, report.Finding, reachability.ProbeADNL)
	}
}

func build(policyPath, logPath, probeKind string) (reachability.Report, error) {
	if policyPath == "" || logPath == "" {
		return reachability.Report{}, errors.New("a policy and a study log are required")
	}
	policyBytes, err := os.ReadFile(policyPath)
	if err != nil {
		return reachability.Report{}, errors.New("read policy")
	}
	policy, err := reachability.DecodePolicyJSON(policyBytes)
	if err != nil {
		return reachability.Report{}, err
	}
	logBytes, err := os.ReadFile(logPath)
	if err != nil {
		return reachability.Report{}, errors.New("read study log")
	}
	trials, err := reachability.DecodeTrialLog(logBytes)
	if err != nil {
		return reachability.Report{}, err
	}
	return reachability.Aggregate(policy, trials, reachability.ProbeKind(probeKind))
}
