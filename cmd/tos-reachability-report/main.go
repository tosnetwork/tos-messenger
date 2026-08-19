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
	"io"
	"os"

	"github.com/tosnetwork/tos-messenger/pkg/reachability"
)

func main() {
	policyPath := flag.String("policy", "", "predeclared acceptance policy")
	logPath := flag.String("log", "", "study log of trial records")
	probeKind := flag.String("probe", string(reachability.ProbeUDP), "probe to aggregate, udp or adnl")
	flag.Parse()
	os.Exit(run(*policyPath, *logPath, *probeKind, os.Stdout, os.Stderr))
}

// run returns the process exit code, so the code is a tested value rather than a
// side effect: 2 for a tooling or input failure, 1 for a valid report that
// supports no route decision (including an insufficient study or a UDP
// feasibility result), and 0 only when the evidence actually supports a route
// decision. A build gate reads this without parsing prose.
func run(policyPath, logPath, probeKind string, stdout, stderr io.Writer) int {
	report, err := build(policyPath, logPath, probeKind)
	if err != nil {
		fmt.Fprintln(stderr, "tos-reachability-report:", err)
		return 2
	}
	encoded, err := reachability.EncodeReportJSON(report)
	if err != nil {
		fmt.Fprintln(stderr, "tos-reachability-report:", err)
		return 2
	}
	fmt.Fprintln(stdout, string(encoded))
	if report.Finding == reachability.FindingInsufficient {
		fmt.Fprintln(stderr, "tos-reachability-report: the study does not meet its own predeclared minimums")
	} else if !report.SupportsRouteDecision() {
		// A feasibility result is not a route decision. Saying so plainly is not
		// enough: the exit code has to carry it, or a gate that only reads the
		// status treats network feasibility as a frozen transport answer.
		fmt.Fprintf(stderr,
			"tos-reachability-report: %s evidence yields %q, which is network feasibility and not a route decision; freezing a transport needs an %s study\n",
			report.Probe, report.Finding, reachability.ProbeADNL)
	}
	return exitCode(report)
}

// exitCode maps a report to the process exit code, kept separate so the mapping
// is a tested pure function rather than a branch buried in I/O: 1 for a report
// that supports no route decision -- an insufficient study, or any feasibility
// result however successful -- and 0 only when the evidence decides a route.
func exitCode(report reachability.Report) int {
	if report.Finding == reachability.FindingInsufficient {
		return 1
	}
	if !report.SupportsRouteDecision() {
		return 1
	}
	return 0
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
