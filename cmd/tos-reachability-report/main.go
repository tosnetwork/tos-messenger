// Command tos-reachability-report aggregates a study log against a predeclared
// policy and prints the matrix and the route decision.
//
// It exits non-zero when the study does not meet its own predeclared minimums.
// That is the point of the tool: a study that has not covered its required
// strata produces no route decision, and a build pipeline should be able to
// tell the difference without reading prose.
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
	if report.Decision == reachability.DecisionInsufficient {
		fmt.Fprintln(os.Stderr, "tos-reachability-report: the study does not support a route decision")
		os.Exit(1)
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
