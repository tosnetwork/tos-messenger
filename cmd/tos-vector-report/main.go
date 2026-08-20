package main

import (
	"flag"
	"fmt"
	"io"
	"os"

	"github.com/tosnetwork/tos-messenger/pkg/conformance"
)

func main() { os.Exit(run(os.Args[1:])) }

func run(arguments []string) int {
	flags := flag.NewFlagSet("tos-vector-report", flag.ContinueOnError)
	flags.SetOutput(os.Stderr)
	reportPath := flags.String("report", "", "signed consumer report")
	objects := flags.String("objects", "internal/vectors/testdata/vectors.json", "object vectors")
	adversarial := flags.String("adversarial", "internal/vectors/testdata/adversarial-corpus.json", "adversarial corpus")
	e2ee := flags.String("e2ee", "pkg/e2ee/testdata/default-suite-vectors.json", "E2EE vectors")
	if flags.Parse(arguments) != nil || flags.NArg() != 0 || *reportPath == "" {
		return 2
	}
	file, err := os.Open(*reportPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	raw, err := io.ReadAll(io.LimitReader(file, conformance.MaxReportBytes+1))
	_ = file.Close()
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	report, err := conformance.DecodeJSON(raw)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	expected, err := conformance.Expected(*objects, *adversarial, *e2ee)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	if err := conformance.VerifyAgainst(report, expected); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	fmt.Printf("implementation=%s commit=%s positive=%d adversarial=%d\n", report.Implementation, report.ImplementationCommit, report.PositiveChecks, report.AdversarialChecks)
	return 0
}
