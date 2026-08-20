package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"github.com/tosnetwork/tos-messenger/pkg/evidence"
)

func main() { os.Exit(run(os.Args[1:])) }

func run(arguments []string) int {
	if len(arguments) == 0 {
		fmt.Fprintln(os.Stderr, "usage: tos-m0-evidence pack|verify")
		return 2
	}
	switch arguments[0] {
	case "pack":
		flags := flag.NewFlagSet("pack", flag.ContinueOnError)
		flags.SetOutput(os.Stderr)
		root := flags.String("root", "", "evidence input directory")
		output := flags.String("out", "", "output .zip path")
		commit := flags.String("commit", "", "40-hex source commit")
		toolchain := flags.String("toolchain", "", "toolchain identity")
		if flags.Parse(arguments[1:]) != nil || flags.NArg() != 0 || *root == "" || *output == "" {
			return 2
		}
		absoluteRoot, err := filepath.Abs(*root)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			return 2
		}
		absoluteOutput, err := filepath.Abs(*output)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			return 2
		}
		manifest, err := evidence.Pack(absoluteRoot, absoluteOutput, *commit, *toolchain)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			return 1
		}
		printManifest(manifest)
		return 0
	case "verify":
		flags := flag.NewFlagSet("verify", flag.ContinueOnError)
		flags.SetOutput(os.Stderr)
		input := flags.String("in", "", "evidence .zip path")
		if flags.Parse(arguments[1:]) != nil || flags.NArg() != 0 || *input == "" {
			return 2
		}
		absolute, err := filepath.Abs(*input)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			return 2
		}
		manifest, err := evidence.Verify(absolute)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			return 1
		}
		printManifest(manifest)
		return 0
	default:
		fmt.Fprintln(os.Stderr, "unknown subcommand")
		return 2
	}
}

func printManifest(manifest evidence.Manifest) {
	encoded, _ := json.Marshal(manifest)
	fmt.Println(string(encoded))
}
