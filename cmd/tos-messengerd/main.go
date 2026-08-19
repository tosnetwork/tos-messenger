// Command tos-messengerd runs one Messenger installation.
//
// It owns one state directory and serves one owner-private socket. What it
// cannot do yet is carry a message: the transport is frozen only after the
// reachability study, so an installation states `"transport": "none"` and
// queues outbound events durably without sealing them. That is a working
// daemon doing what this milestone can honestly do, not a stub.
package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/tosnetwork/tos-messenger/pkg/daemon"
	"github.com/tosnetwork/tos-messenger/pkg/dispatch"
	"github.com/tosnetwork/tos-messenger/pkg/eventlog"
)

func main() {
	configPath := flag.String("config", "", "daemon configuration file")
	check := flag.Bool("check", false, "validate the configuration and exit")
	flag.Parse()

	if err := run(*configPath, *check); err != nil {
		fmt.Fprintln(os.Stderr, "tos-messengerd:", err)
		os.Exit(1)
	}
}

func run(configPath string, checkOnly bool) error {
	if configPath == "" {
		return errNoConfig
	}
	config, err := daemon.LoadConfig(configPath)
	if err != nil {
		return err
	}
	if checkOnly {
		fmt.Printf("configuration is valid: state_dir=%s runtime_socket=%s owner_socket=%s transport=%s\n",
			config.StateDir, config.SocketPath, config.OwnerSocketPath, config.Transport)
		return nil
	}

	instance, err := daemon.Open(config, reporter{})
	if err != nil {
		return err
	}

	// Both signals mean the same thing here: stop taking work and release the
	// state directory. A daemon that exited without releasing it would make
	// its replacement fail to start for a reason nobody could see.
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	fmt.Printf("runtime_socket=%s owner_socket=%s state_dir=%s transport=%s\n",
		instance.SocketPath(), instance.OwnerSocketPath(), config.StateDir, config.Transport)
	if config.Transport == daemon.TransportNone {
		fmt.Println("no transport is configured: outbound events are queued and not sent")
	}
	return instance.Run(ctx)
}

var errNoConfig = fmt.Errorf("a configuration file is required")

// reporter writes what the daemon did to standard output, one line per event.
type reporter struct{}

func (reporter) Swept(summary dispatch.Summary) {
	if summary == (dispatch.Summary{}) {
		return
	}
	fmt.Printf("swept sent=%d sealed=%d retried=%d held=%d abandoned=%d\n",
		summary.Sent, summary.Sealed, summary.Retried, summary.Held, summary.Abandoned)
}

func (reporter) Maintained(expired int, report eventlog.PruneReport) {
	if expired == 0 && report.ClaimsRemoved == 0 && report.DeliveriesRemoved == 0 && len(report.Unreadable) == 0 {
		return
	}
	fmt.Printf("maintained expired=%d claims_removed=%d deliveries_removed=%d unreadable=%d\n",
		expired, report.ClaimsRemoved, report.DeliveriesRemoved, len(report.Unreadable))
	for _, name := range report.Unreadable {
		// Damaged records are kept, so an operator has to be told they exist
		// or they will sit there unnoticed until they matter.
		fmt.Printf("unreadable record retained: %s\n", name)
	}
}

func (reporter) Failed(stage string, err error) {
	fmt.Fprintf(os.Stderr, "tos-messengerd: %s: %v\n", stage, err)
}
