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
	"time"

	"github.com/tosnetwork/tos-messenger/pkg/attachmentops"
	"github.com/tosnetwork/tos-messenger/pkg/daemon"
	"github.com/tosnetwork/tos-messenger/pkg/directory"
	"github.com/tosnetwork/tos-messenger/pkg/dispatch"
	"github.com/tosnetwork/tos-messenger/pkg/eventlog"
	"github.com/tosnetwork/tos-messenger/pkg/publicationops"
)

func main() {
	configPath := flag.String("config", "", "daemon configuration file")
	publicationPath := flag.String("publication-operator-config", "", "operator publication resources (required to publish public prekey generations)")
	attachmentPath := flag.String("attachment-emission-operator-config", "", "operator storage and external Endpoint signer resources for outbound attachments")
	check := flag.Bool("check", false, "validate the configuration and exit")
	flag.Parse()

	if err := run(*configPath, *publicationPath, *attachmentPath, *check); err != nil {
		fmt.Fprintln(os.Stderr, "tos-messengerd:", err)
		os.Exit(1)
	}
}

func run(configPath, publicationPath, attachmentPath string, checkOnly bool) error {
	if configPath == "" {
		return errNoConfig
	}
	config, err := daemon.LoadConfig(configPath)
	if err != nil {
		return err
	}
	var publicationConfig publicationops.Config
	if publicationPath != "" {
		publicationConfig, err = publicationops.Load(publicationPath)
		if err != nil {
			return err
		}
	}
	var attachmentConfig attachmentops.Config
	if attachmentPath != "" {
		attachmentConfig, err = attachmentops.Load(attachmentPath)
		if err != nil {
			return err
		}
	}
	if config.Publication.Mode == daemon.PublicationNone && publicationPath != "" {
		return fmt.Errorf("publication operator resources require publication mode prekeys")
	}
	if checkOnly {
		fmt.Printf("configuration is valid: state_dir=%s runtime_socket=%s owner_socket=%s prekey_socket=%s transport=%s\n",
			config.StateDir, config.SocketPath, config.OwnerSocketPath, config.Publication.DeviceSocketPath, config.Transport)
		if publicationPath != "" {
			fmt.Println("publication operator configuration is structurally valid; live delegation, DHT, HTTPS root, and signer are checked at startup")
		}
		if attachmentPath != "" {
			fmt.Println("attachment emission operator configuration is structurally valid; live delegation, storage authority, and signer are checked at startup")
		}
		return nil
	}

	var instance *daemon.Daemon
	if publicationPath == "" && attachmentPath == "" {
		instance, err = daemon.Open(config, reporter{})
	} else {
		delegation, verifyErr := daemon.VerifyFinalizedDelegation(config, time.Now())
		if verifyErr != nil {
			return fmt.Errorf("verify operator authority: %w", verifyErr)
		}
		var publisher *directory.GenerationPublisher
		if publicationPath != "" {
			resources, assembleErr := publicationops.Assemble(publicationConfig, delegation)
			if assembleErr != nil {
				return fmt.Errorf("assemble publication resources: %w", assembleErr)
			}
			defer resources.Close()
			publisher = resources.Publisher
		}
		var attachmentResources *attachmentops.Resources
		if attachmentPath != "" {
			assembled, assembleErr := attachmentops.Assemble(attachmentConfig, delegation)
			if assembleErr != nil {
				return fmt.Errorf("assemble attachment emission resources: %w", assembleErr)
			}
			attachmentResources = &assembled
		}
		instance, err = daemon.OpenWithOperatorResources(config, reporter{}, publisher, attachmentResources)
	}
	if err != nil {
		return err
	}

	// Both signals mean the same thing here: stop taking work and release the
	// state directory. A daemon that exited without releasing it would make
	// its replacement fail to start for a reason nobody could see.
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	fmt.Printf("runtime_socket=%s owner_socket=%s prekey_socket=%s state_dir=%s transport=%s\n",
		instance.SocketPath(), instance.OwnerSocketPath(), instance.PrekeySocketPath(), config.StateDir, config.Transport)
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
