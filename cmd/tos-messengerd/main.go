// Command tos-messengerd runs one Messenger installation.
//
// It owns one state directory, owner-private sockets, and optionally the
// descriptor-bound HTTPS bootstrap ingress. That fallback is not an M0-R
// production-route claim.
package main

import (
	"context"
	"flag"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/tosnetwork/tos-messenger/internal/safehttps"
	"github.com/tosnetwork/tos-messenger/pkg/attachmentops"
	"github.com/tosnetwork/tos-messenger/pkg/daemon"
	"github.com/tosnetwork/tos-messenger/pkg/directhttps"
	"github.com/tosnetwork/tos-messenger/pkg/directory"
	"github.com/tosnetwork/tos-messenger/pkg/dispatch"
	"github.com/tosnetwork/tos-messenger/pkg/eventlog"
	"github.com/tosnetwork/tos-messenger/pkg/publicationops"
)

func main() {
	configPath := flag.String("config", "", "daemon configuration file")
	publicationPath := flag.String("publication-operator-config", "", "operator publication resources (required to publish public prekey generations)")
	attachmentPath := flag.String("attachment-emission-operator-config", "", "operator storage and external Endpoint signer resources for outbound attachments")
	httpsListen := flag.String("https-listen", "", "HTTPS bootstrap listen address (for example :8443 behind the descriptor's public :443 endpoint)")
	httpsCert := flag.String("https-cert", "", "HTTPS bootstrap TLS certificate chain")
	httpsKey := flag.String("https-key", "", "HTTPS bootstrap TLS private key")
	check := flag.Bool("check", false, "validate the configuration and exit")
	flag.Parse()

	if err := run(*configPath, *publicationPath, *attachmentPath, *httpsListen, *httpsCert, *httpsKey, *check); err != nil {
		fmt.Fprintln(os.Stderr, "tos-messengerd:", err)
		os.Exit(1)
	}
}

func run(configPath, publicationPath, attachmentPath, httpsListen, httpsCert, httpsKey string, checkOnly bool) error {
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
	httpsConfigured := httpsListen != "" || httpsCert != "" || httpsKey != ""
	if config.Transport == daemon.TransportHTTPSBootstrap {
		if httpsListen == "" || httpsCert == "" || httpsKey == "" || publicationPath == "" {
			return fmt.Errorf("https-bootstrap needs listen, certificate, key, and publication operator resources")
		}
		if !filepath.IsAbs(httpsCert) || filepath.Clean(httpsCert) != httpsCert ||
			!filepath.IsAbs(httpsKey) || filepath.Clean(httpsKey) != httpsKey {
			return fmt.Errorf("HTTPS certificate and key paths must be absolute and clean")
		}
		published, parseErr := safehttps.ParseURL(publicationConfig.HTTPSEndpoint)
		if parseErr != nil || published.Path != directhttps.IngressPath {
			return fmt.Errorf("publication HTTPS endpoint must be the canonical Messenger ingress")
		}
	} else if httpsConfigured {
		return fmt.Errorf("HTTPS ingress flags require transport https-bootstrap")
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
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	fmt.Printf("runtime_socket=%s owner_socket=%s prekey_socket=%s state_dir=%s transport=%s\n",
		instance.SocketPath(), instance.OwnerSocketPath(), instance.PrekeySocketPath(), config.StateDir, config.Transport)
	if config.Transport == daemon.TransportNone {
		fmt.Println("no transport is configured: outbound events are queued and not sent")
	}
	var httpsServer *http.Server
	httpsErrors := make(chan error, 1)
	if config.Transport == daemon.TransportHTTPSBootstrap {
		handler, handlerErr := instance.HTTPSHandler()
		if handlerErr != nil {
			return handlerErr
		}
		httpsServer = &http.Server{Addr: httpsListen, Handler: handler,
			ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 30 * time.Second,
			WriteTimeout: 30 * time.Second, IdleTimeout: 30 * time.Second,
			MaxHeaderBytes: 16 << 10}
		go func() {
			err := httpsServer.ListenAndServeTLS(httpsCert, httpsKey)
			if err != nil && err != http.ErrServerClosed {
				httpsErrors <- err
				cancel()
			}
		}()
		defer func() {
			shutdown, done := context.WithTimeout(context.Background(), 5*time.Second)
			defer done()
			_ = httpsServer.Shutdown(shutdown)
		}()
		fmt.Printf("https_bootstrap_listen=%s\n", httpsListen)
	}
	daemonErr := instance.Run(ctx)
	select {
	case httpsErr := <-httpsErrors:
		return fmt.Errorf("serve HTTPS bootstrap: %w", httpsErr)
	default:
		return daemonErr
	}
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
