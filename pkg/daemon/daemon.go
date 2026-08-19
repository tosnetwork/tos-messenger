package daemon

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/tosnetwork/tos-messenger/pkg/dispatch"
	"github.com/tosnetwork/tos-messenger/pkg/eventlog"
	"github.com/tosnetwork/tos-messenger/pkg/localapi"
)

const (
	// SaltFile holds the per-install value that keeps decision records from
	// correlating across installations.
	SaltFile = "install.salt"
	// SaltBytes is its length.
	SaltBytes = 32
)

// Observer receives what the daemon did. It exists so a caller can watch
// without the daemon deciding how logs are formatted or where they go.
type Observer interface {
	Swept(dispatch.Summary)
	Maintained(expired int, report eventlog.PruneReport)
	Failed(stage string, err error)
}

// Daemon is one running installation.
type Daemon struct {
	config   Config
	journal  *eventlog.Journal
	dispatch *dispatch.Dispatcher
	server   *localapi.Server
	listener net.Listener
	owner    net.Listener
	salt     []byte
	observer Observer

	closeOnce sync.Once
}

// Open assembles a daemon and takes ownership of its state.
//
// Ownership is taken before anything else: the journal's directory lock is
// what makes a second daemon on the same state fail immediately rather than
// two of them interleaving writes for a while first.
func Open(config Config, observer Observer) (*Daemon, error) {
	if err := config.Validate(); err != nil {
		return nil, err
	}
	journal, err := eventlog.Open(config.StateDir)
	if err != nil {
		return nil, err
	}
	instance := &Daemon{config: config, journal: journal, observer: observer}

	salt, err := loadOrCreateSalt(filepath.Join(config.StateDir, SaltFile))
	if err != nil {
		_ = journal.Close()
		return nil, err
	}
	instance.salt = salt

	// With no transport the dispatcher can queue and not send, which is what
	// this installation can honestly do.
	dispatcher, err := dispatch.New(dispatch.Config{Journal: journal, Identity: config.Identity()})
	if err != nil {
		_ = journal.Close()
		return nil, err
	}
	instance.dispatch = dispatcher

	server, err := localapi.NewServer(localapi.Config{Policy: config.FirewallPolicy(), Journal: journal, Dispatcher: dispatcher})
	if err != nil {
		_ = journal.Close()
		return nil, err
	}
	instance.server = server

	listener, err := localapi.Listen(config.SocketPath)
	if err != nil {
		_ = journal.Close()
		return nil, err
	}
	instance.listener = listener

	owner, err := localapi.Listen(config.OwnerSocketPath)
	if err != nil {
		_ = listener.Close()
		_ = os.Remove(config.SocketPath)
		_ = journal.Close()
		return nil, err
	}
	instance.owner = owner
	return instance, nil
}

// InstallSalt returns the per-install value used for decision records.
func (d *Daemon) InstallSalt() []byte {
	if d == nil {
		return nil
	}
	return append([]byte(nil), d.salt...)
}

// SocketPath returns where the Agent runtime connects.
func (d *Daemon) SocketPath() string {
	if d == nil {
		return ""
	}
	return d.config.SocketPath
}

// OwnerSocketPath returns where the owner decides.
func (d *Daemon) OwnerSocketPath() string {
	if d == nil {
		return ""
	}
	return d.config.OwnerSocketPath
}

// Run serves the local API and keeps the schedule until the context ends.
//
// It returns when everything has stopped, so a caller that waits on Run knows
// the state directory is released rather than merely no longer in use.
func (d *Daemon) Run(ctx context.Context) error {
	if d == nil {
		return errors.New("no daemon")
	}
	var group sync.WaitGroup
	for _, endpoint := range []struct {
		listener  net.Listener
		principal localapi.Principal
	}{
		{d.listener, localapi.PrincipalRuntime},
		{d.owner, localapi.PrincipalOwner},
	} {
		group.Add(1)
		go func(listener net.Listener, principal localapi.Principal) {
			defer group.Done()
			if err := d.server.Serve(ctx, listener, principal); err != nil && !isClosed(err) {
				d.report("serve", err)
			}
		}(endpoint.listener, endpoint.principal)
	}

	group.Add(1)
	go func() {
		defer group.Done()
		d.schedule(ctx)
	}()

	<-ctx.Done()
	// Closing the listeners is what unblocks Accept; the schedule stops on the
	// same context.
	_ = d.listener.Close()
	_ = d.owner.Close()
	group.Wait()
	return d.Close()
}

// Close releases the state directory and removes the socket.
func (d *Daemon) Close() error {
	if d == nil {
		return nil
	}
	var err error
	d.closeOnce.Do(func() {
		_ = d.listener.Close()
		_ = d.owner.Close()
		// The sockets are removed only by the daemon that created them, and
		// only once it is done with the state it was serving.
		_ = os.Remove(d.config.SocketPath)
		_ = os.Remove(d.config.OwnerSocketPath)
		err = d.journal.Close()
	})
	return err
}

func (d *Daemon) schedule(ctx context.Context) {
	sweep := time.NewTicker(d.config.SweepInterval())
	defer sweep.Stop()
	maintenance := time.NewTicker(d.config.MaintenanceInterval())
	defer maintenance.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-sweep.C:
			d.Sweep(ctx)
		case <-maintenance.C:
			d.Maintain()
		}
	}
}

// Sweep attempts every due delivery. With no transport it does nothing and
// says so once rather than reporting an empty success on every tick.
func (d *Daemon) Sweep(ctx context.Context) {
	if !d.dispatch.CanSend() {
		return
	}
	summary, err := d.dispatch.Sweep(ctx, 0)
	if err != nil {
		d.report("sweep", err)
		return
	}
	if d.observer != nil {
		d.observer.Swept(summary)
	}
}

// Maintain settles what has expired and removes what is finished.
//
// Expiry runs before pruning, because an event that has just expired is
// finished work and the sweep that removes finished work should see it in the
// same pass rather than a maintenance interval later.
func (d *Daemon) Maintain() {
	now := time.Now()
	expired, err := d.journal.ExpireDeliveries(now)
	if err != nil {
		d.report("expire", err)
		return
	}
	report, err := d.journal.Prune(now, d.config.Retention())
	if err != nil {
		d.report("prune", err)
		return
	}
	if d.observer != nil {
		d.observer.Maintained(expired, report)
	}
}

func (d *Daemon) report(stage string, err error) {
	if d.observer != nil {
		d.observer.Failed(stage, err)
	}
}

// loadOrCreateSalt keeps decision records correlatable within one install and
// meaningless outside it. A salt regenerated on every start would make a
// node's own logs uncorrelatable with themselves.
func loadOrCreateSalt(path string) ([]byte, error) {
	raw, err := os.ReadFile(path)
	if err == nil {
		decoded, err := hex.DecodeString(strings.TrimSpace(string(raw)))
		if err != nil || len(decoded) < SaltBytes {
			return nil, errors.New("install salt file is unusable")
		}
		return decoded, nil
	}
	if !os.IsNotExist(err) {
		return nil, errors.New("read install salt")
	}
	salt := make([]byte, SaltBytes)
	if _, err := rand.Read(salt); err != nil {
		return nil, errors.New("generate install salt")
	}
	if err := os.WriteFile(path, []byte(hex.EncodeToString(salt)+"\n"), 0o600); err != nil {
		return nil, errors.New("write install salt")
	}
	return salt, nil
}

func isClosed(err error) bool {
	return errors.Is(err, net.ErrClosed) || errors.Is(err, context.Canceled)
}
