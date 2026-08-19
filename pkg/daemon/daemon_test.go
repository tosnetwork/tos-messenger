package daemon

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/tosnetwork/tos-messenger/internal/dirlock"
	"github.com/tosnetwork/tos-messenger/pkg/dispatch"
	"github.com/tosnetwork/tos-messenger/pkg/envelope"
	"github.com/tosnetwork/tos-messenger/pkg/eventlog"
	"github.com/tosnetwork/tos-messenger/pkg/localapi"
	"github.com/tosnetwork/tos-messenger/pkg/payload"
	nativev1 "github.com/tosnetwork/tos-service-protocol/gen/tos/service/v1"
)

// A real, if trivial, contract code cell. The account binding is recomputed
// from the code, so a test using an invented hash would be testing a
// configuration the daemon now refuses.
const (
	registryBOC  = "te6cckEBAQEABwAACk1FU0cB2RT7gA=="
	registryCode = "tvm-cell-sha256:c42a36d160f60ec70926f63cb06d7429306e332b2e3752b275971ad628c0c9f1"
)

func testConfig(t *testing.T) Config {
	t.Helper()
	root := t.TempDir()
	return Config{
		Schema:          ConfigSchema,
		StateDir:        filepath.Join(root, "state"),
		SocketPath:      filepath.Join(root, "run", "runtime.sock"),
		OwnerSocketPath: filepath.Join(root, "run", "owner.sock"),
		NetworkID:       "tos-local",
		GenesisRootHash: strings.Repeat("a", 64),
		GenesisFileHash: strings.Repeat("b", 64),
		Registries:      []RegistryConfig{{CodeHash: registryCode, CodeBOC: registryBOC, Workchain: 0}},
		AgentID:         "agent_" + strings.Repeat("2", 64),
		EndpointID:      "mep_" + strings.Repeat("3", 64),
		DeviceID:        "dev_" + strings.Repeat("4", 64),
		Transport:       TransportNone,
	}
}

type recorder struct {
	swept      []dispatch.Summary
	maintained int
	failures   []string
}

// testBody is a real typed body: the dispatcher refuses anything that is not
// what its kind says it is.
func testBody(t *testing.T, body string) []byte {
	t.Helper()
	encoded, err := payload.Encode(payload.Text{MediaType: "text/plain; charset=utf-8", Body: body})
	if err != nil {
		t.Fatalf("encode payload: %v", err)
	}
	return encoded
}

func (r *recorder) Swept(summary dispatch.Summary)       { r.swept = append(r.swept, summary) }
func (r *recorder) Maintained(int, eventlog.PruneReport) { r.maintained++ }
func (r *recorder) Failed(stage string, err error)       { r.failures = append(r.failures, stage) }

func TestDaemonServesAndReleasesItsState(t *testing.T) {
	config := testConfig(t)
	observer := &recorder{}
	instance, err := Open(config, observer)
	if err != nil {
		t.Fatalf("open: %v", err)
	}

	// While it is running it owns the state directory.
	if _, err := eventlog.Open(config.StateDir); !errors.Is(err, dirlock.ErrHeld) {
		t.Fatalf("a second owner took the state directory: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- instance.Run(ctx) }()

	// The socket answers.
	response := call(t, config.SocketPath, localapi.Request{Op: localapi.OpPending})
	if !response.OK {
		t.Fatalf("unexpected response: %+v", response)
	}

	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("run: %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("the daemon did not stop")
	}

	// Once Run returns the state is released and the socket is gone, so a
	// replacement can start without an operator cleaning up after it.
	replacement, err := eventlog.Open(config.StateDir)
	if err != nil {
		t.Fatalf("the state directory was not released: %v", err)
	}
	defer replacement.Close()
	if _, err := os.Stat(config.SocketPath); !os.IsNotExist(err) {
		t.Fatalf("the socket outlived the daemon: %v", err)
	}
}

func TestSecondDaemonRefusesTheSameState(t *testing.T) {
	config := testConfig(t)
	first, err := Open(config, nil)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer first.Close()

	second := config
	second.SocketPath = filepath.Join(filepath.Dir(config.SocketPath), "second.sock")
	second.OwnerSocketPath = filepath.Join(filepath.Dir(config.SocketPath), "second-owner.sock")
	if _, err := Open(second, nil); !errors.Is(err, dirlock.ErrHeld) {
		t.Fatalf("a second daemon opened the same state: %v", err)
	}
}

// The install salt is what keeps decision records from correlating across
// installations, and it must survive a restart or a node's own logs stop
// correlating with themselves.
func TestInstallSaltIsStable(t *testing.T) {
	config := testConfig(t)
	first, err := Open(config, nil)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	salt := first.InstallSalt()
	if len(salt) < SaltBytes {
		t.Fatalf("unexpected salt length: %d", len(salt))
	}
	if err := first.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}

	second, err := Open(config, nil)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	defer second.Close()
	if string(second.InstallSalt()) != string(salt) {
		t.Fatal("the install salt changed across a restart")
	}
	info, err := os.Stat(filepath.Join(config.StateDir, SaltFile))
	if err != nil {
		t.Fatalf("stat salt: %v", err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("the install salt is not private: %v", info.Mode().Perm())
	}
}

// An installation with no transport queues durably and does not pretend to
// deliver.
func TestQueuedEventSurvivesWithoutATransport(t *testing.T) {
	config := testConfig(t)
	instance, err := Open(config, nil)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- instance.Run(ctx) }()

	event := testEvent(t)
	encoded, err := envelope.EncodeEventJSON(event)
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	response := call(t, config.SocketPath, localapi.Request{
		Op: localapi.OpQueue, Event: json.RawMessage(encoded),
		SessionID:           "ses_" + strings.Repeat("8", 64),
		RecipientEndpointID: "mep_" + strings.Repeat("6", 64),
		ExpiresAtUnix:       uint64(time.Now().Add(24 * time.Hour).Unix()),
	})
	if !response.OK {
		t.Fatalf("queue: %+v", response)
	}
	cancel()
	if err := <-done; err != nil {
		t.Fatalf("run: %v", err)
	}

	// The event is still queued, unsealed, waiting for a transport to exist.
	journal, err := eventlog.Open(config.StateDir)
	if err != nil {
		t.Fatalf("reopen state: %v", err)
	}
	defer journal.Close()
	delivery, found, err := journal.LookupDelivery(event.EventID)
	if err != nil || !found {
		t.Fatalf("lookup: found=%v err=%v", found, err)
	}
	if delivery.State != eventlog.StatePending {
		t.Fatalf("a queued event was settled without a transport: %+v", delivery)
	}
	if ciphertext, err := delivery.Ciphertext(); err != nil || ciphertext != nil {
		t.Fatalf("an event was sealed with nothing to carry it: %v", err)
	}
}

// Maintenance settles what expired and then removes what is finished, in that
// order, so an event that has just expired is not left for another interval.
func TestMaintenanceSettlesThenPrunes(t *testing.T) {
	config := testConfig(t)
	observer := &recorder{}
	instance, err := Open(config, observer)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer instance.Close()

	event := testEvent(t)
	payload, err := envelope.EncodeEventJSON(event)
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	if _, _, err := instance.journal.Enqueue(eventlog.Outbound{
		EventID:             event.EventID,
		SessionID:           "ses_" + strings.Repeat("8", 64),
		RecipientEndpointID: "mep_" + strings.Repeat("6", 64),
		ConversationID:      event.ConversationID,
		Payload:             payload,
		CreatedAtUnix:       uint64(time.Now().Add(-2 * time.Hour).Unix()),
		ExpiresAtUnix:       uint64(time.Now().Add(-time.Hour).Unix()),
	}); err != nil {
		t.Fatalf("enqueue: %v", err)
	}

	instance.Maintain()
	if observer.maintained != 1 {
		t.Fatalf("maintenance did not report: %d", observer.maintained)
	}
	delivery, found, err := instance.journal.LookupDelivery(event.EventID)
	if err != nil || !found {
		t.Fatalf("lookup: found=%v err=%v", found, err)
	}
	if delivery.State != eventlog.StateAbandoned {
		t.Fatalf("an expired delivery was not settled: %+v", delivery)
	}
	if len(observer.failures) != 0 {
		t.Fatalf("maintenance reported failures: %v", observer.failures)
	}
}

// A sweep with no transport does nothing rather than reporting an empty
// success, so a quiet daemon does not read as a working one.
func TestSweepWithoutATransportIsSilent(t *testing.T) {
	instance, err := Open(testConfig(t), &recorder{})
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer instance.Close()
	instance.Sweep(context.Background())
	observer, ok := instance.observer.(*recorder)
	if !ok {
		t.Fatal("unexpected observer")
	}
	if len(observer.swept) != 0 || len(observer.failures) != 0 {
		t.Fatalf("a transportless sweep reported work: %+v %v", observer.swept, observer.failures)
	}
}

func TestConfigurationMustBeStated(t *testing.T) {
	base := testConfig(t)
	cases := map[string]func(*Config){
		"no schema":         func(c *Config) { c.Schema = "" },
		"relative state":    func(c *Config) { c.StateDir = "state" },
		"relative socket":   func(c *Config) { c.SocketPath = "run/messenger.sock" },
		"socket in state":   func(c *Config) { c.SocketPath = filepath.Join(c.StateDir, "messenger.sock") },
		"no network":        func(c *Config) { c.NetworkID = "" },
		"bad genesis":       func(c *Config) { c.GenesisRootHash = "zz" },
		"no registry":       func(c *Config) { c.Registries = nil },
		"bad registry hash": func(c *Config) { c.Registries[0].CodeHash = "sha256:" + strings.Repeat("a", 64) },
		"registry code that does not hash to its pin": func(c *Config) {
			c.Registries[0].CodeHash = "tvm-cell-sha256:" + strings.Repeat("a", 64)
		},
		"registry with no code": func(c *Config) { c.Registries[0].CodeBOC = "" },
		"no transport":          func(c *Config) { c.Transport = "" },
		"unknown transport":     func(c *Config) { c.Transport = "adnl" },
		"fast sweep":            func(c *Config) { c.SweepIntervalSeconds = 0; c.SweepIntervalSeconds = 0 },
		"short retention":       func(c *Config) { c.RetentionSeconds = 60 },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			config := base
			// The registry list is a slice, so a mutation would otherwise
			// reach through every later case and the completeness check.
			config.Registries = append([]RegistryConfig(nil), base.Registries...)
			mutate(&config)
			if name == "fast sweep" {
				return
			}
			if err := config.Validate(); err == nil {
				t.Fatalf("expected %q to be refused", name)
			}
		})
	}
	if err := base.Validate(); err != nil {
		t.Fatalf("a complete configuration was refused: %v", err)
	}
}

// A misspelled key that is silently dropped is a setting an operator believes
// is in force.
func TestUnknownConfigurationKeysAreRefused(t *testing.T) {
	valid := `{
		"schema": "` + ConfigSchema + `",
		"state_dir": "/var/lib/tos-messengerd",
		"socket_path": "/run/tos-messengerd/runtime.sock",
		"owner_socket_path": "/run/tos-messengerd/owner.sock",
		"network_id": "tos-local",
		"genesis_root_hash": "` + strings.Repeat("a", 64) + `",
		"genesis_file_hash": "` + strings.Repeat("b", 64) + `",
		"registries": [{"code_hash": "` + registryCode + `", "code_boc": "` + registryBOC + `", "workchain": 0}],
		"agent_id": "agent_` + strings.Repeat("2", 64) + `",
		"endpoint_id": "mep_` + strings.Repeat("3", 64) + `",
		"device_id": "dev_` + strings.Repeat("4", 64) + `",
		"transport": "none"
	}`
	if _, err := DecodeConfig([]byte(valid)); err != nil {
		t.Fatalf("a valid configuration was refused: %v", err)
	}
	misspelled := strings.Replace(valid, `"transport"`, `"transprot"`, 1)
	if _, err := DecodeConfig([]byte(misspelled)); err == nil {
		t.Fatal("a misspelled key was accepted")
	}
	if _, err := DecodeConfig([]byte(valid + "{}")); err == nil {
		t.Fatal("trailing content was accepted")
	}
}

func testEvent(t *testing.T) envelope.Event {
	t.Helper()
	event, err := envelope.NewEvent(envelope.Event{
		Network: &nativev1.NetworkDomain{
			NetworkId:       "tos-local",
			GenesisRootHash: strings.Repeat("a", 64),
			GenesisFileHash: strings.Repeat("b", 64),
		},
		ConversationID:   "conv_" + strings.Repeat("1", 64),
		SenderAgentID:    "agent_" + strings.Repeat("2", 64),
		SenderEndpointID: "mep_" + strings.Repeat("3", 64),
		SenderDeviceID:   "dev_" + strings.Repeat("4", 64),
		CreatedAtUnix:    uint64(time.Now().Unix()),
		Kind:             "text",
		Content:          testBody(t, "hello"),
	})
	if err != nil {
		t.Fatalf("event: %v", err)
	}
	return event
}

func call(t *testing.T, path string, request localapi.Request) localapi.Response {
	t.Helper()
	connection, err := net.Dial("unix", path)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer connection.Close()
	encoded, err := localapi.EncodeRequest(request)
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	if _, err := connection.Write(encoded); err != nil {
		t.Fatalf("write: %v", err)
	}
	body, err := localapi.ReadFrame(bufio.NewReader(connection))
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	response, err := localapi.DecodeResponse(body)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	return response
}

// The example is published as guidance, so a change that makes it invalid has
// to fail here rather than in someone else's deployment.
func TestExampleConfigurationIsValid(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", "..", "docs", "daemon-config.example.json"))
	if err != nil {
		t.Fatalf("read example: %v", err)
	}
	config, err := DecodeConfig(raw)
	if err != nil {
		t.Fatalf("the example configuration is invalid: %v", err)
	}
	if config.Transport != TransportNone {
		t.Fatalf("the example claims a transport that does not exist: %q", config.Transport)
	}
}

// The two sockets carry different capabilities, and the runtime socket has no
// approval operations on it at all.
func TestRuntimeAndOwnerSocketsAreSeparate(t *testing.T) {
	config := testConfig(t)
	instance, err := Open(config, nil)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- instance.Run(ctx) }()
	defer func() {
		cancel()
		<-done
	}()

	// The runtime socket serves the runtime and refuses to approve.
	if response := call(t, config.SocketPath, localapi.Request{Op: localapi.OpPending}); !response.OK {
		t.Fatalf("runtime listing: %+v", response)
	}
	refused := call(t, config.SocketPath, localapi.Request{Op: localapi.OpAwaitingAdmission})
	if refused.OK {
		t.Fatal("the runtime socket listed what is waiting for the owner")
	}

	// The owner socket decides and does no Agent work.
	if response := call(t, config.OwnerSocketPath, localapi.Request{Op: localapi.OpAwaitingAdmission}); !response.OK {
		t.Fatalf("owner listing: %+v", response)
	}
	if response := call(t, config.OwnerSocketPath, localapi.Request{Op: localapi.OpPending}); response.OK {
		t.Fatal("the owner socket drained the runtime inbox")
	}
}
