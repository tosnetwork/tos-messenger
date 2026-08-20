package probe

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"sync"
	"sync/atomic"
	"time"
)

// SidecarProtocol is the one protocol revision this driver speaks. A sidecar
// announcing anything else is refused outright: guessing at an unknown
// revision's semantics would attribute its behavior to the network.
const SidecarProtocol = "tos-adnl-probe/1"

const (
	// sidecarHelloTimeout bounds the wait for the hello event a healthy
	// sidecar emits immediately on start.
	sidecarHelloTimeout = 10 * time.Second
	// sidecarControlTimeout bounds the commands that carry no window of their
	// own: identity, punch, close. None of them waits on the network beyond a
	// bounded burst.
	sidecarControlTimeout = 10 * time.Second
	// sidecarListenTimeout bounds the listen command, which retries a
	// just-released port internally (20 x 50ms) before reporting.
	sidecarListenTimeout = 15 * time.Second
	// sidecarCompletionGrace pads every windowed command's wait past its own
	// timeout, covering the sidecar's report of the timeout itself.
	sidecarCompletionGrace = 5 * time.Second
)

// SidecarInfo is what the sidecar's hello declared about its build. The
// collector manifest is constructed from it, so every field the manifest
// needs is validated non-empty at start.
type SidecarInfo struct {
	Protocol             string
	Implementation       string
	ImplementationCommit string
	Toolchain            string
	Target               string
}

// SidecarSession is a dial or await completion: either an established session
// with its latency and the address that carried it, or a classified failure.
type SidecarSession struct {
	Established  bool
	Millis       uint64
	PeerAddr     string
	FailureClass string
}

// sidecarEvent is one line the read loop produced: a decoded protocol object,
// or the error that ended the stream.
type sidecarEvent struct {
	fields map[string]any
	err    error
}

// Sidecar drives one tos-adnl-probe process over its line-delimited JSON
// protocol. Commands are sequential -- the probe flow is sequential by nature
// -- and every wait is hard-bounded, because a sidecar that stops answering
// must become a classified tooling failure rather than a hang.
type Sidecar struct {
	info    SidecarInfo
	process *exec.Cmd
	stdin   io.WriteCloser
	events  chan sidecarEvent
	nextID  atomic.Int64
	stop    sync.Once
	waited  chan struct{}
}

// StartSidecar launches the binary, validates its hello, and returns a ready
// driver. The process is bound to the context -- cancellation kills it -- and
// its stderr passes through to this process's stderr, because the sidecar's
// diagnostics belong to the operator, not to the protocol stream.
func StartSidecar(ctx context.Context, path string, args ...string) (*Sidecar, error) {
	if path == "" {
		return nil, errors.New("a sidecar binary path is required")
	}
	process := exec.CommandContext(ctx, path, args...)
	process.Stderr = os.Stderr
	stdin, err := process.StdinPipe()
	if err != nil {
		return nil, errors.New("open sidecar stdin")
	}
	stdout, err := process.StdoutPipe()
	if err != nil {
		return nil, errors.New("open sidecar stdout")
	}
	if err := process.Start(); err != nil {
		return nil, fmt.Errorf("start sidecar: %w", err)
	}

	sidecar := &Sidecar{
		process: process,
		stdin:   stdin,
		events:  make(chan sidecarEvent, 8),
		waited:  make(chan struct{}),
	}
	go sidecar.readLoop(stdout)

	hello, err := sidecar.awaitEvent(sidecarHelloTimeout)
	if err != nil {
		sidecar.Stop()
		return nil, fmt.Errorf("sidecar sent no hello: %w", err)
	}
	if event, _ := hello["event"].(string); event != "hello" {
		sidecar.Stop()
		return nil, errors.New("sidecar's first event was not a hello")
	}
	info := SidecarInfo{
		Protocol:             stringField(hello, "protocol"),
		Implementation:       stringField(hello, "implementation"),
		ImplementationCommit: stringField(hello, "implementation_commit"),
		Toolchain:            stringField(hello, "toolchain"),
		Target:               stringField(hello, "target"),
	}
	if info.Protocol != SidecarProtocol {
		sidecar.Stop()
		return nil, fmt.Errorf("sidecar speaks %q, this driver speaks %q", info.Protocol, SidecarProtocol)
	}
	// The hello is the manifest's source of truth for what spoke ADNL on the
	// wire; a build that cannot say what it is must not measure.
	if info.Implementation == "" || info.ImplementationCommit == "" ||
		info.Toolchain == "" || info.Target == "" {
		sidecar.Stop()
		return nil, errors.New("sidecar hello does not fully describe its build")
	}
	sidecar.info = info
	return sidecar, nil
}

// Info reports what the hello declared.
func (s *Sidecar) Info() SidecarInfo {
	return s.info
}

// readLoop turns stdout lines into events, fails closed on anything that is
// not one protocol object per line, and ends the stream with the error that
// stopped it -- including the process simply dying, which the flow must see
// as a failed command rather than a silence.
func (s *Sidecar) readLoop(stdout io.Reader) {
	scanner := bufio.NewScanner(stdout)
	scanner.Buffer(make([]byte, 64*1024), 1024*1024)
	for scanner.Scan() {
		var fields map[string]any
		if err := json.Unmarshal(scanner.Bytes(), &fields); err != nil {
			s.events <- sidecarEvent{err: errors.New("sidecar emitted a malformed protocol line")}
			close(s.events)
			return
		}
		s.events <- sidecarEvent{fields: fields}
	}
	err := scanner.Err()
	if err == nil {
		err = errors.New("sidecar closed its protocol stream")
	}
	s.events <- sidecarEvent{err: err}
	close(s.events)
}

// sidecarWaitForTest lets a test shrink every driver wait, so the
// timeout-and-fail-closed paths can be asserted without sitting through
// production-sized windows. It is written only by tests, before their drivers
// start, and the production path reads only its zero.
var sidecarWaitForTest time.Duration

// awaitEvent returns the next protocol object within the window.
func (s *Sidecar) awaitEvent(window time.Duration) (map[string]any, error) {
	if sidecarWaitForTest > 0 && window > sidecarWaitForTest {
		window = sidecarWaitForTest
	}
	timer := time.NewTimer(window)
	defer timer.Stop()
	select {
	case event, open := <-s.events:
		if !open {
			return nil, errors.New("sidecar protocol stream already ended")
		}
		if event.err != nil {
			return nil, event.err
		}
		return event.fields, nil
	case <-timer.C:
		return nil, errors.New("sidecar answered nothing inside the wait window")
	}
}

// command sends one command and returns its completion event. Every command
// is answered by exactly one completion carrying the same id; anything else
// -- a different id, a missing id, an error event -- fails closed, and an
// error event's message is surfaced verbatim.
func (s *Sidecar) command(window time.Duration, cmd string, fields map[string]any) (map[string]any, error) {
	id := s.nextID.Add(1)
	payload := map[string]any{"id": id, "cmd": cmd}
	for key, value := range fields {
		payload[key] = value
	}
	line, err := json.Marshal(payload)
	if err != nil {
		return nil, errors.New("encode sidecar command")
	}
	if _, err := s.stdin.Write(append(line, '\n')); err != nil {
		return nil, fmt.Errorf("sidecar stdin: %w", err)
	}
	completion, err := s.awaitEvent(window)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", cmd, err)
	}
	gotID, ok := completion["id"].(float64)
	if !ok || int64(gotID) != id {
		return nil, fmt.Errorf("%s: sidecar answered with an unexpected id", cmd)
	}
	if event, _ := completion["event"].(string); event == "error" {
		return nil, fmt.Errorf("%s: sidecar error: %s", cmd, stringField(completion, "message"))
	}
	return completion, nil
}

// expectEvent narrows a completion to the one event name the command defines,
// with dial and await's two-way completion handled by their own wrapper.
func expectEvent(completion map[string]any, cmd, want string) error {
	if event, _ := completion["event"].(string); event != want {
		return fmt.Errorf("%s: sidecar answered with event %q, want %q", cmd, event, want)
	}
	return nil
}

// Identity returns the transport public key the sidecar will listen under,
// without binding anything: the rendezvous needs the key before the port
// handoff.
func (s *Sidecar) Identity() (string, error) {
	completion, err := s.command(sidecarControlTimeout, "identity", nil)
	if err != nil {
		return "", err
	}
	if err := expectEvent(completion, "identity", "identity"); err != nil {
		return "", err
	}
	key := stringField(completion, "adnl_pubkey_hex")
	if key == "" {
		return "", errors.New("identity: sidecar reported no transport key")
	}
	return key, nil
}

// Listen binds the ADNL stack. The sidecar retries a just-released port
// internally, which is what the rendezvous handoff relies on.
func (s *Sidecar) Listen(bind string) (addr string, pubkeyHex string, err error) {
	completion, err := s.command(sidecarListenTimeout, "listen", map[string]any{"bind": bind})
	if err != nil {
		return "", "", err
	}
	if err := expectEvent(completion, "listen", "listening"); err != nil {
		return "", "", err
	}
	return stringField(completion, "addr"), stringField(completion, "adnl_pubkey_hex"), nil
}

// Punch opens NAT mappings toward the targets with raw datagrams from the
// ADNL socket.
func (s *Sidecar) Punch(targets []string, rounds, intervalMillis int) error {
	completion, err := s.command(sidecarControlTimeout, "punch", map[string]any{
		"targets": targets, "rounds": rounds, "interval_ms": intervalMillis,
	})
	if err != nil {
		return err
	}
	return expectEvent(completion, "punch", "punched")
}

// Dial establishes toward the peer's candidates and confirms with a query
// round trip, inside the window.
func (s *Sidecar) Dial(peerPubkeyHex string, candidates []string, window time.Duration) (SidecarSession, error) {
	completion, err := s.command(window+sidecarCompletionGrace, "dial", map[string]any{
		"peer_pubkey_hex": peerPubkeyHex, "candidates": candidates,
		"timeout_ms": window.Milliseconds(),
	})
	if err != nil {
		return SidecarSession{}, err
	}
	return sessionCompletion(completion, "dial")
}

// Await accepts the inbound session from the named peer and confirms it with
// the sidecar's own query round trip. It never dials.
func (s *Sidecar) Await(peerPubkeyHex string, window time.Duration) (SidecarSession, error) {
	completion, err := s.command(window+sidecarCompletionGrace, "await", map[string]any{
		"peer_pubkey_hex": peerPubkeyHex, "timeout_ms": window.Milliseconds(),
	})
	if err != nil {
		return SidecarSession{}, err
	}
	return sessionCompletion(completion, "await")
}

// sessionCompletion decodes the established/failed union dial and await
// share.
func sessionCompletion(completion map[string]any, cmd string) (SidecarSession, error) {
	switch event, _ := completion["event"].(string); event {
	case "established":
		return SidecarSession{
			Established: true,
			Millis:      numberField(completion, "millis"),
			PeerAddr:    stringField(completion, "peer_addr"),
		}, nil
	case "failed":
		class := stringField(completion, "class")
		if class == "" {
			return SidecarSession{}, fmt.Errorf("%s: sidecar failed without a class", cmd)
		}
		return SidecarSession{FailureClass: class}, nil
	default:
		return SidecarSession{}, fmt.Errorf("%s: sidecar answered with event %q", cmd, event)
	}
}

// Hold keeps the confirmed session alive with keepalive round trips until the
// window elapses or the session is judged dead.
func (s *Sidecar) Hold(window, keepalive time.Duration) (survivalSeconds uint64, completed bool, err error) {
	completion, err := s.command(window+sidecarCompletionGrace, "hold", map[string]any{
		"window_ms": window.Milliseconds(), "keepalive_ms": keepalive.Milliseconds(),
	})
	if err != nil {
		return 0, false, err
	}
	if err := expectEvent(completion, "hold", "held"); err != nil {
		return 0, false, err
	}
	return numberField(completion, "survival_seconds"), boolField(completion, "completed"), nil
}

// Reconnect deliberately drops the negotiated channel and times the
// re-establishment.
func (s *Sidecar) Reconnect(window time.Duration) (millis uint64, succeeded bool, err error) {
	completion, err := s.command(window+sidecarCompletionGrace, "reconnect", map[string]any{
		"timeout_ms": window.Milliseconds(),
	})
	if err != nil {
		return 0, false, err
	}
	if err := expectEvent(completion, "reconnect", "reconnected"); err != nil {
		return 0, false, err
	}
	return numberField(completion, "millis"), boolField(completion, "succeeded"), nil
}

// Echo runs one sized echo round trip over the confirmed session.
func (s *Sidecar) Echo(size int, window time.Duration) (EchoResult, error) {
	completion, err := s.command(window+sidecarCompletionGrace, "echo", map[string]any{
		"bytes": size, "timeout_ms": window.Milliseconds(),
	})
	if err != nil {
		return EchoResult{}, err
	}
	if err := expectEvent(completion, "echo", "echoed"); err != nil {
		return EchoResult{}, err
	}
	result := EchoResult{Bytes: size, OK: boolField(completion, "ok")}
	if result.OK {
		result.Millis = numberField(completion, "millis")
		if result.Millis == 0 {
			result.Millis = 1
		}
	}
	return result, nil
}

// Close asks for a clean shutdown, then guarantees the process is gone either
// way.
func (s *Sidecar) Close() {
	_, _ = s.command(sidecarControlTimeout, "close", nil)
	s.Stop()
}

// Stop force-terminates the process. It is idempotent and safe on every
// path, including after a clean Close.
func (s *Sidecar) Stop() {
	s.stop.Do(func() {
		_ = s.stdin.Close()
		if s.process.Process != nil {
			_ = s.process.Process.Kill()
		}
		go func() {
			_ = s.process.Wait()
			close(s.waited)
		}()
	})
	s.awaitExit(sidecarControlTimeout)
}

// awaitExit waits for the process to be reaped, bounded so a wedged process
// cannot wedge the probe.
func (s *Sidecar) awaitExit(window time.Duration) {
	timer := time.NewTimer(window)
	defer timer.Stop()
	select {
	case <-s.waited:
	case <-timer.C:
	}
}

// SidecarHello launches the binary just long enough to read its hello, for
// building the collector manifest before anything measures.
func SidecarHello(ctx context.Context, path string, args ...string) (SidecarInfo, error) {
	sidecar, err := StartSidecar(ctx, path, args...)
	if err != nil {
		return SidecarInfo{}, err
	}
	info := sidecar.Info()
	sidecar.Close()
	return info, nil
}

func stringField(fields map[string]any, key string) string {
	value, _ := fields[key].(string)
	return value
}

func boolField(fields map[string]any, key string) bool {
	value, _ := fields[key].(bool)
	return value
}

// numberField reads a JSON number as an unsigned count, treating anything
// unusable as zero -- which every caller reads as "not measured", never as a
// measurement.
func numberField(fields map[string]any, key string) uint64 {
	value, ok := fields[key].(float64)
	if !ok || value < 0 {
		return 0
	}
	return uint64(value)
}
