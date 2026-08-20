package probe

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"
)

// The driver is tested against a fake sidecar: this very test binary,
// re-executed with a mode that makes it speak the protocol from the other
// side of the pipe. That keeps the fakes in one language and one file, with
// no interpreter dependency, and exercises the real subprocess plumbing --
// pipes, exit codes, kill paths -- rather than an in-process stand-in.
const fakeSidecarModeEnv = "PROBE_FAKE_SIDECAR_MODE"

// TestSidecarFakeProcess is not a test: it is the fake sidecar's entry point,
// selected by the environment variable and skipped in every normal run. It
// must write nothing to stdout except protocol lines, so it exits the process
// before the test framework can print its verdict.
func TestSidecarFakeProcess(t *testing.T) {
	mode := os.Getenv(fakeSidecarModeEnv)
	if mode == "" {
		t.Skip("not running as a fake sidecar")
	}
	runFakeSidecar(mode)
	os.Exit(0)
}

func emitLine(fields map[string]any) {
	encoded, err := json.Marshal(fields)
	if err != nil {
		os.Exit(3)
	}
	fmt.Println(string(encoded))
}

func fakeHello() map[string]any {
	return map[string]any{
		"event": "hello", "protocol": SidecarProtocol,
		"implementation": "fake-native-adnl", "implementation_commit": strings.Repeat("f", 40),
		"toolchain": "fake-cc-1.0", "target": "test/fake",
	}
}

// runFakeSidecar speaks one scripted behavior per mode.
func runFakeSidecar(mode string) {
	switch mode {
	case "wrong-protocol":
		hello := fakeHello()
		hello["protocol"] = "tos-adnl-probe/999"
		emitLine(hello)
		os.Exit(0)
	case "bare-hello":
		hello := fakeHello()
		delete(hello, "implementation_commit")
		emitLine(hello)
		os.Exit(0)
	case "no-hello":
		os.Exit(0)
	}

	emitLine(fakeHello())
	scanner := bufio.NewScanner(os.Stdin)
	for scanner.Scan() {
		var command map[string]any
		if err := json.Unmarshal(scanner.Bytes(), &command); err != nil {
			os.Exit(3)
		}
		id := command["id"]
		name, _ := command["cmd"].(string)
		switch mode {
		case "happy":
			switch name {
			case "identity":
				emitLine(map[string]any{"id": id, "event": "identity",
					"adnl_pubkey_hex": strings.Repeat("ab", 32), "adnl_id_hex": strings.Repeat("cd", 32)})
			case "listen":
				emitLine(map[string]any{"id": id, "event": "listening", "addr": "0.0.0.0:7777",
					"adnl_pubkey_hex": strings.Repeat("ab", 32), "adnl_id_hex": strings.Repeat("cd", 32)})
			case "punch":
				emitLine(map[string]any{"id": id, "event": "punched"})
			case "dial":
				emitLine(map[string]any{"id": id, "event": "established", "millis": 42, "peer_addr": "127.0.0.1:9999"})
			case "await":
				emitLine(map[string]any{"id": id, "event": "failed", "class": "handshake-timeout"})
			case "hold":
				emitLine(map[string]any{"id": id, "event": "held", "survival_seconds": 3, "completed": true})
			case "reconnect":
				emitLine(map[string]any{"id": id, "event": "reconnected", "millis": 17, "succeeded": true})
			case "echo":
				emitLine(map[string]any{"id": id, "event": "echoed", "ok": true,
					"sha256_hex": strings.Repeat("ee", 32), "millis": 5})
			case "close":
				emitLine(map[string]any{"id": id, "event": "closed"})
				os.Exit(0)
			default:
				emitLine(map[string]any{"id": id, "event": "error", "message": "unknown cmd"})
			}
		case "error-event":
			emitLine(map[string]any{"id": id, "event": "error", "message": "scripted refusal"})
		case "die-mid-command":
			os.Exit(1)
		case "silent":
			// Answer nothing, ever: the driver's wait must expire.
		case "wrong-id":
			emitLine(map[string]any{"id": 424242, "event": "identity",
				"adnl_pubkey_hex": strings.Repeat("ab", 32)})
		case "wrong-event":
			emitLine(map[string]any{"id": id, "event": "punched"})
		case "malformed":
			fmt.Println("this is not a protocol object")
		default:
			os.Exit(3)
		}
	}
	os.Exit(0)
}

// startFake launches this test binary as a fake sidecar in the given mode.
func startFake(t *testing.T, mode string) (*Sidecar, error) {
	t.Helper()
	t.Setenv(fakeSidecarModeEnv, mode)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	t.Cleanup(cancel)
	sidecar, err := StartSidecar(ctx, os.Args[0], "-test.run=TestSidecarFakeProcess$")
	if sidecar != nil {
		t.Cleanup(sidecar.Stop)
	}
	return sidecar, err
}

// The full command set against a well-behaved fake: every wrapper decodes the
// completion event it defines, and the union completion carries both of its
// arms.
func TestSidecarDriverHappyPath(t *testing.T) {
	sidecar, err := startFake(t, "happy")
	if err != nil {
		t.Fatalf("start: %v", err)
	}
	info := sidecar.Info()
	if info.Implementation != "fake-native-adnl" || info.ImplementationCommit != strings.Repeat("f", 40) ||
		info.Toolchain != "fake-cc-1.0" || info.Target != "test/fake" {
		t.Fatalf("hello was not captured: %+v", info)
	}
	key, err := sidecar.Identity()
	if err != nil || key != strings.Repeat("ab", 32) {
		t.Fatalf("identity: key=%q err=%v", key, err)
	}
	addr, boundKey, err := sidecar.Listen("0.0.0.0:7777")
	if err != nil || addr != "0.0.0.0:7777" || boundKey != key {
		t.Fatalf("listen: addr=%q key=%q err=%v", addr, boundKey, err)
	}
	if err := sidecar.Punch([]string{"127.0.0.1:1"}, 3, 100); err != nil {
		t.Fatalf("punch: %v", err)
	}
	session, err := sidecar.Dial(key, []string{"127.0.0.1:1"}, time.Second)
	if err != nil || !session.Established || session.Millis != 42 || session.PeerAddr != "127.0.0.1:9999" {
		t.Fatalf("dial: %+v err=%v", session, err)
	}
	refused, err := sidecar.Await(key, time.Second)
	if err != nil || refused.Established || refused.FailureClass != "handshake-timeout" {
		t.Fatalf("await: %+v err=%v", refused, err)
	}
	survival, completed, err := sidecar.Hold(3*time.Second, time.Second)
	if err != nil || survival != 3 || !completed {
		t.Fatalf("hold: survival=%d completed=%t err=%v", survival, completed, err)
	}
	millis, succeeded, err := sidecar.Reconnect(time.Second)
	if err != nil || millis != 17 || !succeeded {
		t.Fatalf("reconnect: millis=%d succeeded=%t err=%v", millis, succeeded, err)
	}
	echoed, err := sidecar.Echo(1024, time.Second)
	if err != nil || !echoed.OK || echoed.Millis != 5 || echoed.Bytes != 1024 {
		t.Fatalf("echo: %+v err=%v", echoed, err)
	}
	sidecar.Close()
}

// A hello that names another protocol revision, describes no build, or never
// arrives refuses the whole driver: guessing at unknown semantics would
// attribute the sidecar's behavior to the network.
func TestSidecarDriverRefusesBadHello(t *testing.T) {
	sidecarWaitForTest = 500 * time.Millisecond
	defer func() { sidecarWaitForTest = 0 }()

	if _, err := startFake(t, "wrong-protocol"); err == nil {
		t.Fatal("a foreign protocol revision was accepted")
	}
	if _, err := startFake(t, "bare-hello"); err == nil {
		t.Fatal("a hello without the build description was accepted")
	}
	if _, err := startFake(t, "no-hello"); err == nil {
		t.Fatal("a sidecar that never said hello was accepted")
	}
}

// Every deviation from one-completion-per-command fails the command closed:
// error events, an answer under another id, a wrong event name, a line that
// is not a protocol object, silence, and the process dying mid-command.
func TestSidecarDriverFailsClosed(t *testing.T) {
	sidecarWaitForTest = time.Second
	defer func() { sidecarWaitForTest = 0 }()

	cases := []struct {
		mode string
		want string
	}{
		{"error-event", "scripted refusal"},
		{"wrong-id", "unexpected id"},
		{"wrong-event", `event "punched"`},
		{"malformed", "malformed protocol line"},
		{"silent", "answered nothing"},
		{"die-mid-command", ""},
	}
	for _, test := range cases {
		sidecar, err := startFake(t, test.mode)
		if err != nil {
			t.Fatalf("%s: start: %v", test.mode, err)
		}
		_, err = sidecar.Identity()
		if err == nil {
			t.Fatalf("%s: the command claimed to complete", test.mode)
		}
		if test.want != "" && !strings.Contains(err.Error(), test.want) {
			t.Fatalf("%s: error %q does not name its cause %q", test.mode, err, test.want)
		}
		// After a violation the stream is dead or poisoned: later commands
		// must also fail rather than pair with a stale event.
		if _, err := sidecar.Identity(); err == nil && test.mode != "silent" {
			t.Fatalf("%s: a command after a violation claimed to complete", test.mode)
		}
		sidecar.Stop()
	}
}

// A cancelled context kills the subprocess: nothing may outlive the run that
// started it.
func TestSidecarDriverContextKillsProcess(t *testing.T) {
	t.Setenv(fakeSidecarModeEnv, "silent")
	ctx, cancel := context.WithCancel(context.Background())
	sidecar, err := StartSidecar(ctx, os.Args[0], "-test.run=TestSidecarFakeProcess$")
	if err != nil {
		t.Fatalf("start: %v", err)
	}
	cancel()
	done := make(chan struct{})
	go func() {
		_, _ = sidecar.awaitEvent(5 * time.Second)
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("the protocol stream survived the context")
	}
	sidecar.Stop()
}
