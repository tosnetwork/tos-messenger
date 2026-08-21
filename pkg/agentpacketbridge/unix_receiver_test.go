package agentpacketbridge

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/tosnetwork/tos-service-protocol/pkg/agentpacket"
)

func TestUnixReceiverDeliversCanonicalPacketToPrivateSocket(t *testing.T) {
	packet := bridgePacket(t, ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize)),
		"agent_"+repeatHex("1", 64), "agent_"+repeatHex("2", 64), 3, 1_800_000_000, "typed work")
	wire, err := agentpacket.EncodeJSON(packet)
	if err != nil {
		t.Fatal(err)
	}
	socket := filepath.Join(t.TempDir(), "provider.sock")
	listener, err := net.Listen("unix", socket)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(socket, 0o600); err != nil {
		t.Fatal(err)
	}
	server := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		body, readErr := io.ReadAll(request.Body)
		if readErr != nil || request.Method != http.MethodPost || request.URL.Path != unixReceiverPath ||
			request.Header.Get("Content-Type") != "application/json" || !bytes.Equal(body, wire) {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		w.WriteHeader(http.StatusAccepted)
	})}
	done := make(chan error, 1)
	go func() { done <- server.Serve(listener) }()
	defer func() {
		_ = server.Shutdown(context.Background())
		<-done
	}()
	receiver, err := NewUnixReceiver(socket, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if err := receiver.Receive(context.Background(), packet); err != nil {
		t.Fatal(err)
	}
}

func TestUnixReceiverRejectsProviderFailureAndInvalidConfig(t *testing.T) {
	for _, configured := range []struct {
		path    string
		timeout time.Duration
	}{
		{path: "relative.sock", timeout: time.Second},
		{path: "/tmp/../tmp/provider.sock", timeout: time.Second},
		{path: "/tmp/provider.sock", timeout: time.Millisecond},
		{path: "/tmp/provider.sock", timeout: 6 * time.Minute},
	} {
		if _, err := NewUnixReceiver(configured.path, configured.timeout); err == nil {
			t.Fatalf("invalid Unix receiver config accepted: %+v", configured)
		}
	}
	socket := filepath.Join(t.TempDir(), "provider.sock")
	listener, err := net.Listen("unix", socket)
	if err != nil {
		t.Fatal(err)
	}
	server := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusUnprocessableEntity)
	})}
	done := make(chan error, 1)
	go func() { done <- server.Serve(listener) }()
	defer func() {
		_ = server.Shutdown(context.Background())
		<-done
	}()
	receiver, err := NewUnixReceiver(socket, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	packet := bridgePacket(t, ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize)),
		"agent_"+repeatHex("1", 64), "agent_"+repeatHex("2", 64), 4, 1_800_000_000, "rejected")
	if err := receiver.Receive(context.Background(), packet); err == nil {
		t.Fatal("provider rejection was hidden")
	}
}

func repeatHex(value string, count int) string {
	result := ""
	for range count {
		result += value
	}
	return result
}
