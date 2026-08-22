package protocolbridge

import (
	"bytes"
	"context"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/tosnetwork/tos-messenger/pkg/envelope"
	"github.com/tosnetwork/tos-messenger/pkg/payload"
	nativev1 "github.com/tosnetwork/tos-service-protocol/gen/tos/service/v1"
)

func TestUnixReceiverDeliversCanonicalEventToFixedProfilePath(t *testing.T) {
	event := protocolEvent(t, "a2a.message", "a2a")
	wire, err := envelope.EncodeEventJSON(event)
	if err != nil {
		t.Fatal(err)
	}
	socket := filepath.Join(t.TempDir(), "a2a.sock")
	listener, err := net.Listen("unix", socket)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(socket, 0o600); err != nil {
		t.Fatal(err)
	}
	server := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		body, readErr := io.ReadAll(request.Body)
		if readErr != nil || request.Method != http.MethodPost || request.URL.Path != a2aReceiverPath ||
			request.Header.Get("Content-Type") != eventContentType || !bytes.Equal(body, wire) {
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
	receiver, err := NewUnixReceiver(socket, ProfileA2A, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if err := receiver.Receive(context.Background(), event); err != nil {
		t.Fatal(err)
	}
	if err := receiver.Receive(context.Background(), protocolEvent(t, "mcp.call", "mcp")); err == nil {
		t.Fatal("A2A receiver accepted an MCP event")
	}
}

func TestUnixReceiverRejectsInvalidConfigurationAndConsumerFailure(t *testing.T) {
	for _, configured := range []struct {
		path    string
		profile Profile
		timeout time.Duration
	}{
		{"relative.sock", ProfileA2A, time.Second},
		{"/tmp/../tmp/a2a.sock", ProfileA2A, time.Second},
		{"/tmp/a2a.sock", "unknown", time.Second},
		{"/tmp/a2a.sock", ProfileA2A, time.Millisecond},
		{"/tmp/a2a.sock", ProfileA2A, 6 * time.Minute},
	} {
		if _, err := NewUnixReceiver(configured.path, configured.profile, configured.timeout); err == nil {
			t.Fatalf("invalid receiver configuration accepted: %+v", configured)
		}
	}
	socket := filepath.Join(t.TempDir(), "mcp.sock")
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
	receiver, err := NewUnixReceiver(socket, ProfileMCP, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if err := receiver.Receive(context.Background(), protocolEvent(t, "mcp.result", "mcp")); err == nil {
		t.Fatal("consumer rejection was hidden")
	}
}

func protocolEvent(t *testing.T, kind, protocol string) envelope.Event {
	t.Helper()
	foreign := payload.Foreign{Protocol: protocol, Version: "1", Body: []byte(`{"ok":true}`)}
	var value payload.Payload
	switch kind {
	case "a2a.message":
		value = payload.A2AMessage{Foreign: foreign}
	case "mcp.call":
		value = payload.MCPCall{Foreign: foreign}
	case "mcp.result":
		value = payload.MCPResult{Foreign: foreign}
	default:
		t.Fatalf("unsupported test kind %q", kind)
	}
	body, err := payload.Encode(value)
	if err != nil {
		t.Fatal(err)
	}
	event, err := envelope.NewEvent(envelope.Event{
		Network: &nativev1.NetworkDomain{NetworkId: "tos-local", GenesisRootHash: strings.Repeat("a", 64),
			GenesisFileHash: strings.Repeat("b", 64)},
		ConversationID: "conv_" + strings.Repeat("1", 64), SenderAgentID: "agent_" + strings.Repeat("2", 64),
		SenderEndpointID: "mep_" + strings.Repeat("3", 64), SenderDeviceID: "dev_" + strings.Repeat("4", 64),
		CreatedAtUnix: 1_800_000_000, Kind: kind, Content: body,
	})
	if err != nil {
		t.Fatal(err)
	}
	return event
}
