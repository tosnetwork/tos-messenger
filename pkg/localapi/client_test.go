package localapi

import (
	"context"
	"net"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestClientCallsOneBoundedLocalOperation(t *testing.T) {
	path := filepath.Join(t.TempDir(), "owner.sock")
	listener, err := net.Listen("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	done := make(chan error, 1)
	go func() {
		connection, acceptErr := listener.Accept()
		if acceptErr != nil {
			done <- acceptErr
			return
		}
		defer connection.Close()
		raw, readErr := ReadFrame(connection)
		if readErr != nil {
			done <- readErr
			return
		}
		request, decodeErr := DecodeRequest(raw)
		if decodeErr != nil {
			done <- decodeErr
			return
		}
		if request.Op != OpPendingActions || request.Limit != 7 {
			done <- context.Canceled
			return
		}
		encoded, encodeErr := EncodeResponse(Response{OK: true, Actions: []WaitingAction{{ActionID: "act_" + strings.Repeat("a", 64)}}})
		if encodeErr == nil {
			_, encodeErr = connection.Write(encoded)
		}
		done <- encodeErr
	}()
	client, err := NewClient(path, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	response, err := client.Call(context.Background(), Request{Op: OpPendingActions, Limit: 7})
	if err != nil || len(response.Actions) != 1 {
		t.Fatalf("call: response=%+v err=%v", response, err)
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

func TestClientRejectsUnsafeConfigurationAndRefusals(t *testing.T) {
	if _, err := NewClient("relative.sock", time.Second); err == nil {
		t.Fatal("relative socket accepted")
	}
	if _, err := NewClient("/tmp/owner.sock", time.Millisecond); err == nil {
		t.Fatal("unbounded timeout accepted")
	}
	path := filepath.Join(t.TempDir(), "owner.sock")
	listener, err := net.Listen("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	go func() {
		connection, acceptErr := listener.Accept()
		if acceptErr != nil {
			return
		}
		defer connection.Close()
		_, _ = ReadFrame(connection)
		encoded, _ := EncodeResponse(Response{OK: false, Code: "internal", Detail: "no"})
		_, _ = connection.Write(encoded)
	}()
	client, _ := NewClient(path, time.Second)
	if _, err := client.Call(context.Background(), Request{Op: OpPendingActions}); err == nil || !strings.Contains(err.Error(), "refused") {
		t.Fatalf("refusal not surfaced: %v", err)
	}
}
