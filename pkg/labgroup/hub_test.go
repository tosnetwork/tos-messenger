package labgroup

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const (
	alice = "agent_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	bob   = "agent_bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	eve   = "agent_eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"
)

func TestHubCreatesChatsPersistsAndRejectsNonMembers(t *testing.T) {
	path := filepath.Join(t.TempDir(), "hub.json")
	credentials := []Credential{{AgentID: alice, Token: "alice-token-0001"}, {AgentID: bob, Token: "bob-token-0000002"}, {AgentID: eve, Token: "eve-token-00000003"}}
	hub, err := Open(path, credentials)
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(hub.Handler())

	room := call[Room](t, server, alice, "alice-token-0001", http.MethodPost, "/v1/rooms", createRoomRequest{Label: "builders", Members: []string{bob, alice}}, http.StatusCreated)
	if !roomPattern.MatchString(room.RoomID) || room.Members[0] != alice {
		t.Fatalf("unexpected room: %+v", room)
	}

	message := call[Message](t, server, alice, "alice-token-0001", http.MethodPost, "/v1/messages", sendRequest{RoomID: room.RoomID, ClientID: "turn-1", Content: "hello group"}, http.StatusCreated)
	replayed := call[Message](t, server, alice, "alice-token-0001", http.MethodPost, "/v1/messages", sendRequest{RoomID: room.RoomID, ClientID: "turn-1", Content: "hello group"}, http.StatusOK)
	if replayed.MessageID != message.MessageID || replayed.Sequence != message.Sequence {
		t.Fatal("idempotent replay changed the message")
	}

	var listing struct {
		Messages []Message `json:"messages"`
	}
	listing = call[struct {
		Messages []Message `json:"messages"`
	}](t, server, bob, "bob-token-0000002", http.MethodGet, "/v1/messages?room_id="+room.RoomID+"&after=0", nil, http.StatusOK)
	if len(listing.Messages) != 1 || listing.Messages[0].Content != "hello group" {
		t.Fatalf("unexpected messages: %+v", listing.Messages)
	}
	call[map[string]any](t, server, eve, "eve-token-00000003", http.MethodGet, "/v1/messages?room_id="+room.RoomID+"&after=0", nil, http.StatusForbidden)
	server.Close()

	restarted, err := Open(path, credentials)
	if err != nil {
		t.Fatal(err)
	}
	server = httptest.NewServer(restarted.Handler())
	defer server.Close()
	listing = call[struct {
		Messages []Message `json:"messages"`
	}](t, server, bob, "bob-token-0000002", http.MethodGet, "/v1/messages?room_id="+room.RoomID+"&after=0", nil, http.StatusOK)
	if len(listing.Messages) != 1 || listing.Messages[0].MessageID != message.MessageID {
		t.Fatal("restart lost the message")
	}
}

func TestHubRejectsCredentialAndIdempotencyConflicts(t *testing.T) {
	hub, err := Open(filepath.Join(t.TempDir(), "hub.json"), []Credential{{AgentID: alice, Token: "alice-token-0001"}, {AgentID: bob, Token: "bob-token-0000002"}})
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(hub.Handler())
	defer server.Close()
	call[map[string]any](t, server, alice, "wrong-token-0000", http.MethodGet, "/v1/rooms", nil, http.StatusUnauthorized)
	room := call[Room](t, server, alice, "alice-token-0001", http.MethodPost, "/v1/rooms", createRoomRequest{Label: "builders", Members: []string{alice, bob}}, http.StatusCreated)
	call[Message](t, server, alice, "alice-token-0001", http.MethodPost, "/v1/messages", sendRequest{RoomID: room.RoomID, ClientID: "same", Content: "one"}, http.StatusCreated)
	call[map[string]any](t, server, alice, "alice-token-0001", http.MethodPost, "/v1/messages", sendRequest{RoomID: room.RoomID, ClientID: "same", Content: "two"}, http.StatusConflict)
}

func TestHubBindsReplyToAnEarlierMessageInTheSameRoom(t *testing.T) {
	hub, err := Open(filepath.Join(t.TempDir(), "hub.json"), []Credential{
		{AgentID: alice, Token: "alice-token-0001"},
		{AgentID: bob, Token: "bob-token-0000002"},
		{AgentID: eve, Token: "eve-token-00000003"},
	})
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(hub.Handler())
	defer server.Close()
	room := call[Room](t, server, alice, "alice-token-0001", http.MethodPost, "/v1/rooms",
		createRoomRequest{Label: "builders", Members: []string{alice, bob}}, http.StatusCreated)
	otherRoom := call[Room](t, server, alice, "alice-token-0001", http.MethodPost, "/v1/rooms",
		createRoomRequest{Label: "auditors", Members: []string{alice, eve}}, http.StatusCreated)
	parent := call[Message](t, server, alice, "alice-token-0001", http.MethodPost, "/v1/messages",
		sendRequest{RoomID: room.RoomID, ClientID: "parent", Content: "request"}, http.StatusCreated)
	other := call[Message](t, server, eve, "eve-token-00000003", http.MethodPost, "/v1/messages",
		sendRequest{RoomID: otherRoom.RoomID, ClientID: "other", Content: "unrelated"}, http.StatusCreated)
	reply := call[Message](t, server, bob, "bob-token-0000002", http.MethodPost, "/v1/messages",
		sendRequest{RoomID: room.RoomID, ClientID: "reply", ReplyToEventID: parent.MessageID, Content: "accepted"},
		http.StatusCreated)
	if reply.ReplyToEventID != parent.MessageID || reply.MessageID == deriveMessageID(room.RoomID, bob, "reply", "accepted") {
		t.Fatalf("reply was not bound into the durable message: %+v", reply)
	}
	call[map[string]any](t, server, bob, "bob-token-0000002", http.MethodPost, "/v1/messages",
		sendRequest{RoomID: room.RoomID, ClientID: "cross-room", ReplyToEventID: other.MessageID, Content: "invalid"},
		http.StatusBadRequest)
}

func TestHubFailsClosedOnDurableMessageTampering(t *testing.T) {
	path := filepath.Join(t.TempDir(), "hub.json")
	credentials := []Credential{{AgentID: alice, Token: "alice-token-0001"}, {AgentID: bob, Token: "bob-token-0000002"}}
	hub, err := Open(path, credentials)
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(hub.Handler())
	room := call[Room](t, server, alice, "alice-token-0001", http.MethodPost, "/v1/rooms", createRoomRequest{Label: "builders", Members: []string{alice, bob}}, http.StatusCreated)
	call[Message](t, server, alice, "alice-token-0001", http.MethodPost, "/v1/messages", sendRequest{RoomID: room.RoomID, ClientID: "one", Content: "original"}, http.StatusCreated)
	server.Close()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var damaged state
	if err := json.Unmarshal(raw, &damaged); err != nil {
		t.Fatal(err)
	}
	damaged.Messages[0].Content = "changed"
	raw, err = json.Marshal(damaged)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(path, credentials); err == nil {
		t.Fatal("tampered durable message was accepted")
	}
}

func call[T any](t *testing.T, server *httptest.Server, agentID, token, method, path string, body any, status int) T {
	t.Helper()
	var raw []byte
	if body != nil {
		var err error
		raw, err = json.Marshal(body)
		if err != nil {
			t.Fatal(err)
		}
	}
	request, err := http.NewRequest(method, server.URL+path, bytes.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("X-Tos-Agent-Id", agentID)
	request.Header.Set("Authorization", "Bearer "+token)
	response, err := http.DefaultClient.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	if response.StatusCode != status {
		t.Fatalf("got status %d, want %d", response.StatusCode, status)
	}
	var result T
	if !strings.Contains(response.Header.Get("Content-Type"), "application/json") {
		t.Fatal("missing JSON response")
	}
	if err := json.NewDecoder(response.Body).Decode(&result); err != nil {
		t.Fatal(err)
	}
	return result
}
