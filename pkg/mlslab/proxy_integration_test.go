package mlslab

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/tosnetwork/tos-messenger/pkg/group"
	"github.com/tosnetwork/tos-messenger/pkg/labgroup"
)

func TestOpenMLSProxiesEncryptOpaqueRelayAndRestart(t *testing.T) {
	binary := os.Getenv("TOS_OPENMLS_DRIVER")
	if binary == "" {
		t.Skip("TOS_OPENMLS_DRIVER is set by make test-openmls")
	}
	driver := &group.OpenMLSSidecar{Command: []string{binary}, Timeout: 10 * time.Second}
	members := []string{
		"agent_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		"agent_bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
		"agent_cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
	}
	tokens := []string{"alice-secret-token", "bob-secret-token-01", "carol-secret-token"}
	stateDir := filepath.Join(t.TempDir(), "agents")
	room, err := Bootstrap(stateDir, "encrypted-builders", members, driver)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Bootstrap(stateDir, "encrypted-builders", members, driver); err == nil {
		t.Fatal("bootstrap replaced private state")
	}
	relayPath := filepath.Join(t.TempDir(), "relay.json")
	credentials := make([]labgroup.Credential, len(members))
	for i := range members {
		credentials[i] = labgroup.Credential{AgentID: members[i], Token: tokens[i]}
	}
	hub, err := labgroup.Open(relayPath, credentials)
	if err != nil {
		t.Fatal(err)
	}
	relay := httptest.NewServer(hub.Handler())
	defer relay.Close()

	proxies := openTestProxies(t, stateDir, members, tokens, driver, relay)
	created := callProxy[labgroup.Room](t, proxies[0], members[0], tokens[0], http.MethodPost, "/v1/rooms", map[string]any{"label": room.Label, "members": room.Members})
	if created.RoomID != room.RoomID {
		t.Fatalf("room = %q", created.RoomID)
	}
	for i := 1; i < len(proxies); i++ {
		listed := callProxy[struct {
			Rooms []labgroup.Room `json:"rooms"`
		}](t, proxies[i], members[i], tokens[i], http.MethodGet, "/v1/rooms", nil)
		if len(listed.Rooms) != 1 || listed.Rooms[0].RoomID != room.RoomID {
			t.Fatalf("agent %d rooms = %+v", i, listed.Rooms)
		}
	}

	opening := "plaintext must never reach the relay"
	sent := callProxy[Message](t, proxies[0], members[0], tokens[0], http.MethodPost, "/v1/messages", map[string]string{"room_id": room.RoomID, "client_id": "opening-1", "content": opening})
	if sent.Content != opening {
		t.Fatalf("send response = %q", sent.Content)
	}
	aliceAfterSend, err := os.ReadFile(StatePath(stateDir, members[0]))
	if err != nil {
		t.Fatal(err)
	}
	retried := callProxy[Message](t, proxies[0], members[0], tokens[0], http.MethodPost, "/v1/messages", map[string]string{"room_id": room.RoomID, "client_id": "opening-1", "content": opening})
	if retried.MessageID != sent.MessageID {
		t.Fatal("exact retry created another Relay message")
	}
	aliceAfterRetry, err := os.ReadFile(StatePath(stateDir, members[0]))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(aliceAfterSend, aliceAfterRetry) {
		t.Fatal("exact retry advanced the MLS sender ratchet")
	}
	relayRaw, err := os.ReadFile(relayPath)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(relayRaw, []byte(opening)) || bytes.Contains(relayRaw, []byte("opaque_state")) {
		t.Fatal("opaque Relay persisted plaintext or private MLS state")
	}
	carolPath := StatePath(stateDir, members[2])
	beforeTamper, err := os.ReadFile(carolPath)
	if err != nil {
		t.Fatal(err)
	}
	tamperedClient := &http.Client{Transport: tamperMessages{base: relay.Client().Transport}}
	tamperedProxy, err := Open(carolPath, members[2], tokens[2], driver, tamperedClient, relay.URL)
	if err != nil {
		t.Fatal(err)
	}
	tamperedRequest := httptest.NewRequest(http.MethodGet, "/v1/messages?room_id="+room.RoomID+"&after=0", nil)
	tamperedRequest.Header.Set("X-Tos-Agent-Id", members[2])
	tamperedRequest.Header.Set("Authorization", "Bearer "+tokens[2])
	tamperedResponse := httptest.NewRecorder()
	tamperedProxy.Handler().ServeHTTP(tamperedResponse, tamperedRequest)
	if tamperedResponse.Code != http.StatusBadGateway {
		t.Fatalf("tampered ciphertext status = %d", tamperedResponse.Code)
	}
	afterTamper, err := os.ReadFile(carolPath)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(beforeTamper, afterTamper) {
		t.Fatal("failed ciphertext authentication changed durable MLS state")
	}
	for i := 1; i < len(proxies); i++ {
		messages := callProxy[struct {
			Messages []Message `json:"messages"`
		}](t, proxies[i], members[i], tokens[i], http.MethodGet, "/v1/messages?room_id="+room.RoomID+"&after=0", nil)
		if len(messages.Messages) != 1 || messages.Messages[0].Content != opening {
			t.Fatalf("agent %d messages = %+v", i, messages.Messages)
		}
	}

	proxies = openTestProxies(t, stateDir, members, tokens, driver, relay)
	reply := "reply after every Agent proxy restarted"
	replied := callProxy[Message](t, proxies[2], members[2], tokens[2], http.MethodPost, "/v1/messages", map[string]string{
		"room_id": room.RoomID, "client_id": "reply-1", "content": reply, "reply_to_event_id": sent.MessageID,
	})
	if replied.ReplyToEventID != sent.MessageID {
		t.Fatalf("send response lost encrypted reply binding: %+v", replied)
	}
	messages := callProxy[struct {
		Messages []Message `json:"messages"`
	}](t, proxies[0], members[0], tokens[0], http.MethodGet, "/v1/messages?room_id="+room.RoomID+"&after=1", nil)
	if len(messages.Messages) != 1 || messages.Messages[0].Content != reply ||
		messages.Messages[0].ReplyToEventID != sent.MessageID {
		t.Fatalf("post-restart reply = %+v", messages.Messages)
	}
	relayRaw, err = os.ReadFile(relayPath)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(relayRaw, []byte(reply)) || bytes.Contains(relayRaw, []byte("reply_to_event_id")) {
		t.Fatal("opaque Relay persisted reply plaintext metadata")
	}
	assertReplySubstitutionRefused(t, proxies[2], members[2], tokens[2], room.RoomID, reply)
	wrong := httptest.NewRequest(http.MethodGet, "/v1/rooms", nil)
	wrong.Header.Set("X-Tos-Agent-Id", members[0])
	wrong.Header.Set("Authorization", "Bearer wrong-secret-token")
	recorder := httptest.NewRecorder()
	proxies[0].ServeHTTP(recorder, wrong)
	if recorder.Code != http.StatusUnauthorized {
		t.Fatalf("wrong credential status = %d", recorder.Code)
	}
}

func assertReplySubstitutionRefused(t *testing.T, handler http.Handler, agentID, token, roomID, content string) {
	t.Helper()
	encoded, err := json.Marshal(map[string]string{
		"room_id": roomID, "client_id": "reply-1", "content": content,
		"reply_to_event_id": "msg_" + strings.Repeat("f", 64),
	})
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodPost, "/v1/messages", bytes.NewReader(encoded))
	request.Header.Set("X-Tos-Agent-Id", agentID)
	request.Header.Set("Authorization", "Bearer "+token)
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusConflict {
		t.Fatalf("reply-reference substitution status = %d, want %d", recorder.Code, http.StatusConflict)
	}
}

type tamperMessages struct{ base http.RoundTripper }

func (t tamperMessages) RoundTrip(request *http.Request) (*http.Response, error) {
	response, err := t.base.RoundTrip(request)
	if err != nil || request.Method != http.MethodGet || request.URL.Path != "/v1/messages" {
		return response, err
	}
	raw, err := io.ReadAll(response.Body)
	response.Body.Close()
	if err != nil {
		return nil, err
	}
	var result struct {
		Messages []labgroup.Message `json:"messages"`
	}
	if err := json.Unmarshal(raw, &result); err != nil {
		return nil, err
	}
	if len(result.Messages) > 0 {
		ciphertext, err := base64.StdEncoding.Strict().DecodeString(result.Messages[0].Content)
		if err != nil {
			return nil, err
		}
		ciphertext[len(ciphertext)-1] ^= 0x80
		result.Messages[0].Content = base64.StdEncoding.EncodeToString(ciphertext)
		result.Messages[0].MessageID = labgroup.DeriveMessageID(result.Messages[0].RoomID, result.Messages[0].SenderAgentID, result.Messages[0].ClientID, result.Messages[0].Content)
	}
	raw, err = json.Marshal(result)
	if err != nil {
		return nil, err
	}
	response.Body = io.NopCloser(bytes.NewReader(raw))
	response.ContentLength = int64(len(raw))
	return response, nil
}

func openTestProxies(t *testing.T, stateDir string, members, tokens []string, driver *group.OpenMLSSidecar, relay *httptest.Server) []http.Handler {
	t.Helper()
	result := make([]http.Handler, len(members))
	for i := range members {
		proxy, err := Open(StatePath(stateDir, members[i]), members[i], tokens[i], driver, relay.Client(), relay.URL)
		if err != nil {
			t.Fatal(err)
		}
		result[i] = proxy.Handler()
	}
	return result
}

func callProxy[T any](t *testing.T, handler http.Handler, agentID, token, method, path string, body any) T {
	t.Helper()
	var input io.Reader
	if body != nil {
		encoded, err := json.Marshal(body)
		if err != nil {
			t.Fatal(err)
		}
		input = bytes.NewReader(encoded)
	}
	request := httptest.NewRequestWithContext(context.Background(), method, path, input)
	request.Header.Set("X-Tos-Agent-Id", agentID)
	request.Header.Set("Authorization", "Bearer "+token)
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)
	if recorder.Code < 200 || recorder.Code >= 300 {
		var detail map[string]string
		_ = json.Unmarshal(recorder.Body.Bytes(), &detail)
		t.Fatalf("%s %s: status=%d detail=%q", method, path, recorder.Code, detail["error"])
	}
	var result T
	decoder := json.NewDecoder(recorder.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&result); err != nil {
		t.Fatal(err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		t.Fatal("trailing proxy response")
	}
	return result
}

func TestMessageAADSeparatesSenderAndClient(t *testing.T) {
	first := messageAAD("room_"+strings.Repeat("a", 64), "agent_"+strings.Repeat("b", 64), "one")
	second := messageAAD("room_"+strings.Repeat("a", 64), "agent_"+strings.Repeat("b", 64), "two")
	if bytes.Equal(first, second) {
		t.Fatal("client id did not separate MLS AAD")
	}
}

func TestEncryptedMessageFrameIsStrictAndMigratesLegacyContent(t *testing.T) {
	replyTo := "msg_" + strings.Repeat("a", 64)
	encoded, err := encodeEncryptedMessage("bound reply", replyTo)
	if err != nil {
		t.Fatal(err)
	}
	content, decodedReply, err := decodeEncryptedMessage(encoded)
	if err != nil || content != "bound reply" || decodedReply != replyTo {
		t.Fatalf("round trip = %q, %q, %v", content, decodedReply, err)
	}
	legacyContent, legacyReply, err := decodeEncryptedMessage([]byte("legacy in-flight content"))
	if err != nil || legacyContent != "legacy in-flight content" || legacyReply != "" {
		t.Fatalf("legacy migration = %q, %q, %v", legacyContent, legacyReply, err)
	}
	for name, raw := range map[string][]byte{
		"unknown field":   append(append([]byte(encryptedMessagePrefix), []byte(`{"schema":"`+EncryptedMessageSchema+`","content":"x","extra":true}`)...), '\n'),
		"duplicate field": append([]byte(encryptedMessagePrefix), []byte(`{"schema":"`+EncryptedMessageSchema+`","content":"first","content":"second"}`)...),
		"noncanonical":    append([]byte(encryptedMessagePrefix), []byte(`{ "schema":"`+EncryptedMessageSchema+`", "content":"x" }`)...),
		"bad reply":       append([]byte(encryptedMessagePrefix), []byte(`{"schema":"`+EncryptedMessageSchema+`","content":"x","reply_to_event_id":"msg_bad"}`)...),
		"trailing":        append(encoded, []byte(`{"extra":true}`)...),
	} {
		t.Run(name, func(t *testing.T) {
			if _, _, err := decodeEncryptedMessage(raw); err == nil {
				t.Fatal("invalid encrypted message frame was accepted")
			}
		})
	}
}
