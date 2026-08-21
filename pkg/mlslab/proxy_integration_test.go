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

func TestOpenMLSProxyRemovalSurvivesRestartAndExcludesFormerMember(t *testing.T) {
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
	room, err := Bootstrap(stateDir, "removal-builders", members, driver)
	if err != nil {
		t.Fatal(err)
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
	callProxy[labgroup.Room](t, proxies[0], members[0], tokens[0], http.MethodPost, "/v1/rooms",
		map[string]any{"label": room.Label, "members": room.Members})

	opening := callProxy[Message](t, proxies[0], members[0], tokens[0], http.MethodPost, "/v1/messages",
		map[string]string{"room_id": room.RoomID, "client_id": "before-removal", "content": "three members are live"})
	for i := 1; i < len(proxies); i++ {
		messages := callProxy[struct {
			Messages []Message `json:"messages"`
		}](t, proxies[i], members[i], tokens[i], http.MethodGet, "/v1/messages?room_id="+room.RoomID+"&after=0", nil)
		if len(messages.Messages) != 1 || messages.Messages[0].MessageID != opening.MessageID {
			t.Fatalf("member %d did not receive the opening: %+v", i, messages.Messages)
		}
	}
	aliceRaw, err := os.ReadFile(StatePath(stateDir, members[0]))
	if err != nil {
		t.Fatal(err)
	}
	var aliceBeforeRemoval AgentState
	if err := json.Unmarshal(aliceRaw, &aliceBeforeRemoval); err != nil {
		t.Fatal(err)
	}
	legacy := cloneState(aliceBeforeRemoval)
	legacy.Schema = LegacyStateSchema
	legacy.Room.ControllerAgentID = ""
	legacy.Room.ActiveMembers = nil
	legacyPath := filepath.Join(t.TempDir(), "legacy-alice.json")
	if err := persist(legacyPath, legacy); err != nil {
		t.Fatal(err)
	}
	legacyProxy, err := Open(legacyPath, members[0], tokens[0], driver, relay.Client(), relay.URL)
	if err != nil {
		t.Fatalf("v1 message-only state no longer opens: %v", err)
	}
	if status := proxyStatus(t, legacyProxy.Handler(), members[0], tokens[0], http.MethodPost, "/v1/members/remove",
		map[string]string{"room_id": room.RoomID, "client_id": "legacy-remove", "removed_agent_id": members[2]}); status != http.StatusConflict {
		t.Fatalf("legacy state removal status = %d", status)
	}
	aliceOpaque, err := decodeOpaque(aliceBeforeRemoval.Room)
	if err != nil {
		t.Fatal(err)
	}
	_, alternateCommit, _, err := driver.Commit(aliceOpaque, []group.LeafOperation{{
		Kind: group.LeafRemove, Prior: &group.Leaf{CredentialIdentity: []byte(members[1])},
	}})
	if err != nil {
		t.Fatal(err)
	}

	removed := callProxy[MembershipChange](t, proxies[0], members[0], tokens[0], http.MethodPost, "/v1/members/remove",
		map[string]string{"room_id": room.RoomID, "client_id": "remove-carol-1", "removed_agent_id": members[2]})
	if removed.RemovedAgentID != members[2] || removed.MLSEpoch != 3 {
		t.Fatalf("removal = %+v", removed)
	}
	retried := callProxy[MembershipChange](t, proxies[0], members[0], tokens[0], http.MethodPost, "/v1/members/remove",
		map[string]string{"room_id": room.RoomID, "client_id": "remove-carol-1", "removed_agent_id": members[2]})
	if retried != removed {
		t.Fatalf("exact removal retry changed result: first=%+v retry=%+v", removed, retried)
	}
	conflict := proxyStatus(t, proxies[0], members[0], tokens[0], http.MethodPost, "/v1/members/remove",
		map[string]string{"room_id": room.RoomID, "client_id": "remove-carol-1", "removed_agent_id": members[1]})
	if conflict != http.StatusConflict {
		t.Fatalf("removal substitution status = %d", conflict)
	}
	if status := proxyStatus(t, proxies[1], members[1], tokens[1], http.MethodPost, "/v1/members/remove",
		map[string]string{"room_id": room.RoomID, "client_id": "bob-removes-carol", "removed_agent_id": members[2]}); status != http.StatusForbidden {
		t.Fatalf("non-controller removal status = %d", status)
	}
	removalWire := callRelay[struct {
		Messages []labgroup.Message `json:"messages"`
	}](t, relay, members[2], tokens[2], "/v1/messages?room_id="+room.RoomID+"&after=1")
	if len(removalWire.Messages) != 1 || removalWire.Messages[0].MessageID != removed.MessageID {
		t.Fatalf("Relay removal frame = %+v", removalWire.Messages)
	}
	opaqueRemoval, err := base64.StdEncoding.Strict().DecodeString(removalWire.Messages[0].Content)
	if err != nil || bytes.Contains(opaqueRemoval, []byte(members[2])) ||
		bytes.Contains(opaqueRemoval, []byte(base64.StdEncoding.EncodeToString([]byte(members[2])))) {
		t.Fatal("Relay-visible removal frame disclosed the removed Agent identity")
	}
	carolBeforeTamper, err := os.ReadFile(StatePath(stateDir, members[2]))
	if err != nil {
		t.Fatal(err)
	}
	tamperedClient := &http.Client{Transport: spliceRemovalCommit{base: relay.Client().Transport, commit: alternateCommit}}
	tamperedCarol, err := Open(StatePath(stateDir, members[2]), members[2], tokens[2], driver, tamperedClient, relay.URL)
	if err != nil {
		t.Fatal(err)
	}
	if status := proxyStatus(t, tamperedCarol.Handler(), members[2], tokens[2], http.MethodGet,
		"/v1/messages?room_id="+room.RoomID+"&after=0", nil); status != http.StatusBadGateway {
		t.Fatalf("tampered removal frame status = %d", status)
	}
	carolAfterTamper, err := os.ReadFile(StatePath(stateDir, members[2]))
	if err != nil || !bytes.Equal(carolBeforeTamper, carolAfterTamper) {
		t.Fatal("tampered removal frame changed durable MLS state")
	}

	messages := callProxy[struct {
		Messages []Message `json:"messages"`
	}](t, proxies[1], members[1], tokens[1], http.MethodGet, "/v1/messages?room_id="+room.RoomID+"&after=0", nil)
	if len(messages.Messages) != 1 {
		t.Fatalf("membership control leaked into Bob transcript: %+v", messages.Messages)
	}
	rooms := callProxy[struct {
		Rooms []labgroup.Room `json:"rooms"`
	}](t, proxies[1], members[1], tokens[1], http.MethodGet, "/v1/rooms", nil)
	if len(rooms.Rooms) != 1 || !equalStrings(rooms.Rooms[0].Members, members[:2]) {
		t.Fatalf("Bob active room view = %+v", rooms.Rooms)
	}
	proxies = openTestProxies(t, stateDir, members, tokens, driver, relay)
	postRemoval := callProxy[Message](t, proxies[0], members[0], tokens[0], http.MethodPost, "/v1/messages",
		map[string]string{"room_id": room.RoomID, "client_id": "after-removal", "content": "only Alice and Bob can read this"})
	bobMessages := callProxy[struct {
		Messages []Message `json:"messages"`
	}](t, proxies[1], members[1], tokens[1], http.MethodGet, "/v1/messages?room_id="+room.RoomID+"&after=0", nil)
	if len(bobMessages.Messages) != 2 || bobMessages.Messages[1].MessageID != postRemoval.MessageID {
		t.Fatalf("remaining member did not receive future message: %+v", bobMessages.Messages)
	}
	carolBefore, err := os.ReadFile(StatePath(stateDir, members[2]))
	if err != nil {
		t.Fatal(err)
	}
	carolMessages := callProxy[struct {
		Messages []Message `json:"messages"`
	}](t, proxies[2], members[2], tokens[2], http.MethodGet, "/v1/messages?room_id="+room.RoomID+"&after=0", nil)
	if len(carolMessages.Messages) != 1 || carolMessages.Messages[0].MessageID != opening.MessageID {
		t.Fatalf("removal batch leaked a control or future message: %+v", carolMessages.Messages)
	}
	carolAfter, err := os.ReadFile(StatePath(stateDir, members[2]))
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(carolBefore, carolAfter) {
		t.Fatal("batch processing rolled the authenticated removal back")
	}
	var durable AgentState
	decoder := json.NewDecoder(bytes.NewReader(carolAfter))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&durable); err != nil || contains(durable.Room.ActiveMembers, members[2]) ||
		durable.Room.MLSEpoch != removed.MLSEpoch || durable.RelayAfter != 2 {
		t.Fatalf("batch processing did not stop at the exact removal boundary: state=%+v err=%v", durable.Room, err)
	}
	if status := proxyStatus(t, proxies[2], members[2], tokens[2], http.MethodGet,
		"/v1/messages?room_id="+room.RoomID+"&after=0", nil); status != http.StatusGone {
		t.Fatalf("removed member subsequent poll status = %d", status)
	}
	if status := proxyStatus(t, proxies[2], members[2], tokens[2], http.MethodPost, "/v1/rooms",
		map[string]any{"label": room.Label, "members": room.Members}); status != http.StatusGone {
		t.Fatalf("removed member room replay status = %d", status)
	}
	health := callProxy[struct {
		OK           bool     `json:"ok"`
		ActiveMember bool     `json:"active_member"`
		RoomID       string   `json:"room_id"`
		RoomLabel    string   `json:"room_label"`
		Members      []string `json:"members"`
		MLSEpoch     uint64   `json:"mls_epoch"`
		Encryption   string   `json:"encryption"`
	}](t, proxies[2], members[2], tokens[2], http.MethodGet, "/livez", nil)
	if !health.OK || health.ActiveMember || health.RoomID != room.RoomID || health.RoomLabel != room.Label ||
		!equalStrings(health.Members, room.Members) || health.MLSEpoch != removed.MLSEpoch ||
		health.Encryption != "openmls-0.8.1-suite-0x0001" {
		t.Fatalf("removed member health = %+v", health)
	}
	carolRooms := callProxy[struct {
		Rooms []labgroup.Room `json:"rooms"`
	}](t, proxies[2], members[2], tokens[2], http.MethodGet, "/v1/rooms", nil)
	if len(carolRooms.Rooms) != 0 {
		t.Fatalf("removed Carol still lists the room: %+v", carolRooms.Rooms)
	}
	if status := proxyStatus(t, proxies[2], members[2], tokens[2], http.MethodPost, "/v1/messages",
		map[string]string{"room_id": room.RoomID, "client_id": "removed-send", "content": "should fail"}); status != http.StatusForbidden {
		t.Fatalf("removed member send status = %d", status)
	}

	var relayMessages struct {
		Messages []labgroup.Message `json:"messages"`
	}
	relayMessages = callRelay[struct {
		Messages []labgroup.Message `json:"messages"`
	}](t, relay, members[2], tokens[2], "/v1/messages?room_id="+room.RoomID+"&after=2")
	if len(relayMessages.Messages) != 1 || relayMessages.Messages[0].MessageID != postRemoval.MessageID {
		t.Fatalf("Relay did not continue delivering ciphertext to removed member: %+v", relayMessages.Messages)
	}
	futureCiphertext, err := base64.StdEncoding.Strict().DecodeString(relayMessages.Messages[0].Content)
	if err != nil {
		t.Fatal(err)
	}
	removedState, err := decodeOpaque(durable.Room)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := driver.Open(removedState,
		messageAAD(room.RoomID, members[0], "after-removal"), futureCiphertext); err == nil {
		t.Fatal("removed member's exact durable state decrypted future Relay ciphertext")
	}
	relayRaw, err := os.ReadFile(relayPath)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(relayRaw, []byte("only Alice and Bob can read this")) {
		t.Fatal("Relay persisted post-removal plaintext")
	}
}

func proxyStatus(t *testing.T, handler http.Handler, agentID, token, method, path string, body any) int {
	t.Helper()
	var input io.Reader
	if body != nil {
		raw, err := json.Marshal(body)
		if err != nil {
			t.Fatal(err)
		}
		input = bytes.NewReader(raw)
	}
	request := httptest.NewRequest(method, path, input)
	request.Header.Set("X-Tos-Agent-Id", agentID)
	request.Header.Set("Authorization", "Bearer "+token)
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)
	return recorder.Code
}

func callRelay[T any](t *testing.T, relay *httptest.Server, agentID, token, path string) T {
	t.Helper()
	request, err := http.NewRequest(http.MethodGet, relay.URL+path, nil)
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("X-Tos-Agent-Id", agentID)
	request.Header.Set("Authorization", "Bearer "+token)
	response, err := relay.Client().Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		t.Fatalf("Relay status = %d", response.StatusCode)
	}
	var result T
	decoder := json.NewDecoder(response.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&result); err != nil {
		t.Fatal(err)
	}
	return result
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

type spliceRemovalCommit struct {
	base   http.RoundTripper
	commit []byte
}

func (s spliceRemovalCommit) RoundTrip(request *http.Request) (*http.Response, error) {
	response, err := s.base.RoundTrip(request)
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
		frame, err := base64.StdEncoding.Strict().DecodeString(result.Messages[0].Content)
		if err != nil {
			return nil, err
		}
		notice, _, err := decodeRemovalFrame(frame)
		if err != nil {
			return nil, err
		}
		frame, err = encodeRemovalFrame(notice, s.commit)
		if err != nil {
			return nil, err
		}
		result.Messages[0].Content = base64.StdEncoding.EncodeToString(frame)
		result.Messages[0].MessageID = labgroup.DeriveMessageID(result.Messages[0].RoomID,
			result.Messages[0].SenderAgentID, result.Messages[0].ClientID, result.Messages[0].Content)
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
