// Package mlslab provides a local acceptance boundary between OpenFox and an
// untrusted group delivery service. Each Proxy owns exactly one Agent's
// OpenMLS state. The labgroup Hub receives only MLS ciphertext and metadata;
// it never receives plaintext or an MLS private snapshot.
package mlslab

import (
	"bytes"
	"context"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"

	"github.com/tosnetwork/tos-messenger/internal/canon"
	"github.com/tosnetwork/tos-messenger/pkg/group"
	"github.com/tosnetwork/tos-messenger/pkg/labgroup"
)

const (
	StateSchema            = "tos.messaging.openfox-mls-agent.v1"
	EncryptedMessageSchema = "tos.messaging.openfox-mls-plaintext.v1"
	MaxReplyBytes          = 2 << 20
	MaxCachedMessage       = 10_000
)

const encryptedMessagePrefix = "tos-openfox-mls-message/1\n"

var messageIDPattern = regexp.MustCompile(`^msg_[0-9a-f]{64}$`)

type RoomState struct {
	RoomID            string   `json:"room_id"`
	Label             string   `json:"label"`
	Members           []string `json:"members"`
	MLSEpoch          uint64   `json:"mls_epoch"`
	OpaqueState       string   `json:"opaque_state_base64"`
	OpaqueStateDigest string   `json:"opaque_state_digest"`
}

type Pending struct {
	ClientID        string `json:"client_id"`
	PlaintextSchema string `json:"plaintext_schema,omitempty"`
	PlaintextDigest string `json:"plaintext_digest"`
	ReplyToEventID  string `json:"reply_to_event_id,omitempty"`
	Ciphertext      string `json:"ciphertext_base64"`
}

// Message is the authenticated plaintext view returned to one OpenFox
// process. ReplyToEventID is encrypted inside the MLS application message; it
// is never part of the opaque Relay record.
type Message struct {
	Sequence       uint64 `json:"sequence"`
	MessageID      string `json:"message_id"`
	ClientID       string `json:"client_id"`
	RoomID         string `json:"room_id"`
	SenderAgentID  string `json:"sender_agent_id"`
	ReplyToEventID string `json:"reply_to_event_id,omitempty"`
	Content        string `json:"content"`
	CreatedAtUnix  uint64 `json:"created_at_unix"`
}

type AgentState struct {
	Schema     string             `json:"schema"`
	AgentID    string             `json:"agent_id"`
	Room       RoomState          `json:"room"`
	RelayAfter uint64             `json:"relay_after"`
	Pending    map[string]Pending `json:"pending"`
	Sent       map[string]Pending `json:"sent"`
	Messages   []Message          `json:"messages,omitempty"`
}

type Proxy struct {
	mu       sync.Mutex
	path     string
	token    string
	state    AgentState
	driver   *group.OpenMLSSidecar
	client   *http.Client
	endpoint string
}

// Open loads one Agent's private snapshot. relayClient may use either a Unix
// transport or an httptest transport; endpoint is normally http://unix.
func Open(path, agentID, token string, driver *group.OpenMLSSidecar, relayClient *http.Client, endpoint string) (*Proxy, error) {
	if path == "" || agentID == "" || len(token) < 16 || driver == nil || relayClient == nil || endpoint == "" {
		return nil, errors.New("invalid MLS lab proxy configuration")
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read MLS Agent state: %w", err)
	}
	var state AgentState
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&state); err != nil {
		return nil, errors.New("invalid MLS Agent state")
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return nil, errors.New("MLS Agent state has trailing JSON")
	}
	if state.AgentID != agentID {
		return nil, errors.New("MLS Agent state belongs to another Agent")
	}
	if err := validateState(state, driver); err != nil {
		return nil, err
	}
	return &Proxy{path: path, token: token, state: state, driver: driver, client: relayClient, endpoint: strings.TrimRight(endpoint, "/")}, nil
}

func (p *Proxy) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /v1/rooms", p.createRoom)
	mux.HandleFunc("GET /v1/rooms", p.listRooms)
	mux.HandleFunc("POST /v1/messages", p.sendMessage)
	mux.HandleFunc("GET /v1/messages", p.listMessages)
	mux.HandleFunc("GET /livez", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusOK, map[string]any{"ok": true, "encryption": "openmls-0.8.1-suite-0x0001"})
	})
	return mux
}

func (p *Proxy) authenticate(w http.ResponseWriter, r *http.Request) bool {
	agentID := strings.TrimSpace(r.Header.Get("X-Tos-Agent-Id"))
	token := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
	if agentID != p.state.AgentID || token == "" || subtle.ConstantTimeCompare([]byte(token), []byte(p.token)) != 1 {
		writeError(w, http.StatusUnauthorized, "invalid Agent credential")
		return false
	}
	return true
}

func (p *Proxy) createRoom(w http.ResponseWriter, r *http.Request) {
	if !p.authenticate(w, r) {
		return
	}
	var request struct {
		Label   string   `json:"label"`
		Members []string `json:"members"`
	}
	if !decodeBody(w, r, &request) {
		return
	}
	members, err := labgroup.NormalizeMembers(request.Members)
	if err != nil || strings.TrimSpace(request.Label) != p.state.Room.Label || !equalStrings(members, p.state.Room.Members) {
		writeError(w, http.StatusBadRequest, "room does not match bootstrapped MLS state")
		return
	}
	var room labgroup.Room
	if err := p.relay(r.Context(), http.MethodPost, "/v1/rooms", request, &room); err != nil {
		writeError(w, http.StatusBadGateway, err.Error())
		return
	}
	if err := p.validateRoom(room); err != nil {
		writeError(w, http.StatusBadGateway, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, room)
}

func (p *Proxy) listRooms(w http.ResponseWriter, r *http.Request) {
	if !p.authenticate(w, r) {
		return
	}
	var response struct {
		Rooms []labgroup.Room `json:"rooms"`
	}
	if err := p.relay(r.Context(), http.MethodGet, "/v1/rooms", nil, &response); err != nil {
		writeError(w, http.StatusBadGateway, err.Error())
		return
	}
	for _, room := range response.Rooms {
		if room.RoomID == p.state.Room.RoomID {
			if err := p.validateRoom(room); err != nil {
				writeError(w, http.StatusBadGateway, err.Error())
				return
			}
			writeJSON(w, http.StatusOK, map[string]any{"rooms": []labgroup.Room{room}})
			return
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{"rooms": []labgroup.Room{}})
}

func (p *Proxy) sendMessage(w http.ResponseWriter, r *http.Request) {
	if !p.authenticate(w, r) {
		return
	}
	var request struct {
		RoomID         string `json:"room_id"`
		ClientID       string `json:"client_id"`
		ReplyToEventID string `json:"reply_to_event_id,omitempty"`
		Content        string `json:"content"`
	}
	if !decodeBody(w, r, &request) {
		return
	}
	if request.RoomID != p.state.Room.RoomID || !validClientID(request.ClientID) ||
		!validReplyTo(request.ReplyToEventID) || request.Content == "" || len(request.Content) > labgroup.MaxContentBytes {
		writeError(w, http.StatusBadRequest, "invalid encrypted room message")
		return
	}
	plaintext, err := encodeEncryptedMessage(request.Content, request.ReplyToEventID)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	digest := canon.Digest(plaintext)
	pending, found := p.state.Pending[request.ClientID]
	if sent, completed := p.state.Sent[request.ClientID]; completed {
		pending, found = sent, true
	}
	if found && !matchesPlaintext(pending, request.Content, request.ReplyToEventID, digest) {
		writeError(w, http.StatusConflict, "client id was already used for different plaintext")
		return
	}
	if !found {
		if len(p.state.Sent) >= MaxCachedMessage {
			writeError(w, http.StatusInsufficientStorage, "durable MLS retry record limit reached")
			return
		}
		working := cloneState(p.state)
		state, err := decodeOpaque(working.Room)
		if err != nil {
			writeError(w, http.StatusInternalServerError, err.Error())
			return
		}
		next, ciphertext, err := p.driver.Seal(state, messageAAD(request.RoomID, p.state.AgentID, request.ClientID), plaintext)
		if err != nil {
			writeError(w, http.StatusInternalServerError, err.Error())
			return
		}
		setOpaque(&working.Room, next)
		pending = Pending{ClientID: request.ClientID, PlaintextSchema: EncryptedMessageSchema,
			PlaintextDigest: digest, ReplyToEventID: request.ReplyToEventID,
			Ciphertext: base64.StdEncoding.EncodeToString(ciphertext)}
		working.Pending[request.ClientID] = pending
		if err := persist(p.path, working); err != nil {
			writeError(w, http.StatusInternalServerError, err.Error())
			return
		}
		p.state = working
	}
	var result labgroup.Message
	err = p.relay(r.Context(), http.MethodPost, "/v1/messages", map[string]string{
		"room_id": request.RoomID, "client_id": request.ClientID, "content": pending.Ciphertext,
	}, &result)
	if err != nil {
		writeError(w, http.StatusBadGateway, err.Error())
		return
	}
	if result.RoomID != request.RoomID || result.SenderAgentID != p.state.AgentID || result.ClientID != request.ClientID || result.Content != pending.Ciphertext || result.MessageID != labgroup.DeriveMessageID(result.RoomID, result.SenderAgentID, result.ClientID, result.Content) {
		writeError(w, http.StatusBadGateway, "opaque relay substituted sent message")
		return
	}
	working := cloneState(p.state)
	delete(working.Pending, request.ClientID)
	working.Sent[request.ClientID] = pending
	if err := persist(p.path, working); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	p.state = working
	writeJSON(w, http.StatusOK, decryptedMessage(result, request.Content, request.ReplyToEventID))
}

func (p *Proxy) listMessages(w http.ResponseWriter, r *http.Request) {
	if !p.authenticate(w, r) {
		return
	}
	roomID := r.URL.Query().Get("room_id")
	after, err := strconv.ParseUint(defaultString(r.URL.Query().Get("after"), "0"), 10, 64)
	limit, limitErr := strconv.Atoi(defaultString(r.URL.Query().Get("limit"), "64"))
	if err != nil || limitErr != nil || limit < 1 || limit > 256 || roomID != p.state.Room.RoomID {
		writeError(w, http.StatusBadRequest, "invalid message cursor")
		return
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	working := cloneState(p.state)
	path := "/v1/messages?room_id=" + url.QueryEscape(roomID) + "&after=" + strconv.FormatUint(working.RelayAfter, 10) + "&limit=256"
	var response struct {
		Messages []labgroup.Message `json:"messages"`
	}
	if err := p.relay(r.Context(), http.MethodGet, path, nil, &response); err != nil {
		writeError(w, http.StatusBadGateway, err.Error())
		return
	}
	changed := false
	for _, message := range response.Messages {
		if message.Sequence <= working.RelayAfter || message.RoomID != roomID || !contains(working.Room.Members, message.SenderAgentID) || !validClientID(message.ClientID) || message.MessageID != labgroup.DeriveMessageID(message.RoomID, message.SenderAgentID, message.ClientID, message.Content) {
			writeError(w, http.StatusBadGateway, "opaque relay returned an invalid sequence")
			return
		}
		plain, replyTo := "", ""
		if message.SenderAgentID != working.AgentID {
			ciphertext, err := base64.StdEncoding.Strict().DecodeString(message.Content)
			if err != nil || len(ciphertext) == 0 || len(ciphertext) > group.MaxOpenMLSMessageBytes {
				writeError(w, http.StatusBadGateway, "opaque relay returned invalid MLS ciphertext")
				return
			}
			state, err := decodeOpaque(working.Room)
			if err != nil {
				writeError(w, http.StatusInternalServerError, err.Error())
				return
			}
			next, plaintext, err := p.driver.Open(state, messageAAD(roomID, message.SenderAgentID, message.ClientID), ciphertext)
			if err != nil {
				writeError(w, http.StatusBadGateway, "MLS ciphertext authentication failed")
				return
			}
			setOpaque(&working.Room, next)
			plain, replyTo, err = decodeEncryptedMessage(plaintext)
			if err != nil {
				writeError(w, http.StatusBadGateway, "invalid decrypted message")
				return
			}
		} else if sent, ok := working.Sent[message.ClientID]; ok && sent.PlaintextSchema == EncryptedMessageSchema {
			replyTo = sent.ReplyToEventID
		}
		working.Messages = append(working.Messages, decryptedMessage(message, plain, replyTo))
		if len(working.Messages) > MaxCachedMessage {
			working.Messages = append([]Message(nil), working.Messages[len(working.Messages)-MaxCachedMessage:]...)
		}
		working.RelayAfter = message.Sequence
		changed = true
	}
	if changed {
		if err := persist(p.path, working); err != nil {
			writeError(w, http.StatusInternalServerError, err.Error())
			return
		}
		p.state = working
	}
	result := make([]Message, 0)
	for _, message := range p.state.Messages {
		if message.Sequence > after {
			result = append(result, message)
			if len(result) == limit {
				break
			}
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{"messages": result})
}

func cloneState(state AgentState) AgentState {
	cloned := state
	cloned.Room.Members = append([]string(nil), state.Room.Members...)
	cloned.Pending = make(map[string]Pending, len(state.Pending))
	for key, value := range state.Pending {
		cloned.Pending[key] = value
	}
	cloned.Sent = make(map[string]Pending, len(state.Sent))
	for key, value := range state.Sent {
		cloned.Sent[key] = value
	}
	cloned.Messages = append([]Message(nil), state.Messages...)
	return cloned
}

func (p *Proxy) validateRoom(room labgroup.Room) error {
	if room.RoomID != p.state.Room.RoomID || strings.TrimSpace(room.Label) != p.state.Room.Label {
		return errors.New("opaque relay substituted room")
	}
	members, err := labgroup.NormalizeMembers(room.Members)
	if err != nil || !equalStrings(members, p.state.Room.Members) {
		return errors.New("opaque relay substituted room membership")
	}
	return nil
}

func (p *Proxy) relay(ctx context.Context, method, path string, body, result any) error {
	var input io.Reader
	if body != nil {
		encoded, err := json.Marshal(body)
		if err != nil {
			return err
		}
		input = bytes.NewReader(encoded)
	}
	request, err := http.NewRequestWithContext(ctx, method, p.endpoint+path, input)
	if err != nil {
		return err
	}
	request.Header.Set("X-Tos-Agent-Id", p.state.AgentID)
	request.Header.Set("Authorization", "Bearer "+p.token)
	request.Header.Set("Content-Type", "application/json")
	response, err := p.client.Do(request)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(response.Body, MaxReplyBytes+1))
	if err != nil {
		return err
	}
	if len(raw) > MaxReplyBytes {
		return errors.New("opaque relay response exceeds bound")
	}
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return fmt.Errorf("opaque relay returned %s: %s", response.Status, strings.TrimSpace(string(raw)))
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(result); err != nil {
		return err
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return errors.New("opaque relay response has trailing JSON")
	}
	return nil
}

func validateState(state AgentState, driver *group.OpenMLSSidecar) error {
	if state.Schema != StateSchema || state.AgentID == "" || state.Room.RoomID == "" || len(state.Pending) > 1024 || len(state.Sent) > MaxCachedMessage || len(state.Messages) > MaxCachedMessage {
		return errors.New("invalid MLS Agent state")
	}
	members, err := labgroup.NormalizeMembers(state.Room.Members)
	if err != nil || strings.TrimSpace(state.Room.Label) == "" || len(state.Room.Label) > 128 || strings.ContainsRune(state.Room.Label, 0) || !equalStrings(members, state.Room.Members) || !contains(members, state.AgentID) || labgroup.DeriveRoomID(state.Room.Label, members) != state.Room.RoomID {
		return errors.New("invalid MLS Agent room binding")
	}
	opaque, err := decodeOpaque(state.Room)
	if err != nil {
		return err
	}
	info, err := driver.Inspect(opaque)
	groupID, decodeErr := hex.DecodeString(strings.TrimPrefix(state.Room.RoomID, "room_"))
	if err != nil || decodeErr != nil || !bytes.Equal(info.GroupID, groupID) || info.Epoch != state.Room.MLSEpoch {
		return errors.New("MLS snapshot does not match its room binding")
	}
	if state.Pending == nil || state.Sent == nil {
		return errors.New("MLS Agent send maps are missing")
	}
	for _, records := range []map[string]Pending{state.Pending, state.Sent} {
		for clientID, pending := range records {
			ciphertext, err := base64.StdEncoding.Strict().DecodeString(pending.Ciphertext)
			if !validClientID(clientID) || pending.ClientID != clientID || !canon.ValidDigest(pending.PlaintextDigest) || err != nil || len(ciphertext) == 0 || len(ciphertext) > group.MaxOpenMLSMessageBytes {
				return errors.New("invalid durable MLS send record")
			}
			if pending.PlaintextSchema == "" {
				if pending.ReplyToEventID != "" {
					return errors.New("legacy MLS send record carries a reply reference")
				}
			} else if pending.PlaintextSchema != EncryptedMessageSchema || !validReplyTo(pending.ReplyToEventID) {
				return errors.New("invalid durable MLS plaintext binding")
			}
		}
	}
	for clientID := range state.Pending {
		if _, completed := state.Sent[clientID]; completed {
			return errors.New("MLS send record is both pending and complete")
		}
	}
	var prior uint64
	for _, message := range state.Messages {
		if message.Sequence <= prior || message.Sequence > state.RelayAfter || message.RoomID != state.Room.RoomID ||
			!contains(members, message.SenderAgentID) || !validReplyTo(message.ReplyToEventID) {
			return errors.New("invalid decrypted MLS message cache")
		}
		prior = message.Sequence
	}
	return nil
}

func decodeOpaque(room RoomState) ([]byte, error) {
	raw, err := base64.StdEncoding.Strict().DecodeString(room.OpaqueState)
	if err != nil || len(raw) == 0 || len(raw) > group.MaxOpenMLSStateBytes || canon.Digest(raw) != room.OpaqueStateDigest {
		return nil, errors.New("invalid private MLS snapshot")
	}
	return raw, nil
}

func setOpaque(room *RoomState, raw []byte) {
	room.OpaqueState = base64.StdEncoding.EncodeToString(raw)
	room.OpaqueStateDigest = canon.Digest(raw)
}

func messageAAD(roomID, sender, clientID string) []byte {
	buffer := bytes.NewBufferString(canon.DomainOpenFoxMLSAAD)
	canon.Text(buffer, roomID)
	canon.Text(buffer, sender)
	canon.Text(buffer, clientID)
	return buffer.Bytes()
}

type encryptedMessage struct {
	Schema         string `json:"schema"`
	Content        string `json:"content"`
	ReplyToEventID string `json:"reply_to_event_id,omitempty"`
}

func encodeEncryptedMessage(content, replyTo string) ([]byte, error) {
	if content == "" || len(content) > labgroup.MaxContentBytes || !validReplyTo(replyTo) {
		return nil, errors.New("invalid encrypted message plaintext")
	}
	encoded, err := json.Marshal(encryptedMessage{Schema: EncryptedMessageSchema, Content: content, ReplyToEventID: replyTo})
	if err != nil {
		return nil, err
	}
	return append([]byte(encryptedMessagePrefix), encoded...), nil
}

func decodeEncryptedMessage(raw []byte) (string, string, error) {
	if !bytes.HasPrefix(raw, []byte(encryptedMessagePrefix)) {
		// States created before the authenticated reply-reference frame sealed
		// raw content. Accept it only as a reply-less legacy message so an
		// in-flight durable retry survives this pre-launch migration.
		if len(raw) == 0 || len(raw) > labgroup.MaxContentBytes {
			return "", "", errors.New("invalid legacy MLS plaintext")
		}
		return string(raw), "", nil
	}
	decoder := json.NewDecoder(bytes.NewReader(raw[len(encryptedMessagePrefix):]))
	decoder.DisallowUnknownFields()
	var message encryptedMessage
	if err := decoder.Decode(&message); err != nil {
		return "", "", errors.New("invalid encrypted message frame")
	}
	var trailing any
	canonical, marshalErr := json.Marshal(message)
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) || marshalErr != nil ||
		!bytes.Equal(canonical, raw[len(encryptedMessagePrefix):]) || message.Schema != EncryptedMessageSchema ||
		message.Content == "" || len(message.Content) > labgroup.MaxContentBytes || !validReplyTo(message.ReplyToEventID) {
		return "", "", errors.New("invalid encrypted message frame")
	}
	return message.Content, message.ReplyToEventID, nil
}

func matchesPlaintext(pending Pending, content, replyTo, framedDigest string) bool {
	if pending.PlaintextSchema == "" {
		return replyTo == "" && pending.PlaintextDigest == canon.Digest([]byte(content))
	}
	return pending.PlaintextSchema == EncryptedMessageSchema && pending.ReplyToEventID == replyTo &&
		pending.PlaintextDigest == framedDigest
}

func decryptedMessage(relay labgroup.Message, content, replyTo string) Message {
	return Message{Sequence: relay.Sequence, MessageID: relay.MessageID, ClientID: relay.ClientID,
		RoomID: relay.RoomID, SenderAgentID: relay.SenderAgentID, ReplyToEventID: replyTo,
		Content: content, CreatedAtUnix: relay.CreatedAtUnix}
}

func validReplyTo(value string) bool {
	return value == "" || messageIDPattern.MatchString(value)
}

func persist(path string, state AgentState) error {
	encoded, err := json.Marshal(state)
	if err != nil {
		return err
	}
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	temporary, err := os.CreateTemp(dir, ".openfox-mls-*.tmp")
	if err != nil {
		return err
	}
	name := temporary.Name()
	defer os.Remove(name)
	if err := temporary.Chmod(0o600); err != nil {
		temporary.Close()
		return err
	}
	if _, err := temporary.Write(encoded); err != nil {
		temporary.Close()
		return err
	}
	if err := temporary.Sync(); err != nil {
		temporary.Close()
		return err
	}
	if err := temporary.Close(); err != nil {
		return err
	}
	if err := os.Rename(name, path); err != nil {
		return err
	}
	directory, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer directory.Close()
	return directory.Sync()
}

func writeState(path string, state AgentState) error { return persist(path, state) }

func decodeBody(w http.ResponseWriter, r *http.Request, target any) bool {
	r.Body = http.MaxBytesReader(w, r.Body, labgroup.MaxContentBytes+4096)
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON request")
		return false
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		writeError(w, http.StatusBadRequest, "request has trailing JSON")
		return false
	}
	return true
}

func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}
func writeError(w http.ResponseWriter, status int, detail string) {
	writeJSON(w, status, map[string]string{"error": detail})
}
func defaultString(value, fallback string) string {
	if value == "" {
		return fallback
	}
	return value
}
func equalStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
func contains(values []string, want string) bool {
	return sort.SearchStrings(values, want) < len(values) && values[sort.SearchStrings(values, want)] == want
}
func validClientID(value string) bool {
	if len(value) < 1 || len(value) > 128 {
		return false
	}
	for _, c := range value {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || strings.ContainsRune("._~-", c)) {
			return false
		}
	}
	return true
}
