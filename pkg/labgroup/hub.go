// Package labgroup provides a local-only group-chat carrier for integration
// testing. It is deliberately not a production Messenger transport: it binds
// a Unix socket, carries plaintext, and makes no routing decision. Its job is
// to let multiple Agent runtimes exercise room creation, membership checks,
// durable fan-out, idempotency, and restart behaviour while M0-R remains open.
package labgroup

import (
	"bytes"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/tosnetwork/tos-messenger/internal/canon"
)

const (
	StateSchema     = "tos.messaging.lab-group-state.v1"
	MaxContentBytes = 128 << 10
	MaxMessages     = 10_000
	MaxRooms        = 256
	MaxMembers      = 64
	DefaultLimit    = 64
	MaxLimit        = 256
)

var (
	agentPattern  = regexp.MustCompile(`^agent_[0-9a-f]{64}$`)
	roomPattern   = regexp.MustCompile(`^room_[0-9a-f]{64}$`)
	clientPattern = regexp.MustCompile(`^[A-Za-z0-9._~-]{1,128}$`)
)

type Credential struct {
	AgentID string
	Token   string
}

type Room struct {
	RoomID        string   `json:"room_id"`
	Label         string   `json:"label"`
	Members       []string `json:"members"`
	CreatedBy     string   `json:"created_by"`
	CreatedAtUnix uint64   `json:"created_at_unix"`
}

type Message struct {
	Sequence      uint64 `json:"sequence"`
	MessageID     string `json:"message_id"`
	ClientID      string `json:"client_id"`
	RoomID        string `json:"room_id"`
	SenderAgentID string `json:"sender_agent_id"`
	Content       string `json:"content"`
	CreatedAtUnix uint64 `json:"created_at_unix"`
}

type state struct {
	Schema       string            `json:"schema"`
	TokenHashes  map[string]string `json:"token_hashes"`
	Rooms        map[string]Room   `json:"rooms"`
	Messages     []Message         `json:"messages"`
	NextSequence uint64            `json:"next_sequence"`
}

type Hub struct {
	mu    sync.Mutex
	path  string
	now   func() time.Time
	state state
}

func Open(path string, credentials []Credential) (*Hub, error) {
	if strings.TrimSpace(path) == "" {
		return nil, errors.New("lab group hub needs a state path")
	}
	wanted, err := credentialHashes(credentials)
	if err != nil {
		return nil, err
	}
	h := &Hub{path: path, now: time.Now}
	raw, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		h.state = state{Schema: StateSchema, TokenHashes: wanted, Rooms: map[string]Room{}, NextSequence: 1}
		if _, err := h.persist(); err != nil {
			return nil, err
		}
		return h, nil
	}
	if err != nil {
		return nil, fmt.Errorf("read lab group state: %w", err)
	}
	if err := json.Unmarshal(raw, &h.state); err != nil {
		return nil, errors.New("invalid lab group state")
	}
	if err := validateState(h.state); err != nil {
		return nil, err
	}
	if !equalStringMap(h.state.TokenHashes, wanted) {
		return nil, errors.New("configured lab credentials differ from durable state")
	}
	return h, nil
}

func (h *Hub) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /v1/rooms", h.createRoom)
	mux.HandleFunc("GET /v1/rooms", h.listRooms)
	mux.HandleFunc("POST /v1/messages", h.sendMessage)
	mux.HandleFunc("GET /v1/messages", h.listMessages)
	mux.HandleFunc("GET /livez", func(w http.ResponseWriter, _ *http.Request) { writeJSON(w, http.StatusOK, map[string]bool{"ok": true}) })
	return mux
}

type createRoomRequest struct {
	Label   string   `json:"label"`
	Members []string `json:"members"`
}

func (h *Hub) createRoom(w http.ResponseWriter, r *http.Request) {
	agentID, ok := h.authenticate(w, r)
	if !ok {
		return
	}
	var request createRoomRequest
	if !decodeBody(w, r, &request) {
		return
	}
	members, err := normalizeMembers(request.Members)
	if err != nil || !contains(members, agentID) || len(request.Label) > 128 || strings.TrimSpace(request.Label) == "" || strings.ContainsRune(request.Label, 0) {
		writeError(w, http.StatusBadRequest, "invalid room definition")
		return
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	for _, member := range members {
		if _, known := h.state.TokenHashes[member]; !known {
			writeError(w, http.StatusBadRequest, "room contains an unregistered agent")
			return
		}
	}
	roomID := deriveRoomID(request.Label, members)
	if existing, found := h.state.Rooms[roomID]; found {
		writeJSON(w, http.StatusOK, existing)
		return
	}
	if len(h.state.Rooms) >= MaxRooms {
		writeError(w, http.StatusInsufficientStorage, "room limit reached")
		return
	}
	now := h.now()
	if now.IsZero() || now.Unix() < 0 {
		writeError(w, http.StatusInternalServerError, "invalid clock")
		return
	}
	room := Room{RoomID: roomID, Label: request.Label, Members: members, CreatedBy: agentID, CreatedAtUnix: uint64(now.Unix())}
	h.state.Rooms[roomID] = room
	if replaced, err := h.persist(); err != nil {
		if !replaced {
			delete(h.state.Rooms, roomID)
		}
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusCreated, room)
}

func (h *Hub) listRooms(w http.ResponseWriter, r *http.Request) {
	agentID, ok := h.authenticate(w, r)
	if !ok {
		return
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	rooms := make([]Room, 0)
	for _, room := range h.state.Rooms {
		if contains(room.Members, agentID) {
			rooms = append(rooms, room)
		}
	}
	sort.Slice(rooms, func(i, j int) bool { return rooms[i].RoomID < rooms[j].RoomID })
	writeJSON(w, http.StatusOK, map[string]any{"rooms": rooms})
}

type sendRequest struct {
	RoomID   string `json:"room_id"`
	ClientID string `json:"client_id"`
	Content  string `json:"content"`
}

func (h *Hub) sendMessage(w http.ResponseWriter, r *http.Request) {
	agentID, ok := h.authenticate(w, r)
	if !ok {
		return
	}
	var request sendRequest
	if !decodeBody(w, r, &request) {
		return
	}
	if !roomPattern.MatchString(request.RoomID) || !clientPattern.MatchString(request.ClientID) || len(request.Content) == 0 || len(request.Content) > MaxContentBytes {
		writeError(w, http.StatusBadRequest, "invalid message")
		return
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	room, found := h.state.Rooms[request.RoomID]
	if !found {
		writeError(w, http.StatusNotFound, "room not found")
		return
	}
	if !contains(room.Members, agentID) {
		writeError(w, http.StatusForbidden, "agent is not a room member")
		return
	}
	messageID := deriveMessageID(request.RoomID, agentID, request.ClientID, request.Content)
	for _, existing := range h.state.Messages {
		if existing.SenderAgentID == agentID && existing.ClientID == request.ClientID {
			if existing.MessageID != messageID {
				writeError(w, http.StatusConflict, "client id was already used for different content")
				return
			}
			writeJSON(w, http.StatusOK, existing)
			return
		}
	}
	if len(h.state.Messages) >= MaxMessages {
		writeError(w, http.StatusInsufficientStorage, "message limit reached")
		return
	}
	now := h.now()
	if now.IsZero() || now.Unix() < 0 {
		writeError(w, http.StatusInternalServerError, "invalid clock")
		return
	}
	message := Message{Sequence: h.state.NextSequence, MessageID: messageID, ClientID: request.ClientID, RoomID: request.RoomID, SenderAgentID: agentID, Content: request.Content, CreatedAtUnix: uint64(now.Unix())}
	h.state.NextSequence++
	h.state.Messages = append(h.state.Messages, message)
	if replaced, err := h.persist(); err != nil {
		if !replaced {
			h.state.Messages = h.state.Messages[:len(h.state.Messages)-1]
			h.state.NextSequence--
		}
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusCreated, message)
}

func (h *Hub) listMessages(w http.ResponseWriter, r *http.Request) {
	agentID, ok := h.authenticate(w, r)
	if !ok {
		return
	}
	roomID := r.URL.Query().Get("room_id")
	after, err := strconv.ParseUint(defaultString(r.URL.Query().Get("after"), "0"), 10, 64)
	if err != nil || !roomPattern.MatchString(roomID) {
		writeError(w, http.StatusBadRequest, "invalid message cursor")
		return
	}
	limit, err := strconv.Atoi(defaultString(r.URL.Query().Get("limit"), strconv.Itoa(DefaultLimit)))
	if err != nil || limit < 1 || limit > MaxLimit {
		writeError(w, http.StatusBadRequest, "invalid message limit")
		return
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	room, found := h.state.Rooms[roomID]
	if !found {
		writeError(w, http.StatusNotFound, "room not found")
		return
	}
	if !contains(room.Members, agentID) {
		writeError(w, http.StatusForbidden, "agent is not a room member")
		return
	}
	messages := make([]Message, 0, limit)
	for _, message := range h.state.Messages {
		if message.RoomID == roomID && message.Sequence > after {
			messages = append(messages, message)
			if len(messages) == limit {
				break
			}
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{"messages": messages})
}

func (h *Hub) authenticate(w http.ResponseWriter, r *http.Request) (string, bool) {
	agentID := strings.TrimSpace(r.Header.Get("X-Tos-Agent-Id"))
	token := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
	h.mu.Lock()
	want, found := h.state.TokenHashes[agentID]
	h.mu.Unlock()
	got := tokenHash(token)
	if !found || token == "" || subtle.ConstantTimeCompare([]byte(got), []byte(want)) != 1 {
		writeError(w, http.StatusUnauthorized, "invalid agent credential")
		return "", false
	}
	return agentID, true
}

func credentialHashes(credentials []Credential) (map[string]string, error) {
	result := make(map[string]string, len(credentials))
	for _, credential := range credentials {
		if !agentPattern.MatchString(credential.AgentID) || len(credential.Token) < 16 || len(credential.Token) > 256 {
			return nil, errors.New("invalid lab agent credential")
		}
		if _, duplicate := result[credential.AgentID]; duplicate {
			return nil, errors.New("duplicate lab agent credential")
		}
		result[credential.AgentID] = tokenHash(credential.Token)
	}
	if len(result) < 2 {
		return nil, errors.New("lab group hub needs at least two agents")
	}
	return result, nil
}

func tokenHash(token string) string {
	buffer := bytes.NewBufferString(canon.DomainLabToken)
	canon.Text(buffer, token)
	sum := sha256.Sum256(buffer.Bytes())
	return hex.EncodeToString(sum[:])
}
func deriveRoomID(label string, members []string) string {
	buffer := bytes.NewBufferString(canon.DomainLabRoom)
	canon.Text(buffer, label)
	canon.Uint32(buffer, uint32(len(members)))
	for _, member := range members {
		canon.Text(buffer, member)
	}
	sum := sha256.Sum256(buffer.Bytes())
	return "room_" + hex.EncodeToString(sum[:])
}

// DeriveRoomID returns the carrier room identifier for an already normalized
// member set. Encrypted per-Agent proxies use it to bind their private MLS
// state to the exact room the opaque relay exposes.
func DeriveRoomID(label string, members []string) string {
	return deriveRoomID(label, members)
}

// NormalizeMembers validates and sorts a lab room member set.
func NormalizeMembers(members []string) ([]string, error) {
	return normalizeMembers(members)
}
func deriveMessageID(roomID, sender, clientID, content string) string {
	buffer := bytes.NewBufferString(canon.DomainLabMessage)
	for _, value := range []string{roomID, sender, clientID, content} {
		canon.Text(buffer, value)
	}
	sum := sha256.Sum256(buffer.Bytes())
	return "msg_" + hex.EncodeToString(sum[:])
}

// DeriveMessageID binds the opaque Relay record to its room, sender,
// idempotency key, and exact ciphertext content.
func DeriveMessageID(roomID, sender, clientID, content string) string {
	return deriveMessageID(roomID, sender, clientID, content)
}

func normalizeMembers(members []string) ([]string, error) {
	if len(members) < 2 || len(members) > MaxMembers {
		return nil, errors.New("invalid member count")
	}
	result := append([]string(nil), members...)
	sort.Strings(result)
	for i, member := range result {
		if !agentPattern.MatchString(member) || (i > 0 && result[i-1] == member) {
			return nil, errors.New("invalid room member")
		}
	}
	return result, nil
}

// persist reports whether the destination file was already replaced. Callers
// must not roll back in-memory state after replacement: a directory-sync
// failure is an ambiguous durability result, and keeping memory aligned with
// the visible file lets an idempotent retry converge safely.
func (h *Hub) persist() (bool, error) {
	encoded, err := json.Marshal(h.state)
	if err != nil {
		return false, err
	}
	dir := filepath.Dir(h.path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return false, err
	}
	temporary, err := os.CreateTemp(dir, ".lab-group-*.tmp")
	if err != nil {
		return false, err
	}
	name := temporary.Name()
	defer os.Remove(name)
	if err := temporary.Chmod(0o600); err != nil {
		temporary.Close()
		return false, err
	}
	if _, err := temporary.Write(encoded); err != nil {
		temporary.Close()
		return false, err
	}
	if err := temporary.Sync(); err != nil {
		temporary.Close()
		return false, err
	}
	if err := temporary.Close(); err != nil {
		return false, err
	}
	if err := os.Rename(name, h.path); err != nil {
		return false, err
	}
	directory, err := os.Open(dir)
	if err != nil {
		return true, err
	}
	defer directory.Close()
	return true, directory.Sync()
}

func validateState(s state) error {
	if s.Schema != StateSchema || s.Rooms == nil || s.TokenHashes == nil || s.NextSequence == 0 || len(s.Rooms) > MaxRooms || len(s.Messages) > MaxMessages {
		return errors.New("invalid lab group state")
	}
	for id, hash := range s.TokenHashes {
		decoded, err := hex.DecodeString(hash)
		if !agentPattern.MatchString(id) || err != nil || len(decoded) != sha256.Size {
			return errors.New("invalid lab group credential state")
		}
	}
	for id, room := range s.Rooms {
		members, err := normalizeMembers(room.Members)
		if err != nil || id != room.RoomID || !roomPattern.MatchString(id) || strings.TrimSpace(room.Label) == "" ||
			len(room.Label) > 128 || strings.ContainsRune(room.Label, 0) || deriveRoomID(room.Label, members) != room.RoomID ||
			!contains(members, room.CreatedBy) || room.CreatedAtUnix == 0 {
			return errors.New("invalid lab room state")
		}
		for _, member := range members {
			if _, known := s.TokenHashes[member]; !known {
				return errors.New("invalid lab room member state")
			}
		}
	}
	var prior uint64
	for _, message := range s.Messages {
		room, found := s.Rooms[message.RoomID]
		if message.Sequence <= prior || message.Sequence >= s.NextSequence || !found || !clientPattern.MatchString(message.ClientID) ||
			len(message.Content) == 0 || len(message.Content) > MaxContentBytes || message.CreatedAtUnix == 0 ||
			!contains(room.Members, message.SenderAgentID) || deriveMessageID(message.RoomID, message.SenderAgentID, message.ClientID, message.Content) != message.MessageID {
			return errors.New("invalid lab message state")
		}
		prior = message.Sequence
	}
	return nil
}

func decodeBody(w http.ResponseWriter, r *http.Request, target any) bool {
	r.Body = http.MaxBytesReader(w, r.Body, MaxContentBytes+4096)
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
func contains(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}
func equalStringMap(a, b map[string]string) bool {
	if len(a) != len(b) {
		return false
	}
	for k, v := range a {
		if b[k] != v {
			return false
		}
	}
	return true
}
func defaultString(value, fallback string) string {
	if value == "" {
		return fallback
	}
	return value
}
