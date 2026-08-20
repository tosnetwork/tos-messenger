package eventlog

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"time"

	"github.com/tosnetwork/tos-messenger/internal/canon"
	"github.com/tosnetwork/tos-messenger/internal/ids"
)

const (
	agentPacketDir             = "agent-packets"
	AgentPacketRecordSchema    = "tos.messaging.agent-packet-record.v1"
	MaxAgentPacketRecords      = 4096
	MaxCarriedAgentPacketBytes = 128 << 10
	MaxAgentPacketClaimSeconds = 8 * 24 * 60 * 60
)

type AgentPacketRecord struct {
	Schema          string `json:"schema"`
	ClaimID         string `json:"claim_id"`
	SenderAgentID   string `json:"sender_agent_id"`
	NonceHex        string `json:"nonce_hex"`
	PacketDigest    string `json:"packet_digest"`
	PacketBase64    string `json:"packet_base64"`
	CreatedAtUnix   uint64 `json:"created_at_unix"`
	ExpiresAtUnix   uint64 `json:"expires_at_unix"`
	CompletedAtUnix uint64 `json:"completed_at_unix,omitempty"`
}

func (r AgentPacketRecord) Packet() ([]byte, error) {
	raw, err := base64.StdEncoding.Strict().DecodeString(r.PacketBase64)
	if err != nil || len(raw) == 0 || len(raw) > MaxCarriedAgentPacketBytes || canon.Digest(raw) != r.PacketDigest {
		return nil, errors.New("invalid stored Agent Packet")
	}
	return raw, nil
}

// ClaimAgentPacket durably records a verified packet before it reaches an
// execution adapter. Exact retry returns the pending/completed record; another
// packet wearing the same sender nonce is a conflict.
func (j *Journal) ClaimAgentPacket(sender string, nonce [32]byte, packet []byte, created, expires uint64, now time.Time) (AgentPacketRecord, bool, error) {
	if err := j.usable(); err != nil {
		return AgentPacketRecord{}, false, err
	}
	if !ids.Agent.MatchString(sender) || canon.IsZero(nonce[:]) || len(packet) == 0 || len(packet) > MaxCarriedAgentPacketBytes || created == 0 || expires <= created || expires-created > MaxAgentPacketClaimSeconds || now.IsZero() || now.Unix() < 0 || uint64(now.Unix()) >= expires {
		return AgentPacketRecord{}, false, errors.New("invalid Agent Packet claim")
	}
	claimID := agentPacketClaimID(sender, nonce)
	digest := canon.Digest(packet)
	j.mutex.Lock()
	defer j.mutex.Unlock()
	if err := j.sweepAgentPackets(uint64(now.Unix())); err != nil {
		return AgentPacketRecord{}, false, err
	}
	existing, found, err := j.readAgentPacket(claimID)
	if err != nil {
		return AgentPacketRecord{}, false, err
	}
	if found {
		raw, err := existing.Packet()
		if err != nil {
			return AgentPacketRecord{}, false, err
		}
		if existing.SenderAgentID != sender || existing.NonceHex != hex.EncodeToString(nonce[:]) || existing.PacketDigest != digest || !bytes.Equal(raw, packet) {
			return AgentPacketRecord{}, false, ErrConflict
		}
		return existing, false, nil
	}
	entries, err := os.ReadDir(filepath.Join(j.root, agentPacketDir))
	if err != nil {
		return AgentPacketRecord{}, false, errors.New("read Agent Packet claims")
	}
	if len(entries) >= MaxAgentPacketRecords {
		return AgentPacketRecord{}, false, errors.New("Agent Packet replay ledger is full")
	}
	record := AgentPacketRecord{Schema: AgentPacketRecordSchema, ClaimID: claimID, SenderAgentID: sender, NonceHex: hex.EncodeToString(nonce[:]), PacketDigest: digest, PacketBase64: base64.StdEncoding.EncodeToString(packet), CreatedAtUnix: created, ExpiresAtUnix: expires}
	encoded, err := json.Marshal(record)
	if err != nil {
		return AgentPacketRecord{}, false, err
	}
	if err := j.replace(j.agentPacketPath(claimID), encoded); err != nil {
		return AgentPacketRecord{}, false, err
	}
	return record, true, nil
}

func (j *Journal) CompleteAgentPacket(claimID, packetDigest string, now time.Time) error {
	if err := j.usable(); err != nil {
		return err
	}
	if !canon.ValidDigest(packetDigest) || now.IsZero() || now.Unix() < 0 {
		return errors.New("invalid Agent Packet completion")
	}
	j.mutex.Lock()
	defer j.mutex.Unlock()
	record, found, err := j.readAgentPacket(claimID)
	if err != nil {
		return err
	}
	if !found {
		return ErrUnknown
	}
	if record.PacketDigest != packetDigest {
		return ErrConflict
	}
	if record.CompletedAtUnix != 0 {
		return nil
	}
	if uint64(now.Unix()) < record.CreatedAtUnix || uint64(now.Unix()) >= record.ExpiresAtUnix {
		return errors.New("Agent Packet completion is outside its replay window")
	}
	record.CompletedAtUnix = uint64(now.Unix())
	encoded, err := json.Marshal(record)
	if err != nil {
		return err
	}
	return j.replace(j.agentPacketPath(claimID), encoded)
}

func agentPacketClaimID(sender string, nonce [32]byte) string {
	b := bytes.NewBufferString(canon.DomainAgentPacketClaim)
	canon.Text(b, sender)
	canon.Bytes(b, nonce[:])
	return canon.Digest(b.Bytes())
}
func (j *Journal) agentPacketPath(id string) string {
	return filepath.Join(j.root, agentPacketDir, id[len("sha256:"):]+".json")
}

func (j *Journal) readAgentPacket(id string) (AgentPacketRecord, bool, error) {
	if !canon.ValidDigest(id) {
		return AgentPacketRecord{}, false, errors.New("invalid Agent Packet claim identifier")
	}
	raw, err := os.ReadFile(j.agentPacketPath(id))
	if errors.Is(err, os.ErrNotExist) {
		return AgentPacketRecord{}, false, nil
	}
	if err != nil {
		return AgentPacketRecord{}, false, errors.New("read Agent Packet claim")
	}
	if len(raw) > MaxRecordBytes {
		return AgentPacketRecord{}, false, errors.New("Agent Packet claim exceeds its bound")
	}
	var record AgentPacketRecord
	if err := json.Unmarshal(raw, &record); err != nil {
		return AgentPacketRecord{}, false, errors.New("invalid Agent Packet claim")
	}
	nonce, err := hex.DecodeString(record.NonceHex)
	if err != nil || len(nonce) != 32 {
		return AgentPacketRecord{}, false, errors.New("invalid Agent Packet claim nonce")
	}
	var nonceValue [32]byte
	copy(nonceValue[:], nonce)
	if record.Schema != AgentPacketRecordSchema || record.ClaimID != id || record.ClaimID != agentPacketClaimID(record.SenderAgentID, nonceValue) || !ids.Agent.MatchString(record.SenderAgentID) || record.CreatedAtUnix == 0 || record.ExpiresAtUnix <= record.CreatedAtUnix || record.ExpiresAtUnix-record.CreatedAtUnix > MaxAgentPacketClaimSeconds || (record.CompletedAtUnix != 0 && (record.CompletedAtUnix < record.CreatedAtUnix || record.CompletedAtUnix >= record.ExpiresAtUnix)) {
		return AgentPacketRecord{}, false, errors.New("invalid Agent Packet claim binding")
	}
	if _, err := record.Packet(); err != nil {
		return AgentPacketRecord{}, false, err
	}
	return record, true, nil
}

func (j *Journal) sweepAgentPackets(now uint64) error {
	entries, err := os.ReadDir(filepath.Join(j.root, agentPacketDir))
	if err != nil {
		return errors.New("read Agent Packet claims")
	}
	removed := false
	for _, entry := range entries {
		if entry.IsDir() || filepath.Ext(entry.Name()) != ".json" {
			continue
		}
		id := "sha256:" + entry.Name()[:len(entry.Name())-len(".json")]
		record, found, err := j.readAgentPacket(id)
		if err != nil {
			return err
		}
		if found && record.ExpiresAtUnix <= now {
			if err := os.Remove(j.agentPacketPath(id)); err != nil {
				return errors.New("remove expired Agent Packet claim")
			}
			removed = true
		}
	}
	if removed {
		return syncDirectory(filepath.Join(j.root, agentPacketDir))
	}
	return nil
}
