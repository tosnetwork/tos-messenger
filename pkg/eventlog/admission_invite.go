package eventlog

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"time"

	"github.com/tosnetwork/tos-messenger/internal/canon"
	"github.com/tosnetwork/tos-messenger/internal/ids"
)

const (
	admissionInviteDir          = "admission-invites"
	AdmissionInviteRecordSchema = "tos.messaging.admission-invite-record.v1"
	AdmissionInvitePrefix       = "invite_"
	MaxAdmissionInvites         = 4096
	MaxAdmissionInviteLifetime  = 30 * 24 * time.Hour
)

var ErrAdmissionInviteSpent = errors.New("admission invite is already bound to another event")

// CheckAdmissionInvite verifies that an unclaimed bearer is live and scoped
// to the authenticated sender without consuming it. Callers use this before
// parsing an admitted payload, then ClaimAdmissionInvite immediately before
// accepting the event durably. Claim repeats every check under the journal's
// single-writer lock, so this method is never an authorization by itself.
func (j *Journal) CheckAdmissionInvite(
	token, recipientEndpointID, senderAgentID, eventID string,
	now time.Time,
) error {
	if err := j.usable(); err != nil {
		return err
	}
	raw, err := decodeAdmissionInvite(token)
	if err != nil || !ids.Endpoint.MatchString(recipientEndpointID) ||
		!ids.Agent.MatchString(senderAgentID) || !ids.Event.MatchString(eventID) ||
		now.IsZero() || now.Unix() < 0 {
		return errors.New("invalid admission invite check")
	}
	digest := admissionInviteDigest(raw)
	j.mutex.Lock()
	defer j.mutex.Unlock()
	record, found, err := j.readAdmissionInvite(digest)
	if err != nil {
		return err
	}
	if !found || record.RecipientEndpointID != recipientEndpointID ||
		(record.InvitedAgentID != "" && record.InvitedAgentID != senderAgentID) {
		return errors.New("admission invite is unknown or out of scope")
	}
	if record.ClaimedEventID != "" {
		if record.ClaimedEventID == eventID && record.ClaimedSenderAgentID == senderAgentID {
			return nil
		}
		return ErrAdmissionInviteSpent
	}
	if uint64(now.Unix()) >= record.ExpiresAtUnix {
		return errors.New("admission invite expired")
	}
	return nil
}

// AdmissionInviteRecord is the recipient-private state of one random bearer.
// InviteDigest is a domain-separated SHA-256 digest; the token never lands on
// disk. An optional invited Agent narrows who may spend it without revealing
// that identity to a Relay carrying the opaque token.
type AdmissionInviteRecord struct {
	Schema               string `json:"schema"`
	InviteDigest         string `json:"invite_digest"`
	RecipientEndpointID  string `json:"recipient_messaging_endpoint_id"`
	InvitedAgentID       string `json:"invited_agent_id,omitempty"`
	ExpiresAtUnix        uint64 `json:"expires_at_unix"`
	CreatedAtUnix        uint64 `json:"created_at_unix"`
	ClaimedEventID       string `json:"claimed_event_id,omitempty"`
	ClaimedSenderAgentID string `json:"claimed_sender_agent_id,omitempty"`
	ClaimedAtUnix        uint64 `json:"claimed_at_unix,omitempty"`
}

// CreateAdmissionInvite persists only a digest of caller-generated 256-bit
// entropy and returns the opaque bearer for out-of-band delivery.
func (j *Journal) CreateAdmissionInvite(
	entropy [32]byte,
	recipientEndpointID, invitedAgentID string,
	expires time.Time,
	now time.Time,
) (string, AdmissionInviteRecord, error) {
	if err := j.usable(); err != nil {
		return "", AdmissionInviteRecord{}, err
	}
	if canon.IsZero(entropy[:]) || !ids.Endpoint.MatchString(recipientEndpointID) ||
		(invitedAgentID != "" && !ids.Agent.MatchString(invitedAgentID)) ||
		now.IsZero() || now.Unix() < 0 || expires.IsZero() || !expires.After(now) ||
		expires.Sub(now) > MaxAdmissionInviteLifetime {
		return "", AdmissionInviteRecord{}, errors.New("invalid admission invite")
	}
	token := AdmissionInvitePrefix + base64.RawURLEncoding.EncodeToString(entropy[:])
	digest := admissionInviteDigest(entropy[:])
	j.mutex.Lock()
	defer j.mutex.Unlock()
	if err := j.sweepAdmissionInvites(uint64(now.Unix())); err != nil {
		return "", AdmissionInviteRecord{}, err
	}
	existing, found, err := j.readAdmissionInvite(digest)
	if err != nil {
		return "", AdmissionInviteRecord{}, err
	}
	if found {
		if existing.RecipientEndpointID != recipientEndpointID || existing.InvitedAgentID != invitedAgentID ||
			existing.ExpiresAtUnix != uint64(expires.Unix()) {
			return "", AdmissionInviteRecord{}, ErrConflict
		}
		return token, existing, nil
	}
	entries, err := os.ReadDir(filepath.Join(j.root, admissionInviteDir))
	if err != nil {
		return "", AdmissionInviteRecord{}, errors.New("read admission invites")
	}
	if len(entries) >= MaxAdmissionInvites {
		return "", AdmissionInviteRecord{}, errors.New("admission invite ledger is full")
	}
	record := AdmissionInviteRecord{
		Schema: AdmissionInviteRecordSchema, InviteDigest: digest,
		RecipientEndpointID: recipientEndpointID, InvitedAgentID: invitedAgentID,
		ExpiresAtUnix: uint64(expires.Unix()), CreatedAtUnix: uint64(now.Unix()),
	}
	encoded, err := json.Marshal(record)
	if err != nil {
		return "", AdmissionInviteRecord{}, err
	}
	if err := j.replace(j.admissionInvitePath(digest), encoded); err != nil {
		return "", AdmissionInviteRecord{}, err
	}
	return token, record, nil
}

// ClaimAdmissionInvite atomically binds a bearer to the first authenticated
// sender and Event ID. An exact retry is idempotent, including after token
// expiry while the replay record is retained; a different event never reuses
// the authority.
func (j *Journal) ClaimAdmissionInvite(
	token, recipientEndpointID, senderAgentID, eventID string,
	now time.Time,
) (bool, error) {
	if err := j.usable(); err != nil {
		return false, err
	}
	raw, err := decodeAdmissionInvite(token)
	if err != nil || !ids.Endpoint.MatchString(recipientEndpointID) ||
		!ids.Agent.MatchString(senderAgentID) || !ids.Event.MatchString(eventID) || now.IsZero() || now.Unix() < 0 {
		return false, errors.New("invalid admission invite claim")
	}
	digest := admissionInviteDigest(raw)
	j.mutex.Lock()
	defer j.mutex.Unlock()
	record, found, err := j.readAdmissionInvite(digest)
	if err != nil {
		return false, err
	}
	if !found || record.RecipientEndpointID != recipientEndpointID ||
		(record.InvitedAgentID != "" && record.InvitedAgentID != senderAgentID) {
		return false, errors.New("admission invite is unknown or out of scope")
	}
	if record.ClaimedEventID != "" {
		if record.ClaimedEventID == eventID && record.ClaimedSenderAgentID == senderAgentID {
			return false, nil
		}
		return false, ErrAdmissionInviteSpent
	}
	if uint64(now.Unix()) >= record.ExpiresAtUnix {
		return false, errors.New("admission invite expired")
	}
	record.ClaimedEventID = eventID
	record.ClaimedSenderAgentID = senderAgentID
	record.ClaimedAtUnix = uint64(now.Unix())
	encoded, err := json.Marshal(record)
	if err != nil {
		return false, err
	}
	if err := j.replace(j.admissionInvitePath(digest), encoded); err != nil {
		return false, err
	}
	return true, nil
}

func decodeAdmissionInvite(token string) ([]byte, error) {
	if len(token) != len(AdmissionInvitePrefix)+base64.RawURLEncoding.EncodedLen(32) ||
		token[:len(AdmissionInvitePrefix)] != AdmissionInvitePrefix {
		return nil, errors.New("invalid admission invite encoding")
	}
	raw, err := base64.RawURLEncoding.Strict().DecodeString(token[len(AdmissionInvitePrefix):])
	if err != nil || len(raw) != 32 || canon.IsZero(raw) {
		return nil, errors.New("invalid admission invite encoding")
	}
	return raw, nil
}

func admissionInviteDigest(raw []byte) string {
	buffer := bytes.NewBufferString(canon.DomainAdmissionInvite)
	canon.Bytes(buffer, raw)
	return canon.Digest(buffer.Bytes())
}

func (j *Journal) admissionInvitePath(digest string) string {
	return filepath.Join(j.root, admissionInviteDir, digest[len("sha256:"):]+".json")
}

func (j *Journal) readAdmissionInvite(digest string) (AdmissionInviteRecord, bool, error) {
	if !canon.ValidDigest(digest) {
		return AdmissionInviteRecord{}, false, errors.New("invalid admission invite digest")
	}
	raw, err := os.ReadFile(j.admissionInvitePath(digest))
	if errors.Is(err, os.ErrNotExist) {
		return AdmissionInviteRecord{}, false, nil
	}
	if err != nil || len(raw) > MaxRecordBytes {
		return AdmissionInviteRecord{}, false, errors.New("read admission invite")
	}
	var record AdmissionInviteRecord
	if err := json.Unmarshal(raw, &record); err != nil || record.Schema != AdmissionInviteRecordSchema ||
		record.InviteDigest != digest || !ids.Endpoint.MatchString(record.RecipientEndpointID) ||
		(record.InvitedAgentID != "" && !ids.Agent.MatchString(record.InvitedAgentID)) ||
		record.CreatedAtUnix == 0 || record.ExpiresAtUnix <= record.CreatedAtUnix ||
		record.ExpiresAtUnix-record.CreatedAtUnix > uint64(MaxAdmissionInviteLifetime/time.Second) ||
		(record.ClaimedEventID == "") != (record.ClaimedSenderAgentID == "") ||
		(record.ClaimedEventID == "") != (record.ClaimedAtUnix == 0) ||
		(record.ClaimedEventID != "" && (!ids.Event.MatchString(record.ClaimedEventID) ||
			!ids.Agent.MatchString(record.ClaimedSenderAgentID) || record.ClaimedAtUnix < record.CreatedAtUnix ||
			record.ClaimedAtUnix >= record.ExpiresAtUnix)) {
		return AdmissionInviteRecord{}, false, errors.New("invalid admission invite record")
	}
	return record, true, nil
}

func (j *Journal) sweepAdmissionInvites(now uint64) error {
	entries, err := os.ReadDir(filepath.Join(j.root, admissionInviteDir))
	if err != nil {
		return errors.New("read admission invites")
	}
	removed := false
	for _, entry := range entries {
		if entry.IsDir() || filepath.Ext(entry.Name()) != ".json" {
			continue
		}
		digest := "sha256:" + entry.Name()[:len(entry.Name())-len(".json")]
		record, found, err := j.readAdmissionInvite(digest)
		if err != nil {
			return err
		}
		retainUntil := record.ExpiresAtUnix
		if record.ClaimedAtUnix != 0 && record.ClaimedAtUnix+uint64(MinClaimRetention/time.Second) > retainUntil {
			retainUntil = record.ClaimedAtUnix + uint64(MinClaimRetention/time.Second)
		}
		if found && retainUntil <= now {
			if err := os.Remove(j.admissionInvitePath(digest)); err != nil {
				return errors.New("remove expired admission invite")
			}
			removed = true
		}
	}
	if removed {
		return syncDirectory(filepath.Join(j.root, admissionInviteDir))
	}
	return nil
}
