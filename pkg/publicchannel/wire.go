package publicchannel

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"

	"github.com/tosnetwork/tos-messenger/internal/canon"
	nativev1 "github.com/tosnetwork/tos-service-protocol/gen/tos/service/v1"
)

const (
	HeadSchema      = "tos.messaging.public-channel-head.v1"
	MaxProfileBytes = 64 << 10
	MaxEventBytes   = 128 << 10
	MaxHeadBytes    = 8 << 10
)

type wireProfile struct {
	Schema                   string                  `json:"schema"`
	Network                  *nativev1.NetworkDomain `json:"network"`
	ChannelID                string                  `json:"channel_id"`
	Epoch                    uint64                  `json:"epoch"`
	PreviousProfileDigest    string                  `json:"previous_profile_digest,omitempty"`
	AuthorityAgentID         string                  `json:"authority_agent_id"`
	AuthorityEndpointID      string                  `json:"authority_messaging_endpoint_id"`
	Principals               []Principal             `json:"principals"`
	IssuedAtUnix             uint64                  `json:"issued_at_unix"`
	ExpiresAtUnix            uint64                  `json:"expires_at_unix"`
	AuthoritySignatureBase64 string                  `json:"authority_signature_base64"`
}

type wireEvent struct {
	Schema                   string    `json:"schema"`
	EventID                  string    `json:"event_id"`
	ChannelID                string    `json:"channel_id"`
	ProfileDigest            string    `json:"profile_digest"`
	PublisherAgentID         string    `json:"publisher_agent_id"`
	PublisherEndpointID      string    `json:"publisher_messaging_endpoint_id"`
	Sequence                 uint64    `json:"publisher_sequence"`
	PreviousPublisherEventID string    `json:"previous_publisher_event_id,omitempty"`
	Parents                  []string  `json:"causal_parents,omitempty"`
	PublishedAtUnix          uint64    `json:"published_at_unix"`
	Kind                     EventKind `json:"kind"`
	TargetEventID            string    `json:"target_event_id,omitempty"`
	MediaType                string    `json:"media_type,omitempty"`
	ContentBase64            string    `json:"content_base64,omitempty"`
	PublisherSignatureBase64 string    `json:"publisher_signature_base64"`
}

// Head is a compact claim about one complete event set. A consumer verifies
// it only by fetching Events, running VerifyHistory, and matching every field.
type Head struct {
	Schema        string   `json:"schema"`
	ChannelID     string   `json:"channel_id"`
	ProfileDigest string   `json:"profile_digest"`
	EventCount    uint32   `json:"event_count"`
	Tips          []string `json:"tips"`
	HistoryDigest string   `json:"history_digest"`
}

func (h History) Head() Head {
	return Head{Schema: HeadSchema, ChannelID: h.channelID, ProfileDigest: h.profileDigest,
		EventCount: uint32(len(h.events)), Tips: h.Tips(), HistoryDigest: h.digest}
}

func (h Head) Matches(history History) bool {
	if validateHead(h) != nil {
		return false
	}
	expected := history.Head()
	return h.ChannelID == expected.ChannelID && h.ProfileDigest == expected.ProfileDigest &&
		h.EventCount == expected.EventCount && h.HistoryDigest == expected.HistoryDigest &&
		equalStrings(h.Tips, expected.Tips)
}

func EncodeProfileJSON(profile Profile) ([]byte, error) {
	if err := validateProfile(profile, true); err != nil {
		return nil, err
	}
	raw, err := json.Marshal(wireProfile{Schema: ProfileSchema, Network: profile.Network,
		ChannelID: profile.ChannelID, Epoch: profile.Epoch, PreviousProfileDigest: profile.PreviousProfileDigest,
		AuthorityAgentID:    profile.AuthorityAgentID,
		AuthorityEndpointID: profile.AuthorityEndpointID, Principals: profile.Principals,
		IssuedAtUnix: profile.IssuedAtUnix, ExpiresAtUnix: profile.ExpiresAtUnix,
		AuthoritySignatureBase64: base64.RawStdEncoding.EncodeToString(profile.AuthoritySignature)})
	if err != nil || len(raw) > MaxProfileBytes {
		return nil, errors.New("encode public channel profile")
	}
	return raw, nil
}

func DecodeProfileJSON(raw []byte) (Profile, error) {
	if len(raw) == 0 || len(raw) > MaxProfileBytes {
		return Profile{}, errors.New("public channel profile wire is outside its bound")
	}
	var wire wireProfile
	if err := strictJSON(raw, &wire); err != nil || wire.Schema != ProfileSchema {
		return Profile{}, errors.New("decode public channel profile")
	}
	signature, err := base64.RawStdEncoding.Strict().DecodeString(wire.AuthoritySignatureBase64)
	if err != nil {
		return Profile{}, errors.New("decode public channel profile signature")
	}
	profile := Profile{Network: wire.Network, ChannelID: wire.ChannelID, Epoch: wire.Epoch,
		PreviousProfileDigest: wire.PreviousProfileDigest,
		AuthorityAgentID:      wire.AuthorityAgentID, AuthorityEndpointID: wire.AuthorityEndpointID,
		Principals: wire.Principals, IssuedAtUnix: wire.IssuedAtUnix, ExpiresAtUnix: wire.ExpiresAtUnix,
		AuthoritySignature: signature}
	if err := validateProfile(profile, true); err != nil {
		return Profile{}, err
	}
	return profile, nil
}

func EncodeEventJSON(event Event) ([]byte, error) {
	if err := validateEvent(event, true); err != nil {
		return nil, err
	}
	id, _ := event.ID()
	raw, err := json.Marshal(wireEvent{Schema: EventSchema, EventID: id, ChannelID: event.ChannelID,
		ProfileDigest: event.ProfileDigest, PublisherAgentID: event.PublisherAgentID,
		PublisherEndpointID: event.PublisherEndpointID, Sequence: event.Sequence,
		PreviousPublisherEventID: event.PreviousPublisherEventID, Parents: event.Parents,
		PublishedAtUnix: event.PublishedAtUnix, Kind: event.Kind, TargetEventID: event.TargetEventID,
		MediaType: event.MediaType, ContentBase64: base64.RawStdEncoding.EncodeToString(event.Content),
		PublisherSignatureBase64: base64.RawStdEncoding.EncodeToString(event.PublisherSignature)})
	if err != nil || len(raw) > MaxEventBytes {
		return nil, errors.New("encode public channel Event")
	}
	return raw, nil
}

func DecodeEventJSON(raw []byte) (Event, error) {
	if len(raw) == 0 || len(raw) > MaxEventBytes {
		return Event{}, errors.New("public channel Event wire is outside its bound")
	}
	var wire wireEvent
	if err := strictJSON(raw, &wire); err != nil || wire.Schema != EventSchema || !publicEventPattern.MatchString(wire.EventID) {
		return Event{}, errors.New("decode public channel Event")
	}
	content, contentErr := base64.RawStdEncoding.Strict().DecodeString(wire.ContentBase64)
	signature, signatureErr := base64.RawStdEncoding.Strict().DecodeString(wire.PublisherSignatureBase64)
	if contentErr != nil || signatureErr != nil {
		return Event{}, errors.New("decode public channel Event body")
	}
	event := Event{ChannelID: wire.ChannelID, ProfileDigest: wire.ProfileDigest,
		PublisherAgentID: wire.PublisherAgentID, PublisherEndpointID: wire.PublisherEndpointID,
		Sequence: wire.Sequence, PreviousPublisherEventID: wire.PreviousPublisherEventID,
		Parents: wire.Parents, PublishedAtUnix: wire.PublishedAtUnix, Kind: wire.Kind,
		TargetEventID: wire.TargetEventID, MediaType: wire.MediaType, Content: content,
		PublisherSignature: signature}
	if err := validateEvent(event, true); err != nil {
		return Event{}, err
	}
	id, _ := event.ID()
	if id != wire.EventID {
		return Event{}, errors.New("public channel Event ID does not match its content")
	}
	return event, nil
}

func EncodeHeadJSON(head Head) ([]byte, error) {
	if err := validateHead(head); err != nil {
		return nil, err
	}
	raw, err := json.Marshal(head)
	if err != nil || len(raw) > MaxHeadBytes {
		return nil, errors.New("encode public channel head")
	}
	return raw, nil
}

func DecodeHeadJSON(raw []byte) (Head, error) {
	if len(raw) == 0 || len(raw) > MaxHeadBytes {
		return Head{}, errors.New("public channel head wire is outside its bound")
	}
	var head Head
	if err := strictJSON(raw, &head); err != nil || validateHead(head) != nil {
		return Head{}, errors.New("decode public channel head")
	}
	return head, nil
}

func validateHead(head Head) error {
	if head.Schema != HeadSchema || !channelPattern.MatchString(head.ChannelID) ||
		!canon.ValidDigest(head.ProfileDigest) || head.EventCount == 0 || head.EventCount > MaxHistoryEvents ||
		len(head.Tips) == 0 || len(head.Tips) > MaxPrincipals+MaxEventParents || !canon.ValidDigest(head.HistoryDigest) {
		return errors.New("invalid public channel head")
	}
	for index, tip := range head.Tips {
		if !publicEventPattern.MatchString(tip) || index > 0 && head.Tips[index-1] >= tip {
			return errors.New("invalid public channel head tips")
		}
	}
	return nil
}

func strictJSON(raw []byte, value any) error {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(value); err != nil {
		return err
	}
	if err := decoder.Decode(new(any)); !errors.Is(err, io.EOF) {
		return errors.New("public channel wire has trailing JSON")
	}
	return nil
}

func equalStrings(first, second []string) bool {
	if len(first) != len(second) {
		return false
	}
	for index := range first {
		if first[index] != second[index] {
			return false
		}
	}
	return true
}
