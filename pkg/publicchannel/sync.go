package publicchannel

import (
	"encoding/json"
	"errors"
	"sort"
	"time"

	"github.com/tosnetwork/tos-messenger/internal/canon"
	"github.com/tosnetwork/tos-messenger/pkg/identity"
)

const (
	FetchRequestSchema    = "tos.messaging.public-channel-fetch-request.v1"
	FetchResponseSchema   = "tos.messaging.public-channel-fetch-response.v1"
	MaxFetchEvents        = 64
	MaxFetchRequestBytes  = 8 << 10
	MaxFetchResponseBytes = 9 << 20
)

var ErrSyncStalled = errors.New("public channel synchronization cannot discover the claimed history")

type FetchRequest struct {
	Schema        string   `json:"schema"`
	ChannelID     string   `json:"channel_id"`
	ProfileDigest string   `json:"profile_digest"`
	EventIDs      []string `json:"event_ids"`
}

type fetchResponse struct {
	Schema        string            `json:"schema"`
	ChannelID     string            `json:"channel_id"`
	ProfileDigest string            `json:"profile_digest"`
	Events        []json.RawMessage `json:"events"`
	Unavailable   []string          `json:"unavailable_event_ids"`
}

// NextFetch starts at the untrusted head's tips and recursively follows exact
// causal IDs. A head that claims more Events but exposes no next ID fails
// instead of granting a Relay completeness authority.
func NextFetch(head Head, known []Event) (FetchRequest, bool, error) {
	if err := validateHead(head); err != nil {
		return FetchRequest{}, false, err
	}
	if len(known) > int(head.EventCount) {
		return FetchRequest{}, false, errors.New("public channel sync exceeds the claimed Event count")
	}
	knownIDs := make(map[string]struct{}, len(known))
	for _, event := range known {
		if event.ChannelID != head.ChannelID || event.ProfileDigest != head.ProfileDigest {
			return FetchRequest{}, false, errors.New("public channel sync Event is bound to another head")
		}
		id, err := event.ID()
		if err != nil {
			return FetchRequest{}, false, err
		}
		if _, duplicate := knownIDs[id]; duplicate {
			return FetchRequest{}, false, errors.New("duplicate public channel sync Event")
		}
		knownIDs[id] = struct{}{}
	}
	if len(known) == int(head.EventCount) {
		return FetchRequest{}, false, nil
	}
	wanted := map[string]struct{}{}
	for _, tip := range head.Tips {
		if _, found := knownIDs[tip]; !found {
			wanted[tip] = struct{}{}
		}
	}
	missing, err := MissingReferences(known)
	if err != nil {
		return FetchRequest{}, false, err
	}
	for _, id := range missing {
		wanted[id] = struct{}{}
	}
	ids := make([]string, 0, len(wanted))
	for id := range wanted {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	if len(ids) == 0 {
		return FetchRequest{}, false, ErrSyncStalled
	}
	if len(ids) > MaxFetchEvents {
		ids = ids[:MaxFetchEvents]
	}
	return FetchRequest{Schema: FetchRequestSchema, ChannelID: head.ChannelID,
		ProfileDigest: head.ProfileDigest, EventIDs: ids}, true, nil
}

func EncodeFetchRequestJSON(request FetchRequest) ([]byte, error) {
	if err := validateFetchRequest(request); err != nil {
		return nil, err
	}
	raw, err := json.Marshal(request)
	if err != nil || len(raw) > MaxFetchRequestBytes {
		return nil, errors.New("encode public channel fetch request")
	}
	return raw, nil
}

func DecodeFetchRequestJSON(raw []byte) (FetchRequest, error) {
	if len(raw) == 0 || len(raw) > MaxFetchRequestBytes {
		return FetchRequest{}, errors.New("public channel fetch request is outside its bound")
	}
	var request FetchRequest
	if err := strictJSON(raw, &request); err != nil || validateFetchRequest(request) != nil {
		return FetchRequest{}, errors.New("decode public channel fetch request")
	}
	return request, nil
}

// EncodeFetchResponseJSON returns exactly one result for every requested ID.
// Unavailable is a retryable observation, never proof that history is complete.
func EncodeFetchResponseJSON(request FetchRequest, available map[string]Event) ([]byte, error) {
	if err := validateFetchRequest(request); err != nil {
		return nil, err
	}
	response := fetchResponse{Schema: FetchResponseSchema, ChannelID: request.ChannelID,
		ProfileDigest: request.ProfileDigest, Events: []json.RawMessage{}, Unavailable: []string{}}
	for _, id := range request.EventIDs {
		event, found := available[id]
		if !found {
			response.Unavailable = append(response.Unavailable, id)
			continue
		}
		actual, err := event.ID()
		if err != nil || actual != id || event.ChannelID != request.ChannelID || event.ProfileDigest != request.ProfileDigest {
			return nil, errors.New("public channel fetch object does not match its requested ID")
		}
		raw, err := EncodeEventJSON(event)
		if err != nil {
			return nil, err
		}
		response.Events = append(response.Events, raw)
	}
	raw, err := json.Marshal(response)
	if err != nil || len(raw) > MaxFetchResponseBytes {
		return nil, errors.New("encode public channel fetch response")
	}
	return raw, nil
}

// DecodeFetchResponseJSON checks the exact request partition and each Event's
// content ID/binding. Signatures remain caller-supplied-finality checks and are
// verified by VerifyFetchedEvents or VerifySyncedHistory.
func DecodeFetchResponseJSON(raw []byte, request FetchRequest) ([]Event, []string, error) {
	if validateFetchRequest(request) != nil || len(raw) == 0 || len(raw) > MaxFetchResponseBytes {
		return nil, nil, errors.New("invalid public channel fetch response input")
	}
	var response fetchResponse
	if err := strictJSON(raw, &response); err != nil || response.Schema != FetchResponseSchema ||
		response.ChannelID != request.ChannelID || response.ProfileDigest != request.ProfileDigest ||
		len(response.Events)+len(response.Unavailable) != len(request.EventIDs) {
		return nil, nil, errors.New("decode public channel fetch response")
	}
	requested := make(map[string]struct{}, len(request.EventIDs))
	for _, id := range request.EventIDs {
		requested[id] = struct{}{}
	}
	seen := make(map[string]struct{}, len(request.EventIDs))
	events := make([]Event, 0, len(response.Events))
	for _, object := range response.Events {
		event, err := DecodeEventJSON(object)
		if err != nil {
			return nil, nil, err
		}
		id, _ := event.ID()
		if _, wanted := requested[id]; !wanted || event.ChannelID != request.ChannelID ||
			event.ProfileDigest != request.ProfileDigest {
			return nil, nil, errors.New("public channel fetch returned an unrequested Event")
		}
		if _, duplicate := seen[id]; duplicate {
			return nil, nil, errors.New("public channel fetch returned a duplicate result")
		}
		seen[id] = struct{}{}
		events = append(events, event)
	}
	for index, id := range response.Unavailable {
		if _, wanted := requested[id]; !wanted || index > 0 && response.Unavailable[index-1] >= id {
			return nil, nil, errors.New("public channel fetch returned invalid unavailable IDs")
		}
		if _, duplicate := seen[id]; duplicate {
			return nil, nil, errors.New("public channel fetch returned a duplicate result")
		}
		seen[id] = struct{}{}
	}
	if len(seen) != len(requested) {
		return nil, nil, errors.New("public channel fetch response omitted a requested ID")
	}
	return events, append([]string(nil), response.Unavailable...), nil
}

func VerifyFetchedEvents(profile Profile, events []Event, authority identity.Delegation,
	delegations map[string]identity.Delegation, now time.Time) error {
	if err := VerifyProfile(profile, authority, delegations, now); err != nil {
		return err
	}
	for _, event := range events {
		delegation, found := delegations[event.PublisherEndpointID]
		if !found {
			return errors.New("missing public channel fetched-Event delegation")
		}
		if err := VerifyEvent(event, profile, delegation, now); err != nil {
			return err
		}
	}
	return nil
}

func MergeFetchedEvents(known, fetched []Event) ([]Event, error) {
	byID := make(map[string]Event, len(known)+len(fetched))
	for _, event := range append(append([]Event(nil), known...), fetched...) {
		id, err := event.ID()
		if err != nil {
			return nil, err
		}
		if _, duplicate := byID[id]; duplicate {
			continue
		}
		byID[id] = cloneEvent(event)
	}
	ids := make([]string, 0, len(byID))
	for id := range byID {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	merged := make([]Event, 0, len(ids))
	for _, id := range ids {
		merged = append(merged, byID[id])
	}
	return merged, nil
}

func VerifySyncedHistory(head Head, profile Profile, events []Event, authority identity.Delegation,
	delegations map[string]identity.Delegation, now time.Time) (History, error) {
	history, err := VerifyHistory(profile, events, authority, delegations, now)
	if err != nil || !head.Matches(history) {
		return History{}, errors.New("public channel Events do not reproduce the claimed head")
	}
	return history, nil
}

func validateFetchRequest(request FetchRequest) error {
	if request.Schema != FetchRequestSchema || !channelPattern.MatchString(request.ChannelID) ||
		!canon.ValidDigest(request.ProfileDigest) || len(request.EventIDs) == 0 || len(request.EventIDs) > MaxFetchEvents {
		return errors.New("invalid public channel fetch request")
	}
	for index, id := range request.EventIDs {
		if !publicEventPattern.MatchString(id) || index > 0 && request.EventIDs[index-1] >= id {
			return errors.New("invalid public channel fetch request IDs")
		}
	}
	return nil
}
