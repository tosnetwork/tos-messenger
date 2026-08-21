package publicchannel

import (
	"bytes"
	"errors"
	"sort"
	"time"

	"github.com/tosnetwork/tos-messenger/internal/canon"
	"github.com/tosnetwork/tos-messenger/pkg/identity"
)

const (
	MaxHistoryEvents = 65_536
	MaxHistoryBytes  = 64 << 20
)

// History is a verified complete event set. Events use deterministic display
// order only; that order grants no role or causal authority.
type History struct {
	channelID     string
	profileDigest string
	events        []Event
	tips          []string
	digest        string
}

func (h History) ChannelID() string     { return h.channelID }
func (h History) ProfileDigest() string { return h.profileDigest }
func (h History) Digest() string        { return h.digest }
func (h History) Events() []Event {
	result := make([]Event, len(h.events))
	for index, event := range h.events {
		result[index] = cloneEvent(event)
	}
	return result
}
func (h History) Tips() []string { return append([]string(nil), h.tips...) }

// MissingReferences reports the exact content IDs a partial replica must
// fetch before it can verify a complete history. It never guesses ranges or
// trusts a Relay's claim that a gap is unavailable.
func MissingReferences(events []Event) ([]string, error) {
	known := make(map[string]struct{}, len(events))
	for _, event := range events {
		event = cloneEvent(event)
		id, err := event.ID()
		if err != nil {
			return nil, err
		}
		if _, duplicate := known[id]; duplicate {
			return nil, errors.New("duplicate public channel Event")
		}
		known[id] = struct{}{}
	}
	missing := map[string]struct{}{}
	for _, event := range events {
		for _, reference := range event.Parents {
			if _, found := known[reference]; !found {
				missing[reference] = struct{}{}
			}
		}
		if event.TargetEventID != "" {
			if _, found := known[event.TargetEventID]; !found {
				missing[event.TargetEventID] = struct{}{}
			}
		}
	}
	result := make([]string, 0, len(missing))
	for id := range missing {
		result = append(result, id)
	}
	sort.Strings(result)
	return result, nil
}

// VerifyHistory validates profile authority, every publisher signature, each
// per-publisher sequence, all causal references, moderation targets and the
// bounded complete set. Input/Relay arrival order does not affect the result.
func VerifyHistory(profile Profile, events []Event, authority identity.Delegation,
	delegations map[string]identity.Delegation, now time.Time) (History, error) {
	if len(events) == 0 || len(events) > MaxHistoryEvents {
		return History{}, errors.New("public channel history count is outside its bound")
	}
	if err := VerifyProfile(profile, authority, delegations, now); err != nil {
		return History{}, err
	}
	profileDigest, _ := profile.Digest()
	type item struct {
		id    string
		event Event
	}
	items := make([]item, 0, len(events))
	byID := make(map[string]Event, len(events))
	total := 0
	for _, event := range events {
		delegation, found := delegations[event.PublisherEndpointID]
		if !found {
			return History{}, errors.New("missing public channel publisher delegation")
		}
		if err := VerifyEvent(event, profile, delegation, now); err != nil {
			return History{}, err
		}
		id, _ := event.ID()
		if _, duplicate := byID[id]; duplicate {
			return History{}, errors.New("duplicate public channel Event")
		}
		total += len(event.Content)
		if total > MaxHistoryBytes {
			return History{}, errors.New("public channel history bytes exceed their bound")
		}
		byID[id] = event
		items = append(items, item{id: id, event: event})
	}
	missing, err := MissingReferences(events)
	if err != nil || len(missing) != 0 {
		return History{}, errors.New("public channel history has missing references")
	}
	for _, item := range items {
		for _, parentID := range item.event.Parents {
			parent := byID[parentID]
			if parent.PublishedAtUnix > item.event.PublishedAtUnix {
				return History{}, errors.New("public channel Event cites a future parent")
			}
		}
		if item.event.TargetEventID != "" {
			target := byID[item.event.TargetEventID]
			if target.Kind != KindPost || target.PublishedAtUnix > item.event.PublishedAtUnix {
				return History{}, errors.New("public channel moderation target is invalid")
			}
		}
	}
	byPublisher := map[string][]item{}
	for _, item := range items {
		key := item.event.PublisherAgentID + "\x00" + item.event.PublisherEndpointID
		byPublisher[key] = append(byPublisher[key], item)
	}
	for _, chain := range byPublisher {
		sort.Slice(chain, func(i, j int) bool { return chain[i].event.Sequence < chain[j].event.Sequence })
		for index, item := range chain {
			expected := uint64(index + 1)
			if item.event.Sequence != expected || index > 0 && item.event.PreviousPublisherEventID != chain[index-1].id {
				return History{}, errors.New("public channel publisher sequence has a gap or fork")
			}
		}
	}
	sort.Slice(items, func(i, j int) bool {
		if items[i].event.PublishedAtUnix != items[j].event.PublishedAtUnix {
			return items[i].event.PublishedAtUnix < items[j].event.PublishedAtUnix
		}
		return items[i].id < items[j].id
	})
	ordered := make([]Event, 0, len(items))
	ids := make([]string, 0, len(items))
	referenced := make(map[string]struct{})
	for _, item := range items {
		ordered = append(ordered, item.event)
		ids = append(ids, item.id)
		for _, parent := range item.event.Parents {
			referenced[parent] = struct{}{}
		}
	}
	sortedIDs := append([]string(nil), ids...)
	sort.Strings(sortedIDs)
	tips := make([]string, 0)
	for _, id := range sortedIDs {
		if _, used := referenced[id]; !used {
			tips = append(tips, id)
		}
	}
	digest := historyDigest(profile.ChannelID, profileDigest, sortedIDs)
	return History{channelID: profile.ChannelID, profileDigest: profileDigest,
		events: ordered, tips: tips, digest: digest}, nil
}

// VisiblePosts applies moderation deterministically after verification. The
// latest `(published_at,event_id)` moderation wins; immutable source Events are
// retained in History regardless of presentation.
func (h History) VisiblePosts() ([]Event, error) {
	if !channelPattern.MatchString(h.channelID) || !canon.ValidDigest(h.profileDigest) || !canon.ValidDigest(h.digest) {
		return nil, errors.New("invalid verified public channel history")
	}
	states := map[string]EventKind{}
	ids := make([]string, len(h.events))
	for index, event := range h.events {
		id, err := event.ID()
		if err != nil {
			return nil, err
		}
		ids[index] = id
		if event.Kind == KindHide || event.Kind == KindRestore {
			states[event.TargetEventID] = event.Kind
		}
	}
	sortedIDs := append([]string(nil), ids...)
	sort.Strings(sortedIDs)
	if historyDigest(h.channelID, h.profileDigest, sortedIDs) != h.digest {
		return nil, errors.New("verified public channel history was altered")
	}
	visible := make([]Event, 0)
	for index, event := range h.events {
		if event.Kind == KindPost && states[ids[index]] != KindHide {
			visible = append(visible, cloneEvent(event))
		}
	}
	return visible, nil
}

func cloneEvent(event Event) Event {
	event.Parents = append([]string(nil), event.Parents...)
	event.Content = append([]byte(nil), event.Content...)
	event.PublisherSignature = append([]byte(nil), event.PublisherSignature...)
	return event
}

func historyDigest(channelID, profileDigest string, eventIDs []string) string {
	b := bytes.NewBufferString(canon.DomainPublicChannelHistory)
	canon.Text(b, channelID)
	canon.Text(b, profileDigest)
	canon.Uint32(b, uint32(len(eventIDs)))
	for _, id := range eventIDs {
		canon.Text(b, id)
	}
	return canon.Digest(b.Bytes())
}
