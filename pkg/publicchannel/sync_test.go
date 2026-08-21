package publicchannel

import (
	"encoding/json"
	"errors"
	"sort"
	"strings"
	"testing"
	"time"
)

func TestPublicChannelSyncWalksUntrustedHeadByExactIDs(t *testing.T) {
	profile, authority, authorityKey, publisher, publisherKey, delegations := storeFixture(t)
	digest, _ := profile.Digest()
	first := signedPost(t, profile, digest, publisher, publisherKey, 1, "", nil, channelNow, "sync root")
	firstID, _ := first.ID()
	hide, err := SignEvent(Event{ChannelID: profile.ChannelID, ProfileDigest: digest,
		PublisherAgentID: authority.AgentID, PublisherEndpointID: authority.EndpointID,
		Sequence: 1, Parents: []string{firstID}, PublishedAtUnix: channelNow + 1,
		Kind: KindHide, TargetEventID: firstID}, authorityKey)
	if err != nil {
		t.Fatal(err)
	}
	hideID, _ := hide.ID()
	now := time.Unix(int64(channelNow+2), 0)
	want, err := VerifyHistory(profile, []Event{first, hide}, authority, delegations, now)
	if err != nil {
		t.Fatal(err)
	}
	head := want.Head()
	available := map[string]Event{firstID: first, hideID: hide}
	var known []Event

	request, needed, err := NextFetch(head, known)
	if err != nil || !needed || len(request.EventIDs) != 1 || request.EventIDs[0] != hideID {
		t.Fatalf("initial tip request: %+v needed=%v err=%v", request, needed, err)
	}
	requestRaw, err := EncodeFetchRequestJSON(request)
	if err != nil {
		t.Fatal(err)
	}
	request, err = DecodeFetchRequestJSON(requestRaw)
	if err != nil {
		t.Fatal(err)
	}
	responseRaw, err := EncodeFetchResponseJSON(request, available)
	if err != nil {
		t.Fatal(err)
	}
	fetched, unavailable, err := DecodeFetchResponseJSON(responseRaw, request)
	if err != nil || len(unavailable) != 0 || VerifyFetchedEvents(profile, fetched, authority, delegations, now) != nil {
		t.Fatalf("tip response: unavailable=%v err=%v", unavailable, err)
	}
	known, err = MergeFetchedEvents(known, fetched)
	if err != nil {
		t.Fatal(err)
	}
	request, needed, err = NextFetch(head, known)
	if err != nil || !needed || len(request.EventIDs) != 1 || request.EventIDs[0] != firstID {
		t.Fatalf("parent request: %+v needed=%v err=%v", request, needed, err)
	}

	retryRaw, err := EncodeFetchResponseJSON(request, map[string]Event{})
	if err != nil {
		t.Fatal(err)
	}
	fetched, unavailable, err = DecodeFetchResponseJSON(retryRaw, request)
	if err != nil || len(fetched) != 0 || len(unavailable) != 1 || unavailable[0] != firstID {
		t.Fatalf("retryable unavailable result: fetched=%d unavailable=%v err=%v", len(fetched), unavailable, err)
	}
	retry, needed, err := NextFetch(head, known)
	if err != nil || !needed || retry.EventIDs[0] != firstID {
		t.Fatalf("Relay unavailability became completeness authority: %+v err=%v", retry, err)
	}
	responseRaw, _ = EncodeFetchResponseJSON(request, available)
	fetched, _, err = DecodeFetchResponseJSON(responseRaw, request)
	if err != nil {
		t.Fatal(err)
	}
	known, err = MergeFetchedEvents(known, fetched)
	if err != nil {
		t.Fatal(err)
	}
	known, err = MergeFetchedEvents(known, fetched)
	if err != nil || len(known) != 2 {
		t.Fatalf("exact fetch replay was not idempotent: count=%d err=%v", len(known), err)
	}
	if _, needed, err = NextFetch(head, known); err != nil || needed {
		t.Fatalf("complete sync requested more Events: needed=%v err=%v", needed, err)
	}
	got, err := VerifySyncedHistory(head, profile, known, authority, delegations, now)
	if err != nil || got.Digest() != want.Digest() {
		t.Fatalf("synced history mismatch: digest=%q err=%v", got.Digest(), err)
	}
}

func TestPublicChannelSyncRefusesPartitionAndCompletenessSubstitution(t *testing.T) {
	profile, authority, authorityKey, publisher, publisherKey, delegations := storeFixture(t)
	digest, _ := profile.Digest()
	first := signedPost(t, profile, digest, publisher, publisherKey, 1, "", nil, channelNow, "root")
	firstID, _ := first.ID()
	hide, _ := SignEvent(Event{ChannelID: profile.ChannelID, ProfileDigest: digest,
		PublisherAgentID: authority.AgentID, PublisherEndpointID: authority.EndpointID,
		Sequence: 1, Parents: []string{firstID}, PublishedAtUnix: channelNow + 1,
		Kind: KindHide, TargetEventID: firstID}, authorityKey)
	hideID, _ := hide.ID()
	ids := []string{firstID, hideID}
	sort.Strings(ids)
	request := FetchRequest{Schema: FetchRequestSchema, ChannelID: profile.ChannelID, ProfileDigest: digest, EventIDs: ids}
	firstRaw, _ := EncodeEventJSON(first)
	duplicatePartition, _ := json.Marshal(fetchResponse{Schema: FetchResponseSchema, ChannelID: profile.ChannelID,
		ProfileDigest: digest, Events: []json.RawMessage{firstRaw}, Unavailable: []string{firstID}})
	if _, _, err := DecodeFetchResponseJSON(duplicatePartition, request); err == nil {
		t.Fatal("fetch response counted one ID as both returned and unavailable")
	}
	if _, err := DecodeFetchRequestJSON([]byte(`{"schema":"tos.messaging.public-channel-fetch-request.v1","unknown":true}`)); err == nil {
		t.Fatal("fetch request accepted an unknown field")
	}

	now := time.Unix(int64(channelNow+2), 0)
	history, err := VerifyHistory(profile, []Event{first, hide}, authority, delegations, now)
	if err != nil {
		t.Fatal(err)
	}
	falseHead := history.Head()
	falseHead.EventCount++
	if _, err := VerifySyncedHistory(falseHead, profile, []Event{first, hide}, authority, delegations, now); err == nil {
		t.Fatal("Event count substitution reproduced a head")
	}
	if _, _, err := NextFetch(falseHead, []Event{first, hide}); !errors.Is(err, ErrSyncStalled) {
		t.Fatalf("undiscoverable claimed Event error = %v", err)
	}
	forged := first
	forged.PublisherSignature = append([]byte(nil), hide.PublisherSignature...)
	if err := VerifyFetchedEvents(profile, []Event{forged}, authority, delegations, now); err == nil {
		t.Fatal("fetched publisher-signature substitution verified")
	}
}

func TestFetchCursorIncrementallyWalksCausalHistory(t *testing.T) {
	profile, authority, authorityKey, publisher, publisherKey, delegations := storeFixture(t)
	digest, _ := profile.Digest()
	first := signedPost(t, profile, digest, publisher, publisherKey, 1, "", nil, channelNow, "cursor root")
	firstID, _ := first.ID()
	hide, err := SignEvent(Event{ChannelID: profile.ChannelID, ProfileDigest: digest,
		PublisherAgentID: authority.AgentID, PublisherEndpointID: authority.EndpointID,
		Sequence: 1, Parents: []string{firstID}, PublishedAtUnix: channelNow + 1,
		Kind: KindHide, TargetEventID: firstID}, authorityKey)
	if err != nil {
		t.Fatal(err)
	}
	hideID, _ := hide.ID()
	now := time.Unix(int64(channelNow+2), 0)
	want, err := VerifyHistory(profile, []Event{hide, first}, authority, delegations, now)
	if err != nil {
		t.Fatal(err)
	}
	cursor, err := NewFetchCursor(want.Head(), nil)
	if err != nil {
		t.Fatal(err)
	}
	request, needed, err := cursor.Next()
	if err != nil || !needed || len(request.EventIDs) != 1 || request.EventIDs[0] != hideID {
		t.Fatalf("initial cursor request: %+v needed=%v err=%v", request, needed, err)
	}
	if err := cursor.Merge([]Event{hide}); err != nil {
		t.Fatal(err)
	}
	request, needed, err = cursor.Next()
	if err != nil || !needed || len(request.EventIDs) != 1 || request.EventIDs[0] != firstID {
		t.Fatalf("parent cursor request: %+v needed=%v err=%v", request, needed, err)
	}
	if err := cursor.Merge([]Event{first}); err != nil {
		t.Fatal(err)
	}
	if _, needed, err = cursor.Next(); err != nil || needed {
		t.Fatalf("complete cursor requested more Events: needed=%v err=%v", needed, err)
	}
	got, err := VerifySyncedHistory(want.Head(), profile, cursor.Events(), authority, delegations, now)
	if err != nil || got.Digest() != want.Digest() {
		t.Fatalf("cursor history mismatch: digest=%q err=%v", got.Digest(), err)
	}
}

func TestFetchCursorRefusesUnsolicitedDuplicateAndFalseHead(t *testing.T) {
	profile, authority, authorityKey, publisher, publisherKey, delegations := storeFixture(t)
	digest, _ := profile.Digest()
	first := signedPost(t, profile, digest, publisher, publisherKey, 1, "", nil, channelNow, "cursor root")
	firstID, _ := first.ID()
	hide, err := SignEvent(Event{ChannelID: profile.ChannelID, ProfileDigest: digest,
		PublisherAgentID: authority.AgentID, PublisherEndpointID: authority.EndpointID,
		Sequence: 1, Parents: []string{firstID}, PublishedAtUnix: channelNow + 1,
		Kind: KindHide, TargetEventID: firstID}, authorityKey)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Unix(int64(channelNow+2), 0)
	history, err := VerifyHistory(profile, []Event{first, hide}, authority, delegations, now)
	if err != nil {
		t.Fatal(err)
	}

	t.Run("unsolicited", func(t *testing.T) {
		cursor, err := NewFetchCursor(history.Head(), nil)
		if err != nil {
			t.Fatal(err)
		}
		if err := cursor.Merge([]Event{first}); err == nil {
			t.Fatal("cursor accepted an Event that was not requested")
		}
		if err := cursor.Merge([]Event{hide, first}); err == nil {
			t.Fatal("cursor accepted a batch containing an unrequested Event")
		}
		request, needed, err := cursor.Next()
		if err != nil || !needed {
			t.Fatalf("rejected batch mutated cursor: request=%+v needed=%v err=%v", request, needed, err)
		}
		hideID, _ := hide.ID()
		if len(request.EventIDs) != 1 || request.EventIDs[0] != hideID {
			t.Fatalf("rejected batch changed pending IDs: %+v", request.EventIDs)
		}
	})

	t.Run("duplicate", func(t *testing.T) {
		cursor, err := NewFetchCursor(history.Head(), nil)
		if err != nil {
			t.Fatal(err)
		}
		if err := cursor.Merge([]Event{hide}); err != nil {
			t.Fatal(err)
		}
		if err := cursor.Merge([]Event{hide}); err == nil {
			t.Fatal("cursor accepted a duplicate fetched Event")
		}
	})

	t.Run("wrong binding", func(t *testing.T) {
		cursor, err := NewFetchCursor(history.Head(), nil)
		if err != nil {
			t.Fatal(err)
		}
		wrong := hide
		wrong.ProfileDigest = "sha256:" + strings.Repeat("0", 64)
		if err := cursor.Merge([]Event{wrong}); err == nil {
			t.Fatal("cursor accepted an Event bound to another head")
		}
	})

	t.Run("count overflow", func(t *testing.T) {
		falseHead := history.Head()
		falseHead.EventCount = 1
		cursor, err := NewFetchCursor(falseHead, nil)
		if err != nil {
			t.Fatal(err)
		}
		if err := cursor.Merge([]Event{hide}); err != nil {
			t.Fatal(err)
		}
		if err := cursor.Merge([]Event{first}); err == nil {
			t.Fatal("cursor exceeded the head's claimed Event count")
		}
	})

	t.Run("stalled false head", func(t *testing.T) {
		falseHead := history.Head()
		falseHead.EventCount++
		cursor, err := NewFetchCursor(falseHead, history.Events())
		if err != nil {
			t.Fatal(err)
		}
		if _, _, err := cursor.Next(); !errors.Is(err, ErrSyncStalled) {
			t.Fatalf("false head error = %v", err)
		}
	})

	t.Run("duplicate known", func(t *testing.T) {
		if _, err := NewFetchCursor(history.Head(), []Event{first, first}); err == nil {
			t.Fatal("cursor accepted duplicate known Events")
		}
	})
}
