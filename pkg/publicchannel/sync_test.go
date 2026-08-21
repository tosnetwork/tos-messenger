package publicchannel

import (
	"encoding/json"
	"errors"
	"sort"
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
