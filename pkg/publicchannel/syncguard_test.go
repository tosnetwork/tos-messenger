package publicchannel

import (
	"strings"
	"testing"
	"time"
)

func TestPublicChannelSyncGuardCountsDistinctPeersWithoutGrantingAuthority(t *testing.T) {
	profile, authority, _, publisher, publisherKey, delegations := storeFixture(t)
	digest, _ := profile.Digest()
	event := signedPost(t, profile, digest, publisher, publisherKey, 1, "", nil, channelNow, "guard")
	history, err := VerifyHistory(profile, []Event{event}, authority, delegations, time.Unix(int64(channelNow+1), 0))
	if err != nil {
		t.Fatal(err)
	}
	limits := DefaultSyncLimits()
	limits.Peers = 2
	limits.CandidateHeadsPerPeer = 2
	guard, err := NewSyncGuard(profile.ChannelID, digest, limits)
	if err != nil {
		t.Fatal(err)
	}
	firstPeer := "peer_" + strings.Repeat("a", 64)
	secondPeer := "peer_" + strings.Repeat("b", 64)
	if err := guard.ObserveHead(firstPeer, history.Head()); err != nil {
		t.Fatal(err)
	}
	if err := guard.ObserveHead(firstPeer, history.Head()); err != nil {
		t.Fatalf("exact head replay consumed a claim: %v", err)
	}
	if candidates, err := guard.Candidates(2); err != nil || len(candidates) != 0 {
		t.Fatalf("one peer counted twice: candidates=%v err=%v", candidates, err)
	}
	if err := guard.ObserveHead(secondPeer, history.Head()); err != nil {
		t.Fatal(err)
	}
	candidates, err := guard.Candidates(2)
	if err != nil || len(candidates) != 1 || candidates[0].Support != 2 || !candidates[0].Head.Matches(history) {
		t.Fatalf("distinct peer support: candidates=%+v err=%v", candidates, err)
	}
	candidates[0].Head.Tips[0] = "pce_" + strings.Repeat("f", 64)
	again, _ := guard.Candidates(2)
	if !again[0].Head.Matches(history) {
		t.Fatal("caller mutated a guarded head")
	}
	if err := guard.ObserveHead("peer_"+strings.Repeat("c", 64), history.Head()); err == nil {
		t.Fatal("sync peer ceiling was bypassed")
	}
	falseHead := history.Head()
	falseHead.HistoryDigest = "sha256:" + strings.Repeat("f", 64)
	if err := guard.ObserveHead(firstPeer, falseHead); err != nil {
		t.Fatal(err)
	}
	candidates, err = guard.Candidates(1)
	if err != nil || len(candidates) != 2 || candidates[0].Support != 2 || candidates[1].Support != 1 {
		t.Fatalf("candidate priority: %+v err=%v", candidates, err)
	}
	if _, err := VerifySyncedHistory(falseHead, profile, []Event{event}, authority, delegations,
		time.Unix(int64(channelNow+1), 0)); err == nil {
		t.Fatal("peer support made a false head authoritative")
	}
}

func TestPublicChannelSyncGuardEnforcesPerAttemptWorkLimits(t *testing.T) {
	profile, authority, _, publisher, publisherKey, delegations := storeFixture(t)
	digest, _ := profile.Digest()
	event := signedPost(t, profile, digest, publisher, publisherKey, 1, "", nil, channelNow, "guard")
	history, err := VerifyHistory(profile, []Event{event}, authority, delegations, time.Unix(int64(channelNow+1), 0))
	if err != nil {
		t.Fatal(err)
	}
	limits := DefaultSyncLimits()
	limits.FetchesPerPeer = 3
	limits.UnavailablePerPeer = 1
	limits.ResponseBytesPerPeer = MaxFetchResponseBytes
	limits.TotalResponseBytes = MaxFetchResponseBytes
	guard, err := NewSyncGuard(profile.ChannelID, digest, limits)
	if err != nil {
		t.Fatal(err)
	}
	peer := "peer_" + strings.Repeat("d", 64)
	if err := guard.ObserveHead(peer, history.Head()); err != nil {
		t.Fatal(err)
	}
	if err := guard.ChargeFetch(peer, 1, 1); err != nil {
		t.Fatal(err)
	}
	if err := guard.ChargeFetch(peer, 1, 1); err == nil {
		t.Fatal("unavailable-result budget was bypassed")
	}
	if err := guard.ChargeFetch(peer, 1, 0); err != nil {
		t.Fatal(err)
	}
	if err := guard.ChargeFetch(peer, 1, 0); err == nil {
		t.Fatal("fetch-count budget was bypassed")
	}
	if err := guard.ChargeFetch("peer_"+strings.Repeat("e", 64), 1, 0); err == nil {
		t.Fatal("unobserved peer consumed sync resources")
	}
	if _, err := NewSyncGuard(profile.ChannelID, digest, SyncLimits{}); err == nil {
		t.Fatal("zero sync limits were accepted")
	}
}

func TestNativeCarrierInboundBudgetsAndAnnouncementReplay(t *testing.T) {
	profile, _, _, _, _, _ := storeFixture(t)
	digest, _ := profile.Digest()
	limits := DefaultSyncLimits()
	limits.FetchesPerPeer = 2
	limits.CandidateHeadsPerPeer = 1
	limits.UnavailablePerPeer = 1
	limits.ResponseBytesPerPeer = MaxFetchResponseBytes
	limits.TotalResponseBytes = MaxFetchResponseBytes
	guard, err := NewSyncGuard(profile.ChannelID, digest, limits)
	if err != nil {
		t.Fatal(err)
	}
	carrier := &NativeCarrier{guard: guard, seenHeads: map[string]struct{}{}, seenEvents: map[string]struct{}{}}
	if err := carrier.beginServeFetch(); err != nil {
		t.Fatal(err)
	}
	if err := carrier.chargeServeResponse(1, 1); err != nil {
		t.Fatal(err)
	}
	if err := carrier.beginServeFetch(); err != nil {
		t.Fatal(err)
	}
	if err := carrier.beginServeFetch(); err == nil {
		t.Fatal("silent inbound fetch bypassed its attempt ceiling")
	}
	if err := carrier.chargeServeResponse(1, 1); err == nil {
		t.Fatal("inbound unavailable response bypassed its ceiling")
	}
	if !carrier.claimAnnouncement("event-one", false) || carrier.claimAnnouncement("event-one", false) {
		t.Fatal("native Event announcement replay was not idempotent")
	}
	if !carrier.claimAnnouncement("head-one", true) || carrier.claimAnnouncement("head-one", true) ||
		carrier.claimAnnouncement("head-two", true) {
		t.Fatal("native head replay/distinct-head ceiling was not enforced")
	}
	carrier.releaseAnnouncement("event-one", false)
	if !carrier.claimAnnouncement("event-one", false) {
		t.Fatal("failed application callback could not retry its announcement")
	}
}
