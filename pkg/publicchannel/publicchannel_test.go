package publicchannel

import (
	"bytes"
	"crypto/ed25519"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/tosnetwork/tos-messenger/pkg/identity"
	nativev1 "github.com/tosnetwork/tos-service-protocol/gen/tos/service/v1"
)

const channelNow = uint64(1_900_000_000)

func TestPublicChannelHistoryConvergesAndModerationIsPresentationOnly(t *testing.T) {
	network := channelNetwork()
	authority, authorityKey := channelDelegation(t, network, 'a')
	publisher, publisherKey := channelDelegation(t, network, 'b')
	channelID, err := DeriveID(network, authority.AgentID, authority.EndpointID, bytes.Repeat([]byte{7}, 32))
	if err != nil {
		t.Fatal(err)
	}
	principals := []Principal{
		{AgentID: authority.AgentID, EndpointID: authority.EndpointID, Publisher: true, Moderator: true},
		{AgentID: publisher.AgentID, EndpointID: publisher.EndpointID, Publisher: true},
	}
	sort.Slice(principals, func(i, j int) bool {
		return principals[i].AgentID+principals[i].EndpointID < principals[j].AgentID+principals[j].EndpointID
	})
	profile, err := SignProfile(Profile{Network: network, ChannelID: channelID, Epoch: 1,
		AuthorityAgentID: authority.AgentID, AuthorityEndpointID: authority.EndpointID,
		Principals: principals, IssuedAtUnix: channelNow - 10, ExpiresAtUnix: channelNow + 3600}, authorityKey)
	if err != nil {
		t.Fatal(err)
	}
	delegations := map[string]identity.Delegation{authority.EndpointID: authority, publisher.EndpointID: publisher}
	if err := VerifyProfile(profile, authority, delegations, time.Unix(int64(channelNow), 0)); err != nil {
		t.Fatal(err)
	}
	profileDigest, _ := profile.Digest()
	first := signedPost(t, profile, profileDigest, authority, authorityKey, 1, "", nil, channelNow, "authority post")
	firstID, _ := first.ID()
	second := signedPost(t, profile, profileDigest, publisher, publisherKey, 1, "", []string{firstID}, channelNow+1, "publisher post")
	secondID, _ := second.ID()
	parents := []string{firstID, secondID}
	sort.Strings(parents)
	hide, err := SignEvent(Event{ChannelID: channelID, ProfileDigest: profileDigest,
		PublisherAgentID: authority.AgentID, PublisherEndpointID: authority.EndpointID,
		Sequence: 2, PreviousPublisherEventID: firstID, Parents: parents, PublishedAtUnix: channelNow + 2,
		Kind: KindHide, TargetEventID: secondID}, authorityKey)
	if err != nil {
		t.Fatal(err)
	}

	one, err := VerifyHistory(profile, []Event{hide, first, second}, authority, delegations,
		time.Unix(int64(channelNow+3), 0))
	if err != nil {
		t.Fatal(err)
	}
	two, err := VerifyHistory(profile, []Event{second, hide, first}, authority, delegations,
		time.Unix(int64(channelNow+3), 0))
	if err != nil || one.Digest() != two.Digest() || len(one.Tips()) != 1 {
		t.Fatalf("arrival order changed history: one=%+v two=%+v err=%v", one, two, err)
	}
	visible, err := one.VisiblePosts()
	if err != nil || len(visible) != 1 {
		t.Fatalf("moderated view: %+v err=%v", visible, err)
	}
	visibleID, _ := visible[0].ID()
	if visibleID != firstID || len(one.Events()) != 3 {
		t.Fatal("moderation deleted immutable history or hid another post")
	}
	profileWire, err := EncodeProfileJSON(profile)
	if err != nil {
		t.Fatal(err)
	}
	decodedProfile, err := DecodeProfileJSON(profileWire)
	if err != nil {
		t.Fatal(err)
	}
	if decodedDigest, _ := decodedProfile.Digest(); decodedDigest != profileDigest {
		t.Fatal("profile wire changed its signed digest")
	}
	eventWire, err := EncodeEventJSON(second)
	if err != nil {
		t.Fatal(err)
	}
	decodedEvent, err := DecodeEventJSON(eventWire)
	decodedID, _ := decodedEvent.ID()
	if err != nil || decodedID != secondID {
		t.Fatalf("Event wire changed identity: %s err=%v", decodedID, err)
	}
	headWire, err := EncodeHeadJSON(one.Head())
	if err != nil {
		t.Fatal(err)
	}
	head, err := DecodeHeadJSON(headWire)
	if err != nil || !head.Matches(one) {
		t.Fatalf("history head mismatch: %+v err=%v", head, err)
	}
}

func TestPublicChannelFindsGapsAndRefusesForksOrAuthoritySubstitution(t *testing.T) {
	network := channelNetwork()
	authority, authorityKey := channelDelegation(t, network, 'a')
	publisher, publisherKey := channelDelegation(t, network, 'b')
	channelID, _ := DeriveID(network, authority.AgentID, authority.EndpointID, bytes.Repeat([]byte{9}, 32))
	principals := []Principal{
		{AgentID: authority.AgentID, EndpointID: authority.EndpointID, Publisher: true, Moderator: true},
		{AgentID: publisher.AgentID, EndpointID: publisher.EndpointID, Publisher: true},
	}
	sort.Slice(principals, func(i, j int) bool { return principals[i].AgentID < principals[j].AgentID })
	profile, _ := SignProfile(Profile{Network: network, ChannelID: channelID, Epoch: 1,
		AuthorityAgentID: authority.AgentID, AuthorityEndpointID: authority.EndpointID, Principals: principals,
		IssuedAtUnix: channelNow - 10, ExpiresAtUnix: channelNow + 3600}, authorityKey)
	digest, _ := profile.Digest()
	first := signedPost(t, profile, digest, publisher, publisherKey, 1, "", nil, channelNow, "one")
	firstID, _ := first.ID()
	second := signedPost(t, profile, digest, publisher, publisherKey, 2, firstID, []string{firstID}, channelNow+1, "two")
	secondID, _ := second.ID()
	missing, err := MissingReferences([]Event{second})
	if err != nil || len(missing) != 1 || missing[0] != firstID {
		t.Fatalf("gap repair: %v err=%v", missing, err)
	}
	delegations := map[string]identity.Delegation{authority.EndpointID: authority, publisher.EndpointID: publisher}
	if _, err := VerifyHistory(profile, []Event{second}, authority, delegations, time.Unix(int64(channelNow+2), 0)); err == nil {
		t.Fatal("incomplete history verified")
	}
	fork := signedPost(t, profile, digest, publisher, publisherKey, 2, firstID, []string{firstID}, channelNow+1, "fork")
	if _, err := VerifyHistory(profile, []Event{first, second, fork}, authority, delegations,
		time.Unix(int64(channelNow+2), 0)); err == nil {
		t.Fatal("publisher sequence fork verified")
	}
	forged := second
	forged.PublisherSignature = ed25519.Sign(authorityKey, mustEventBytes(t, forged))
	if err := VerifyEvent(forged, profile, publisher, time.Unix(int64(channelNow+2), 0)); err == nil {
		t.Fatal("another Endpoint signed as the publisher")
	}
	if secondID == firstID {
		t.Fatal("distinct public Events share an identifier")
	}
}

func TestPublicChannelProfileAndEventsFailClosed(t *testing.T) {
	network := channelNetwork()
	authority, key := channelDelegation(t, network, 'a')
	channelID, _ := DeriveID(network, authority.AgentID, authority.EndpointID, bytes.Repeat([]byte{4}, 32))
	profile := Profile{Network: network, ChannelID: channelID, Epoch: 1,
		AuthorityAgentID: authority.AgentID, AuthorityEndpointID: authority.EndpointID,
		Principals:   []Principal{{AgentID: authority.AgentID, EndpointID: authority.EndpointID, Publisher: true, Moderator: true}},
		IssuedAtUnix: channelNow - 10, ExpiresAtUnix: channelNow + 3600}
	signed, err := SignProfile(profile, key)
	if err != nil {
		t.Fatal(err)
	}
	delegations := map[string]identity.Delegation{authority.EndpointID: authority}
	currentDigest, _ := signed.Digest()
	next, err := SignProfile(Profile{Network: network, ChannelID: channelID, Epoch: 2,
		PreviousProfileDigest: currentDigest, AuthorityAgentID: authority.AgentID,
		AuthorityEndpointID: authority.EndpointID, Principals: profile.Principals,
		IssuedAtUnix: channelNow, ExpiresAtUnix: channelNow + 3500}, key)
	if err != nil || VerifySuccessor(signed, next, authority, delegations, time.Unix(int64(channelNow+1), 0)) != nil {
		t.Fatalf("adjacent profile successor: err=%v", err)
	}
	fork := next
	fork.ExpiresAtUnix--
	fork, err = SignProfile(fork, key)
	if err != nil {
		t.Fatal(err)
	}
	if conflict, err := ProfilesConflict(next, fork); err != nil || !conflict {
		t.Fatalf("equal-epoch profile fork not detected: conflict=%v err=%v", conflict, err)
	}
	wrongPredecessor := next
	wrongPredecessor.PreviousProfileDigest = "sha256:" + strings.Repeat("f", 64)
	wrongPredecessor, _ = SignProfile(wrongPredecessor, key)
	if VerifySuccessor(signed, wrongPredecessor, authority, delegations, time.Unix(int64(channelNow+1), 0)) == nil {
		t.Fatal("profile successor accepted another predecessor")
	}
	wrong, _ := channelDelegation(t, network, 'f')
	if err := VerifyProfile(signed, wrong, delegations, time.Unix(int64(channelNow), 0)); err == nil {
		t.Fatal("profile accepted substituted authority")
	}
	unsorted := profile
	unsorted.Principals = append(unsorted.Principals,
		Principal{AgentID: "agent_" + strings.Repeat("0", 64), EndpointID: authority.EndpointID, Publisher: true})
	if _, err := SignProfile(unsorted, key); err == nil {
		t.Fatal("unordered profile was signed")
	}
	if _, err := DeriveID(network, authority.AgentID, authority.EndpointID, make([]byte, 32)); err == nil {
		t.Fatal("zero channel seed derived an identifier")
	}
	if _, err := DecodeProfileJSON([]byte(`{"schema":"tos.messaging.public-channel-profile.v1","unknown":true}`)); err == nil {
		t.Fatal("profile decoder accepted an unknown field")
	}
	digest, _ := signed.Digest()
	post := Event{ChannelID: channelID, ProfileDigest: digest, PublisherAgentID: authority.AgentID,
		PublisherEndpointID: authority.EndpointID, Sequence: 2, PublishedAtUnix: channelNow,
		Kind: KindPost, MediaType: "text/plain", Content: []byte("gap")}
	if _, err := SignEvent(post, key); err == nil {
		t.Fatal("sequence without predecessor was signed")
	}
}

func signedPost(t testing.TB, profile Profile, digest string, publisher identity.Delegation, key ed25519.PrivateKey,
	sequence uint64, previous string, parents []string, published uint64, content string) Event {
	t.Helper()
	event, err := SignEvent(Event{ChannelID: profile.ChannelID, ProfileDigest: digest,
		PublisherAgentID: publisher.AgentID, PublisherEndpointID: publisher.EndpointID,
		Sequence: sequence, PreviousPublisherEventID: previous, Parents: append([]string(nil), parents...),
		PublishedAtUnix: published, Kind: KindPost, MediaType: "text/plain; charset=utf-8", Content: []byte(content)}, key)
	if err != nil {
		t.Fatal(err)
	}
	return event
}

func mustEventBytes(t *testing.T, event Event) []byte {
	t.Helper()
	event.PublisherSignature = nil
	raw, err := EventSigningBytes(event)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func channelNetwork() *nativev1.NetworkDomain {
	return &nativev1.NetworkDomain{NetworkId: "tos-public-test", GenesisRootHash: strings.Repeat("a", 64), GenesisFileHash: strings.Repeat("b", 64)}
}

func channelDelegation(t testing.TB, network *nativev1.NetworkDomain, marker byte) (identity.Delegation, ed25519.PrivateKey) {
	t.Helper()
	key := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{marker}, ed25519.SeedSize))
	agentID := "agent_" + strings.Repeat(string(marker), 64)
	endpointID, err := identity.DeriveEndpointID(network, agentID, key.Public().(ed25519.PublicKey))
	if err != nil {
		t.Fatal(err)
	}
	return identity.Delegation{Network: network, AgentID: agentID, EndpointID: endpointID,
		IdentityPublicKey: key.Public().(ed25519.PublicKey), AllowedProtocolVersions: []uint32{1},
		AllowedOutboundEventClasses: []string{"public.channel"}, NotBeforeUnix: channelNow - 100,
		ExpiresAtUnix: channelNow + 7200, MaximumSessionLifetimeSeconds: 3600,
		ContactDescriptorPolicyDigest: "sha256:" + strings.Repeat("1", 64),
		InboxAdmissionPolicyDigest:    "sha256:" + strings.Repeat("2", 64)}, key
}
