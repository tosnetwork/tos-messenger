package publicchannel

import (
	"bytes"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"flag"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/tosnetwork/tos-messenger/pkg/identity"
)

var updatePublicChannelVectors = flag.Bool("update-public-channel-vectors", false, "rewrite public channel interoperability vectors")

type publicChannelVectorFile struct {
	Schema            string                     `json:"schema"`
	AuthoritySeedHex  string                     `json:"authority_seed_hex"`
	PublisherSeedHex  string                     `json:"publisher_seed_hex"`
	ProfileJSON       string                     `json:"profile_json"`
	ProfileSigningHex string                     `json:"profile_signing_hex"`
	ProfileDigest     string                     `json:"profile_digest"`
	Events            []publicChannelEventVector `json:"events"`
	HeadJSON          string                     `json:"head_json"`
	HistoryDigest     string                     `json:"history_digest"`
	Adversarial       []publicChannelAdversarial `json:"adversarial"`
}

type publicChannelEventVector struct {
	JSON       string `json:"json"`
	SigningHex string `json:"signing_hex"`
	EventID    string `json:"event_id"`
}

type publicChannelAdversarial struct {
	Name string `json:"name"`
	Kind string `json:"kind"`
	JSON string `json:"json"`
}

func TestPublicChannelInteroperabilityVectors(t *testing.T) {
	want := buildPublicChannelVector(t)
	path := filepath.Join("testdata", "public-channel-vectors.json")
	if *updatePublicChannelVectors {
		encoded, err := json.MarshalIndent(want, "", "  ")
		if err != nil {
			t.Fatal(err)
		}
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, append(encoded, '\n'), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var got publicChannelVectorFile
	if err := json.Unmarshal(raw, &got); err != nil {
		t.Fatal(err)
	}
	wantJSON, _ := json.Marshal(want)
	gotJSON, _ := json.Marshal(got)
	if !bytes.Equal(gotJSON, wantJSON) {
		t.Fatal("public channel vectors changed; inspect the protocol change and regenerate with -update-public-channel-vectors")
	}
	consumePublicChannelVector(t, got)
}

func buildPublicChannelVector(t *testing.T) publicChannelVectorFile {
	t.Helper()
	profile, authority, authorityKey, publisher, publisherKey, delegations := storeFixture(t)
	profileRaw, _ := EncodeProfileJSON(profile)
	profileSigning, _ := ProfileSigningBytes(profile)
	profileDigest, _ := profile.Digest()
	first := signedPost(t, profile, profileDigest, publisher, publisherKey, 1, "", nil, channelNow, "public vector post")
	firstID, _ := first.ID()
	hide, err := SignEvent(Event{ChannelID: profile.ChannelID, ProfileDigest: profileDigest,
		PublisherAgentID: authority.AgentID, PublisherEndpointID: authority.EndpointID,
		Sequence: 1, Parents: []string{firstID}, PublishedAtUnix: channelNow + 1,
		Kind: KindHide, TargetEventID: firstID}, authorityKey)
	if err != nil {
		t.Fatal(err)
	}
	history, err := VerifyHistory(profile, []Event{hide, first}, authority, delegations, time.Unix(int64(channelNow+2), 0))
	if err != nil {
		t.Fatal(err)
	}
	events := []publicChannelEventVector{vectorEvent(t, first), vectorEvent(t, hide)}
	headRaw, _ := EncodeHeadJSON(history.Head())
	unknownProfile := append(append([]byte(nil), profileRaw[:len(profileRaw)-1]...), []byte(`,"unknown":true}`)...)
	firstRaw := []byte(events[0].JSON)
	badID := bytes.Replace(firstRaw, []byte(firstID), []byte("pce_"+strings.Repeat("0", 64)), 1)
	forged := first
	forged.PublisherSignature = ed25519.Sign(authorityKey, mustEventBytes(t, forged))
	forgedRaw, _ := EncodeEventJSON(forged)
	badHead := history.Head()
	badHead.HistoryDigest = "sha256:" + strings.Repeat("f", 64)
	badHeadRaw, _ := EncodeHeadJSON(badHead)
	return publicChannelVectorFile{
		Schema:           "tos.messaging.public-channel-vectors.v1",
		AuthoritySeedHex: hex.EncodeToString(authorityKey.Seed()), PublisherSeedHex: hex.EncodeToString(publisherKey.Seed()),
		ProfileJSON: string(profileRaw), ProfileSigningHex: hex.EncodeToString(profileSigning), ProfileDigest: profileDigest,
		Events: events, HeadJSON: string(headRaw), HistoryDigest: history.Digest(),
		Adversarial: []publicChannelAdversarial{
			{Name: "profile-unknown-field", Kind: "profile-decode", JSON: string(unknownProfile)},
			{Name: "event-id-substitution", Kind: "event-decode", JSON: string(badID)},
			{Name: "publisher-signature-substitution", Kind: "history-verify", JSON: string(forgedRaw)},
			{Name: "missing-causal-parent", Kind: "history-verify", JSON: events[1].JSON},
			{Name: "head-history-substitution", Kind: "head-match", JSON: string(badHeadRaw)},
		},
	}
}

func vectorEvent(t *testing.T, event Event) publicChannelEventVector {
	t.Helper()
	raw, err := EncodeEventJSON(event)
	if err != nil {
		t.Fatal(err)
	}
	signing, _ := EventSigningBytes(event)
	id, _ := event.ID()
	return publicChannelEventVector{JSON: string(raw), SigningHex: hex.EncodeToString(signing), EventID: id}
}

func consumePublicChannelVector(t *testing.T, vector publicChannelVectorFile) {
	t.Helper()
	if vector.Schema != "tos.messaging.public-channel-vectors.v1" || len(vector.Events) != 2 {
		t.Fatal("invalid public channel vector shape")
	}
	profile, err := DecodeProfileJSON([]byte(vector.ProfileJSON))
	if err != nil {
		t.Fatal(err)
	}
	authority, authorityKey := vectorDelegation(t, profile, vector.AuthoritySeedHex, profile.AuthorityAgentID, profile.AuthorityEndpointID)
	var publisherPrincipal Principal
	for _, principal := range profile.Principals {
		if principal.EndpointID != profile.AuthorityEndpointID {
			publisherPrincipal = principal
			break
		}
	}
	if publisherPrincipal.EndpointID == "" {
		t.Fatal("vector has no independent publisher")
	}
	publisher, _ := vectorDelegation(t, profile, vector.PublisherSeedHex, publisherPrincipal.AgentID, publisherPrincipal.EndpointID)
	delegations := map[string]identity.Delegation{authority.EndpointID: authority, publisher.EndpointID: publisher}
	if err := VerifyProfile(profile, authority, delegations, time.Unix(int64(channelNow+2), 0)); err != nil {
		t.Fatal(err)
	}
	profileSigning, _ := ProfileSigningBytes(profile)
	digest, _ := profile.Digest()
	if hex.EncodeToString(profileSigning) != vector.ProfileSigningHex || digest != vector.ProfileDigest ||
		!ed25519.Verify(authorityKey.Public().(ed25519.PublicKey), profileSigning, profile.AuthoritySignature) {
		t.Fatal("profile vector did not reproduce its signing bytes or digest")
	}
	events := make([]Event, 0, len(vector.Events))
	for _, item := range vector.Events {
		event, err := DecodeEventJSON([]byte(item.JSON))
		if err != nil {
			t.Fatal(err)
		}
		signing, _ := EventSigningBytes(event)
		id, _ := event.ID()
		if hex.EncodeToString(signing) != item.SigningHex || id != item.EventID {
			t.Fatal("Event vector did not reproduce its signing bytes or ID")
		}
		events = append(events, event)
	}
	history, err := VerifyHistory(profile, []Event{events[1], events[0]}, authority, delegations, time.Unix(int64(channelNow+2), 0))
	if err != nil || history.Digest() != vector.HistoryDigest {
		t.Fatalf("history vector did not converge: digest=%q err=%v", history.Digest(), err)
	}
	head, err := DecodeHeadJSON([]byte(vector.HeadJSON))
	if err != nil || !head.Matches(history) {
		t.Fatalf("head vector did not match: err=%v", err)
	}
	for _, adversarial := range vector.Adversarial {
		switch adversarial.Kind {
		case "profile-decode":
			if _, err := DecodeProfileJSON([]byte(adversarial.JSON)); err == nil {
				t.Fatalf("%s was accepted", adversarial.Name)
			}
		case "event-decode":
			if _, err := DecodeEventJSON([]byte(adversarial.JSON)); err == nil {
				t.Fatalf("%s was accepted", adversarial.Name)
			}
		case "history-verify":
			event, err := DecodeEventJSON([]byte(adversarial.JSON))
			if err != nil {
				t.Fatalf("%s is not a decode-layer-positive mutation: %v", adversarial.Name, err)
			}
			if _, err := VerifyHistory(profile, []Event{event}, authority, delegations, time.Unix(int64(channelNow+2), 0)); err == nil {
				t.Fatalf("%s was accepted", adversarial.Name)
			}
		case "head-match":
			candidate, err := DecodeHeadJSON([]byte(adversarial.JSON))
			if err != nil || candidate.Matches(history) {
				t.Fatalf("%s did not reach and fail the semantic match layer: %v", adversarial.Name, err)
			}
		default:
			t.Fatalf("unknown adversarial vector kind %q", adversarial.Kind)
		}
	}
}

func vectorDelegation(t *testing.T, profile Profile, seedHex, agentID, endpointID string) (identity.Delegation, ed25519.PrivateKey) {
	t.Helper()
	seed, err := hex.DecodeString(seedHex)
	if err != nil || len(seed) != ed25519.SeedSize {
		t.Fatal("invalid vector Endpoint seed")
	}
	key := ed25519.NewKeyFromSeed(seed)
	derived, err := identity.DeriveEndpointID(profile.Network, agentID, key.Public().(ed25519.PublicKey))
	if err != nil || derived != endpointID {
		t.Fatal("vector Endpoint identity did not reproduce")
	}
	return identity.Delegation{Network: profile.Network, AgentID: agentID, EndpointID: endpointID,
		IdentityPublicKey: key.Public().(ed25519.PublicKey), AllowedProtocolVersions: []uint32{1},
		AllowedOutboundEventClasses: []string{"public.channel"}, NotBeforeUnix: channelNow - 100,
		ExpiresAtUnix: channelNow + 7200, MaximumSessionLifetimeSeconds: 3600,
		ContactDescriptorPolicyDigest: "sha256:" + strings.Repeat("1", 64),
		InboxAdmissionPolicyDigest:    "sha256:" + strings.Repeat("2", 64)}, key
}
