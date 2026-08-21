package publicchannel

import (
	"bytes"
	"crypto/ed25519"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/tosnetwork/tos-messenger/pkg/identity"
)

func TestPublicChannelStoreSurvivesRestartAndRejectsRollback(t *testing.T) {
	root := filepath.Join(t.TempDir(), "channel-store")
	profile, authority, authorityKey, publisher, publisherKey, delegations := storeFixture(t)
	now := time.Unix(int64(channelNow+10), 0)
	store, err := OpenStore(root)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := OpenStore(root); err == nil {
		t.Fatal("a second public channel writer acquired the store")
	}
	changed, err := store.ApplyProfile(profile, authority, delegations, now)
	if err != nil || !changed {
		t.Fatalf("apply first profile: changed=%v err=%v", changed, err)
	}
	changed, err = store.ApplyProfile(profile, authority, delegations, now)
	if err != nil || changed {
		t.Fatalf("profile replay was not idempotent: changed=%v err=%v", changed, err)
	}
	digest, _ := profile.Digest()
	first := signedPost(t, profile, digest, publisher, publisherKey, 1, "", nil, channelNow, "first")
	firstID, _ := first.ID()
	initial, changed, err := store.CommitHistory(profile, []Event{first}, authority, delegations, now)
	if err != nil || !changed {
		t.Fatalf("commit initial history: changed=%v err=%v", changed, err)
	}
	second := signedPost(t, profile, digest, publisher, publisherKey, 2, firstID, []string{firstID}, channelNow+1, "second")
	grown, changed, err := store.CommitHistory(profile, []Event{second, first}, authority, delegations, now)
	if err != nil || !changed || grown.Digest() == initial.Digest() {
		t.Fatalf("grow history: changed=%v err=%v", changed, err)
	}
	if _, _, err := store.CommitHistory(profile, []Event{first}, authority, delegations, now); !errors.Is(err, ErrHistoryRollback) {
		t.Fatalf("history shrink error = %v, want %v", err, ErrHistoryRollback)
	}
	if _, changed, err := store.CommitHistory(profile, []Event{first, second}, authority, delegations, now); err != nil || changed {
		t.Fatalf("history replay was not idempotent: changed=%v err=%v", changed, err)
	}

	next := profile
	next.Epoch = 2
	next.PreviousProfileDigest = digest
	next.IssuedAtUnix++
	next, err = SignProfile(next, authorityKey)
	if err != nil {
		t.Fatal(err)
	}
	if changed, err = store.ApplyProfile(next, authority, delegations, now); err != nil || !changed {
		t.Fatalf("advance profile: changed=%v err=%v", changed, err)
	}
	fork := next
	fork.ExpiresAtUnix--
	fork, _ = SignProfile(fork, authorityKey)
	if _, err := store.ApplyProfile(fork, authority, delegations, now); !errors.Is(err, ErrProfileFork) {
		t.Fatalf("equal-epoch profile fork error = %v", err)
	}
	if _, err := store.ApplyProfile(profile, authority, delegations, now); !errors.Is(err, ErrProfileRollback) {
		t.Fatalf("profile rollback error = %v", err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	store, err = OpenStore(root)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	loaded, found, err := store.LoadHistory(profile, authority, delegations, now)
	if err != nil || !found || loaded.Digest() != grown.Digest() || len(loaded.Events()) != 2 {
		t.Fatalf("restart load: found=%v digest=%q err=%v", found, loaded.Digest(), err)
	}
	if changed, err := store.ApplyProfile(next, authority, delegations, now); err != nil || changed {
		t.Fatalf("successor replay after restart: changed=%v err=%v", changed, err)
	}

	secondID, _ := second.ID()
	third := signedPost(t, profile, digest, publisher, publisherKey, 3, secondID, []string{secondID}, channelNow+2, "orphan")
	thirdID, _ := third.ID()
	thirdRaw, _ := EncodeEventJSON(third)
	if err := putStoreImmutable(store.eventPath(thirdID), thirdRaw); err != nil {
		t.Fatal(err)
	}
	loaded, found, err = store.LoadHistory(profile, authority, delegations, now)
	if err != nil || !found || len(loaded.Events()) != 2 {
		t.Fatalf("orphan became visible: found=%v count=%d err=%v", found, len(loaded.Events()), err)
	}
}

func TestPublicChannelStoreFailsClosedOnCommittedDamage(t *testing.T) {
	t.Run("event", func(t *testing.T) {
		store, profile, authority, delegations, event := committedStoreFixture(t)
		defer store.Close()
		id, _ := event.ID()
		if err := os.WriteFile(store.eventPath(id), []byte(`{"damaged":true}`), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, _, err := store.LoadHistory(profile, authority, delegations, time.Unix(int64(channelNow+10), 0)); err == nil {
			t.Fatal("damaged committed Event loaded")
		}
	})
	t.Run("manifest", func(t *testing.T) {
		store, profile, authority, delegations, _ := committedStoreFixture(t)
		defer store.Close()
		digest, _ := profile.Digest()
		manifest, found, err := store.readHistoryManifestPointer(store.headPath(digest))
		if err != nil || !found {
			t.Fatal(err)
		}
		if err := os.WriteFile(store.historyPath(manifest.HistoryDigest), []byte(`{"damaged":true}`), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, _, err := store.LoadHistory(profile, authority, delegations, time.Unix(int64(channelNow+10), 0)); err == nil {
			t.Fatal("head loaded despite immutable manifest damage")
		}
	})
}

func committedStoreFixture(t *testing.T) (*Store, Profile, identity.Delegation, map[string]identity.Delegation, Event) {
	t.Helper()
	profile, authority, _, publisher, publisherKey, delegations := storeFixture(t)
	store, err := OpenStore(filepath.Join(t.TempDir(), "channel-store"))
	if err != nil {
		t.Fatal(err)
	}
	now := time.Unix(int64(channelNow+10), 0)
	if _, err := store.ApplyProfile(profile, authority, delegations, now); err != nil {
		t.Fatal(err)
	}
	digest, _ := profile.Digest()
	event := signedPost(t, profile, digest, publisher, publisherKey, 1, "", nil, channelNow, "committed")
	if _, _, err := store.CommitHistory(profile, []Event{event}, authority, delegations, now); err != nil {
		t.Fatal(err)
	}
	return store, profile, authority, delegations, event
}

func storeFixture(t testing.TB) (Profile, identity.Delegation, ed25519.PrivateKey, identity.Delegation, ed25519.PrivateKey, map[string]identity.Delegation) {
	t.Helper()
	network := channelNetwork()
	authority, authorityKey := channelDelegation(t, network, 'a')
	publisher, publisherKey := channelDelegation(t, network, 'b')
	channelID, err := DeriveID(network, authority.AgentID, authority.EndpointID, bytes.Repeat([]byte{3}, 32))
	if err != nil {
		t.Fatal(err)
	}
	profile, err := SignProfile(Profile{Network: network, ChannelID: channelID, Epoch: 1,
		AuthorityAgentID: authority.AgentID, AuthorityEndpointID: authority.EndpointID,
		Principals: []Principal{
			{AgentID: authority.AgentID, EndpointID: authority.EndpointID, Publisher: true, Moderator: true},
			{AgentID: publisher.AgentID, EndpointID: publisher.EndpointID, Publisher: true},
		}, IssuedAtUnix: channelNow - 10, ExpiresAtUnix: channelNow + 3600}, authorityKey)
	if err != nil {
		t.Fatal(err)
	}
	delegations := map[string]identity.Delegation{authority.EndpointID: authority, publisher.EndpointID: publisher}
	return profile, authority, authorityKey, publisher, publisherKey, delegations
}
