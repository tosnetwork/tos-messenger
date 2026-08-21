package publicchannel

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestSitesSnapshotExportLoadAndRejectMutation(t *testing.T) {
	profile, authority, authorityKey, publisher, publisherKey, delegations := storeFixture(t)
	digest, _ := profile.Digest()
	first := signedPost(t, profile, digest, publisher, publisherKey, 1, "", nil, channelNow, "sites root")
	firstID, _ := first.ID()
	hide, err := SignEvent(Event{ChannelID: profile.ChannelID, ProfileDigest: digest,
		PublisherAgentID: authority.AgentID, PublisherEndpointID: authority.EndpointID,
		Sequence: 1, Parents: []string{firstID}, PublishedAtUnix: channelNow + 1,
		Kind: KindHide, TargetEventID: firstID}, authorityKey)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Unix(int64(channelNow+2), 0)
	history, err := VerifyHistory(profile, []Event{hide, first}, authority, delegations, now)
	if err != nil {
		t.Fatal(err)
	}
	newSnapshot := func(t *testing.T) string {
		t.Helper()
		parent := filepath.Join(t.TempDir(), "snapshots")
		if err := os.Mkdir(parent, 0o700); err != nil {
			t.Fatal(err)
		}
		path, manifest, err := ExportSitesSnapshot(parent, profile, history, authority, delegations, now)
		if err != nil {
			t.Fatal(err)
		}
		if manifest.HistoryDigest != history.Digest() || len(manifest.EventIDs) != 2 {
			t.Fatalf("unexpected Sites manifest: %#v", manifest)
		}
		return path
	}
	t.Run("round trip and exact replay", func(t *testing.T) {
		path := newSnapshot(t)
		loaded, err := LoadSitesSnapshot(path, authority, delegations, now)
		if err != nil || loaded.Digest() != history.Digest() {
			t.Fatalf("load Sites snapshot: digest=%q err=%v", loaded.Digest(), err)
		}
		path2, _, err := ExportSitesSnapshot(filepath.Dir(path), profile, history, authority, delegations, now)
		if err != nil || path2 != path {
			t.Fatalf("replay Sites snapshot: path=%q err=%v", path2, err)
		}
		for _, name := range []string{"manifest.json", "profile.json", "head.json"} {
			info, err := os.Lstat(filepath.Join(path, name))
			if err != nil || info.Mode().Perm() != 0o600 {
				t.Fatalf("Sites file %s mode=%v err=%v", name, info.Mode().Perm(), err)
			}
		}
	})
	t.Run("extra object", func(t *testing.T) {
		path := newSnapshot(t)
		if err := os.WriteFile(filepath.Join(path, "events", "extra"), []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := LoadSitesSnapshot(path, authority, delegations, now); err == nil {
			t.Fatal("accepted Sites snapshot with an extra object")
		}
	})
	t.Run("noncanonical manifest", func(t *testing.T) {
		path := newSnapshot(t)
		manifestPath := filepath.Join(path, "manifest.json")
		raw, err := os.ReadFile(manifestPath)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(manifestPath, append(raw, '\n'), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := LoadSitesSnapshot(path, authority, delegations, now); err == nil {
			t.Fatal("accepted noncanonical Sites manifest")
		}
	})
	t.Run("finalized delegation substitution", func(t *testing.T) {
		path := newSnapshot(t)
		substituted := cloneDelegations(delegations)
		wrong := substituted[publisher.EndpointID]
		wrong.IdentityPublicKey = ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x79}, ed25519.SeedSize)).Public().(ed25519.PublicKey)
		substituted[publisher.EndpointID] = wrong
		if _, err := LoadSitesSnapshot(path, authority, substituted, now); err == nil {
			t.Fatal("accepted substituted finalized Sites delegation")
		}
	})
	t.Run("durable receipt exact replay and damage", func(t *testing.T) {
		root := filepath.Join(t.TempDir(), "mirror")
		publisher := &countingSitesPublisher{bagID: strings.Repeat("bc", 32)}
		mirror, err := OpenSitesMirror(root, publisher)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := OpenSitesMirror(root, publisher); err == nil {
			t.Fatal("opened a second Sites mirror writer")
		}
		receipt, changed, err := mirror.Publish(context.Background(), profile, history, authority, delegations, now)
		if err != nil || !changed || receipt.BagID != publisher.bagID {
			t.Fatalf("Sites publication receipt=%#v changed=%t err=%v", receipt, changed, err)
		}
		replayed, changed, err := mirror.Publish(context.Background(), profile, history, authority, delegations, now)
		if err != nil || changed || replayed != receipt || publisher.Count() != 1 {
			t.Fatalf("Sites replay receipt=%#v changed=%t calls=%d err=%v", replayed, changed, publisher.Count(), err)
		}
		if err := mirror.Close(); err != nil {
			t.Fatal(err)
		}
		receiptPath := filepath.Join(root, "receipts", strings.TrimPrefix(history.Digest(), "sha256:")+".json")
		if err := os.WriteFile(receiptPath, []byte(`{}`), 0o600); err != nil {
			t.Fatal(err)
		}
		mirror, err = OpenSitesMirror(root, publisher)
		if err != nil {
			t.Fatal(err)
		}
		defer mirror.Close()
		if _, _, err := mirror.Publish(context.Background(), profile, history, authority, delegations, now); err == nil {
			t.Fatal("accepted damaged Sites publication receipt")
		}
		if publisher.Count() != 1 {
			t.Fatal("republished after detecting a damaged Sites receipt")
		}
	})
}

func TestStorageCLIPublisherParsesCanonicalBagID(t *testing.T) {
	root := filepath.Join(t.TempDir(), "publisher with spaces")
	if err := os.Mkdir(root, 0o700); err != nil {
		t.Fatal(err)
	}
	command := filepath.Join(root, "storage-cli")
	key := filepath.Join(root, "client.key")
	public := filepath.Join(root, "server.pub")
	captured := filepath.Join(root, "arguments")
	snapshot := filepath.Join(root, "snapshot with spaces")
	if err := os.Mkdir(snapshot, 0o700); err != nil {
		t.Fatal(err)
	}
	bagID := strings.Repeat("ab", 32)
	script := "#!/bin/sh\nprintf '%s\\n' \"$@\" > " + strconv.Quote(captured) +
		"\nprintf '%s\\n' 'Bag created' 'BagID = " + bagID + "'\n"
	if err := os.WriteFile(command, []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{key, public} {
		if err := os.WriteFile(path, []byte("key"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	publisher := StorageCLIPublisher{Command: command, ServerAddress: "127.0.0.1:5555",
		ClientPrivateKey: key, ServerPublicKey: public, Timeout: time.Second}
	got, err := publisher.Publish(context.Background(), snapshot)
	if err != nil || got != bagID {
		t.Fatalf("Storage CLI BagID=%q err=%v", got, err)
	}
	arguments, err := os.ReadFile(captured)
	if err != nil {
		t.Fatal(err)
	}
	wantCommand := "create --copy -- " + strconv.Quote(snapshot)
	if !strings.Contains(string(arguments), "-c\n"+wantCommand+"\n") {
		t.Fatalf("Storage CLI arguments do not preserve snapshot token: %q", arguments)
	}
	if _, err := SitesSnapshotBagID(got); err != nil {
		t.Fatal(err)
	}
	if parseStorageBagID("BagID = "+strings.ToUpper(bagID)) != "" {
		t.Fatal("accepted noncanonical uppercase BagID")
	}
}

func TestSitesHintStrictRoundTrip(t *testing.T) {
	hint := SitesHint{Schema: SitesHintSchema,
		ChannelID:     "channel_" + strings.Repeat("01", 32),
		ProfileDigest: "sha256:" + strings.Repeat("02", 32),
		HistoryDigest: "sha256:" + strings.Repeat("03", 32),
		BagID:         strings.Repeat("ab", 32)}
	raw, err := EncodeSitesHintJSON(hint)
	if err != nil {
		t.Fatal(err)
	}
	got, err := DecodeSitesHintJSON(raw)
	if err != nil || got != hint {
		t.Fatalf("Sites hint=%#v err=%v", got, err)
	}
	for _, invalid := range [][]byte{
		append(append([]byte(nil), raw...), '\n'),
		[]byte(strings.Replace(string(raw), `"bag_id":`, `"unknown":true,"bag_id":`, 1)),
		[]byte(strings.Replace(string(raw), hint.BagID, strings.ToUpper(hint.BagID), 1)),
	} {
		if _, err := DecodeSitesHintJSON(invalid); err == nil {
			t.Fatalf("accepted invalid Sites hint %q", invalid)
		}
	}
}
