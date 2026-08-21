package publicchannel

import (
	"context"
	"crypto/ed25519"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/tosnetwork/tosutils-go/adnl"
)

func TestSitesCatchUpVerifiesPersistsAndRestarts(t *testing.T) {
	profile, authority, _, publisher, publisherKey, delegations := storeFixture(t)
	profileDigest, _ := profile.Digest()
	event := signedPost(t, profile, profileDigest, publisher, publisherKey, 1, "", nil, channelNow, "catch up")
	now := time.Unix(int64(channelNow+2), 0)
	history, err := VerifyHistory(profile, []Event{event}, authority, delegations, now)
	if err != nil {
		t.Fatal(err)
	}
	sourceParent := filepath.Join(t.TempDir(), "source")
	if err := os.Mkdir(sourceParent, 0o700); err != nil {
		t.Fatal(err)
	}
	source, _, err := ExportSitesSnapshot(sourceParent, profile, history, authority, delegations, now)
	if err != nil {
		t.Fatal(err)
	}
	downloader := &copyingSitesDownloader{source: source}
	root := filepath.Join(t.TempDir(), "catchup")
	catchUp, err := OpenSitesCatchUp(root, downloader)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := OpenSitesCatchUp(root, downloader); err == nil {
		t.Fatal("opened a second public channel Sites catch-up writer")
	}
	hint := SitesHint{Schema: SitesHintSchema, ChannelID: profile.ChannelID,
		ProfileDigest: profileDigest, HistoryDigest: history.Digest(), BagID: strings.Repeat("d1", 32)}
	got, accepted, changed, err := catchUp.Fetch(context.Background(), hint, profile, authority, delegations, now)
	if err != nil || !changed || got.Digest() != history.Digest() || accepted != hint || downloader.Count() != 1 {
		t.Fatalf("catch-up history=%q accepted=%#v changed=%t calls=%d err=%v",
			got.Digest(), accepted, changed, downloader.Count(), err)
	}
	alternate := hint
	alternate.BagID = strings.Repeat("d2", 32)
	got, accepted, changed, err = catchUp.Fetch(context.Background(), alternate, profile, authority, delegations, now)
	if err != nil || changed || got.Digest() != history.Digest() || accepted != hint || downloader.Count() != 1 {
		t.Fatalf("alternate replay history=%q accepted=%#v changed=%t calls=%d err=%v",
			got.Digest(), accepted, changed, downloader.Count(), err)
	}
	if err := catchUp.Close(); err != nil {
		t.Fatal(err)
	}
	catchUp, err = OpenSitesCatchUp(root, downloader)
	if err != nil {
		t.Fatal(err)
	}
	cached, found, err := catchUp.Cached(profile, history, authority, delegations, now)
	if err != nil || !found || cached != hint || downloader.Count() != 1 {
		t.Fatalf("cached hint=%#v found=%t calls=%d err=%v", cached, found, downloader.Count(), err)
	}
	if err := catchUp.Close(); err != nil {
		t.Fatal(err)
	}
	receipt := filepath.Join(root, "download-receipts", strings.TrimPrefix(history.Digest(), "sha256:")+".json")
	if err := os.WriteFile(receipt, []byte(`{}`), 0o600); err != nil {
		t.Fatal(err)
	}
	catchUp, err = OpenSitesCatchUp(root, downloader)
	if err != nil {
		t.Fatal(err)
	}
	defer catchUp.Close()
	if _, _, _, err := catchUp.Fetch(context.Background(), hint, profile, authority, delegations, now); err == nil {
		t.Fatal("accepted damaged public channel Sites download receipt")
	}
	if downloader.Count() != 1 {
		t.Fatal("redownloaded after detecting a damaged receipt")
	}
	t.Run("recover verified download before receipt", func(t *testing.T) {
		recoveryRoot := filepath.Join(t.TempDir(), "catchup")
		recoveryDownloader := &copyingSitesDownloader{source: source}
		recovery, err := OpenSitesCatchUp(recoveryRoot, recoveryDownloader)
		if err != nil {
			t.Fatal(err)
		}
		defer recovery.Close()
		target := filepath.Join(recoveryRoot, "downloads", hint.BagID,
			strings.TrimPrefix(hint.HistoryDigest, "sha256:"))
		if err := copySitesDirectory(source, target); err != nil {
			t.Fatal(err)
		}
		got, accepted, changed, err := recovery.Fetch(context.Background(), hint, profile, authority, delegations, now)
		if err != nil || !changed || got.Digest() != history.Digest() || accepted != hint || recoveryDownloader.Count() != 0 {
			t.Fatalf("crash recovery history=%q accepted=%#v changed=%t calls=%d err=%v",
				got.Digest(), accepted, changed, recoveryDownloader.Count(), err)
		}
	})
}

func TestStorageCLIDownloaderUsesExactBoundedCommands(t *testing.T) {
	root := filepath.Join(t.TempDir(), "downloader with spaces")
	if err := os.Mkdir(root, 0o700); err != nil {
		t.Fatal(err)
	}
	command := filepath.Join(root, "storage-cli")
	key := filepath.Join(root, "client.key")
	public := filepath.Join(root, "server.pub")
	captured := filepath.Join(root, "commands")
	downloads := filepath.Join(root, "downloads")
	if err := os.Mkdir(downloads, 0o700); err != nil {
		t.Fatal(err)
	}
	bagID := strings.Repeat("e1", 32)
	historyDigest := "sha256:" + strings.Repeat("e2", 32)
	hint := SitesHint{Schema: SitesHintSchema, ChannelID: "channel_" + strings.Repeat("e3", 32),
		ProfileDigest: "sha256:" + strings.Repeat("e4", 32), HistoryDigest: historyDigest, BagID: bagID}
	destination := filepath.Join(downloads, "bag with spaces")
	dirName := strings.TrimPrefix(historyDigest, "sha256:")
	script := "#!/bin/sh\nlast=''\nfor arg do last=$arg; done\nprintf '%s\\n' \"$last\" >> " + strconv.Quote(captured) +
		"\ncase \"$last\" in\n  add-by-hash*)\n    mkdir -p " + strconv.Quote(destination) +
		"\n    chmod 700 " + strconv.Quote(destination) +
		"\n    printf '%s\\n' 'Bag added' 'BagID = " + bagID + "' 'Root dir: " + destination + "' 'Download paused'\n    ;;\n" +
		"  get*)\n    printf '%s\\n' 'BagID = " + bagID + "' 'Downloaded: 1/1 (completed)' 'Dir name: " + dirName + "' 'Root dir: " + destination + "'\n    ;;\nesac\n"
	if err := os.WriteFile(command, []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{key, public} {
		if err := os.WriteFile(path, []byte("key"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	downloader := StorageCLIDownloader{Command: command, ServerAddress: "127.0.0.1:5555",
		ClientPrivateKey: key, ServerPublicKey: public, Timeout: time.Second, PollInterval: 10 * time.Millisecond}
	path, err := downloader.Download(context.Background(), hint, destination)
	if err != nil || path != filepath.Join(destination, dirName) {
		t.Fatalf("download path=%q err=%v", path, err)
	}
	raw, err := os.ReadFile(captured)
	if err != nil {
		t.Fatal(err)
	}
	wantAdd := "add-by-hash " + bagID + " -d " + strconv.Quote(destination) + " --no-upload"
	wantGet := "get " + bagID
	if string(raw) != wantAdd+"\n"+wantGet+"\n" {
		t.Fatalf("storage CLI commands=%q want=%q", raw, wantAdd+"\n"+wantGet+"\n")
	}
	for _, output := range []string{
		"BagID = " + strings.Repeat("ff", 32) + "\nDownloaded: 1/1 (completed)\nDir name: " + dirName + "\nRoot dir: " + destination,
		"BagID = " + strings.ToUpper(bagID) + "\nRoot dir: " + destination,
		"BagID = " + bagID + "\nBagID = " + bagID + "\nRoot dir: " + destination,
		"BagID = " + bagID + "\nFATAL ERROR: damage\nRoot dir: " + destination,
	} {
		status, parseErr := parseStorageCLIStatus(output)
		if parseErr == nil && validateStorageDownloadStatus(status, hint, destination) == nil {
			t.Fatalf("accepted substituted Storage CLI status %q", output)
		}
	}
}

func TestNativeNodeCommitsSitesCatchUpAndRestoresLocator(t *testing.T) {
	profile, authority, _, publisher, publisherKey, delegations := storeFixture(t)
	profileDigest, _ := profile.Digest()
	event := signedPost(t, profile, profileDigest, publisher, publisherKey, 1, "", nil, channelNow, "node catch up")
	now := func() time.Time { return time.Unix(int64(channelNow+2), 0) }
	history, err := VerifyHistory(profile, []Event{event}, authority, delegations, now())
	if err != nil {
		t.Fatal(err)
	}
	sourceParent := filepath.Join(t.TempDir(), "source")
	if err := os.Mkdir(sourceParent, 0o700); err != nil {
		t.Fatal(err)
	}
	source, _, err := ExportSitesSnapshot(sourceParent, profile, history, authority, delegations, now())
	if err != nil {
		t.Fatal(err)
	}
	downloader := &copyingSitesDownloader{source: source}
	catchUpRoot := filepath.Join(t.TempDir(), "catchup")
	catchUp, err := OpenSitesCatchUp(catchUpRoot, downloader)
	if err != nil {
		t.Fatal(err)
	}
	storeRoot := filepath.Join(t.TempDir(), "store")
	store := openAppliedNativeStoreAt(t, storeRoot, profile, authority, delegations, now())
	key := ed25519.NewKeyFromSeed([]byte(strings.Repeat("k", ed25519.SeedSize)))
	gateway := adnl.NewGateway(key)
	node, err := NewNativeNode(NativeNodeConfig{Profile: profile, Authority: authority,
		Delegations: delegations, Store: store, LocalKey: key, Gateway: gateway,
		Directory:    &memoryNativeDirectory{records: make(map[string]NativeDiscoveredPeer)},
		SitesCatchUp: catchUp, Now: now})
	if err != nil {
		t.Fatal(err)
	}
	hint := SitesHint{Schema: SitesHintSchema, ChannelID: profile.ChannelID, ProfileDigest: profileDigest,
		HistoryDigest: history.Digest(), BagID: strings.Repeat("f1", 32)}
	if err := node.scheduleSitesCatchUp("peer_fixture", hint); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(5 * time.Second)
	for {
		_, found, events, digest := node.Stats()
		if found && events == 1 && digest == history.Digest() {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("native node did not commit verified Sites history")
		}
		time.Sleep(10 * time.Millisecond)
	}
	node.Close()
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	if err := catchUp.Close(); err != nil {
		t.Fatal(err)
	}
	catchUp, err = OpenSitesCatchUp(catchUpRoot, downloader)
	if err != nil {
		t.Fatal(err)
	}
	defer catchUp.Close()
	store = openAppliedNativeStoreAt(t, storeRoot, profile, authority, delegations, now())
	defer store.Close()
	gateway = adnl.NewGateway(key)
	node, err = NewNativeNode(NativeNodeConfig{Profile: profile, Authority: authority,
		Delegations: delegations, Store: store, LocalKey: key, Gateway: gateway,
		Directory:    &memoryNativeDirectory{records: make(map[string]NativeDiscoveredPeer)},
		SitesCatchUp: catchUp, Now: now})
	if err != nil {
		t.Fatal(err)
	}
	defer node.Close()
	node.mutex.Lock()
	restored := node.sitesFound && node.sitesReceipt.Hint() == hint
	node.mutex.Unlock()
	if !restored || downloader.Count() != 1 {
		t.Fatalf("restarted locator restored=%t downloader calls=%d", restored, downloader.Count())
	}
}

type copyingSitesDownloader struct {
	mutex  sync.Mutex
	source string
	calls  int
}

func (d *copyingSitesDownloader) Download(ctx context.Context, hint SitesHint, destination string) (string, error) {
	select {
	case <-ctx.Done():
		return "", ctx.Err()
	default:
	}
	d.mutex.Lock()
	d.calls++
	d.mutex.Unlock()
	target := filepath.Join(destination, strings.TrimPrefix(hint.HistoryDigest, "sha256:"))
	if err := copySitesDirectory(d.source, target); err != nil {
		return "", err
	}
	return target, nil
}

func (d *copyingSitesDownloader) Count() int {
	d.mutex.Lock()
	defer d.mutex.Unlock()
	return d.calls
}

func copySitesDirectory(source, destination string) error {
	return filepath.WalkDir(source, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		relative, err := filepath.Rel(source, path)
		if err != nil {
			return err
		}
		target := filepath.Join(destination, relative)
		if entry.IsDir() {
			return os.MkdirAll(target, 0o700)
		}
		if entry.Type()&os.ModeSymlink != 0 || !entry.Type().IsRegular() {
			return errors.New("fixture source is not regular")
		}
		raw, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		return os.WriteFile(target, raw, 0o600)
	})
}
