package publicchannel

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/tosnetwork/tos-messenger/internal/dirlock"
	"github.com/tosnetwork/tos-messenger/pkg/identity"
)

const (
	SitesDownloadReceiptSchema = "tos.messaging.public-channel-sites-download-receipt.v1"
	sitesCatchUpLock           = ".public-channel-sites-catchup.lock"
	DefaultSitesDownloadPoll   = time.Second
	MaxSitesDownloadTimeout    = 30 * time.Minute
)

type SitesDownloadReceipt struct {
	Schema        string `json:"schema"`
	ChannelID     string `json:"channel_id"`
	ProfileDigest string `json:"profile_digest"`
	HistoryDigest string `json:"history_digest"`
	BagID         string `json:"bag_id"`
}

func (r SitesDownloadReceipt) Hint() SitesHint {
	return SitesHint{Schema: SitesHintSchema, ChannelID: r.ChannelID,
		ProfileDigest: r.ProfileDigest, HistoryDigest: r.HistoryDigest, BagID: r.BagID}
}

type SitesDownloader interface {
	Download(context.Context, SitesHint, string) (string, error)
}

// SitesCatchUp is the single-writer consumer of untrusted Storage Bag hints.
// A downloaded directory is useful only after its complete history reproduces
// the locally finalized profile and delegations. The receipt records that
// verification so restart does not redownload or advertise an unverified Bag.
type SitesCatchUp struct {
	root       string
	downloader SitesDownloader
	lock       *dirlock.Lock
	mutex      sync.Mutex
}

func OpenSitesCatchUp(root string, downloader SitesDownloader) (*SitesCatchUp, error) {
	if !filepath.IsAbs(root) || filepath.Clean(root) != root || downloader == nil {
		return nil, errors.New("invalid public channel Sites catch-up input")
	}
	if err := os.MkdirAll(root, 0o700); err != nil {
		return nil, err
	}
	for _, path := range []string{root, filepath.Join(root, "downloads"), filepath.Join(root, "download-receipts")} {
		if err := os.MkdirAll(path, 0o700); err != nil {
			return nil, err
		}
		if err := requireStoreDirectory(path); err != nil {
			return nil, err
		}
	}
	lock, err := dirlock.Acquire(root, sitesCatchUpLock)
	if err != nil {
		return nil, err
	}
	return &SitesCatchUp{root: root, downloader: downloader, lock: lock}, nil
}

func (c *SitesCatchUp) Close() error {
	if c == nil {
		return nil
	}
	c.mutex.Lock()
	defer c.mutex.Unlock()
	if c.lock == nil {
		return nil
	}
	lock := c.lock
	c.lock = nil
	return lock.Close()
}

// Fetch downloads one hinted Bag when necessary, verifies every snapshot
// object against finalized authority, and durably records only that exact
// verified locator. The returned bool reports a new durable receipt.
func (c *SitesCatchUp) Fetch(ctx context.Context, hint SitesHint, profile Profile,
	authority identity.Delegation, delegations map[string]identity.Delegation,
	now time.Time) (History, SitesHint, bool, error) {
	if c == nil || ctx == nil || validateSitesHint(hint) != nil {
		return History{}, SitesHint{}, false, errors.New("invalid public channel Sites catch-up request")
	}
	profileDigest, err := profile.Digest()
	if err != nil || profile.ChannelID != hint.ChannelID || profileDigest != hint.ProfileDigest {
		return History{}, SitesHint{}, false, errors.New("public channel Sites hint is bound to another profile")
	}
	c.mutex.Lock()
	defer c.mutex.Unlock()
	if c.lock == nil || !c.lock.Held() {
		return History{}, SitesHint{}, false, errors.New("public channel Sites catch-up is closed")
	}
	if history, cached, found, err := c.cachedLocked(profile, authority, delegations, now, hint.HistoryDigest); found || err != nil {
		return history, cached, false, err
	}
	destination := filepath.Join(c.root, "downloads", hint.BagID)
	expected := filepath.Join(destination, strings.TrimPrefix(hint.HistoryDigest, "sha256:"))
	if _, statErr := os.Lstat(expected); statErr == nil {
		history, loadErr := LoadSitesSnapshot(expected, authority, delegations, now)
		if loadErr != nil || history.Digest() != hint.HistoryDigest || history.profileDigest != hint.ProfileDigest {
			return History{}, SitesHint{}, false, errors.New("unreceipted public channel Sites snapshot does not reproduce hint")
		}
		receipt := SitesDownloadReceipt{Schema: SitesDownloadReceiptSchema, ChannelID: hint.ChannelID,
			ProfileDigest: hint.ProfileDigest, HistoryDigest: hint.HistoryDigest, BagID: hint.BagID}
		raw, _ := json.Marshal(receipt)
		if err := putStoreImmutable(c.receiptPath(hint.HistoryDigest), raw); err != nil {
			return History{}, SitesHint{}, false, err
		}
		return history, receipt.Hint(), true, nil
	} else if !errors.Is(statErr, os.ErrNotExist) {
		return History{}, SitesHint{}, false, statErr
	}
	path, err := c.downloader.Download(ctx, hint, destination)
	if err != nil {
		return History{}, SitesHint{}, false, err
	}
	if path != expected {
		return History{}, SitesHint{}, false, errors.New("public channel Sites downloader returned another path")
	}
	history, err := LoadSitesSnapshot(path, authority, delegations, now)
	if err != nil || history.Digest() != hint.HistoryDigest || history.profileDigest != hint.ProfileDigest {
		return History{}, SitesHint{}, false, errors.New("downloaded public channel Sites snapshot does not reproduce hint")
	}
	receipt := SitesDownloadReceipt{Schema: SitesDownloadReceiptSchema, ChannelID: hint.ChannelID,
		ProfileDigest: hint.ProfileDigest, HistoryDigest: hint.HistoryDigest, BagID: hint.BagID}
	raw, _ := json.Marshal(receipt)
	if err := putStoreImmutable(c.receiptPath(hint.HistoryDigest), raw); err != nil {
		return History{}, SitesHint{}, false, err
	}
	return history, receipt.Hint(), true, nil
}

// Cached re-verifies a previously downloaded snapshot before returning its
// locator. Damage or finalized-delegation drift fails closed at startup.
func (c *SitesCatchUp) Cached(profile Profile, history History, authority identity.Delegation,
	delegations map[string]identity.Delegation, now time.Time) (SitesHint, bool, error) {
	if c == nil {
		return SitesHint{}, false, nil
	}
	c.mutex.Lock()
	defer c.mutex.Unlock()
	if c.lock == nil || !c.lock.Held() {
		return SitesHint{}, false, errors.New("public channel Sites catch-up is closed")
	}
	loaded, hint, found, err := c.cachedLocked(profile, authority, delegations, now, history.Digest())
	if err != nil || !found {
		return SitesHint{}, found, err
	}
	if loaded.Digest() != history.Digest() {
		return SitesHint{}, false, errors.New("cached public channel Sites history conflicts")
	}
	return hint, true, nil
}

func (c *SitesCatchUp) cachedLocked(profile Profile, authority identity.Delegation,
	delegations map[string]identity.Delegation, now time.Time, historyDigest string) (History, SitesHint, bool, error) {
	raw, found, err := readOptionalStoreFile(c.receiptPath(historyDigest), MaxStoreRecordBytes)
	if err != nil || !found {
		return History{}, SitesHint{}, found, err
	}
	var receipt SitesDownloadReceipt
	if strictJSON(raw, &receipt) != nil || validateSitesDownloadReceipt(receipt) != nil {
		return History{}, SitesHint{}, true, errors.New("invalid public channel Sites download receipt")
	}
	canonical, _ := json.Marshal(receipt)
	profileDigest, _ := profile.Digest()
	if !bytes.Equal(raw, canonical) || receipt.ChannelID != profile.ChannelID ||
		receipt.ProfileDigest != profileDigest || receipt.HistoryDigest != historyDigest {
		return History{}, SitesHint{}, true, errors.New("public channel Sites download receipt conflicts")
	}
	path := filepath.Join(c.root, "downloads", receipt.BagID, strings.TrimPrefix(receipt.HistoryDigest, "sha256:"))
	history, err := LoadSitesSnapshot(path, authority, delegations, now)
	if err != nil || history.Digest() != receipt.HistoryDigest || history.profileDigest != receipt.ProfileDigest {
		return History{}, SitesHint{}, true, errors.New("cached public channel Sites snapshot does not reproduce receipt")
	}
	return history, receipt.Hint(), true, nil
}

func (c *SitesCatchUp) receiptPath(historyDigest string) string {
	return filepath.Join(c.root, "download-receipts", strings.TrimPrefix(historyDigest, "sha256:")+".json")
}

func validateSitesDownloadReceipt(receipt SitesDownloadReceipt) error {
	if receipt.Schema != SitesDownloadReceiptSchema {
		return errors.New("invalid public channel Sites download receipt")
	}
	return validateSitesHint(receipt.Hint())
}

type StorageCLIDownloader struct {
	Command          string
	ServerAddress    string
	ClientPrivateKey string
	ServerPublicKey  string
	Timeout          time.Duration
	PollInterval     time.Duration
}

// Download registers an immutable Bag by hash without upload, then polls the
// stock daemon until the complete expected snapshot directory is available.
// CLI output and paths are untrusted and must exactly reproduce the request.
func (d StorageCLIDownloader) Download(ctx context.Context, hint SitesHint, destination string) (string, error) {
	if ctx == nil || validateSitesHint(hint) != nil || !filepath.IsAbs(destination) ||
		filepath.Clean(destination) != destination || !filepath.IsAbs(d.Command) ||
		!filepath.IsAbs(d.ClientPrivateKey) || !filepath.IsAbs(d.ServerPublicKey) || d.ServerAddress == "" {
		return "", errors.New("invalid TOS Storage CLI downloader")
	}
	for _, path := range []string{d.Command, d.ClientPrivateKey, d.ServerPublicKey} {
		info, err := os.Lstat(path)
		if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
			return "", errors.New("TOS Storage CLI downloader path is not a regular file")
		}
	}
	if err := requireStoreDirectory(filepath.Dir(destination)); err != nil {
		return "", err
	}
	if info, err := os.Lstat(destination); err == nil {
		if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm() != 0o700 {
			return "", errors.New("TOS Storage CLI download root is not private")
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return "", err
	}
	timeout := d.Timeout
	if timeout == 0 {
		timeout = 10 * time.Minute
	}
	if timeout < time.Second || timeout > MaxSitesDownloadTimeout {
		return "", errors.New("TOS Storage CLI downloader timeout outside bound")
	}
	poll := d.PollInterval
	if poll == 0 {
		poll = DefaultSitesDownloadPoll
	}
	if poll < 10*time.Millisecond || poll > 30*time.Second {
		return "", errors.New("TOS Storage CLI downloader poll interval outside bound")
	}
	runCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	add := "add-by-hash " + hint.BagID + " -d " + quoteStorageToken(destination) + " --no-upload"
	output, addErr := d.run(runCtx, add)
	if addErr == nil {
		status, err := parseStorageCLIStatus(output)
		if err != nil || validateStorageDownloadStatus(status, hint, destination) != nil {
			return "", errors.New("TOS Storage CLI add returned invalid status")
		}
		if status.completed {
			return expectedSitesDownloadPath(destination, hint), nil
		}
	}
	for {
		output, err := d.run(runCtx, "get "+hint.BagID)
		if err != nil {
			if addErr != nil {
				return "", fmt.Errorf("register public channel TOS Storage Bag: %w; inspect: %v", addErr, err)
			}
			return "", fmt.Errorf("inspect public channel TOS Storage Bag: %w", err)
		}
		status, err := parseStorageCLIStatus(output)
		if err != nil || validateStorageDownloadStatus(status, hint, destination) != nil {
			return "", errors.New("TOS Storage CLI get returned invalid status")
		}
		if status.completed {
			return expectedSitesDownloadPath(destination, hint), nil
		}
		timer := time.NewTimer(poll)
		select {
		case <-runCtx.Done():
			timer.Stop()
			return "", errors.New("public channel TOS Storage Bag download timed out")
		case <-timer.C:
		}
	}
}

func (d StorageCLIDownloader) run(ctx context.Context, command string) (string, error) {
	cmd := exec.CommandContext(ctx, d.Command, "-I", d.ServerAddress, "-k", d.ClientPrivateKey,
		"-p", d.ServerPublicKey, "-c", command)
	output := &boundedSitesOutput{remaining: MaxStorageCLIOutputBytes}
	cmd.Stdout, cmd.Stderr = output, output
	if err := cmd.Run(); err != nil {
		return output.String(), fmt.Errorf("run TOS Storage CLI: %w: %s", err, output.String())
	}
	return output.String(), nil
}

type storageCLIStatus struct {
	bagID      string
	rootDir    string
	dirName    string
	completed  bool
	downloaded bool
	fatal      bool
}

func parseStorageCLIStatus(output string) (storageCLIStatus, error) {
	var status storageCLIStatus
	set := func(target *string, value string) error {
		if *target != "" || value == "" {
			return errors.New("duplicate or empty TOS Storage CLI status field")
		}
		*target = value
		return nil
	}
	for _, raw := range strings.Split(output, "\n") {
		line := strings.TrimSpace(raw)
		switch {
		case strings.HasPrefix(line, "BagID = "):
			if err := set(&status.bagID, strings.TrimSpace(strings.TrimPrefix(line, "BagID = "))); err != nil {
				return storageCLIStatus{}, err
			}
		case strings.HasPrefix(line, "Root dir: "):
			if err := set(&status.rootDir, strings.TrimSpace(strings.TrimPrefix(line, "Root dir: "))); err != nil {
				return storageCLIStatus{}, err
			}
		case strings.HasPrefix(line, "Dir name: "):
			if err := set(&status.dirName, strings.TrimSpace(strings.TrimPrefix(line, "Dir name: "))); err != nil {
				return storageCLIStatus{}, err
			}
		case strings.HasPrefix(line, "Downloaded: "):
			if status.downloaded {
				return storageCLIStatus{}, errors.New("duplicate TOS Storage CLI download status")
			}
			status.downloaded = true
			status.completed = strings.HasSuffix(line, " (completed)")
		case strings.HasPrefix(line, "FATAL ERROR:"):
			status.fatal = true
		}
	}
	if !sitesBagPattern.MatchString(status.bagID) || status.rootDir == "" || status.fatal {
		return storageCLIStatus{}, errors.New("incomplete or fatal TOS Storage CLI status")
	}
	return status, nil
}

func validateStorageDownloadStatus(status storageCLIStatus, hint SitesHint, destination string) error {
	wantDir := strings.TrimPrefix(hint.HistoryDigest, "sha256:")
	if status.bagID != hint.BagID || status.rootDir != destination ||
		status.dirName != "" && status.dirName != wantDir || status.completed && (!status.downloaded || status.dirName != wantDir) {
		return errors.New("TOS Storage CLI status does not reproduce download request")
	}
	return nil
}

func expectedSitesDownloadPath(destination string, hint SitesHint) string {
	return filepath.Join(destination, strings.TrimPrefix(hint.HistoryDigest, "sha256:"))
}
