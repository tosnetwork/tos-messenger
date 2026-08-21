package publicchannel

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/tosnetwork/tos-messenger/internal/canon"
	"github.com/tosnetwork/tos-messenger/internal/dirlock"
	"github.com/tosnetwork/tos-messenger/internal/securefile"
	"github.com/tosnetwork/tos-messenger/pkg/identity"
)

const (
	SitesSnapshotSchema      = "tos.messaging.public-channel-sites-snapshot.v1"
	SitesReceiptSchema       = "tos.messaging.public-channel-sites-receipt.v1"
	SitesHintSchema          = "tos.messaging.public-channel-sites-hint.v1"
	MaxSitesManifestBytes    = 8 << 20
	MaxSitesHintBytes        = 4 << 10
	MaxStorageCLIOutputBytes = 1 << 20
	sitesMirrorLock          = ".public-channel-sites.lock"
)

var sitesBagPattern = regexp.MustCompile(`^[0-9a-f]{64}$`)
var storageCLIBagPattern = regexp.MustCompile(`^([0-9a-f]{64}|[0-9A-F]{64})$`)

type SitesDelegationRecord struct {
	EndpointID string `json:"messaging_endpoint_id"`
	Digest     string `json:"delegation_digest"`
}

type SitesSnapshotManifest struct {
	Schema        string                  `json:"schema"`
	ChannelID     string                  `json:"channel_id"`
	ProfileDigest string                  `json:"profile_digest"`
	HistoryDigest string                  `json:"history_digest"`
	ProfileFile   string                  `json:"profile_file"`
	HeadFile      string                  `json:"head_file"`
	Delegations   []SitesDelegationRecord `json:"delegations"`
	EventIDs      []string                `json:"event_ids"`
}

type SitesPublicationReceipt struct {
	Schema        string `json:"schema"`
	ChannelID     string `json:"channel_id"`
	ProfileDigest string `json:"profile_digest"`
	HistoryDigest string `json:"history_digest"`
	BagID         string `json:"bag_id"`
}

type SitesHint struct {
	Schema        string `json:"schema"`
	ChannelID     string `json:"channel_id"`
	ProfileDigest string `json:"profile_digest"`
	HistoryDigest string `json:"history_digest"`
	BagID         string `json:"bag_id"`
}

func EncodeSitesHintJSON(hint SitesHint) ([]byte, error) {
	if err := validateSitesHint(hint); err != nil {
		return nil, err
	}
	raw, err := json.Marshal(hint)
	if err != nil || len(raw) > MaxSitesHintBytes {
		return nil, errors.New("encode public channel Sites hint")
	}
	return raw, nil
}

func DecodeSitesHintJSON(raw []byte) (SitesHint, error) {
	if len(raw) == 0 || len(raw) > MaxSitesHintBytes {
		return SitesHint{}, errors.New("public channel Sites hint outside bound")
	}
	var hint SitesHint
	if strictJSON(raw, &hint) != nil || validateSitesHint(hint) != nil {
		return SitesHint{}, errors.New("decode public channel Sites hint")
	}
	canonical, _ := json.Marshal(hint)
	if !bytes.Equal(raw, canonical) {
		return SitesHint{}, errors.New("public channel Sites hint is not canonical")
	}
	return hint, nil
}

func validateSitesHint(hint SitesHint) error {
	if hint.Schema != SitesHintSchema || !channelPattern.MatchString(hint.ChannelID) ||
		!canon.ValidDigest(hint.ProfileDigest) || !canon.ValidDigest(hint.HistoryDigest) ||
		!sitesBagPattern.MatchString(hint.BagID) {
		return errors.New("invalid public channel Sites hint")
	}
	return nil
}

func (r SitesPublicationReceipt) Hint() SitesHint {
	return SitesHint{Schema: SitesHintSchema, ChannelID: r.ChannelID, ProfileDigest: r.ProfileDigest,
		HistoryDigest: r.HistoryDigest, BagID: r.BagID}
}

type SitesPublisher interface {
	Publish(context.Context, string) (string, error)
}

// SitesMirror is the single-writer durable bridge from verified histories to
// immutable TOS Storage Bags. A persisted receipt makes restart idempotent.
type SitesMirror struct {
	root      string
	publisher SitesPublisher
	lock      *dirlock.Lock
	mutex     sync.Mutex
}

func OpenSitesMirror(root string, publisher SitesPublisher) (*SitesMirror, error) {
	if !filepath.IsAbs(root) || filepath.Clean(root) != root || publisher == nil {
		return nil, errors.New("invalid public channel Sites mirror input")
	}
	if err := os.MkdirAll(root, 0o700); err != nil {
		return nil, err
	}
	for _, path := range []string{root, filepath.Join(root, "snapshots"), filepath.Join(root, "receipts")} {
		if err := os.MkdirAll(path, 0o700); err != nil {
			return nil, err
		}
		if err := requireStoreDirectory(path); err != nil {
			return nil, err
		}
	}
	lock, err := dirlock.Acquire(root, sitesMirrorLock)
	if err != nil {
		return nil, err
	}
	return &SitesMirror{root: root, publisher: publisher, lock: lock}, nil
}

func (m *SitesMirror) Close() error {
	if m == nil {
		return nil
	}
	m.mutex.Lock()
	defer m.mutex.Unlock()
	if m.lock == nil {
		return nil
	}
	lock := m.lock
	m.lock = nil
	return lock.Close()
}

func (m *SitesMirror) Publish(ctx context.Context, profile Profile, history History,
	authority identity.Delegation, delegations map[string]identity.Delegation, now time.Time) (SitesPublicationReceipt, bool, error) {
	if m == nil {
		return SitesPublicationReceipt{}, false, errors.New("public channel Sites mirror is closed")
	}
	m.mutex.Lock()
	defer m.mutex.Unlock()
	if m == nil || m.lock == nil || !m.lock.Held() || ctx == nil {
		return SitesPublicationReceipt{}, false, errors.New("public channel Sites mirror is closed")
	}
	snapshot, _, err := ExportSitesSnapshot(filepath.Join(m.root, "snapshots"), profile, history, authority, delegations, now)
	if err != nil {
		return SitesPublicationReceipt{}, false, err
	}
	receiptPath := filepath.Join(m.root, "receipts", strings.TrimPrefix(history.Digest(), "sha256:")+".json")
	if raw, found, readErr := readOptionalStoreFile(receiptPath, MaxStoreRecordBytes); found {
		var receipt SitesPublicationReceipt
		var canonical []byte
		if readErr == nil && strictJSON(raw, &receipt) == nil {
			canonical, _ = json.Marshal(receipt)
		}
		profileDigest, _ := profile.Digest()
		if readErr != nil || validateSitesReceipt(receipt) != nil || !bytes.Equal(raw, canonical) ||
			receipt.ChannelID != profile.ChannelID || receipt.ProfileDigest != profileDigest ||
			receipt.HistoryDigest != history.Digest() {
			return SitesPublicationReceipt{}, false, errors.New("public channel Sites receipt conflicts")
		}
		if _, err := LoadSitesSnapshot(snapshot, authority, delegations, now); err != nil {
			return SitesPublicationReceipt{}, false, err
		}
		return receipt, false, nil
	} else if readErr != nil {
		return SitesPublicationReceipt{}, false, readErr
	}
	bagID, err := m.publisher.Publish(ctx, snapshot)
	if err != nil {
		return SitesPublicationReceipt{}, false, err
	}
	profileDigest, _ := profile.Digest()
	receipt := SitesPublicationReceipt{Schema: SitesReceiptSchema, ChannelID: profile.ChannelID,
		ProfileDigest: profileDigest, HistoryDigest: history.Digest(), BagID: bagID}
	if err := validateSitesReceipt(receipt); err != nil {
		return SitesPublicationReceipt{}, false, err
	}
	raw, _ := json.Marshal(receipt)
	if err := putStoreImmutable(receiptPath, raw); err != nil {
		return SitesPublicationReceipt{}, false, err
	}
	return receipt, true, nil
}

func validateSitesReceipt(receipt SitesPublicationReceipt) error {
	if receipt.Schema != SitesReceiptSchema || !channelPattern.MatchString(receipt.ChannelID) ||
		!canon.ValidDigest(receipt.ProfileDigest) || !canon.ValidDigest(receipt.HistoryDigest) ||
		!sitesBagPattern.MatchString(receipt.BagID) {
		return errors.New("invalid public channel Sites receipt")
	}
	return nil
}

// ExportSitesSnapshot writes one deterministic, immutable directory suitable
// for a TOS Storage Bag. Only an already-verified complete history is exported.
// The Bag ID is intentionally outside this manifest to avoid self-reference.
func ExportSitesSnapshot(parent string, profile Profile, history History, authority identity.Delegation,
	delegations map[string]identity.Delegation, now time.Time) (string, SitesSnapshotManifest, error) {
	if !filepath.IsAbs(parent) || filepath.Clean(parent) != parent {
		return "", SitesSnapshotManifest{}, errors.New("invalid public channel Sites snapshot parent")
	}
	if err := requireStoreDirectory(parent); err != nil {
		return "", SitesSnapshotManifest{}, err
	}
	verified, err := VerifyHistory(profile, history.Events(), authority, delegations, now)
	if err != nil || verified.Digest() != history.Digest() {
		return "", SitesSnapshotManifest{}, errors.New("public channel Sites snapshot history is not verified")
	}
	profileDigest, _ := profile.Digest()
	endpointIDs := make([]string, 0, len(profile.Principals))
	seen := make(map[string]struct{})
	for _, principal := range profile.Principals {
		if _, duplicate := seen[principal.EndpointID]; duplicate {
			continue
		}
		seen[principal.EndpointID] = struct{}{}
		endpointIDs = append(endpointIDs, principal.EndpointID)
	}
	sort.Strings(endpointIDs)
	records := make([]SitesDelegationRecord, 0, len(endpointIDs))
	delegationRaw := make(map[string][]byte, len(endpointIDs))
	for _, endpointID := range endpointIDs {
		delegation, ok := delegations[endpointID]
		if !ok {
			return "", SitesSnapshotManifest{}, errors.New("missing public channel Sites delegation")
		}
		digest, digestErr := identity.Digest(delegation)
		raw, encodeErr := identity.EncodeJSON(delegation)
		if digestErr != nil || encodeErr != nil {
			return "", SitesSnapshotManifest{}, errors.New("encode public channel Sites delegation")
		}
		records = append(records, SitesDelegationRecord{EndpointID: endpointID, Digest: digest})
		delegationRaw[endpointID] = raw
	}
	events := history.Events()
	type eventObject struct {
		id  string
		raw []byte
	}
	objects := make([]eventObject, 0, len(events))
	for _, event := range events {
		id, _ := event.ID()
		raw, encodeErr := EncodeEventJSON(event)
		if encodeErr != nil {
			return "", SitesSnapshotManifest{}, encodeErr
		}
		objects = append(objects, eventObject{id: id, raw: raw})
	}
	sort.Slice(objects, func(i, j int) bool { return objects[i].id < objects[j].id })
	eventIDs := make([]string, len(objects))
	for index := range objects {
		eventIDs[index] = objects[index].id
	}
	manifest := SitesSnapshotManifest{Schema: SitesSnapshotSchema, ChannelID: profile.ChannelID,
		ProfileDigest: profileDigest, HistoryDigest: history.Digest(), ProfileFile: "profile.json",
		HeadFile: "head.json", Delegations: records, EventIDs: eventIDs}
	manifestRaw, _ := json.Marshal(manifest)
	if len(manifestRaw) > MaxSitesManifestBytes {
		return "", SitesSnapshotManifest{}, errors.New("public channel Sites manifest exceeds its bound")
	}
	destination := filepath.Join(parent, strings.TrimPrefix(history.Digest(), "sha256:"))
	if _, statErr := os.Lstat(destination); statErr == nil {
		loaded, loadErr := LoadSitesSnapshot(destination, authority, delegations, now)
		if loadErr != nil || loaded.Digest() != history.Digest() {
			return "", SitesSnapshotManifest{}, errors.New("existing public channel Sites snapshot conflicts")
		}
		return destination, manifest, nil
	} else if !errors.Is(statErr, os.ErrNotExist) {
		return "", SitesSnapshotManifest{}, statErr
	}
	temporary, err := os.MkdirTemp(parent, ".public-channel-sites-")
	if err != nil {
		return "", SitesSnapshotManifest{}, err
	}
	committed := false
	defer func() {
		if !committed {
			_ = os.RemoveAll(temporary)
		}
	}()
	if err := os.Chmod(temporary, 0o700); err != nil {
		return "", SitesSnapshotManifest{}, err
	}
	for _, directory := range []string{"delegations", "events"} {
		if err := os.Mkdir(filepath.Join(temporary, directory), 0o700); err != nil {
			return "", SitesSnapshotManifest{}, err
		}
	}
	profileRaw, _ := EncodeProfileJSON(profile)
	headRaw, _ := EncodeHeadJSON(history.Head())
	for path, raw := range map[string][]byte{"profile.json": profileRaw, "head.json": headRaw} {
		if err := writeSitesFile(filepath.Join(temporary, path), raw); err != nil {
			return "", SitesSnapshotManifest{}, err
		}
	}
	for endpointID, raw := range delegationRaw {
		if err := writeSitesFile(filepath.Join(temporary, "delegations", endpointID+".json"), raw); err != nil {
			return "", SitesSnapshotManifest{}, err
		}
	}
	for _, object := range objects {
		if err := writeSitesFile(filepath.Join(temporary, "events", object.id+".json"), object.raw); err != nil {
			return "", SitesSnapshotManifest{}, err
		}
	}
	if err := writeSitesFile(filepath.Join(temporary, "manifest.json"), manifestRaw); err != nil {
		return "", SitesSnapshotManifest{}, err
	}
	for _, directory := range []string{filepath.Join(temporary, "delegations"), filepath.Join(temporary, "events"), temporary} {
		if err := syncStoreDirectory(directory); err != nil {
			return "", SitesSnapshotManifest{}, err
		}
	}
	if err := os.Rename(temporary, destination); err != nil {
		return "", SitesSnapshotManifest{}, err
	}
	committed = true
	if err := syncStoreDirectory(parent); err != nil {
		return "", SitesSnapshotManifest{}, err
	}
	return destination, manifest, nil
}

// LoadSitesSnapshot refuses extra/missing files, checks the exact finalized
// delegations supplied by the caller, and reproduces the complete head. A Bag
// ID or successful download never replaces these checks.
func LoadSitesSnapshot(root string, authority identity.Delegation,
	finalized map[string]identity.Delegation, now time.Time) (History, error) {
	if !filepath.IsAbs(root) || filepath.Clean(root) != root || requireStoreDirectory(root) != nil ||
		requireStoreDirectory(filepath.Join(root, "delegations")) != nil ||
		requireStoreDirectory(filepath.Join(root, "events")) != nil {
		return History{}, errors.New("invalid public channel Sites snapshot root")
	}
	manifestRaw, err := securefile.ReadBoundedRegular(filepath.Join(root, "manifest.json"), MaxSitesManifestBytes)
	if err != nil {
		return History{}, err
	}
	var manifest SitesSnapshotManifest
	if strictJSON(manifestRaw, &manifest) != nil || validateSitesManifest(manifest) != nil {
		return History{}, errors.New("invalid public channel Sites manifest")
	}
	canonicalManifest, _ := json.Marshal(manifest)
	if !bytes.Equal(manifestRaw, canonicalManifest) {
		return History{}, errors.New("public channel Sites manifest is not canonical")
	}
	if err := exactSitesEntries(root, []string{"delegations", "events", "head.json", "manifest.json", "profile.json"}); err != nil {
		return History{}, err
	}
	profileRaw, err := securefile.ReadBoundedRegular(filepath.Join(root, manifest.ProfileFile), MaxProfileBytes)
	if err != nil {
		return History{}, err
	}
	profile, err := DecodeProfileJSON(profileRaw)
	if err != nil {
		return History{}, err
	}
	profileDigest, _ := profile.Digest()
	if profile.ChannelID != manifest.ChannelID || profileDigest != manifest.ProfileDigest {
		return History{}, errors.New("public channel Sites profile does not reproduce manifest")
	}
	delegationNames := make([]string, 0, len(manifest.Delegations))
	for _, record := range manifest.Delegations {
		delegationNames = append(delegationNames, record.EndpointID+".json")
		raw, readErr := securefile.ReadBoundedRegular(filepath.Join(root, "delegations", record.EndpointID+".json"), MaxStoreRecordBytes)
		delegation, decodeErr := identity.DecodeJSON(raw)
		digest, digestErr := identity.Digest(delegation)
		trusted, ok := finalized[record.EndpointID]
		trustedRaw, trustedErr := identity.EncodeJSON(trusted)
		if readErr != nil || decodeErr != nil || digestErr != nil || trustedErr != nil || !ok ||
			delegation.EndpointID != record.EndpointID || digest != record.Digest || !bytes.Equal(raw, trustedRaw) {
			return History{}, errors.New("public channel Sites delegation is not the finalized input")
		}
	}
	if err := exactSitesEntries(filepath.Join(root, "delegations"), delegationNames); err != nil {
		return History{}, err
	}
	eventNames := make([]string, 0, len(manifest.EventIDs))
	events := make([]Event, 0, len(manifest.EventIDs))
	for _, id := range manifest.EventIDs {
		eventNames = append(eventNames, id+".json")
		raw, readErr := securefile.ReadBoundedRegular(filepath.Join(root, "events", id+".json"), MaxEventBytes)
		event, decodeErr := DecodeEventJSON(raw)
		actual, idErr := event.ID()
		if readErr != nil || decodeErr != nil || idErr != nil || actual != id {
			return History{}, errors.New("public channel Sites Event does not reproduce its name")
		}
		events = append(events, event)
	}
	if err := exactSitesEntries(filepath.Join(root, "events"), eventNames); err != nil {
		return History{}, err
	}
	headRaw, err := securefile.ReadBoundedRegular(filepath.Join(root, manifest.HeadFile), MaxHeadBytes)
	if err != nil {
		return History{}, err
	}
	head, err := DecodeHeadJSON(headRaw)
	if err != nil {
		return History{}, err
	}
	history, err := VerifyHistory(profile, events, authority, finalized, now)
	if err != nil || history.Digest() != manifest.HistoryDigest || !head.Matches(history) {
		return History{}, errors.New("public channel Sites history does not reproduce its head")
	}
	return history, nil
}

func validateSitesManifest(manifest SitesSnapshotManifest) error {
	if manifest.Schema != SitesSnapshotSchema || !channelPattern.MatchString(manifest.ChannelID) ||
		!canon.ValidDigest(manifest.ProfileDigest) || !canon.ValidDigest(manifest.HistoryDigest) ||
		manifest.ProfileFile != "profile.json" || manifest.HeadFile != "head.json" ||
		len(manifest.Delegations) == 0 || len(manifest.Delegations) > MaxPrincipals ||
		len(manifest.EventIDs) == 0 || len(manifest.EventIDs) > MaxHistoryEvents {
		return errors.New("invalid public channel Sites manifest fields")
	}
	for index, record := range manifest.Delegations {
		if !identity.EndpointPattern.MatchString(record.EndpointID) || !canon.ValidDigest(record.Digest) ||
			index > 0 && manifest.Delegations[index-1].EndpointID >= record.EndpointID {
			return errors.New("invalid public channel Sites delegation index")
		}
	}
	for index, id := range manifest.EventIDs {
		if !publicEventPattern.MatchString(id) || index > 0 && manifest.EventIDs[index-1] >= id {
			return errors.New("invalid public channel Sites Event index")
		}
	}
	return nil
}

func writeSitesFile(path string, raw []byte) error {
	if len(raw) == 0 || len(raw) > MaxStoreRecordBytes {
		return errors.New("public channel Sites object outside bound")
	}
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	if _, err := file.Write(raw); err != nil {
		_ = file.Close()
		return err
	}
	if err := file.Sync(); err != nil {
		_ = file.Close()
		return err
	}
	return file.Close()
}

func exactSitesEntries(root string, wanted []string) error {
	entries, err := os.ReadDir(root)
	if err != nil || len(entries) != len(wanted) {
		return errors.New("public channel Sites snapshot has unexpected entries")
	}
	actual := make([]string, len(entries))
	for index, entry := range entries {
		actual[index] = entry.Name()
		if entry.Type()&os.ModeSymlink != 0 {
			return errors.New("public channel Sites snapshot contains a symlink")
		}
	}
	sort.Strings(actual)
	sortedWanted := append([]string(nil), wanted...)
	sort.Strings(sortedWanted)
	for index := range actual {
		if actual[index] != sortedWanted[index] {
			return errors.New("public channel Sites snapshot entry set differs")
		}
	}
	return nil
}

type StorageCLIPublisher struct {
	Command          string
	ServerAddress    string
	ClientPrivateKey string
	ServerPublicKey  string
	Timeout          time.Duration
}

// Publish creates and uploads a copied TOS Storage Bag without invoking a
// shell. The returned Bag ID is an untrusted availability locator; a consumer
// must still call LoadSitesSnapshot with finalized delegations.
func (p StorageCLIPublisher) Publish(ctx context.Context, snapshot string) (string, error) {
	if ctx == nil || !filepath.IsAbs(snapshot) || filepath.Clean(snapshot) != snapshot ||
		!filepath.IsAbs(p.Command) || !filepath.IsAbs(p.ClientPrivateKey) || !filepath.IsAbs(p.ServerPublicKey) ||
		p.ServerAddress == "" {
		return "", errors.New("invalid TOS Storage CLI publisher")
	}
	for _, path := range []string{p.Command, p.ClientPrivateKey, p.ServerPublicKey} {
		info, err := os.Lstat(path)
		if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
			return "", errors.New("TOS Storage CLI publisher path is not a regular file")
		}
	}
	timeout := p.Timeout
	if timeout == 0 {
		timeout = 2 * time.Minute
	}
	if timeout < time.Second || timeout > 10*time.Minute {
		return "", errors.New("TOS Storage CLI publisher timeout outside bound")
	}
	runCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	command := "create --copy -- " + quoteStorageToken(snapshot)
	cmd := exec.CommandContext(runCtx, p.Command, "-I", p.ServerAddress, "-k", p.ClientPrivateKey,
		"-p", p.ServerPublicKey, "-c", command)
	output := &boundedSitesOutput{remaining: MaxStorageCLIOutputBytes}
	cmd.Stdout, cmd.Stderr = output, output
	if err := cmd.Run(); err != nil {
		return "", fmt.Errorf("publish public channel TOS Storage Bag: %w: %s", err, output.String())
	}
	bagID := parseStorageBagID(output.String())
	if bagID == "" {
		return "", errors.New("TOS Storage CLI did not return a canonical BagID")
	}
	return bagID, nil
}

func quoteStorageToken(value string) string {
	return strconv.Quote(value)
}

func parseStorageBagID(output string) string {
	const marker = "BagID = "
	for _, line := range strings.Split(output, "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, marker) {
			candidate := strings.TrimSpace(strings.TrimPrefix(line, marker))
			if storageCLIBagPattern.MatchString(candidate) {
				return strings.ToLower(candidate)
			}
		}
	}
	return ""
}

type boundedSitesOutput struct {
	buffer    bytes.Buffer
	remaining int
	overflow  bool
}

func (w *boundedSitesOutput) Write(data []byte) (int, error) {
	if w.remaining <= 0 {
		w.overflow = true
		return 0, errors.New("TOS Storage CLI output exceeds bound")
	}
	written := len(data)
	part := data
	if len(part) > w.remaining {
		part = part[:w.remaining]
		w.overflow = true
	}
	_, _ = w.buffer.Write(part)
	w.remaining -= len(part)
	if len(part) != written {
		return len(part), errors.New("TOS Storage CLI output exceeds bound")
	}
	return written, nil
}

func (w *boundedSitesOutput) String() string {
	if w == nil {
		return ""
	}
	if w.overflow {
		return w.buffer.String() + "[truncated]"
	}
	return w.buffer.String()
}

var _ io.Writer = (*boundedSitesOutput)(nil)

// SitesSnapshotBagID validates the external locator syntax only. It proves no
// relationship to a history until the downloaded directory is re-verified.
func SitesSnapshotBagID(value string) ([]byte, error) {
	if !sitesBagPattern.MatchString(value) {
		return nil, errors.New("invalid public channel TOS Storage BagID")
	}
	return hex.DecodeString(value)
}
