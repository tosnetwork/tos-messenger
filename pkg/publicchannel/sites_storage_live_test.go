package publicchannel

import (
	"bytes"
	"context"
	"encoding/json"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

// TestStorageCLILiveTwoDaemonCatchUp is an explicit operator acceptance test.
// It starts two real TOS storage-daemon binaries, bootstraps them through one
// locally signed DHT node, publishes a verified public-channel snapshot on the
// first process, downloads and re-verifies it on the second, then proves the
// durable catch-up receipt works while the download daemon is offline.
func TestStorageCLILiveTwoDaemonCatchUp(t *testing.T) {
	daemonBinary := os.Getenv("TOS_STORAGE_LIVE_DAEMON")
	cliBinary := os.Getenv("TOS_STORAGE_LIVE_CLI")
	keyTool := os.Getenv("TOS_STORAGE_LIVE_KEY_TOOL")
	seedConfig := os.Getenv("TOS_STORAGE_LIVE_GLOBAL_CONFIG")
	if daemonBinary == "" && cliBinary == "" && keyTool == "" && seedConfig == "" {
		t.Skip("set TOS_STORAGE_LIVE_{DAEMON,CLI,KEY_TOOL,GLOBAL_CONFIG} for two-daemon evidence")
	}
	for name, path := range map[string]string{"daemon": daemonBinary, "cli": cliBinary,
		"key tool": keyTool, "global config": seedConfig} {
		if !filepath.IsAbs(path) || filepath.Clean(path) != path {
			t.Fatalf("live Storage %s path is not absolute and canonical", name)
		}
		info, err := os.Lstat(path)
		if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
			t.Fatalf("live Storage %s path is not a regular file", name)
		}
	}
	root := filepath.Join(t.TempDir(), "two-daemon")
	if err := os.Mkdir(root, 0o700); err != nil {
		t.Fatal(err)
	}
	serverDB := filepath.Join(root, "server")
	clientDB := filepath.Join(root, "client")
	serverADNL, serverControl := reserveStoragePorts(t)
	clientADNL, clientControl := reserveStoragePorts(t)

	server := startLiveStorageDaemon(t, daemonBinary, seedConfig, serverDB, serverADNL, serverControl)
	waitLiveStorageCLI(t, cliBinary, serverControl, serverDB)
	server.Close(t)
	localConfig := filepath.Join(root, "local-global.json")
	writeLiveStorageLocalConfig(t, keyTool, serverDB, serverADNL, localConfig)
	server = startLiveStorageDaemon(t, daemonBinary, localConfig, serverDB, serverADNL, serverControl)
	defer server.Close(t)
	waitLiveStorageCLI(t, cliBinary, serverControl, serverDB)
	client := startLiveStorageDaemon(t, daemonBinary, localConfig, clientDB, clientADNL, clientControl)
	defer client.Close(t)
	waitLiveStorageCLI(t, cliBinary, clientControl, clientDB)

	profile, authority, _, publisher, publisherKey, delegations := storeFixture(t)
	profileDigest, _ := profile.Digest()
	event := signedPost(t, profile, profileDigest, publisher, publisherKey, 1, "", nil, channelNow, "live two-daemon storage")
	now := time.Unix(int64(channelNow+2), 0)
	history, err := VerifyHistory(profile, []Event{event}, authority, delegations, now)
	if err != nil {
		t.Fatal(err)
	}
	snapshotParent := filepath.Join(root, "snapshots")
	if err := os.Mkdir(snapshotParent, 0o700); err != nil {
		t.Fatal(err)
	}
	snapshot, _, err := ExportSitesSnapshot(snapshotParent, profile, history, authority, delegations, now)
	if err != nil {
		t.Fatal(err)
	}
	publisherAdapter := StorageCLIPublisher{Command: cliBinary, ServerAddress: liveStorageAddress(serverControl),
		ClientPrivateKey: liveStorageClientKey(serverDB), ServerPublicKey: liveStorageServerKey(serverDB),
		Timeout: 30 * time.Second}
	bagID, err := publisherAdapter.Publish(context.Background(), snapshot)
	if err != nil {
		t.Fatal(err)
	}
	hint := SitesHint{Schema: SitesHintSchema, ChannelID: profile.ChannelID,
		ProfileDigest: profileDigest, HistoryDigest: history.Digest(), BagID: bagID}
	downloader := StorageCLIDownloader{Command: cliBinary, ServerAddress: liveStorageAddress(clientControl),
		ClientPrivateKey: liveStorageClientKey(clientDB), ServerPublicKey: liveStorageServerKey(clientDB),
		Timeout: 60 * time.Second, PollInterval: 100 * time.Millisecond}
	catchUpRoot := filepath.Join(root, "catchup")
	catchUp, err := OpenSitesCatchUp(catchUpRoot, downloader)
	if err != nil {
		t.Fatal(err)
	}
	loaded, accepted, changed, err := catchUp.Fetch(context.Background(), hint, profile, authority, delegations, now)
	if err != nil || !changed || accepted != hint || loaded.Digest() != history.Digest() {
		t.Fatalf("live two-daemon catch-up digest=%q accepted=%#v changed=%t err=%v",
			loaded.Digest(), accepted, changed, err)
	}
	if err := catchUp.Close(); err != nil {
		t.Fatal(err)
	}
	client.Close(t)
	catchUp, err = OpenSitesCatchUp(catchUpRoot, downloader)
	if err != nil {
		t.Fatal(err)
	}
	defer catchUp.Close()
	loaded, accepted, changed, err = catchUp.Fetch(context.Background(), hint, profile, authority, delegations, now)
	if err != nil || changed || accepted != hint || loaded.Digest() != history.Digest() {
		t.Fatalf("offline receipt replay digest=%q accepted=%#v changed=%t err=%v",
			loaded.Digest(), accepted, changed, err)
	}
	t.Logf("live_storage_two_daemon_bag_id=%s history_digest=%s", bagID, history.Digest())
}

type liveStorageDaemon struct {
	command *exec.Cmd
	log     *os.File
}

func startLiveStorageDaemon(t *testing.T, binary, config, database string, adnlPort, controlPort int) *liveStorageDaemon {
	t.Helper()
	logPath := database + ".log"
	log, err := os.OpenFile(logPath, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	command := exec.Command(binary, "-I", "127.0.0.1:"+strconv.Itoa(adnlPort),
		"-p", strconv.Itoa(controlPort), "-C", config, "-D", database, "-v", "1")
	command.Stdout, command.Stderr = log, log
	if err := command.Start(); err != nil {
		_ = log.Close()
		t.Fatal(err)
	}
	return &liveStorageDaemon{command: command, log: log}
}

func (d *liveStorageDaemon) Close(t *testing.T) {
	t.Helper()
	if d == nil || d.command == nil {
		return
	}
	command := d.command
	d.command = nil
	_ = command.Process.Signal(os.Interrupt)
	done := make(chan error, 1)
	go func() { done <- command.Wait() }()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		_ = command.Process.Kill()
		<-done
	}
	if d.log != nil {
		_ = d.log.Close()
		d.log = nil
	}
}

func waitLiveStorageCLI(t *testing.T, cli string, controlPort int, database string) {
	t.Helper()
	deadline := time.Now().Add(15 * time.Second)
	var last string
	for time.Now().Before(deadline) {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		command := exec.CommandContext(ctx, cli, "-I", liveStorageAddress(controlPort),
			"-k", liveStorageClientKey(database), "-p", liveStorageServerKey(database), "-c", "list --hashes")
		output := &boundedSitesOutput{remaining: MaxStorageCLIOutputBytes}
		command.Stdout, command.Stderr = output, output
		err := command.Run()
		cancel()
		last = output.String()
		if err == nil && strings.Contains(last, "bags") {
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("live Storage daemon did not become ready: %s", last)
}

func writeLiveStorageLocalConfig(t *testing.T, keyTool, database string, adnlPort int, destination string) {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(database, "config.json"))
	if err != nil {
		t.Fatal(err)
	}
	var config struct {
		DHTID struct {
			Key string `json:"key"`
		} `json:"dht_id"`
	}
	if json.Unmarshal(raw, &config) != nil || config.DHTID.Key == "" {
		t.Fatal("live Storage daemon config has no DHT key")
	}
	address := map[string]any{"@type": "adnl.addressList", "addrs": []any{map[string]any{
		"@type": "adnl.address.udp", "ip": 2130706433, "port": adnlPort}},
		"version": 0, "reinit_date": 0, "priority": 0, "expire_at": 0}
	addressRaw, _ := json.Marshal(address)
	entries, err := os.ReadDir(filepath.Join(database, "keyring"))
	if err != nil {
		t.Fatal(err)
	}
	var node json.RawMessage
	for _, entry := range entries {
		if entry.Type()&os.ModeSymlink != 0 || !entry.Type().IsRegular() {
			continue
		}
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		command := exec.CommandContext(ctx, keyTool, "-m", "dht", "-k",
			filepath.Join(database, "keyring", entry.Name()), "-a", string(addressRaw))
		output := &boundedSitesOutput{remaining: MaxStorageCLIOutputBytes}
		command.Stdout, command.Stderr = output, output
		runErr := command.Run()
		cancel()
		if runErr != nil || output.overflow {
			continue
		}
		var candidate struct {
			ID struct {
				Key string `json:"key"`
			} `json:"id"`
		}
		outputRaw := []byte(output.String())
		if json.Unmarshal(outputRaw, &candidate) == nil && candidate.ID.Key == config.DHTID.Key {
			node = append(json.RawMessage(nil), bytes.TrimSpace(outputRaw)...)
			break
		}
	}
	if len(node) == 0 {
		t.Fatal("could not reproduce live Storage DHT identity from its private keyring")
	}
	global := map[string]any{"@type": "config.global", "dht": map[string]any{
		"@type": "dht.config.global", "k": 6, "a": 3,
		"static_nodes": map[string]any{"@type": "dht.nodes", "nodes": []json.RawMessage{node}}}}
	encoded, err := json.Marshal(global)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(destination, encoded, 0o600); err != nil {
		t.Fatal(err)
	}
}

func reserveStoragePorts(t *testing.T) (int, int) {
	t.Helper()
	udp, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	udpPort := udp.LocalAddr().(*net.UDPAddr).Port
	_ = udp.Close()
	tcp, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	tcpPort := tcp.Addr().(*net.TCPAddr).Port
	_ = tcp.Close()
	if udpPort == tcpPort {
		return reserveStoragePorts(t)
	}
	return udpPort, tcpPort
}

func liveStorageAddress(port int) string { return "127.0.0.1:" + strconv.Itoa(port) }
func liveStorageClientKey(database string) string {
	return filepath.Join(database, "cli-keys", "client")
}
func liveStorageServerKey(database string) string {
	return filepath.Join(database, "cli-keys", "server.pub")
}
