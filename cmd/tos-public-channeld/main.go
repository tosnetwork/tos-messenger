// Command tos-public-channeld runs one route-neutral public-channel replica on
// native TOS DHT + ADNL Overlay/RLDP. Publisher keys remain in endpoints; this
// process transports and commits only already-signed, fully verified objects.
package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"net"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/tosnetwork/tos-messenger/internal/securefile"
	"github.com/tosnetwork/tos-messenger/pkg/identity"
	"github.com/tosnetwork/tos-messenger/pkg/publicchannel"
	"github.com/tosnetwork/tosutils-go/adnl"
	"github.com/tosnetwork/tosutils-go/adnl/address"
	"github.com/tosnetwork/tosutils-go/adnl/dht"
)

const maxNodeInputBytes = 1 << 20

type pathsFlag []string

func (p *pathsFlag) String() string         { return strings.Join(*p, ",") }
func (p *pathsFlag) Set(value string) error { *p = append(*p, value); return nil }

type options struct {
	profilePath   string
	authorityPath string
	delegations   []string
	state         string
	keyPath       string
	listen        string
	publicAddress string
	dhtConfigURL  string
	sitesState    string
	storageCLI    string
	storageAddr   string
	storageKey    string
	storagePub    string
	refresh       time.Duration
	ttl           time.Duration
	check         bool
}

func main() {
	var delegationPaths pathsFlag
	profile := flag.String("profile", "", "absolute signed public-channel profile JSON")
	authority := flag.String("authority-delegation", "", "absolute finalized authority delegation JSON")
	flag.Var(&delegationPaths, "delegation", "absolute finalized publisher delegation JSON (repeat)")
	state := flag.String("state", "", "absolute private public-channel state directory")
	key := flag.String("transport-key", "", "mode-0600 canonical hex Ed25519 ADNL transport key")
	listen := flag.String("listen", "", "ADNL UDP listen address")
	publicAddress := flag.String("public-address", "", "advertised UDP address; required when listen IP is unspecified")
	dhtConfig := flag.String("dht-config-url", "", "HTTPS TOS global configuration URL")
	sitesState := flag.String("sites-state", "", "optional absolute private Sites snapshot/receipt directory")
	storageCLI := flag.String("storage-cli", "", "absolute TOS storage-daemon-cli executable")
	storageAddr := flag.String("storage-daemon", "", "TOS storage-daemon ADNL-lite address")
	storageKey := flag.String("storage-client-key", "", "absolute mode-0600 storage client private key")
	storagePub := flag.String("storage-server-key", "", "absolute storage daemon public key")
	refresh := flag.Duration("refresh", publicchannel.DefaultNativeRefreshInterval, "DHT refresh interval")
	ttl := flag.Duration("dht-ttl", publicchannel.DefaultNativeDirectoryTTL, "DHT address/node TTL")
	check := flag.Bool("check", false, "validate local configuration without network or state writes")
	flag.Parse()
	err := run(options{profilePath: *profile, authorityPath: *authority, delegations: delegationPaths,
		state: *state, keyPath: *key, listen: *listen, publicAddress: *publicAddress,
		dhtConfigURL: *dhtConfig, sitesState: *sitesState, storageCLI: *storageCLI,
		storageAddr: *storageAddr, storageKey: *storageKey, storagePub: *storagePub,
		refresh: *refresh, ttl: *ttl, check: *check})
	if err != nil {
		fmt.Fprintln(os.Stderr, "tos-public-channeld:", err)
		os.Exit(1)
	}
}

func run(options options) error {
	profile, authority, delegations, key, advertised, err := loadOptions(options)
	if err != nil {
		return err
	}
	defer zero(key)
	profileDigest, _ := profile.Digest()
	overlayID, _ := publicchannel.NativeOverlayID(profile.ChannelID)
	storagePublisher, err := sitesPublisher(options)
	if err != nil {
		return err
	}
	if options.check {
		fmt.Printf("configuration_valid=true channel_id=%s profile_digest=%s overlay_id=%x transport_public_key=%x sites_enabled=%t\n",
			profile.ChannelID, profileDigest, overlayID, key.Public().(ed25519.PublicKey), storagePublisher != nil)
		return nil
	}
	store, err := publicchannel.OpenStore(options.state)
	if err != nil {
		return err
	}
	defer store.Close()
	if _, err := store.ApplyProfile(profile, authority, delegations, time.Now()); err != nil {
		return fmt.Errorf("apply public channel profile: %w", err)
	}
	var sites *publicchannel.SitesMirror
	if storagePublisher != nil {
		sites, err = publicchannel.OpenSitesMirror(options.sitesState, *storagePublisher)
		if err != nil {
			return fmt.Errorf("open public channel Sites mirror: %w", err)
		}
		defer sites.Close()
	}
	publicGateway := adnl.NewGateway(key)
	if advertised != nil {
		publicGateway.SetAddressList([]address.Address{advertised})
	}
	if err := publicGateway.StartServer(options.listen); err != nil {
		return fmt.Errorf("start public channel ADNL Gateway: %w", err)
	}
	defer publicGateway.Close()
	_, dhtKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return errors.New("generate DHT client transport key")
	}
	defer zero(dhtKey)
	dhtGateway := adnl.NewGateway(dhtKey)
	if err := dhtGateway.StartClient(); err != nil {
		return fmt.Errorf("start DHT client Gateway: %w", err)
	}
	bootstrap, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	dhtClient, err := dht.NewClientFromConfigUrl(bootstrap, dhtGateway, options.dhtConfigURL)
	cancel()
	if err != nil {
		_ = dhtGateway.Close()
		return fmt.Errorf("bootstrap native TOS DHT: %w", err)
	}
	defer dhtClient.Close()
	node, err := publicchannel.NewNativeNode(publicchannel.NativeNodeConfig{Profile: profile,
		Authority: authority, Delegations: delegations, Store: store, LocalKey: key,
		Gateway: publicGateway, Directory: publicchannel.DHTPeerDirectory{Client: dhtClient},
		DirectoryTTL: options.ttl, Sites: sites, Logf: func(format string, values ...any) {
			fmt.Fprintf(os.Stderr, "tos-public-channeld: "+format+"\n", values...)
		}})
	if err != nil {
		return err
	}
	defer node.Close()
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	fmt.Printf("ready=true channel_id=%s profile_digest=%s overlay_id=%x adnl_id=%x listen=%s advertised=%s carrier=tos-dht+adnl-overlay+rldp\n",
		profile.ChannelID, profileDigest, overlayID, publicGateway.GetID(), options.listen, describeAddress(publicGateway.GetAddressList()))
	err = node.Run(ctx, options.refresh)
	if errors.Is(err, context.Canceled) {
		return nil
	}
	return err
}

func sitesPublisher(options options) (*publicchannel.StorageCLIPublisher, error) {
	values := []string{options.sitesState, options.storageCLI, options.storageAddr, options.storageKey, options.storagePub}
	configured := 0
	for _, value := range values {
		if value != "" {
			configured++
		}
	}
	if configured == 0 {
		return nil, nil
	}
	if configured != len(values) {
		return nil, errors.New("Sites publication requires sites-state, storage-cli, storage-daemon, storage-client-key, and storage-server-key together")
	}
	for _, path := range []string{options.sitesState, options.storageCLI, options.storageKey, options.storagePub} {
		if !filepath.IsAbs(path) || filepath.Clean(path) != path {
			return nil, errors.New("Sites publication paths must be absolute and canonical")
		}
	}
	if _, _, err := net.SplitHostPort(options.storageAddr); err != nil {
		return nil, errors.New("storage-daemon must be an IP:port address")
	}
	for _, path := range []string{options.storageCLI, options.storageKey, options.storagePub} {
		info, err := os.Lstat(path)
		if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
			return nil, errors.New("Sites storage command/key path must be a regular file")
		}
	}
	keyInfo, _ := os.Lstat(options.storageKey)
	keyStat, owned := keyInfoSys(keyInfo)
	if !owned || keyStat.Uid != uint32(os.Geteuid()) || keyInfo.Mode().Perm() != 0o600 {
		return nil, errors.New("storage-client-key must be owned by this user with mode 0600")
	}
	return &publicchannel.StorageCLIPublisher{Command: options.storageCLI, ServerAddress: options.storageAddr,
		ClientPrivateKey: options.storageKey, ServerPublicKey: options.storagePub}, nil
}

func loadOptions(options options) (publicchannel.Profile, identity.Delegation,
	map[string]identity.Delegation, ed25519.PrivateKey, address.Address, error) {
	bad := func(err error) (publicchannel.Profile, identity.Delegation, map[string]identity.Delegation,
		ed25519.PrivateKey, address.Address, error) {
		return publicchannel.Profile{}, identity.Delegation{}, nil, nil, nil, err
	}
	for _, path := range []string{options.profilePath, options.authorityPath, options.state, options.keyPath} {
		if !filepath.IsAbs(path) || filepath.Clean(path) != path {
			return bad(errors.New("profile, authority-delegation, state, and transport-key must be absolute canonical paths"))
		}
	}
	if len(options.delegations) == 0 || len(options.delegations) > 4096 {
		return bad(errors.New("one to 4096 publisher delegations are required"))
	}
	if options.refresh < 10*time.Second || options.ttl < time.Minute || options.ttl > 24*time.Hour || options.refresh >= options.ttl {
		return bad(errors.New("refresh/TTL policy is outside its bound"))
	}
	parsedURL, err := url.Parse(options.dhtConfigURL)
	if err != nil || parsedURL.Scheme != "https" || parsedURL.Host == "" || parsedURL.User != nil || parsedURL.Fragment != "" {
		return bad(errors.New("dht-config-url must be an absolute HTTPS URL without userinfo"))
	}
	if _, _, err := net.SplitHostPort(options.listen); err != nil {
		return bad(errors.New("listen must be an IP:port UDP address"))
	}
	profileRaw, err := securefile.ReadBoundedRegular(options.profilePath, maxNodeInputBytes)
	if err != nil {
		return bad(err)
	}
	profile, err := publicchannel.DecodeProfileJSON(profileRaw)
	if err != nil {
		return bad(err)
	}
	authorityRaw, err := securefile.ReadBoundedRegular(options.authorityPath, maxNodeInputBytes)
	if err != nil {
		return bad(err)
	}
	authority, err := identity.DecodeJSON(authorityRaw)
	if err != nil {
		return bad(err)
	}
	delegations := map[string]identity.Delegation{authority.EndpointID: authority}
	for _, path := range options.delegations {
		if !filepath.IsAbs(path) || filepath.Clean(path) != path {
			return bad(errors.New("delegation paths must be absolute and canonical"))
		}
		raw, readErr := securefile.ReadBoundedRegular(path, maxNodeInputBytes)
		if readErr != nil {
			return bad(readErr)
		}
		delegation, decodeErr := identity.DecodeJSON(raw)
		if decodeErr != nil {
			return bad(decodeErr)
		}
		if prior, duplicate := delegations[delegation.EndpointID]; duplicate {
			if !prior.IdentityPublicKey.Equal(delegation.IdentityPublicKey) {
				return bad(errors.New("conflicting delegation endpoint"))
			}
			continue
		}
		delegations[delegation.EndpointID] = delegation
	}
	if err := publicchannel.VerifyProfile(profile, authority, delegations, time.Now()); err != nil {
		return bad(err)
	}
	keyRaw, err := securefile.ReadBoundedRegular(options.keyPath, 256)
	if err != nil {
		return bad(err)
	}
	keyInfo, err := os.Lstat(options.keyPath)
	keyStat, owned := keyInfoSys(keyInfo)
	if err != nil || keyInfo == nil || !keyInfo.Mode().IsRegular() || !owned ||
		keyStat.Uid != uint32(os.Geteuid()) || keyInfo.Mode().Perm() != 0o600 {
		return bad(errors.New("transport-key must be owned by this user with mode 0600"))
	}
	keyText := strings.TrimSuffix(string(keyRaw), "\n")
	keyBytes, err := hex.DecodeString(keyText)
	if err != nil || len(keyBytes) != ed25519.PrivateKeySize || keyText != strings.ToLower(keyText) {
		return bad(errors.New("transport-key must contain one canonical 64-byte Ed25519 private key in lowercase hex"))
	}
	key := ed25519.PrivateKey(keyBytes)
	if !ed25519.NewKeyFromSeed(key[:ed25519.SeedSize]).Equal(key) {
		zero(key)
		return bad(errors.New("transport-key public half does not reproduce its seed"))
	}
	advertised, err := advertisedAddress(options.listen, options.publicAddress)
	if err != nil {
		zero(key)
		return bad(err)
	}
	return profile, authority, delegations, key, advertised, nil
}

func keyInfoSys(info os.FileInfo) (*syscall.Stat_t, bool) {
	if info == nil {
		return nil, false
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	return stat, ok
}

func advertisedAddress(listen, advertised string) (address.Address, error) {
	listenHost, _, _ := net.SplitHostPort(listen)
	listenIP := net.ParseIP(listenHost)
	if listenIP == nil {
		return nil, errors.New("listen host must be an IP literal")
	}
	if advertised == "" && listenIP.IsUnspecified() {
		return nil, errors.New("public-address is required for an unspecified listen IP")
	}
	if advertised == "" {
		return nil, nil
	}
	host, portText, err := net.SplitHostPort(advertised)
	ip := net.ParseIP(host)
	port, portErr := strconv.ParseUint(portText, 10, 16)
	if err != nil || portErr != nil || ip == nil || ip.IsUnspecified() || port == 0 {
		return nil, errors.New("public-address must be a nonzero IP:port UDP address")
	}
	return address.NewAddress(ip, int32(port))
}

func describeAddress(list address.List) string {
	if len(list.Addresses) == 0 {
		return "none"
	}
	value, err := address.DialString(list.Addresses[0])
	if err != nil {
		return "unsupported"
	}
	return value
}

func zero(key ed25519.PrivateKey) {
	for index := range key {
		key[index] = 0
	}
}
