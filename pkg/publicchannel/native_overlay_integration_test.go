package publicchannel

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"errors"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/tosnetwork/tos-messenger/pkg/identity"
	"github.com/tosnetwork/tosutils-go/adnl"
	"github.com/tosnetwork/tosutils-go/adnl/address"
	"github.com/tosnetwork/tosutils-go/adnl/overlay"
)

func TestNativeOverlayIDMatchesDHTNodeDerivation(t *testing.T) {
	if publicChannelRaceEnabled {
		t.Skip("tosutils-go's TL serializer is incompatible with race/checkptr; make test-adnl runs this test without race")
	}
	channelID := "channel_000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
	wantHex := "e1d36115478b0ec32f5aafc4ce748df227a2578d3a727b6542296474974aa64f"
	got, err := NativeOverlayID(channelID)
	if err != nil {
		t.Fatal(err)
	}
	if hex.EncodeToString(got) != wantHex {
		t.Fatalf("native Overlay ID = %x, want %s", got, wantHex)
	}
	key := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x30}, ed25519.SeedSize))
	node, err := overlay.NewNode(mustDecodeHex(t, channelID[len("channel_"):]), key)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(node.Overlay, got) {
		t.Fatalf("DHT node Overlay = %x, carrier Overlay = %x", node.Overlay, got)
	}
}

func mustDecodeHex(t *testing.T, value string) []byte {
	t.Helper()
	raw, err := hex.DecodeString(value)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func TestNativeOverlayADNLRLDPHistoryRoundTrip(t *testing.T) {
	if publicChannelRaceEnabled {
		t.Skip("tosutils-go's TL serializer is incompatible with race/checkptr; make test-adnl runs this test without race")
	}
	profile, authority, authorityKey, publisher, publisherKey, delegations := storeFixture(t)
	digest, _ := profile.Digest()
	first := signedPost(t, profile, digest, publisher, publisherKey, 1, "", nil, channelNow, "native root")
	firstID, _ := first.ID()
	hide, err := SignEvent(Event{ChannelID: profile.ChannelID, ProfileDigest: digest,
		PublisherAgentID: authority.AgentID, PublisherEndpointID: authority.EndpointID,
		Sequence: 1, Parents: []string{firstID}, PublishedAtUnix: channelNow + 1,
		Kind: KindHide, TargetEventID: firstID}, authorityKey)
	if err != nil {
		t.Fatal(err)
	}
	hideID, _ := hide.ID()
	now := time.Unix(int64(channelNow+2), 0)
	want, err := VerifyHistory(profile, []Event{hide, first}, authority, delegations, now)
	if err != nil {
		t.Fatal(err)
	}
	available := map[string]Event{firstID: first, hideID: hide}
	serverKey := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x31}, ed25519.SeedSize))
	clientKey := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x32}, ed25519.SeedSize))

	for attempt := 0; attempt < 2; attempt++ {
		got := runNativeCarrierPair(t, profile, authority, delegations, now, serverKey, clientKey, want, available, first)
		if got.Digest() != want.Digest() {
			t.Fatalf("attempt %d history digest = %q, want %q", attempt, got.Digest(), want.Digest())
		}
	}
}

func TestNativeNodeDiscoversSyncsAndRestartsADNL(t *testing.T) {
	if publicChannelRaceEnabled {
		t.Skip("tosutils-go's TL serializer is incompatible with race/checkptr; make test-adnl runs this test without race")
	}
	profile, authority, _, publisher, publisherKey, delegations := storeFixture(t)
	digest, _ := profile.Digest()
	first := signedPost(t, profile, digest, publisher, publisherKey, 1, "", nil, channelNow, "node assembly")
	want, err := VerifyHistory(profile, []Event{first}, authority, delegations, time.Unix(int64(channelNow+2), 0))
	if err != nil {
		t.Fatal(err)
	}
	now := func() time.Time { return time.Unix(int64(channelNow+2), 0) }
	directory := &memoryNativeDirectory{records: make(map[string]NativeDiscoveredPeer)}
	serverKey := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x41}, ed25519.SeedSize))
	clientKey := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x42}, ed25519.SeedSize))
	serverStore := openAppliedNativeStore(t, profile, authority, delegations, now())
	if _, _, err := serverStore.CommitHistory(profile, want.Events(), authority, delegations, now()); err != nil {
		t.Fatal(err)
	}
	defer serverStore.Close()
	clientRoot := filepath.Join(t.TempDir(), "store")
	clientStore := openAppliedNativeStoreAt(t, clientRoot, profile, authority, delegations, now())
	mirrorRoot := filepath.Join(t.TempDir(), "sites")
	sitesPublisher := &countingSitesPublisher{bagID: strings.Repeat("cd", 32)}
	clientMirror, err := OpenSitesMirror(mirrorRoot, sitesPublisher)
	if err != nil {
		t.Fatal(err)
	}

	serverGateway := adnl.NewGateway(serverKey)
	clientGateway := adnl.NewGateway(clientKey)
	sitesHints := make(chan SitesHint, 1)
	if err := serverGateway.StartServer(reserveNativeUDPAddress(t)); err != nil {
		t.Fatal(err)
	}
	defer serverGateway.Close()
	if err := clientGateway.StartServer(reserveNativeUDPAddress(t)); err != nil {
		t.Fatal(err)
	}
	serverNode, err := NewNativeNode(NativeNodeConfig{Profile: profile, Authority: authority,
		Delegations: delegations, Store: serverStore, LocalKey: serverKey, Gateway: serverGateway,
		Directory: directory, Now: now, OnSitesHint: func(_ string, hint SitesHint) error {
			select {
			case sitesHints <- hint:
			default:
			}
			return nil
		}})
	if err != nil {
		t.Fatal(err)
	}
	defer serverNode.Close()
	clientNode, err := NewNativeNode(NativeNodeConfig{Profile: profile, Authority: authority,
		Delegations: delegations, Store: clientStore, LocalKey: clientKey, Gateway: clientGateway,
		Directory: directory, Sites: clientMirror, Now: now})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	if err := serverNode.Refresh(ctx); err != nil {
		t.Fatal(err)
	}
	if err := clientNode.Refresh(ctx); err != nil {
		t.Fatal(err)
	}
	if err := serverNode.Refresh(ctx); err != nil {
		t.Fatal(err)
	}
	waitNativeHistory(t, ctx, clientStore, profile, authority, delegations, now(), want.Digest())
	waitSitesPublications(t, ctx, sitesPublisher, 1)
	select {
	case hint := <-sitesHints:
		if hint.HistoryDigest != want.Digest() || hint.BagID != sitesPublisher.bagID {
			t.Fatalf("unexpected propagated Sites hint: %#v", hint)
		}
	case <-ctx.Done():
		t.Fatal("Sites BagID hint was not propagated over native Overlay")
	}
	clientNode.Close()
	if err := clientMirror.Close(); err != nil {
		t.Fatal(err)
	}
	if err := clientGateway.Close(); err != nil {
		t.Fatal(err)
	}
	if err := clientStore.Close(); err != nil {
		t.Fatal(err)
	}

	clientStore = openAppliedNativeStoreAt(t, clientRoot, profile, authority, delegations, now())
	defer clientStore.Close()
	clientMirror, err = OpenSitesMirror(mirrorRoot, sitesPublisher)
	if err != nil {
		t.Fatal(err)
	}
	defer clientMirror.Close()
	clientGateway = adnl.NewGateway(clientKey)
	if err := clientGateway.StartServer(reserveNativeUDPAddress(t)); err != nil {
		t.Fatal(err)
	}
	defer clientGateway.Close()
	clientNode, err = NewNativeNode(NativeNodeConfig{Profile: profile, Authority: authority,
		Delegations: delegations, Store: clientStore, LocalKey: clientKey, Gateway: clientGateway,
		Directory: directory, Sites: clientMirror, Now: now})
	if err != nil {
		t.Fatal(err)
	}
	defer clientNode.Close()
	peers, found, events, gotDigest := clientNode.Stats()
	if peers != 0 || !found || events != 1 || gotDigest != want.Digest() {
		t.Fatalf("restarted node stats = peers=%d found=%t events=%d digest=%q", peers, found, events, gotDigest)
	}
	if err := clientNode.Refresh(ctx); err != nil {
		t.Fatal(err)
	}
	if err := serverNode.Refresh(ctx); err != nil {
		t.Fatal(err)
	}
	clientNode.scheduleMirror(want)
	clientNode.Close()
	if sitesPublisher.Count() != 1 {
		t.Fatalf("Sites history republished after durable restart: calls=%d", sitesPublisher.Count())
	}
}

type memoryNativeDirectory struct {
	mutex   sync.Mutex
	records map[string]NativeDiscoveredPeer
}

type countingSitesPublisher struct {
	mutex sync.Mutex
	bagID string
	calls int
}

func (p *countingSitesPublisher) Publish(ctx context.Context, snapshot string) (string, error) {
	if err := ctx.Err(); err != nil {
		return "", err
	}
	if info, err := os.Lstat(snapshot); err != nil || !info.IsDir() {
		return "", errors.New("Sites publisher received no snapshot")
	}
	p.mutex.Lock()
	p.calls++
	p.mutex.Unlock()
	return p.bagID, nil
}

func (p *countingSitesPublisher) Count() int {
	p.mutex.Lock()
	defer p.mutex.Unlock()
	return p.calls
}

func (d *memoryNativeDirectory) Publish(_ context.Context, overlayKey []byte, key ed25519.PrivateKey,
	list address.List, _ time.Duration) error {
	if len(overlayKey) != 32 || len(key) != ed25519.PrivateKeySize {
		return errors.New("invalid memory directory publication")
	}
	addresses := make([]string, 0, len(list.Addresses))
	for _, item := range list.Addresses {
		dial, err := address.DialString(item)
		if err == nil {
			addresses = append(addresses, dial)
		}
	}
	if len(addresses) == 0 {
		return errors.New("memory directory publication has no address")
	}
	public := key.Public().(ed25519.PublicKey)
	d.mutex.Lock()
	d.records[hex.EncodeToString(public)] = NativeDiscoveredPeer{PublicKey: append(ed25519.PublicKey(nil), public...), Addresses: addresses}
	d.mutex.Unlock()
	return nil
}

func (d *memoryNativeDirectory) Discover(context.Context, []byte) ([]NativeDiscoveredPeer, error) {
	d.mutex.Lock()
	defer d.mutex.Unlock()
	result := make([]NativeDiscoveredPeer, 0, len(d.records))
	for _, record := range d.records {
		result = append(result, record)
	}
	return result, nil
}

func openAppliedNativeStore(t *testing.T, profile Profile, authority identity.Delegation,
	delegations map[string]identity.Delegation, now time.Time) *Store {
	t.Helper()
	return openAppliedNativeStoreAt(t, filepath.Join(t.TempDir(), "store"), profile, authority, delegations, now)
}

func openAppliedNativeStoreAt(t *testing.T, root string, profile Profile, authority identity.Delegation,
	delegations map[string]identity.Delegation, now time.Time) *Store {
	t.Helper()
	store, err := OpenStore(root)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.ApplyProfile(profile, authority, delegations, now); err != nil {
		store.Close()
		t.Fatal(err)
	}
	return store
}

func waitNativeHistory(t *testing.T, ctx context.Context, store *Store, profile Profile,
	authority identity.Delegation, delegations map[string]identity.Delegation, now time.Time, want string) {
	t.Helper()
	for {
		history, found, err := store.LoadHistory(profile, authority, delegations, now)
		if err == nil && found && history.Digest() == want {
			return
		}
		select {
		case <-ctx.Done():
			t.Fatalf("native node history was not committed: found=%t err=%v", found, err)
		case <-time.After(20 * time.Millisecond):
		}
	}
}

func waitSitesPublications(t *testing.T, ctx context.Context, publisher *countingSitesPublisher, want int) {
	t.Helper()
	for publisher.Count() != want {
		select {
		case <-ctx.Done():
			t.Fatalf("Sites publication count=%d, want %d", publisher.Count(), want)
		case <-time.After(20 * time.Millisecond):
		}
	}
}

func runNativeCarrierPair(t *testing.T, profile Profile, authority identity.Delegation,
	delegations map[string]identity.Delegation, now time.Time, serverKey, clientKey ed25519.PrivateKey,
	want History, available map[string]Event, announced Event) History {
	t.Helper()
	listen := reserveNativeUDPAddress(t)
	serverGateway := adnl.NewGateway(serverKey)
	clientGateway := adnl.NewGateway(clientKey)
	serverCarriers := make(chan *NativeCarrier, 1)
	serverErrors := make(chan error, 1)
	serverGateway.SetConnectionHandler(func(peer adnl.Peer) error {
		guard, err := NewSyncGuard(profile.ChannelID, want.ProfileDigest(), DefaultSyncLimits())
		if err != nil {
			return err
		}
		carrier, err := NewNativeCarrier(peer, serverKey, NativeCarrierConfig{Profile: profile,
			Authority: authority, Delegations: delegations, Now: func() time.Time { return now }, Guard: guard,
			Provider: func(FetchRequest) (map[string]Event, error) { return available, nil },
			OnEvent: func(_ string, event Event) error {
				id, _ := event.ID()
				wantID, _ := announced.ID()
				if id != wantID {
					return errors.New("native Overlay announced another Event")
				}
				select {
				case serverErrors <- nil:
				default:
				}
				return nil
			},
		})
		if err != nil {
			return err
		}
		select {
		case serverCarriers <- carrier:
		default:
			carrier.Close()
		}
		return nil
	})
	if err := serverGateway.StartServer(listen); err != nil {
		t.Fatal(err)
	}
	defer serverGateway.Close()
	if err := clientGateway.StartClient(); err != nil {
		t.Fatal(err)
	}
	defer clientGateway.Close()
	peer, err := clientGateway.RegisterClient(listen, serverKey.Public().(ed25519.PublicKey))
	if err != nil {
		t.Fatal(err)
	}
	clientGuard, err := NewSyncGuard(profile.ChannelID, want.ProfileDigest(), DefaultSyncLimits())
	if err != nil {
		t.Fatal(err)
	}
	heads := make(chan Head, 1)
	sites := make(chan SitesHint, 1)
	clientCarrier, err := NewNativeCarrier(peer, clientKey, NativeCarrierConfig{Profile: profile,
		Authority: authority, Delegations: delegations, Now: func() time.Time { return now }, Guard: clientGuard,
		OnHead: func(_ string, head Head) error {
			select {
			case heads <- head:
			default:
			}
			return nil
		},
		OnSites: func(_ string, hint SitesHint) error {
			select {
			case sites <- hint:
			default:
			}
			return nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer clientCarrier.Close()
	pingCtx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	_, err = peer.Ping(pingCtx)
	cancel()
	if err != nil {
		t.Fatal(err)
	}
	var serverCarrier *NativeCarrier
	select {
	case serverCarrier = <-serverCarriers:
	case <-time.After(3 * time.Second):
		t.Fatal("native Overlay server carrier was not assembled")
	}
	defer serverCarrier.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := serverCarrier.PublishHead(ctx, want.Head()); err != nil {
		t.Fatal(err)
	}
	var head Head
	select {
	case head = <-heads:
	case <-ctx.Done():
		t.Fatal("native Overlay head announcement was not delivered")
	}
	hint := SitesHint{Schema: SitesHintSchema, ChannelID: profile.ChannelID,
		ProfileDigest: want.ProfileDigest(), HistoryDigest: want.Digest(), BagID: strings.Repeat("ef", 32)}
	if err := serverCarrier.PublishSitesHint(ctx, hint); err != nil {
		t.Fatal(err)
	}
	select {
	case got := <-sites:
		if got != hint {
			t.Fatalf("native Overlay Sites hint = %#v, want %#v", got, hint)
		}
	case <-ctx.Done():
		t.Fatal("native Overlay Sites hint was not delivered")
	}
	if err := clientCarrier.PublishEvent(ctx, announced); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-serverErrors:
		if err != nil {
			t.Fatal(err)
		}
	case <-ctx.Done():
		t.Fatal("native Overlay Event announcement was not delivered")
	}

	var known []Event
	for {
		request, needed, err := NextFetch(head, known)
		if err != nil {
			t.Fatal(err)
		}
		if !needed {
			break
		}
		fetched, unavailable, err := clientCarrier.Fetch(ctx, request)
		if err != nil || len(unavailable) != 0 {
			t.Fatalf("native RLDP fetch: unavailable=%v err=%v", unavailable, err)
		}
		known, err = MergeFetchedEvents(known, fetched)
		if err != nil {
			t.Fatal(err)
		}
	}
	got, err := VerifySyncedHistory(head, profile, known, authority, delegations, now)
	if err != nil {
		t.Fatal(err)
	}
	return got
}

func reserveNativeUDPAddress(t *testing.T) string {
	t.Helper()
	listener, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	address := listener.LocalAddr().String()
	if err := listener.Close(); err != nil {
		t.Fatal(err)
	}
	return address
}
