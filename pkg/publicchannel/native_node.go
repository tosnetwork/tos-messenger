package publicchannel

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/tosnetwork/tos-messenger/pkg/identity"
	"github.com/tosnetwork/tosutils-go/adnl"
	"github.com/tosnetwork/tosutils-go/adnl/address"
	"github.com/tosnetwork/tosutils-go/adnl/dht"
	"github.com/tosnetwork/tosutils-go/adnl/keys"
	"github.com/tosnetwork/tosutils-go/adnl/overlay"
	"github.com/tosnetwork/tosutils-go/tl"
)

const (
	DefaultNativeDirectoryTTL    = 20 * time.Minute
	DefaultNativeRefreshInterval = 5 * time.Minute
	MaxNativePeerAddresses       = 4
)

// NativeDiscoveredPeer is a DHT-authenticated public-channel node. Addresses
// are dial hints only; the ADNL handshake must reproduce PublicKey.
type NativeDiscoveredPeer struct {
	PublicKey ed25519.PublicKey
	Addresses []string
}

// NativePeerDirectory keeps discovery replaceable in tests while production
// uses the native TOS DHT adapter below.
type NativePeerDirectory interface {
	Publish(context.Context, []byte, ed25519.PrivateKey, address.List, time.Duration) error
	Discover(context.Context, []byte) ([]NativeDiscoveredPeer, error)
}

type nativeDHTClient interface {
	StoreAddress(context.Context, address.List, time.Duration, ed25519.PrivateKey) (int, []byte, error)
	StoreOverlayNodes(context.Context, []byte, *overlay.NodesList, time.Duration) (int, []byte, error)
	FindOverlayNodes(context.Context, []byte, ...*dht.Continuation) (*overlay.NodesList, *dht.Continuation, error)
	FindAddresses(context.Context, []byte) (*address.List, ed25519.PublicKey, error)
}

// DHTPeerDirectory publishes and discovers signed overlay.node records through
// the native TOS DHT. The DHT authenticates advertisements; ADNL authenticates
// the resulting connection again before any channel object is accepted.
type DHTPeerDirectory struct{ Client nativeDHTClient }

func (d DHTPeerDirectory) Publish(ctx context.Context, overlayKey []byte, key ed25519.PrivateKey,
	addresses address.List, ttl time.Duration) error {
	if d.Client == nil || ctx == nil || len(overlayKey) != 32 || len(key) != ed25519.PrivateKeySize ||
		len(addresses.Addresses) == 0 || ttl <= 0 {
		return errors.New("invalid native public channel DHT publication")
	}
	stored, adnlID, err := d.Client.StoreAddress(ctx, addresses, ttl, key)
	if err != nil || stored == 0 || len(adnlID) != 32 {
		return fmt.Errorf("publish native public channel address: stored=%d: %w", stored, err)
	}
	node, err := overlay.NewNode(overlayKey, key)
	if err != nil {
		return fmt.Errorf("sign native public channel DHT node: %w", err)
	}
	stored, overlayID, err := d.Client.StoreOverlayNodes(ctx, overlayKey, &overlay.NodesList{List: []overlay.Node{*node}}, ttl)
	wantID, idErr := NativeOverlayID("channel_" + hex.EncodeToString(overlayKey))
	if err != nil || idErr != nil || stored == 0 || !bytes.Equal(overlayID, wantID) {
		return fmt.Errorf("publish native public channel DHT node: stored=%d: %w", stored, errors.Join(err, idErr))
	}
	return nil
}

func (d DHTPeerDirectory) Discover(ctx context.Context, overlayKey []byte) ([]NativeDiscoveredPeer, error) {
	if d.Client == nil || ctx == nil || len(overlayKey) != 32 {
		return nil, errors.New("invalid native public channel DHT discovery")
	}
	nodes, _, err := d.Client.FindOverlayNodes(ctx, overlayKey)
	if err != nil {
		return nil, err
	}
	if nodes == nil {
		return nil, errors.New("native public channel DHT returned no node list")
	}
	wantOverlay, err := NativeOverlayID("channel_" + hex.EncodeToString(overlayKey))
	if err != nil {
		return nil, err
	}
	result := make([]NativeDiscoveredPeer, 0, len(nodes.List))
	seen := make(map[string]struct{})
	for _, node := range nodes.List {
		public, ok := node.ID.(keys.PublicKeyED25519)
		if !ok || len(public.Key) != ed25519.PublicKeySize || !bytes.Equal(node.Overlay, wantOverlay) {
			continue
		}
		adnlID, hashErr := tl.Hash(keys.PublicKeyED25519{Key: public.Key})
		if hashErr != nil || len(adnlID) != 32 {
			continue
		}
		list, owner, findErr := d.Client.FindAddresses(ctx, adnlID)
		if findErr != nil || !bytes.Equal(owner, public.Key) || list == nil {
			continue
		}
		addresses := make([]string, 0, MaxNativePeerAddresses)
		addressSeen := make(map[string]struct{})
		for _, item := range list.Addresses {
			dial, dialErr := address.DialString(item)
			if dialErr != nil {
				continue
			}
			if _, duplicate := addressSeen[dial]; duplicate {
				continue
			}
			addressSeen[dial] = struct{}{}
			addresses = append(addresses, dial)
			if len(addresses) == MaxNativePeerAddresses {
				break
			}
		}
		key := string(adnlID)
		if len(addresses) == 0 {
			continue
		}
		if _, duplicate := seen[key]; duplicate {
			continue
		}
		seen[key] = struct{}{}
		result = append(result, NativeDiscoveredPeer{PublicKey: append(ed25519.PublicKey(nil), public.Key...), Addresses: addresses})
		if len(result) == int(DefaultSyncLimits().Peers) {
			break
		}
	}
	return result, nil
}

type nativeNodeGateway interface {
	GetID() []byte
	GetAddressList() address.List
	RegisterClient(string, ed25519.PublicKey) (adnl.Peer, error)
	SetConnectionHandler(func(adnl.Peer) error)
}

type NativeNodeConfig struct {
	Profile      Profile
	Authority    identity.Delegation
	Delegations  map[string]identity.Delegation
	Store        *Store
	LocalKey     ed25519.PrivateKey
	Gateway      nativeNodeGateway
	Directory    NativePeerDirectory
	DirectoryTTL time.Duration
	Now          func() time.Time
	Logf         func(string, ...any)
}

// NativeNode assembles discovery, authenticated ADNL/Overlay/RLDP carriers and
// the crash-safe verified ledger. It intentionally has no publisher private
// key: application endpoints sign Events before this node transports them.
type NativeNode struct {
	profile      Profile
	authority    identity.Delegation
	delegations  map[string]identity.Delegation
	store        *Store
	localKey     ed25519.PrivateKey
	gateway      nativeNodeGateway
	directory    NativePeerDirectory
	directoryTTL time.Duration
	now          func() time.Time
	logf         func(string, ...any)
	overlayKey   []byte
	localID      string

	mutex        sync.Mutex
	allowed      map[string]ed25519.PublicKey
	carriers     map[string]*NativeCarrier
	syncing      map[string]bool
	history      History
	historyFound bool
	closed       bool
	syncContext  context.Context
	cancelSync   context.CancelFunc
	wait         sync.WaitGroup
}

func NewNativeNode(config NativeNodeConfig) (*NativeNode, error) {
	if config.Store == nil || config.Gateway == nil || config.Directory == nil ||
		len(config.LocalKey) != ed25519.PrivateKeySize {
		return nil, errors.New("invalid native public channel node input")
	}
	now := config.Now
	if now == nil {
		now = time.Now
	}
	if err := VerifyProfile(config.Profile, config.Authority, config.Delegations, now()); err != nil {
		return nil, err
	}
	overlayKey, err := NativeOverlayKey(config.Profile.ChannelID)
	if err != nil {
		return nil, err
	}
	localID := config.Gateway.GetID()
	derived, err := tl.Hash(keys.PublicKeyED25519{Key: config.LocalKey.Public().(ed25519.PublicKey)})
	if err != nil || !bytes.Equal(localID, derived) {
		return nil, errors.New("native public channel Gateway key does not reproduce")
	}
	ttl := config.DirectoryTTL
	if ttl == 0 {
		ttl = DefaultNativeDirectoryTTL
	}
	if ttl < time.Minute || ttl > 24*time.Hour {
		return nil, errors.New("native public channel directory TTL outside bound")
	}
	syncContext, cancelSync := context.WithCancel(context.Background())
	n := &NativeNode{profile: cloneProfile(config.Profile), authority: cloneNativeDelegation(config.Authority),
		delegations: cloneDelegations(config.Delegations), store: config.Store,
		localKey: append(ed25519.PrivateKey(nil), config.LocalKey...), gateway: config.Gateway,
		directory: config.Directory, directoryTTL: ttl, now: now, logf: config.Logf,
		overlayKey: overlayKey, localID: string(localID), allowed: make(map[string]ed25519.PublicKey),
		carriers: make(map[string]*NativeCarrier), syncing: make(map[string]bool),
		syncContext: syncContext, cancelSync: cancelSync}
	history, found, err := n.store.LoadHistory(n.profile, n.authority, n.delegations, n.now())
	if err != nil {
		n.cancelSync()
		n.zeroKey()
		return nil, err
	}
	n.history, n.historyFound = history, found
	n.gateway.SetConnectionHandler(n.acceptInbound)
	return n, nil
}

func NativeOverlayKey(channelID string) ([]byte, error) {
	if !channelPattern.MatchString(channelID) {
		return nil, errors.New("invalid public channel for native Overlay key")
	}
	key, err := hex.DecodeString(channelID[len("channel_"):])
	if err != nil || len(key) != 32 {
		return nil, errors.New("decode public channel native Overlay key")
	}
	return key, nil
}

func (n *NativeNode) Refresh(ctx context.Context) error {
	if n == nil || ctx == nil {
		return errors.New("invalid native public channel refresh")
	}
	n.mutex.Lock()
	if n.closed {
		n.mutex.Unlock()
		return errors.New("native public channel node is closed")
	}
	n.mutex.Unlock()
	addresses := n.gateway.GetAddressList()
	if err := n.directory.Publish(ctx, n.overlayKey, n.localKey, addresses, n.directoryTTL); err != nil {
		return err
	}
	peers, err := n.directory.Discover(ctx, n.overlayKey)
	if err != nil {
		return err
	}
	allowed := make(map[string]ed25519.PublicKey)
	for _, discovered := range peers {
		id, hashErr := tl.Hash(keys.PublicKeyED25519{Key: discovered.PublicKey})
		if hashErr != nil || len(id) != 32 || string(id) == n.localID || len(discovered.Addresses) == 0 {
			continue
		}
		allowed[string(id)] = append(ed25519.PublicKey(nil), discovered.PublicKey...)
		if len(allowed) == int(DefaultSyncLimits().Peers) {
			break
		}
	}
	n.replaceAllowed(allowed)
	for _, discovered := range peers {
		id, hashErr := tl.Hash(keys.PublicKeyED25519{Key: discovered.PublicKey})
		if hashErr != nil {
			continue
		}
		if _, ok := allowed[string(id)]; !ok {
			continue
		}
		if n.hasCarrier(string(id)) {
			continue
		}
		for _, dial := range discovered.Addresses {
			peer, registerErr := n.gateway.RegisterClient(dial, discovered.PublicKey)
			if registerErr != nil {
				continue
			}
			pingCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
			_, pingErr := peer.Ping(pingCtx)
			cancel()
			if pingErr == nil && n.attach(peer) == nil {
				break
			}
		}
	}
	return nil
}

func (n *NativeNode) Run(ctx context.Context, refresh time.Duration) error {
	if n == nil || ctx == nil {
		return errors.New("invalid native public channel run")
	}
	if refresh == 0 {
		refresh = DefaultNativeRefreshInterval
	}
	if refresh < 10*time.Second || refresh >= n.directoryTTL {
		return errors.New("native public channel refresh interval outside bound")
	}
	if err := n.Refresh(ctx); err != nil {
		return err
	}
	ticker := time.NewTicker(refresh)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
			cycle, cancel := context.WithTimeout(ctx, refresh/2)
			err := n.Refresh(cycle)
			cancel()
			if err != nil {
				n.log("public channel refresh failed: %v", err)
			}
		}
	}
}

func (n *NativeNode) acceptInbound(peer adnl.Peer) error {
	if peer == nil {
		return errors.New("nil native public channel inbound peer")
	}
	id := string(peer.GetID())
	n.mutex.Lock()
	key, allowed := n.allowed[id]
	closed := n.closed
	n.mutex.Unlock()
	if closed || !allowed || !bytes.Equal(key, peer.GetPubKey()) {
		return errors.New("native public channel inbound peer is not discovered")
	}
	return n.attach(peer)
}

func (n *NativeNode) attach(peer adnl.Peer) error {
	id := string(peer.GetID())
	n.mutex.Lock()
	if n.closed {
		n.mutex.Unlock()
		return errors.New("native public channel node is closed")
	}
	allowed, ok := n.allowed[id]
	if !ok || !bytes.Equal(allowed, peer.GetPubKey()) {
		n.mutex.Unlock()
		return errors.New("native public channel peer key is not allowed")
	}
	if _, exists := n.carriers[id]; exists {
		n.mutex.Unlock()
		return nil
	}
	n.mutex.Unlock()
	digest, _ := n.profile.Digest()
	guard, err := NewSyncGuard(n.profile.ChannelID, digest, NativeNodeSyncLimits())
	if err != nil {
		return err
	}
	carrier, err := NewNativeCarrier(peer, n.localKey, NativeCarrierConfig{Profile: n.profile,
		Authority: n.authority, Delegations: n.delegations, Now: n.now, Guard: guard,
		Provider: n.provideHistory,
		OnHead: func(peerID string, head Head) error {
			n.scheduleSync(peerID, head)
			return nil
		},
		OnEvent: func(peerID string, event Event) error {
			n.log("verified public channel Event announced peer=%s event=%s", peerID, mustEventID(event))
			return nil
		},
	})
	if err != nil {
		return err
	}
	n.mutex.Lock()
	if n.closed {
		n.mutex.Unlock()
		carrier.Close()
		return errors.New("native public channel node is closed")
	}
	if _, exists := n.carriers[id]; exists {
		n.mutex.Unlock()
		carrier.Close()
		return nil
	}
	n.carriers[id] = carrier
	history, found := n.history, n.historyFound
	n.mutex.Unlock()
	n.log("public channel peer connected peer=%s", carrier.PeerID())
	if found {
		go n.publishHeadTo(carrier, history.Head())
	}
	return nil
}

func NativeNodeSyncLimits() SyncLimits {
	return SyncLimits{Peers: 8, CandidateHeadsPerPeer: 4, FetchesPerPeer: MaxFetchesPerPeer,
		ResponseBytesPerPeer: 128 << 20, UnavailablePerPeer: 1024, TotalResponseBytes: 512 << 20}
}

func (n *NativeNode) provideHistory(request FetchRequest) (map[string]Event, error) {
	n.mutex.Lock()
	history, found := n.history, n.historyFound
	n.mutex.Unlock()
	available := make(map[string]Event)
	if !found {
		return available, nil
	}
	wanted := make(map[string]struct{}, len(request.EventIDs))
	for _, id := range request.EventIDs {
		wanted[id] = struct{}{}
	}
	for _, event := range history.Events() {
		id, _ := event.ID()
		if _, ok := wanted[id]; ok {
			available[id] = event
		}
	}
	return available, nil
}

func (n *NativeNode) syncHead(peerID string, head Head) {
	n.mutex.Lock()
	if n.closed || n.syncing[peerID] {
		n.mutex.Unlock()
		return
	}
	carrier := n.carriers[idFromPeerLabel(peerID)]
	if carrier == nil {
		n.mutex.Unlock()
		return
	}
	if n.historyFound && head.Matches(n.history) {
		n.mutex.Unlock()
		return
	}
	n.syncing[peerID] = true
	n.mutex.Unlock()
	defer func() {
		n.mutex.Lock()
		delete(n.syncing, peerID)
		n.mutex.Unlock()
	}()
	ctx, cancel := context.WithTimeout(n.syncContext, 5*time.Minute)
	defer cancel()
	var known []Event
	for {
		request, needed, err := NextFetch(head, known)
		if err != nil {
			n.log("public channel sync rejected peer=%s: %v", peerID, err)
			return
		}
		if !needed {
			break
		}
		fetched, unavailable, err := carrier.Fetch(ctx, request)
		if err != nil || len(unavailable) != 0 {
			n.log("public channel sync incomplete peer=%s unavailable=%d err=%v", peerID, len(unavailable), err)
			return
		}
		known, err = MergeFetchedEvents(known, fetched)
		if err != nil {
			n.log("public channel sync merge rejected peer=%s: %v", peerID, err)
			return
		}
	}
	if _, err := VerifySyncedHistory(head, n.profile, known, n.authority, n.delegations, n.now()); err != nil {
		n.log("public channel sync head did not reproduce peer=%s: %v", peerID, err)
		return
	}
	history, changed, err := n.store.CommitHistory(n.profile, known, n.authority, n.delegations, n.now())
	if err != nil {
		n.log("public channel sync commit rejected peer=%s: %v", peerID, err)
		return
	}
	n.mutex.Lock()
	n.history, n.historyFound = history, true
	carriers := make([]*NativeCarrier, 0, len(n.carriers))
	for _, item := range n.carriers {
		carriers = append(carriers, item)
	}
	n.mutex.Unlock()
	n.log("public channel history committed peer=%s events=%d changed=%t digest=%s", peerID, len(history.Events()), changed, history.Digest())
	if changed {
		for _, item := range carriers {
			go n.publishHeadTo(item, history.Head())
		}
	}
}

func (n *NativeNode) scheduleSync(peerID string, head Head) {
	n.mutex.Lock()
	if n.closed {
		n.mutex.Unlock()
		return
	}
	n.wait.Add(1)
	n.mutex.Unlock()
	go func() {
		defer n.wait.Done()
		n.syncHead(peerID, head)
	}()
}

func (n *NativeNode) replaceAllowed(next map[string]ed25519.PublicKey) {
	n.mutex.Lock()
	if n.closed {
		n.mutex.Unlock()
		return
	}
	var closeList []*NativeCarrier
	for id, carrier := range n.carriers {
		if _, ok := next[id]; !ok {
			closeList = append(closeList, carrier)
			delete(n.carriers, id)
		}
	}
	n.allowed = next
	n.mutex.Unlock()
	for _, carrier := range closeList {
		carrier.Close()
	}
}

func (n *NativeNode) hasCarrier(id string) bool {
	n.mutex.Lock()
	defer n.mutex.Unlock()
	return n.carriers[id] != nil
}

func (n *NativeNode) publishHeadTo(carrier *NativeCarrier, head Head) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := carrier.PublishHead(ctx, head); err != nil {
		n.log("public channel Head publish failed peer=%s: %v", carrier.PeerID(), err)
	}
}

func (n *NativeNode) Stats() (peers int, historyFound bool, events int, digest string) {
	if n == nil {
		return 0, false, 0, ""
	}
	n.mutex.Lock()
	defer n.mutex.Unlock()
	if n.historyFound {
		return len(n.carriers), true, len(n.history.events), n.history.digest
	}
	return len(n.carriers), false, 0, ""
}

func (n *NativeNode) Close() {
	if n == nil {
		return
	}
	n.mutex.Lock()
	if n.closed {
		n.mutex.Unlock()
		return
	}
	n.closed = true
	n.cancelSync()
	carriers := make([]*NativeCarrier, 0, len(n.carriers))
	for _, carrier := range n.carriers {
		carriers = append(carriers, carrier)
	}
	n.carriers = make(map[string]*NativeCarrier)
	n.allowed = make(map[string]ed25519.PublicKey)
	n.mutex.Unlock()
	for _, carrier := range carriers {
		carrier.Close()
	}
	n.wait.Wait()
	n.zeroKey()
}

func (n *NativeNode) zeroKey() {
	for index := range n.localKey {
		n.localKey[index] = 0
	}
}

func (n *NativeNode) log(format string, values ...any) {
	if n.logf != nil {
		n.logf(format, values...)
	}
}

func idFromPeerLabel(peerID string) string {
	if !syncPeerPattern.MatchString(peerID) {
		return ""
	}
	raw, _ := hex.DecodeString(peerID[len("peer_"):])
	return string(raw)
}

func mustEventID(event Event) string {
	id, _ := event.ID()
	return id
}
