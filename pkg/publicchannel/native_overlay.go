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
	nativev1 "github.com/tosnetwork/tos-service-protocol/gen/tos/service/v1"
	"github.com/tosnetwork/tosutils-go/adnl"
	"github.com/tosnetwork/tosutils-go/adnl/keys"
	"github.com/tosnetwork/tosutils-go/adnl/overlay"
	"github.com/tosnetwork/tosutils-go/adnl/rldp"
	"github.com/tosnetwork/tosutils-go/tl"
)

const (
	nativeAnnouncementKindEvent = "event"
	nativeAnnouncementKindHead  = "head"
	MaxNativeAnnouncementBytes  = MaxEventBytes + 1024
	nativeAnswerTimeout         = 10 * time.Second
)

type nativePublicChannelAnnouncement struct {
	Kind    string `tl:"string"`
	Payload []byte `tl:"bytes"`
}

type nativePublicChannelFetch struct {
	Request []byte `tl:"bytes"`
}

type nativePublicChannelFetchResult struct {
	Response []byte `tl:"bytes"`
}

func init() {
	tl.Register(nativePublicChannelAnnouncement{}, "tosMessenger.publicChannel.announcement kind:string payload:bytes = tosMessenger.publicChannel.Announcement")
	tl.Register(nativePublicChannelFetch{}, "tosMessenger.publicChannel.fetch request:bytes = tosMessenger.publicChannel.FetchResult")
	tl.Register(nativePublicChannelFetchResult{}, "tosMessenger.publicChannel.fetchResult response:bytes = tosMessenger.publicChannel.FetchResult")
}

type NativeHistoryProvider func(FetchRequest) (map[string]Event, error)

type NativeCarrierConfig struct {
	Profile     Profile
	Authority   identity.Delegation
	Delegations map[string]identity.Delegation
	Now         func() time.Time
	Guard       *SyncGuard
	Provider    NativeHistoryProvider
	OnHead      func(peerID string, head Head) error
	OnEvent     func(peerID string, event Event) error
}

// NativeCarrier binds one authenticated ADNL peer to one public-channel
// Overlay. Small live announcements use TOS Overlay two-step broadcast and
// exact history fetches use RLDP. Native transport signatures authenticate the
// peer hop only; finalized public-channel authority is always rechecked here.
type NativeCarrier struct {
	localKey      ed25519.PrivateKey
	localID       []byte
	remoteID      []byte
	peerID        string
	channelID     string
	profileDigest string
	profile       Profile
	authority     identity.Delegation
	delegations   map[string]identity.Delegation
	now           func() time.Time
	guard         *SyncGuard
	provider      NativeHistoryProvider
	onHead        func(string, Head) error
	onEvent       func(string, Event) error

	adnlRoot    *overlay.ADNLWrapper
	adnlOverlay *overlay.ADNLOverlayWrapper
	rldpRoot    *overlay.RLDPWrapper
	rldpOverlay *overlay.RLDPOverlayWrapper
	closeOnce   sync.Once
	usageMutex  sync.Mutex
	served      uint32
	servedBytes uint64
	servedGaps  uint32
	seenHeads   map[string]struct{}
	seenEvents  map[string]struct{}
}

func NativeOverlayID(channelID string) ([]byte, error) {
	if !channelPattern.MatchString(channelID) {
		return nil, errors.New("invalid public channel for native Overlay")
	}
	id, err := hex.DecodeString(channelID[len("channel_"):])
	if err != nil || len(id) != 32 {
		return nil, errors.New("decode public channel native Overlay ID")
	}
	return id, nil
}

func NewNativeCarrier(peer adnl.Peer, localKey ed25519.PrivateKey, config NativeCarrierConfig) (*NativeCarrier, error) {
	if peer == nil || len(localKey) != ed25519.PrivateKeySize || config.Guard == nil {
		return nil, errors.New("invalid native public channel carrier input")
	}
	now := config.Now
	if now == nil {
		now = time.Now
	}
	if err := VerifyProfile(config.Profile, config.Authority, config.Delegations, now()); err != nil {
		return nil, fmt.Errorf("native public channel profile: %w", err)
	}
	profileDigest, _ := config.Profile.Digest()
	if config.Guard.channelID != config.Profile.ChannelID || config.Guard.profileDigest != profileDigest {
		return nil, errors.New("native public channel guard is bound to another profile")
	}
	overlayID, err := NativeOverlayID(config.Profile.ChannelID)
	if err != nil {
		return nil, err
	}
	remoteKey := peer.GetPubKey()
	remoteID, err := tl.Hash(keys.PublicKeyED25519{Key: remoteKey})
	if err != nil || len(remoteKey) != ed25519.PublicKeySize || len(remoteID) != 32 || !bytes.Equal(remoteID, peer.GetID()) {
		return nil, errors.New("native public channel peer identity does not reproduce")
	}
	localID, err := tl.Hash(keys.PublicKeyED25519{Key: localKey.Public().(ed25519.PublicKey)})
	if err != nil || len(localID) != 32 {
		return nil, errors.New("derive native public channel local peer identity")
	}
	adnlRoot := overlay.CreateExtendedADNL(peer)
	adnlOverlay := adnlRoot.CreateOverlayWithSettings(overlayID, 0, true, false)
	adnlOverlay.SetAuthorizedKeys(map[string]uint32{string(remoteID): MaxNativeAnnouncementBytes})
	adnlOverlay.SetFECBroadcastLimits(MaxSyncPeers, int64(MaxNativeAnnouncementBytes)*MaxSyncPeers)
	adnlOverlay.SetBroadcastTwoStepLimits(MaxSyncPeers, int64(MaxNativeAnnouncementBytes)*MaxSyncPeers)
	adnlOverlay.EnableBroadcastTwoStep(localID, overlay.StaticBroadcastPeerSet{adnlOverlay}, nil)

	rldpRoot := overlay.CreateExtendedRLDP(rldp.NewClientV2(adnlRoot))
	rldpOverlay := rldpRoot.CreateOverlay(overlayID)
	carrier := &NativeCarrier{localKey: append(ed25519.PrivateKey(nil), localKey...), localID: localID,
		remoteID: remoteID, peerID: "peer_" + hex.EncodeToString(remoteID), channelID: config.Profile.ChannelID,
		profileDigest: profileDigest, profile: cloneProfile(config.Profile), authority: cloneNativeDelegation(config.Authority),
		delegations: cloneDelegations(config.Delegations), now: now, guard: config.Guard,
		provider: config.Provider, onHead: config.OnHead, onEvent: config.OnEvent,
		adnlRoot: adnlRoot, adnlOverlay: adnlOverlay, rldpRoot: rldpRoot, rldpOverlay: rldpOverlay,
		seenHeads: make(map[string]struct{}), seenEvents: make(map[string]struct{})}
	adnlOverlay.SetBroadcastPrecheckHandler(carrier.precheckAnnouncement)
	adnlOverlay.SetBroadcastHandlerWithInfo(carrier.consumeAnnouncement)
	rldpOverlay.SetOnQuery(carrier.answerFetch)
	return carrier, nil
}

func (c *NativeCarrier) PeerID() string {
	if c == nil {
		return ""
	}
	return c.peerID
}

func (c *NativeCarrier) PublishHead(ctx context.Context, head Head) error {
	if c == nil || validateHead(head) != nil || head.ChannelID != c.channelID || head.ProfileDigest != c.profileDigest {
		return errors.New("invalid native public channel head announcement")
	}
	raw, _ := EncodeHeadJSON(head)
	return c.publish(ctx, nativeAnnouncementKindHead, raw)
}

func (c *NativeCarrier) PublishEvent(ctx context.Context, event Event) error {
	if c == nil || event.ChannelID != c.channelID || event.ProfileDigest != c.profileDigest {
		return errors.New("invalid native public channel Event announcement")
	}
	delegation, found := c.delegations[event.PublisherEndpointID]
	if !found || VerifyEvent(event, c.profile, delegation, c.now()) != nil {
		return errors.New("native public channel Event is not finalized")
	}
	raw, err := EncodeEventJSON(event)
	if err != nil {
		return err
	}
	return c.publish(ctx, nativeAnnouncementKindEvent, raw)
}

func (c *NativeCarrier) publish(ctx context.Context, kind string, raw []byte) error {
	if ctx == nil || c.adnlOverlay == nil || len(raw) == 0 || len(raw) > MaxNativeAnnouncementBytes {
		return errors.New("invalid native public channel announcement")
	}
	result, err := c.adnlOverlay.SendBroadcastTwoStepFromTL(ctx, overlay.BroadcastTwoStepTLSendRequest{
		Key: c.localKey, LocalADNLID: c.localID,
		Payload: nativePublicChannelAnnouncement{Kind: kind, Payload: append([]byte(nil), raw...)},
	})
	if err != nil {
		return fmt.Errorf("native public channel Overlay broadcast: %w", err)
	}
	if result.Sent != 1 || result.Attempted != 1 {
		return errors.New("native public channel Overlay did not reach its peer")
	}
	return nil
}

func (c *NativeCarrier) Fetch(ctx context.Context, request FetchRequest) ([]Event, []string, error) {
	if c == nil || ctx == nil || validateFetchRequest(request) != nil || request.ChannelID != c.channelID ||
		request.ProfileDigest != c.profileDigest {
		return nil, nil, errors.New("invalid native public channel fetch")
	}
	requestRaw, _ := EncodeFetchRequestJSON(request)
	if err := c.guard.BeginFetch(c.peerID); err != nil {
		return nil, nil, err
	}
	var result nativePublicChannelFetchResult
	err := c.rldpOverlay.DoQuery(ctx, MaxFetchResponseBytes, nativePublicChannelFetch{Request: requestRaw}, &result)
	if err != nil {
		return nil, nil, fmt.Errorf("native public channel RLDP fetch: %w", err)
	}
	events, unavailable, decodeErr := DecodeFetchResponseJSON(result.Response, request)
	chargeUnavailable := len(unavailable)
	if decodeErr != nil {
		chargeUnavailable = MaxFetchEvents
	}
	if err := c.guard.ChargeResponse(c.peerID, len(result.Response), chargeUnavailable); err != nil {
		return nil, nil, err
	}
	if decodeErr != nil {
		return nil, nil, decodeErr
	}
	if err := VerifyFetchedEvents(c.profile, events, c.authority, c.delegations, c.now()); err != nil {
		return nil, nil, err
	}
	return events, unavailable, nil
}

func (c *NativeCarrier) precheckAnnouncement(info overlay.BroadcastPrecheckInfo) error {
	if c == nil || !bytes.Equal(info.OverlayID, mustNativeOverlayID(c.channelID)) ||
		!bytes.Equal(info.SourceID, c.remoteID) {
		return errors.New("native public channel announcement source substitution")
	}
	return nil
}

func (c *NativeCarrier) consumeAnnouncement(object tl.Serializable, info overlay.BroadcastInfo) error {
	announcement, ok := object.(nativePublicChannelAnnouncement)
	if !ok || !info.Trusted || !bytes.Equal(info.SourceID, c.remoteID) ||
		!bytes.Equal(info.OverlayID, mustNativeOverlayID(c.channelID)) || len(announcement.Payload) == 0 ||
		len(announcement.Payload) > MaxNativeAnnouncementBytes {
		return errors.New("invalid native public channel announcement")
	}
	switch announcement.Kind {
	case nativeAnnouncementKindHead:
		head, err := DecodeHeadJSON(announcement.Payload)
		if err != nil || head.ChannelID != c.channelID || head.ProfileDigest != c.profileDigest {
			return errors.New("invalid native public channel announced head")
		}
		if err := c.guard.ObserveHead(c.peerID, head); err != nil {
			return err
		}
		headRaw, _ := EncodeHeadJSON(head)
		if !c.claimAnnouncement(string(headRaw), true) {
			return nil
		}
		if c.onHead != nil {
			if err := c.onHead(c.peerID, cloneHead(head)); err != nil {
				c.releaseAnnouncement(string(headRaw), true)
				return err
			}
		}
	case nativeAnnouncementKindEvent:
		event, err := DecodeEventJSON(announcement.Payload)
		if err != nil || event.ChannelID != c.channelID || event.ProfileDigest != c.profileDigest {
			return errors.New("invalid native public channel announced Event")
		}
		delegation, found := c.delegations[event.PublisherEndpointID]
		if !found || VerifyEvent(event, c.profile, delegation, c.now()) != nil {
			return errors.New("native public channel announced Event is not finalized")
		}
		id, _ := event.ID()
		if !c.claimAnnouncement(id, false) {
			return nil
		}
		if c.onEvent != nil {
			if err := c.onEvent(c.peerID, cloneEvent(event)); err != nil {
				c.releaseAnnouncement(id, false)
				return err
			}
		}
	default:
		return errors.New("unknown native public channel announcement kind")
	}
	return nil
}

func (c *NativeCarrier) answerFetch(transferID []byte, query *rldp.Query) error {
	requestObject, ok := query.Data.(nativePublicChannelFetch)
	if c == nil || !ok || c.provider == nil || len(requestObject.Request) == 0 || len(requestObject.Request) > MaxFetchRequestBytes {
		return errors.New("invalid native public channel RLDP query")
	}
	request, err := DecodeFetchRequestJSON(requestObject.Request)
	if err != nil || request.ChannelID != c.channelID || request.ProfileDigest != c.profileDigest {
		return errors.New("native public channel RLDP query is bound to another profile")
	}
	if err := c.beginServeFetch(); err != nil {
		return err
	}
	available, err := c.provider(request)
	if err != nil {
		return err
	}
	response, err := EncodeFetchResponseJSON(request, available)
	if err != nil {
		return err
	}
	_, unavailable, err := DecodeFetchResponseJSON(response, request)
	if err != nil {
		return errors.New("native public channel generated an invalid fetch response")
	}
	if err := c.chargeServeResponse(len(response), len(unavailable)); err != nil {
		return err
	}
	answerWindow := nativeAnswerTimeout
	if deadline := time.Until(time.Unix(int64(query.Timeout), 0)); deadline > 0 && deadline < answerWindow {
		answerWindow = deadline
	}
	if answerWindow <= 0 {
		return errors.New("native public channel RLDP query expired")
	}
	ctx, cancel := context.WithTimeout(context.Background(), answerWindow)
	defer cancel()
	return c.rldpRoot.SendAnswer(ctx, query.MaxAnswerSize, query.Timeout, query.ID, transferID,
		nativePublicChannelFetchResult{Response: response})
}

func (c *NativeCarrier) beginServeFetch() error {
	c.usageMutex.Lock()
	defer c.usageMutex.Unlock()
	if c.served >= c.guard.limits.FetchesPerPeer {
		return errors.New("native public channel inbound fetch limit reached")
	}
	c.served++
	return nil
}

func (c *NativeCarrier) chargeServeResponse(responseBytes, unavailable int) error {
	if responseBytes < 1 || responseBytes > MaxFetchResponseBytes || unavailable < 0 || unavailable > MaxFetchEvents {
		return errors.New("invalid native public channel served response")
	}
	c.usageMutex.Lock()
	defer c.usageMutex.Unlock()
	bytes := uint64(responseBytes)
	gaps := uint32(unavailable)
	if bytes > c.guard.limits.ResponseBytesPerPeer-c.servedBytes || gaps > c.guard.limits.UnavailablePerPeer-c.servedGaps {
		return errors.New("native public channel inbound response limit reached")
	}
	c.servedBytes += bytes
	c.servedGaps += gaps
	return nil
}

func (c *NativeCarrier) claimAnnouncement(key string, head bool) bool {
	c.usageMutex.Lock()
	defer c.usageMutex.Unlock()
	seen := c.seenEvents
	limit := int(c.guard.limits.FetchesPerPeer)
	if head {
		seen = c.seenHeads
		limit = int(c.guard.limits.CandidateHeadsPerPeer)
	}
	if _, replay := seen[key]; replay {
		return false
	}
	if len(seen) >= limit {
		return false
	}
	seen[key] = struct{}{}
	return true
}

func (c *NativeCarrier) releaseAnnouncement(key string, head bool) {
	c.usageMutex.Lock()
	defer c.usageMutex.Unlock()
	if head {
		delete(c.seenHeads, key)
	} else {
		delete(c.seenEvents, key)
	}
}

func (c *NativeCarrier) Close() {
	if c == nil {
		return
	}
	c.closeOnce.Do(func() {
		if c.rldpOverlay != nil {
			c.rldpOverlay.Close()
		}
		if c.adnlOverlay != nil {
			c.adnlOverlay.Close()
		}
		if c.rldpRoot != nil {
			c.rldpRoot.Close()
		}
		for index := range c.localKey {
			c.localKey[index] = 0
		}
	})
}

func mustNativeOverlayID(channelID string) []byte {
	id, _ := NativeOverlayID(channelID)
	return id
}

func cloneDelegations(source map[string]identity.Delegation) map[string]identity.Delegation {
	result := make(map[string]identity.Delegation, len(source))
	for key, delegation := range source {
		result[key] = cloneNativeDelegation(delegation)
	}
	return result
}

func cloneProfile(profile Profile) Profile {
	profile.Network = cloneNativeNetwork(profile.Network)
	profile.Principals = append([]Principal(nil), profile.Principals...)
	profile.AuthoritySignature = append([]byte(nil), profile.AuthoritySignature...)
	return profile
}

func cloneNativeDelegation(delegation identity.Delegation) identity.Delegation {
	delegation.Network = cloneNativeNetwork(delegation.Network)
	delegation.IdentityPublicKey = append(ed25519.PublicKey(nil), delegation.IdentityPublicKey...)
	delegation.AllowedProtocolVersions = append([]uint32(nil), delegation.AllowedProtocolVersions...)
	delegation.AllowedOutboundEventClasses = append([]string(nil), delegation.AllowedOutboundEventClasses...)
	return delegation
}

func cloneNativeNetwork(network *nativev1.NetworkDomain) *nativev1.NetworkDomain {
	if network == nil {
		return nil
	}
	return &nativev1.NetworkDomain{NetworkId: network.NetworkId, GenesisRootHash: network.GenesisRootHash,
		GenesisFileHash: network.GenesisFileHash}
}
