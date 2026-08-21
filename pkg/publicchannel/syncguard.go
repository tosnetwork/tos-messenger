package publicchannel

import (
	"errors"
	"regexp"
	"sort"
	"sync"

	"github.com/tosnetwork/tos-messenger/internal/canon"
)

const (
	MaxSyncPeers             = 32
	MaxCandidateHeadsPerPeer = 8
	MaxFetchesPerPeer        = 1024
	MaxSyncPeerBytes         = 1 << 30
	MaxSyncTotalBytes        = 4 << 30
)

var syncPeerPattern = regexp.MustCompile(`^peer_[0-9a-f]{64}$`)

type SyncLimits struct {
	Peers                 uint32
	CandidateHeadsPerPeer uint32
	FetchesPerPeer        uint32
	ResponseBytesPerPeer  uint64
	UnavailablePerPeer    uint32
	TotalResponseBytes    uint64
}

func DefaultSyncLimits() SyncLimits {
	return SyncLimits{Peers: 8, CandidateHeadsPerPeer: 4, FetchesPerPeer: 256,
		ResponseBytesPerPeer: 64 << 20, UnavailablePerPeer: 256, TotalResponseBytes: 256 << 20}
}

type HeadCandidate struct {
	Head    Head
	Support uint32
}

type syncPeerUsage struct {
	heads       map[string]Head
	fetches     uint32
	bytes       uint64
	unavailable uint32
}

// SyncGuard bounds one channel/profile synchronization attempt. It prioritizes
// independently observed heads but never turns peer count into validity: only
// VerifySyncedHistory can authorize a commit.
type SyncGuard struct {
	channelID     string
	profileDigest string
	limits        SyncLimits
	mutex         sync.Mutex
	peers         map[string]*syncPeerUsage
	totalBytes    uint64
}

func NewSyncGuard(channelID, profileDigest string, limits SyncLimits) (*SyncGuard, error) {
	if !channelPattern.MatchString(channelID) || !canon.ValidDigest(profileDigest) || validateSyncLimits(limits) != nil {
		return nil, errors.New("invalid public channel sync guard")
	}
	return &SyncGuard{channelID: channelID, profileDigest: profileDigest, limits: limits,
		peers: make(map[string]*syncPeerUsage)}, nil
}

// ObserveHead registers one authenticated native transport peer's bounded
// claim. Exact replay is free; distinct claims consume that peer's head budget.
func (g *SyncGuard) ObserveHead(peerID string, head Head) error {
	if g == nil || !syncPeerPattern.MatchString(peerID) || validateHead(head) != nil ||
		head.ChannelID != g.channelID || head.ProfileDigest != g.profileDigest {
		return errors.New("invalid public channel peer head")
	}
	raw, _ := EncodeHeadJSON(head)
	key := string(raw)
	g.mutex.Lock()
	defer g.mutex.Unlock()
	peer, found := g.peers[peerID]
	if !found {
		if uint32(len(g.peers)) >= g.limits.Peers {
			return errors.New("public channel sync peer limit reached")
		}
		peer = &syncPeerUsage{heads: make(map[string]Head)}
		g.peers[peerID] = peer
	}
	if _, replay := peer.heads[key]; replay {
		return nil
	}
	if uint32(len(peer.heads)) >= g.limits.CandidateHeadsPerPeer {
		return errors.New("public channel peer head limit reached")
	}
	peer.heads[key] = cloneHead(head)
	return nil
}

// ChargeFetch accounts bounded work after the transport-level response-size
// ceiling has already stopped the read. A peer reporting unavailable IDs still
// consumes both fetch and unavailable budgets.
func (g *SyncGuard) ChargeFetch(peerID string, responseBytes int, unavailable int) error {
	if g == nil || responseBytes < 1 || responseBytes > MaxFetchResponseBytes ||
		unavailable < 0 || unavailable > MaxFetchEvents {
		return errors.New("invalid public channel fetch charge")
	}
	g.mutex.Lock()
	defer g.mutex.Unlock()
	peer, found := g.peers[peerID]
	if !found {
		return errors.New("unobserved public channel sync peer")
	}
	bytes := uint64(responseBytes)
	missing := uint32(unavailable)
	if peer.fetches >= g.limits.FetchesPerPeer || bytes > g.limits.ResponseBytesPerPeer-peer.bytes ||
		missing > g.limits.UnavailablePerPeer-peer.unavailable || bytes > g.limits.TotalResponseBytes-g.totalBytes {
		return errors.New("public channel sync resource limit reached")
	}
	peer.fetches++
	peer.bytes += bytes
	peer.unavailable += missing
	g.totalBytes += bytes
	return nil
}

// Candidates returns fetch priority only. A support threshold can avoid work
// on one-peer noise, but digest tie-breaking never grants authority or commits.
func (g *SyncGuard) Candidates(minSupport uint32) ([]HeadCandidate, error) {
	if g == nil || minSupport == 0 || minSupport > g.limits.Peers {
		return nil, errors.New("invalid public channel head support threshold")
	}
	g.mutex.Lock()
	defer g.mutex.Unlock()
	type aggregate struct {
		head  Head
		peers map[string]struct{}
	}
	byHead := map[string]*aggregate{}
	for peerID, peer := range g.peers {
		for key, head := range peer.heads {
			item := byHead[key]
			if item == nil {
				item = &aggregate{head: head, peers: make(map[string]struct{})}
				byHead[key] = item
			}
			item.peers[peerID] = struct{}{}
		}
	}
	result := make([]HeadCandidate, 0, len(byHead))
	for _, item := range byHead {
		if uint32(len(item.peers)) >= minSupport {
			result = append(result, HeadCandidate{Head: cloneHead(item.head), Support: uint32(len(item.peers))})
		}
	}
	sort.Slice(result, func(i, j int) bool {
		if result[i].Support != result[j].Support {
			return result[i].Support > result[j].Support
		}
		return result[i].Head.HistoryDigest < result[j].Head.HistoryDigest
	})
	return result, nil
}

func validateSyncLimits(limits SyncLimits) error {
	if limits.Peers == 0 || limits.Peers > MaxSyncPeers || limits.CandidateHeadsPerPeer == 0 ||
		limits.CandidateHeadsPerPeer > MaxCandidateHeadsPerPeer || limits.FetchesPerPeer == 0 ||
		limits.FetchesPerPeer > MaxFetchesPerPeer || limits.ResponseBytesPerPeer < MaxFetchResponseBytes ||
		limits.ResponseBytesPerPeer > MaxSyncPeerBytes || limits.UnavailablePerPeer == 0 ||
		limits.UnavailablePerPeer > MaxHistoryEvents || limits.TotalResponseBytes < limits.ResponseBytesPerPeer ||
		limits.TotalResponseBytes > MaxSyncTotalBytes {
		return errors.New("invalid public channel sync limits")
	}
	return nil
}

func cloneHead(head Head) Head {
	head.Tips = append([]string(nil), head.Tips...)
	return head
}
