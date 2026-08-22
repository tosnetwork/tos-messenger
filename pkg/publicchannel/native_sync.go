package publicchannel

import "errors"

const maxPendingNativeSyncs = MaxSyncPeers * MaxCandidateHeadsPerPeer

type nativeSyncCandidate struct {
	peerID string
	key    string
	head   Head
}

func newNativeSyncCandidate(peerID string, head Head) (nativeSyncCandidate, error) {
	if !syncPeerPattern.MatchString(peerID) || validateHead(head) != nil {
		return nativeSyncCandidate{}, errors.New("invalid native public channel sync candidate")
	}
	raw, err := EncodeHeadJSON(head)
	if err != nil {
		return nativeSyncCandidate{}, err
	}
	return nativeSyncCandidate{peerID: peerID, key: string(raw), head: cloneHead(head)}, nil
}

// nativeSyncScheduler is protected by NativeNode.mutex. At most one peer may
// fetch an exact Head and at most one Head may occupy a peer. Other authenticated
// observations are retained as a bounded FIFO so a failed peer can be replaced
// without multiplying successful synchronization work.
type nativeSyncScheduler struct {
	activePeers map[string]string
	activeHeads map[string]string
	pending     []nativeSyncCandidate
}

func (s *nativeSyncScheduler) enqueue(candidate nativeSyncCandidate) (bool, error) {
	canonical, err := newNativeSyncCandidate(candidate.peerID, candidate.head)
	if err != nil || candidate.key != canonical.key {
		return false, errors.New("invalid native public channel sync candidate")
	}
	s.ensureMaps()
	if s.activePeers[candidate.peerID] == candidate.key || s.pendingContains(candidate) {
		return false, nil
	}
	if _, peerBusy := s.activePeers[candidate.peerID]; !peerBusy {
		if _, headBusy := s.activeHeads[candidate.key]; !headBusy {
			s.activate(candidate)
			return true, nil
		}
	}
	if len(s.pending) >= maxPendingNativeSyncs {
		return false, errors.New("native public channel sync queue is full")
	}
	s.pending = append(s.pending, candidate)
	return false, nil
}

func (s *nativeSyncScheduler) complete(candidate nativeSyncCandidate, succeeded bool,
	available func(string) bool) []nativeSyncCandidate {
	s.ensureMaps()
	if s.activePeers[candidate.peerID] != candidate.key || s.activeHeads[candidate.key] != candidate.peerID {
		return nil
	}
	delete(s.activePeers, candidate.peerID)
	delete(s.activeHeads, candidate.key)
	if succeeded {
		s.dropHead(candidate.key)
	} else if next, found := s.takeHead(candidate.key, available); found {
		s.activate(next)
		return append([]nativeSyncCandidate{next}, s.activateReady(available)...)
	}
	return s.activateReady(available)
}

func (s *nativeSyncScheduler) reset() {
	s.activePeers = make(map[string]string)
	s.activeHeads = make(map[string]string)
	s.pending = nil
}

func (s *nativeSyncScheduler) ensureMaps() {
	if s.activePeers == nil {
		s.activePeers = make(map[string]string)
	}
	if s.activeHeads == nil {
		s.activeHeads = make(map[string]string)
	}
}

func (s *nativeSyncScheduler) activate(candidate nativeSyncCandidate) {
	s.activePeers[candidate.peerID] = candidate.key
	s.activeHeads[candidate.key] = candidate.peerID
}

func (s *nativeSyncScheduler) pendingContains(candidate nativeSyncCandidate) bool {
	for _, queued := range s.pending {
		if queued.peerID == candidate.peerID && queued.key == candidate.key {
			return true
		}
	}
	return false
}

func (s *nativeSyncScheduler) dropHead(key string) {
	kept := s.pending[:0]
	for _, candidate := range s.pending {
		if candidate.key != key {
			kept = append(kept, candidate)
		}
	}
	s.pending = kept
}

func (s *nativeSyncScheduler) takeHead(key string, available func(string) bool) (nativeSyncCandidate, bool) {
	for index := 0; index < len(s.pending); {
		candidate := s.pending[index]
		if available != nil && !available(candidate.peerID) {
			s.pending = append(s.pending[:index], s.pending[index+1:]...)
			continue
		}
		if candidate.key == key && s.activePeers[candidate.peerID] == "" {
			s.pending = append(s.pending[:index], s.pending[index+1:]...)
			return candidate, true
		}
		index++
	}
	return nativeSyncCandidate{}, false
}

func (s *nativeSyncScheduler) activateReady(available func(string) bool) []nativeSyncCandidate {
	started := make([]nativeSyncCandidate, 0)
	for index := 0; index < len(s.pending); {
		candidate := s.pending[index]
		if available != nil && !available(candidate.peerID) {
			s.pending = append(s.pending[:index], s.pending[index+1:]...)
			continue
		}
		_, peerBusy := s.activePeers[candidate.peerID]
		_, headBusy := s.activeHeads[candidate.key]
		if peerBusy || headBusy {
			index++
			continue
		}
		s.pending = append(s.pending[:index], s.pending[index+1:]...)
		s.activate(candidate)
		started = append(started, candidate)
	}
	return started
}
