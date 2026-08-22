package publicchannel

import (
	"fmt"
	"strings"
	"testing"
)

func TestNativeSyncSchedulerSingleFlightsHeadAndFailsOver(t *testing.T) {
	head := nativeSchedulerHead("a")
	first := mustNativeSyncCandidate(t, 1, head)
	var scheduler nativeSyncScheduler
	started, err := scheduler.enqueue(first)
	if err != nil || !started {
		t.Fatalf("first candidate: started=%t err=%v", started, err)
	}
	for peer := 2; peer <= MaxSyncPeers; peer++ {
		candidate := mustNativeSyncCandidate(t, peer, head)
		if started, err := scheduler.enqueue(candidate); err != nil || started {
			t.Fatalf("duplicate Head peer %d: started=%t err=%v", peer, started, err)
		}
	}
	second := mustNativeSyncCandidate(t, 2, head)
	if started, err := scheduler.enqueue(second); err != nil || started || len(scheduler.pending) != MaxSyncPeers-1 {
		t.Fatalf("queued replay: started=%t pending=%d err=%v", started, len(scheduler.pending), err)
	}
	starts := scheduler.complete(first, false, func(string) bool { return true })
	if len(starts) != 1 || starts[0].peerID != second.peerID ||
		scheduler.activeHeads[first.key] != second.peerID || len(scheduler.pending) != MaxSyncPeers-2 {
		t.Fatalf("failure did not select exactly one fallback: starts=%+v pending=%d", starts, len(scheduler.pending))
	}
	if stale := scheduler.complete(first, true, func(string) bool { return true }); len(stale) != 0 ||
		scheduler.activeHeads[first.key] != second.peerID {
		t.Fatal("stale completion replaced the active fallback")
	}
	if starts := scheduler.complete(second, true, func(string) bool { return true }); len(starts) != 0 ||
		len(scheduler.activeHeads) != 0 || len(scheduler.activePeers) != 0 || len(scheduler.pending) != 0 {
		t.Fatalf("successful fallback retained duplicate work: starts=%+v scheduler=%+v", starts, scheduler)
	}
}

func TestNativeSyncSchedulerPreservesDistinctHeadsAndDropsGonePeers(t *testing.T) {
	first := mustNativeSyncCandidate(t, 1, nativeSchedulerHead("a"))
	samePeerNext := mustNativeSyncCandidate(t, 1, nativeSchedulerHead("b"))
	sameHeadFallback := mustNativeSyncCandidate(t, 2, first.head)
	var scheduler nativeSyncScheduler
	if started, err := scheduler.enqueue(first); err != nil || !started {
		t.Fatal("first Head did not start")
	}
	if started, err := scheduler.enqueue(samePeerNext); err != nil || started {
		t.Fatal("one peer started two Heads")
	}
	if started, err := scheduler.enqueue(sameHeadFallback); err != nil || started {
		t.Fatal("one Head started on two peers")
	}
	starts := scheduler.complete(first, false, func(peerID string) bool {
		return peerID != sameHeadFallback.peerID
	})
	if len(starts) != 1 || starts[0].key != samePeerNext.key || starts[0].peerID != first.peerID {
		t.Fatalf("gone fallback blocked a distinct queued Head: %+v", starts)
	}
	if len(scheduler.pending) != 0 || len(scheduler.activeHeads) != 1 {
		t.Fatalf("scheduler retained a gone peer: %+v", scheduler)
	}
	scheduler.reset()
	if len(scheduler.pending) != 0 || len(scheduler.activeHeads) != 0 || len(scheduler.activePeers) != 0 {
		t.Fatal("scheduler reset retained work")
	}
}

func TestNativeSyncSchedulerUsesExactHeadAndBoundsQueue(t *testing.T) {
	firstHead := nativeSchedulerHead("a")
	secondHead := firstHead
	secondHead.Tips = []string{"pce_" + strings.Repeat("b", 64)}
	first := mustNativeSyncCandidate(t, 1, firstHead)
	second := mustNativeSyncCandidate(t, 2, secondHead)
	if first.key == second.key {
		t.Fatal("Head-tip substitution shared a synchronization key")
	}
	var scheduler nativeSyncScheduler
	if started, err := scheduler.enqueue(first); err != nil || !started {
		t.Fatal("first candidate did not start")
	}
	if started, err := scheduler.enqueue(second); err != nil || !started {
		t.Fatal("distinct exact Head was incorrectly suppressed")
	}
	corrupt := first
	corrupt.key += "-substituted"
	if started, err := scheduler.enqueue(corrupt); err == nil || started {
		t.Fatalf("candidate key substitution: started=%t err=%v", started, err)
	}
	for queued := 0; queued < maxPendingNativeSyncs; queued++ {
		head := nativeSchedulerHead("a")
		head.HistoryDigest = "sha256:" + fmt.Sprintf("%064x", queued+10)
		candidate := mustNativeSyncCandidate(t, 1, head)
		if started, err := scheduler.enqueue(candidate); err != nil || started {
			t.Fatalf("queue fill %d: started=%t err=%v", queued, started, err)
		}
	}
	overflowHead := nativeSchedulerHead("f")
	overflowHead.HistoryDigest = "sha256:" + strings.Repeat("e", 64)
	overflow := mustNativeSyncCandidate(t, 1, overflowHead)
	if started, err := scheduler.enqueue(overflow); err == nil || started {
		t.Fatalf("queue overflow: started=%t err=%v", started, err)
	}
}

func TestNativeNodeCloseClearsSyncSchedule(t *testing.T) {
	first := mustNativeSyncCandidate(t, 1, nativeSchedulerHead("a"))
	second := mustNativeSyncCandidate(t, 2, first.head)
	var scheduler nativeSyncScheduler
	if started, err := scheduler.enqueue(first); err != nil || !started {
		t.Fatal("first candidate did not start")
	}
	if started, err := scheduler.enqueue(second); err != nil || started {
		t.Fatal("duplicate Head did not queue")
	}
	node := &NativeNode{syncs: scheduler, cancelSync: func() {}}
	node.Close()
	if !node.closed || len(node.syncs.pending) != 0 || len(node.syncs.activeHeads) != 0 ||
		len(node.syncs.activePeers) != 0 {
		t.Fatalf("closed node retained synchronization work: %+v", node.syncs)
	}
}

func nativeSchedulerHead(marker string) Head {
	return Head{Schema: HeadSchema,
		ChannelID:     "channel_" + strings.Repeat("1", 64),
		ProfileDigest: "sha256:" + strings.Repeat("2", 64),
		EventCount:    1,
		Tips:          []string{"pce_" + strings.Repeat(marker, 64)},
		HistoryDigest: "sha256:" + strings.Repeat("3", 64)}
}

func mustNativeSyncCandidate(t *testing.T, peer int, head Head) nativeSyncCandidate {
	t.Helper()
	candidate, err := newNativeSyncCandidate(fmt.Sprintf("peer_%064x", peer), head)
	if err != nil {
		t.Fatal(err)
	}
	return candidate
}
