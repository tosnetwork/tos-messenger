package publicchannel

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/tosnetwork/tos-messenger/pkg/identity"
)

type publicChannelCalibration struct {
	profile     Profile
	authority   identity.Delegation
	delegations map[string]identity.Delegation
	events      []Event
	history     History
	now         time.Time
}

func newPublicChannelCalibration(tb testing.TB, count int) publicChannelCalibration {
	tb.Helper()
	if count < 1 || count > MaxHistoryEvents {
		tb.Fatalf("invalid calibration Event count %d", count)
	}
	profile, authority, _, publisher, publisherKey, delegations := storeFixture(tb)
	digest, err := profile.Digest()
	if err != nil {
		tb.Fatal(err)
	}
	events := make([]Event, 0, count)
	previous := ""
	content := strings.Repeat("x", 256)
	for sequence := 1; sequence <= count; sequence++ {
		parents := []string(nil)
		if previous != "" {
			parents = []string{previous}
		}
		event := signedPost(tb, profile, digest, publisher, publisherKey, uint64(sequence), previous,
			parents, channelNow, fmt.Sprintf("%06d:%s", sequence, content))
		previous, err = event.ID()
		if err != nil {
			tb.Fatal(err)
		}
		events = append(events, event)
	}
	now := time.Unix(int64(channelNow+1), 0)
	history, err := VerifyHistory(profile, events, authority, delegations, now)
	if err != nil {
		tb.Fatal(err)
	}
	return publicChannelCalibration{profile: profile, authority: authority, delegations: delegations,
		events: events, history: history, now: now}
}

func calibrationSizes() []int {
	return []int{1, 256, 4096, MaxHistoryEvents}
}

func fetchCalibrationSizes() []int {
	return []int{1, 256, 1024, 4096, MaxHistoryEvents}
}

func BenchmarkPublicChannelVerifyHistory(b *testing.B) {
	for _, count := range calibrationSizes() {
		b.Run(fmt.Sprintf("events-%d", count), func(b *testing.B) {
			fixture := newPublicChannelCalibration(b, count)
			b.ReportAllocs()
			b.SetBytes(int64(count * 256))
			b.ResetTimer()
			for iteration := 0; iteration < b.N; iteration++ {
				if _, err := VerifyHistory(fixture.profile, fixture.events, fixture.authority,
					fixture.delegations, fixture.now); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

func BenchmarkPublicChannelFetchCursor(b *testing.B) {
	for _, count := range fetchCalibrationSizes() {
		b.Run(fmt.Sprintf("events-%d", count), func(b *testing.B) {
			fixture := newPublicChannelCalibration(b, count)
			available := make(map[string]Event, len(fixture.events))
			for _, event := range fixture.events {
				id, _ := event.ID()
				available[id] = event
			}
			b.ReportAllocs()
			b.ResetTimer()
			for iteration := 0; iteration < b.N; iteration++ {
				cursor, err := NewFetchCursor(fixture.history.Head(), nil)
				if err != nil {
					b.Fatal(err)
				}
				for {
					request, needed, nextErr := cursor.Next()
					if nextErr != nil {
						b.Fatal(nextErr)
					}
					if !needed {
						break
					}
					fetched := make([]Event, len(request.EventIDs))
					for index, id := range request.EventIDs {
						fetched[index] = available[id]
					}
					if err := cursor.Merge(fetched); err != nil {
						b.Fatal(err)
					}
				}
				if len(cursor.Events()) != count {
					b.Fatal("cursor did not discover the complete history")
				}
			}
		})
	}
}

// This benchmark covers the production work omitted by the cursor-only
// calibration: concurrent authenticated peers, strict wire encode/decode,
// resource charging, fetched-Event verification and final head reproduction.
// Each peer owns a carrier/guard just as NativeNode does.
func BenchmarkConcurrentPublicChannelPeerSync(b *testing.B) {
	const count = 1024
	fixture := newPublicChannelCalibration(b, count)
	available := make(map[string]Event, len(fixture.events))
	for _, event := range fixture.events {
		id, _ := event.ID()
		available[id] = event
	}
	for _, peers := range []int{1, 8, MaxSyncPeers} {
		b.Run(fmt.Sprintf("peers-%d/events-%d", peers, count), func(b *testing.B) {
			b.ReportAllocs()
			b.SetBytes(int64(peers * count * 256))
			b.ReportMetric(float64(count), "fetches/peer")
			b.ResetTimer()
			for iteration := 0; iteration < b.N; iteration++ {
				errors := make(chan error, peers)
				var wait sync.WaitGroup
				for peer := 0; peer < peers; peer++ {
					wait.Add(1)
					go func(peer int) {
						defer wait.Done()
						errors <- runCalibratedPeerSync(fixture, available, peer)
					}(peer)
				}
				wait.Wait()
				close(errors)
				for err := range errors {
					if err != nil {
						b.Fatal(err)
					}
				}
			}
		})
	}
}

func runCalibratedPeerSync(fixture publicChannelCalibration, available map[string]Event, peer int) error {
	peerID := fmt.Sprintf("peer_%064x", peer+1)
	guard, err := NewSyncGuard(fixture.profile.ChannelID, fixture.history.ProfileDigest(), NativeNodeSyncLimits())
	if err != nil {
		return err
	}
	if err := guard.ObserveHead(peerID, fixture.history.Head()); err != nil {
		return err
	}
	cursor, err := NewFetchCursor(fixture.history.Head(), nil)
	if err != nil {
		return err
	}
	for fetches := 0; ; fetches++ {
		request, needed, nextErr := cursor.Next()
		if nextErr != nil {
			return nextErr
		}
		if !needed {
			if fetches != len(fixture.events) {
				return fmt.Errorf("peer %d used %d fetches for %d-event causal chain", peer, fetches, len(fixture.events))
			}
			break
		}
		if err := guard.BeginFetch(peerID); err != nil {
			return err
		}
		raw, err := EncodeFetchResponseJSON(request, available)
		if err != nil {
			return err
		}
		fetched, unavailable, err := DecodeFetchResponseJSON(raw, request)
		if err != nil {
			return err
		}
		if err := guard.ChargeResponse(peerID, len(raw), len(unavailable)); err != nil {
			return err
		}
		if len(unavailable) != 0 {
			return fmt.Errorf("peer %d observed unavailable calibrated history", peer)
		}
		if err := VerifyFetchedEvents(fixture.profile, fetched, fixture.authority, fixture.delegations, fixture.now); err != nil {
			return err
		}
		if err := cursor.Merge(fetched); err != nil {
			return err
		}
	}
	_, err = VerifySyncedHistory(fixture.history.Head(), fixture.profile, cursor.Events(), fixture.authority,
		fixture.delegations, fixture.now)
	return err
}

func BenchmarkPublicChannelNativeProviderIndex(b *testing.B) {
	for _, count := range fetchCalibrationSizes() {
		b.Run(fmt.Sprintf("events-%d", count), func(b *testing.B) {
			fixture := newPublicChannelCalibration(b, count)
			index, err := indexNativeHistory(fixture.history)
			if err != nil {
				b.Fatal(err)
			}
			id, _ := fixture.events[count/2].ID()
			node := &NativeNode{history: fixture.history, historyByID: index, historyFound: true}
			request := FetchRequest{EventIDs: []string{id}}
			b.ReportAllocs()
			b.ResetTimer()
			for iteration := 0; iteration < b.N; iteration++ {
				available, err := node.provideHistory(request)
				if err != nil || len(available) != 1 {
					b.Fatalf("indexed history response: events=%d err=%v", len(available), err)
				}
			}
		})
	}
}

func TestNativeHistoryIndexReturnsIndependentEvents(t *testing.T) {
	fixture := newPublicChannelCalibration(t, 2)
	index, err := indexNativeHistory(fixture.history)
	if err != nil {
		t.Fatal(err)
	}
	id, _ := fixture.events[0].ID()
	node := &NativeNode{history: fixture.history, historyByID: index, historyFound: true}
	request := FetchRequest{EventIDs: []string{id, "pce_" + strings.Repeat("f", 64)}}
	first, err := node.provideHistory(request)
	if err != nil || len(first) != 1 {
		t.Fatalf("first indexed response: events=%d err=%v", len(first), err)
	}
	mutated := first[id]
	mutated.Content[0] ^= 0xff
	first[id] = mutated
	second, err := node.provideHistory(request)
	if err != nil || len(second) != 1 || !strings.HasPrefix(string(second[id].Content), "000001:") {
		t.Fatalf("caller mutated indexed Event: event=%+v err=%v", second[id], err)
	}
	node.historyByID[id] = len(node.history.events)
	if _, err := node.provideHistory(request); err == nil {
		t.Fatal("damaged native history index did not fail closed")
	}
	if NativeNodeSyncLimits().FetchesPerPeer != MaxHistoryEvents || MaxFetchesPerPeer != MaxHistoryEvents {
		t.Fatal("native fetch ceiling cannot cover a maximum-size linear causal history")
	}
}

// This compatibility-path benchmark makes regressions visible without running
// the quadratic walk at the protocol maximum. NativeNode uses FetchCursor.
func BenchmarkPublicChannelLegacyFetchWalk(b *testing.B) {
	for _, count := range []int{1, 256, 1024} {
		b.Run(fmt.Sprintf("events-%d", count), func(b *testing.B) {
			fixture := newPublicChannelCalibration(b, count)
			available := make(map[string]Event, len(fixture.events))
			for _, event := range fixture.events {
				id, _ := event.ID()
				available[id] = event
			}
			b.ReportAllocs()
			b.ResetTimer()
			for iteration := 0; iteration < b.N; iteration++ {
				var known []Event
				for {
					request, needed, err := NextFetch(fixture.history.Head(), known)
					if err != nil {
						b.Fatal(err)
					}
					if !needed {
						break
					}
					fetched := make([]Event, len(request.EventIDs))
					for index, id := range request.EventIDs {
						fetched[index] = available[id]
					}
					known, err = MergeFetchedEvents(known, fetched)
					if err != nil {
						b.Fatal(err)
					}
				}
			}
		})
	}
}

func BenchmarkPublicChannelSitesSnapshot(b *testing.B) {
	for _, count := range calibrationSizes() {
		b.Run(fmt.Sprintf("export/events-%d", count), func(b *testing.B) {
			fixture := newPublicChannelCalibration(b, count)
			root := b.TempDir()
			b.ReportAllocs()
			b.ResetTimer()
			for iteration := 0; iteration < b.N; iteration++ {
				b.StopTimer()
				parent := filepath.Join(root, fmt.Sprintf("export-%d", iteration))
				if err := os.Mkdir(parent, 0o700); err != nil {
					b.Fatal(err)
				}
				b.StartTimer()
				if _, _, err := ExportSitesSnapshot(parent, fixture.profile, fixture.history,
					fixture.authority, fixture.delegations, fixture.now); err != nil {
					b.Fatal(err)
				}
				b.StopTimer()
				if err := os.RemoveAll(parent); err != nil {
					b.Fatal(err)
				}
			}
		})
		b.Run(fmt.Sprintf("load/events-%d", count), func(b *testing.B) {
			fixture := newPublicChannelCalibration(b, count)
			parent := filepath.Join(b.TempDir(), "snapshot")
			if err := os.Mkdir(parent, 0o700); err != nil {
				b.Fatal(err)
			}
			root, _, err := ExportSitesSnapshot(parent, fixture.profile, fixture.history,
				fixture.authority, fixture.delegations, fixture.now)
			if err != nil {
				b.Fatal(err)
			}
			b.ReportAllocs()
			b.ResetTimer()
			for iteration := 0; iteration < b.N; iteration++ {
				if _, err := LoadSitesSnapshot(root, fixture.authority, fixture.delegations, fixture.now); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}
