package publicchannel

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
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
