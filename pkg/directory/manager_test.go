package directory

import (
	"context"
	"sync"
	"testing"
	"time"
)

type recordingObserver struct {
	mutex  sync.Mutex
	calls  int
	cancel context.CancelFunc
}

func (o *recordingObserver) RefreshCompleted(_ string, _ RefreshResult, _ error) {
	o.mutex.Lock()
	o.calls++
	cancel := o.cancel
	o.mutex.Unlock()
	if cancel != nil {
		cancel()
	}
}

func TestManagerCachesUntilDeadlineAndInvalidates(t *testing.T) {
	source, refresher, _ := refreshFixture(t)
	now := time.Unix(int64(baseUnix)+60, 0)
	refresher.Now = func() time.Time { return now }
	observer := &recordingObserver{}
	manager := &Manager{Refresher: refresher, Lead: 5 * time.Minute, Observer: observer}

	if _, err := manager.Ensure(context.Background(), agentID); err != nil {
		t.Fatal(err)
	}
	if _, err := manager.Ensure(context.Background(), agentID); err != nil {
		t.Fatal(err)
	}
	if got := len(source.calls); got != 5 {
		t.Fatalf("fresh cache caused retrieval: calls=%d", got)
	}
	manager.Invalidate(agentID)
	if _, err := manager.Ensure(context.Background(), agentID); err != nil {
		t.Fatal(err)
	}
	if got := len(source.calls); got != 10 {
		t.Fatalf("invalidation did not cause retrieval: calls=%d", got)
	}
	now = time.Unix(int64(baseUnix+3300), 0)
	if _, err := manager.Ensure(context.Background(), agentID); err != nil {
		t.Fatal(err)
	}
	if got := len(source.calls); got != 15 {
		t.Fatalf("deadline did not cause retrieval: calls=%d", got)
	}
}

func TestManagerRunRefreshesImmediatelyAndStops(t *testing.T) {
	_, refresher, _ := refreshFixture(t)
	ctx, cancel := context.WithCancel(context.Background())
	observer := &recordingObserver{cancel: cancel}
	manager := &Manager{Refresher: refresher, Lead: 5 * time.Minute, Observer: observer}
	if err := manager.Run(ctx, []string{agentID}, time.Second); err != nil {
		t.Fatal(err)
	}
	observer.mutex.Lock()
	calls := observer.calls
	observer.mutex.Unlock()
	if calls != 1 {
		t.Fatalf("observer calls=%d", calls)
	}
}

func TestManagerRunRechecksFinalizedAuthorityDespiteFreshCache(t *testing.T) {
	source, refresher, _ := refreshFixture(t)
	manager := &Manager{Refresher: refresher, Lead: 5 * time.Minute}
	if _, err := manager.Ensure(context.Background(), agentID); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	observer := &recordingObserver{cancel: cancel}
	manager.Observer = observer
	if err := manager.Run(ctx, []string{agentID}, time.Hour); err != nil {
		t.Fatal(err)
	}
	if got := len(source.calls); got != 10 {
		t.Fatalf("scheduled refresh reused cache: calls=%d", got)
	}
}

func TestManagerRejectsUnboundedPeerSet(t *testing.T) {
	manager := &Manager{}
	if err := manager.Run(context.Background(), nil, time.Second); err == nil {
		t.Fatal("empty peer set accepted")
	}
	if err := manager.Run(context.Background(), []string{agentID}, time.Millisecond); err == nil {
		t.Fatal("sub-second loop accepted")
	}
}
