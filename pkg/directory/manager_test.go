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
	if got := len(source.calls); got != 4 {
		t.Fatalf("fresh cache caused retrieval: calls=%d", got)
	}
	manager.Invalidate(agentID)
	if _, err := manager.Ensure(context.Background(), agentID); err != nil {
		t.Fatal(err)
	}
	if got := len(source.calls); got != 8 {
		t.Fatalf("invalidation did not cause retrieval: calls=%d", got)
	}
	now = time.Unix(int64(baseUnix+3300), 0)
	if _, err := manager.Ensure(context.Background(), agentID); err != nil {
		t.Fatal(err)
	}
	if got := len(source.calls); got != 12 {
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

func TestManagerRejectsUnboundedPeerSet(t *testing.T) {
	manager := &Manager{}
	if err := manager.Run(context.Background(), nil, time.Second); err == nil {
		t.Fatal("empty peer set accepted")
	}
	if err := manager.Run(context.Background(), []string{agentID}, time.Millisecond); err == nil {
		t.Fatal("sub-second loop accepted")
	}
}
