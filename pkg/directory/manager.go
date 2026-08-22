package directory

import (
	"context"
	"errors"
	"sync"
	"time"
)

// RefreshObserver receives completed attempts for operational visibility.
// Implementations must not use it as an authority source.
type RefreshObserver interface {
	RefreshCompleted(agentID string, result RefreshResult, err error)
}

// Manager keeps verified peer discovery snapshots fresh without choosing a
// message route. A failed refresh never extends the old snapshot's expiry.
type Manager struct {
	Refresher Refresher
	Lead      time.Duration
	Observer  RefreshObserver

	mutex   sync.RWMutex
	entries map[string]managedEntry
}

type managedEntry struct {
	result    RefreshResult
	refreshAt time.Time
}

// Ensure returns a verified snapshot, refreshing it when its conservative
// deadline has arrived. Concurrent callers may duplicate retrieval work, but
// only a fully verified result replaces the cache.
func (m *Manager) Ensure(ctx context.Context, agentID string) (RefreshResult, error) {
	if m == nil {
		return RefreshResult{}, errors.New("no directory manager")
	}
	now := time.Now()
	if m.Refresher.Now != nil {
		now = m.Refresher.Now()
	}
	m.mutex.RLock()
	entry, found := m.entries[agentID]
	m.mutex.RUnlock()
	if found && now.Before(entry.refreshAt) {
		return cloneRefreshResult(entry.result), nil
	}
	result, err := m.Refresher.Refresh(ctx, agentID)
	if m.Observer != nil {
		m.Observer.RefreshCompleted(agentID, cloneRefreshResult(result), err)
	}
	if err != nil {
		return RefreshResult{}, err
	}
	refreshAt, err := RefreshAt(result, m.Lead)
	if err != nil {
		return RefreshResult{}, err
	}
	m.mutex.Lock()
	if m.entries == nil {
		m.entries = make(map[string]managedEntry)
	}
	m.entries[agentID] = managedEntry{result: cloneRefreshResult(result), refreshAt: refreshAt}
	m.mutex.Unlock()
	return cloneRefreshResult(result), nil
}

// Invalidate forces finalized authority and every signed cache object to be
// resolved again on the next access. It is used after an unknown-device or
// stale-session signal; it does not make the previous snapshot valid longer.
func (m *Manager) Invalidate(agentID string) {
	if m == nil {
		return
	}
	m.mutex.Lock()
	delete(m.entries, agentID)
	m.mutex.Unlock()
}

// Run periodically refreshes a bounded, caller-owned peer set. It deliberately
// has no transport logic: the supplied RefreshSource remains responsible for
// DHT and descriptor retrieval after M0-R decides how those operations route.
func (m *Manager) Run(ctx context.Context, agentIDs []string, interval time.Duration) error {
	if ctx == nil {
		return errors.New("directory manager needs a context")
	}
	if len(agentIDs) == 0 || len(agentIDs) > 4096 {
		return errors.New("invalid directory peer set size")
	}
	if interval < time.Second {
		return errors.New("directory refresh interval is below its floor")
	}
	run := func() {
		for _, agentID := range agentIDs {
			if ctx.Err() != nil {
				return
			}
			// A scheduled refresh is a finalized-authority recheck, not a
			// cache read. Without invalidation, a long-lived descriptor could
			// postpone revocation until its near-expiry refresh deadline even
			// while this loop wakes every few minutes.
			m.Invalidate(agentID)
			_, _ = m.Ensure(ctx, agentID)
		}
	}
	run()
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
			run()
		}
	}
}
