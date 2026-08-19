package eventlog

import (
	"errors"
	"os"
	"path/filepath"
	"sort"
	"time"

	"github.com/tosnetwork/tos-messenger/pkg/envelope"
)

// MinClaimRetention is the floor for how long a delivered event's claim is
// kept.
//
// Replay protection can only be dropped once a replay is no longer possible. A
// Mailbox Relay may hold the same ciphertext for the full envelope retention
// bound, so a claim pruned before that reopens exactly the window it exists to
// close: the ciphertext is still out there and the journal has forgotten it.
// The floor is derived from the envelope bound rather than restated, so the two
// cannot drift apart.
const MinClaimRetention = envelope.MaxEnvelopeLifetimeSeconds * time.Second

// PruneReport is what one sweep did.
type PruneReport struct {
	// ClaimsRemoved counts inbound claims whose replay window has closed.
	ClaimsRemoved int
	// DeliveriesRemoved counts settled outbound records that were removed.
	DeliveriesRemoved int
	// Unreadable names records the sweep could not parse. They are left in
	// place; see Prune for why.
	Unreadable []string
}

// Prune removes records whose purpose has ended.
//
// An unreadable record is reported and kept. Deleting it would be worse than
// leaving it: a corrupt inbound claim currently fails closed and blocks its
// event, while a sweep that removed corrupt files would turn "damage the
// record" into "replay the event", which is a bypass anyone with write access
// to the directory could use.
//
// Pending and held deliveries are never removed. They are live work, not
// history, and their own expiry is what ends them.
func (j *Journal) Prune(now time.Time, retention time.Duration) (PruneReport, error) {
	if err := j.usable(); err != nil {
		return PruneReport{}, err
	}
	if now.IsZero() || now.Unix() < 0 {
		return PruneReport{}, errors.New("invalid prune time")
	}
	if retention < MinClaimRetention {
		return PruneReport{}, errors.New("retention is shorter than the replay window it must cover")
	}
	j.mutex.Lock()
	defer j.mutex.Unlock()

	seconds := uint64(now.Unix())
	horizon := uint64(retention / time.Second)
	report := PruneReport{}

	claims, err := j.sweep(j.inboundRoot(), func(path string) (bool, error) {
		record, err := readRecord(path)
		if err != nil {
			return false, err
		}
		// A queued or claimed event is work nobody has finished. Removing it
		// would delete a message that was accepted and never delivered, which
		// is the failure this journal exists to prevent.
		if !record.Terminal() {
			return false, nil
		}
		// The replay window runs from receipt, not from completion: the
		// ciphertext a Relay may still be holding was created when the event
		// was sent.
		return record.ReceivedAtUnix+horizon <= seconds, nil
	})
	if err != nil {
		return PruneReport{}, err
	}
	report.ClaimsRemoved = claims.removed
	report.Unreadable = append(report.Unreadable, claims.unreadable...)

	deliveries, err := j.sweep(j.outboundRoot(), func(path string) (bool, error) {
		delivery, err := readDelivery(path)
		if err != nil {
			return false, err
		}
		if delivery.State != StateDelivered && delivery.State != StateAbandoned {
			return false, nil
		}
		settled := delivery.SettledAtUnix
		if settled == 0 {
			settled = delivery.CreatedAtUnix
		}
		return settled+horizon <= seconds, nil
	})
	if err != nil {
		return PruneReport{}, err
	}
	report.DeliveriesRemoved = deliveries.removed
	report.Unreadable = append(report.Unreadable, deliveries.unreadable...)
	sort.Strings(report.Unreadable)
	return report, nil
}

type sweepResult struct {
	removed    int
	unreadable []string
}

func (j *Journal) sweep(root string, expired func(string) (bool, error)) (sweepResult, error) {
	entries, err := os.ReadDir(root)
	if err != nil {
		return sweepResult{}, errors.New("read event journal directory")
	}
	result := sweepResult{}
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		path := filepath.Join(root, entry.Name())
		drop, err := expired(path)
		if err != nil {
			result.unreadable = append(result.unreadable, entry.Name())
			continue
		}
		if !drop {
			continue
		}
		if err := os.Remove(path); err != nil {
			return sweepResult{}, errors.New("remove event journal record")
		}
		result.removed++
	}
	if result.removed > 0 {
		if err := syncDirectory(root); err != nil {
			return sweepResult{}, err
		}
	}
	return result, nil
}
