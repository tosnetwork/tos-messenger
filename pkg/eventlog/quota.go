package eventlog

import (
	"errors"
	"os"
	"path/filepath"
	"time"

	"github.com/tosnetwork/tos-messenger/pkg/fault"
)

// expiredCode is what an undecided event is refused with.
const expiredCode = fault.CodeEventOutsideWindow

// Defaults for what may wait on an owner. They are bounds rather than
// preferences: a queue only a person can drain is one a stranger can fill.
const (
	// DefaultMaxPendingAdmissions bounds how many events may wait at once.
	DefaultMaxPendingAdmissions = 256
	// DefaultMaxPendingPerSender bounds how many one sender may contribute. An
	// Agent that is delegated and inside its scope can still send a different
	// event identifier every second, and content-addressed identifiers mean
	// every one of them is a new event rather than a duplicate.
	DefaultMaxPendingPerSender = 16
	// DefaultMaxPendingBytes bounds what the waiting set may occupy.
	DefaultMaxPendingBytes = 32 << 20
	// DefaultMaxPendingAge bounds how long an undecided event is kept. An
	// event nobody decided about in a week is not a decision still pending; it
	// is a decision that was never going to be made.
	DefaultMaxPendingAge = 7 * 24 * time.Hour
)

// ErrPendingFull reports that the owner's queue is at one of its bounds.
//
// It is a refusal rather than a silent drop, so the sender learns their event
// did not enter and can try again later, and the owner's queue keeps the
// events that were already in it.
var ErrPendingFull = errors.New("this installation holds as many undecided events as it may")

// Quota bounds what may wait for an owner decision.
type Quota struct {
	MaxPendingAdmissions int
	MaxPendingPerSender  int
	MaxPendingBytes      int
	MaxPendingAge        time.Duration
}

// DefaultQuota returns the bounds an installation starts with.
func DefaultQuota() Quota {
	return Quota{
		MaxPendingAdmissions: DefaultMaxPendingAdmissions,
		MaxPendingPerSender:  DefaultMaxPendingPerSender,
		MaxPendingBytes:      DefaultMaxPendingBytes,
		MaxPendingAge:        DefaultMaxPendingAge,
	}
}

// Validate enforces bounds that actually bound something.
func (q Quota) Validate() error {
	if q.MaxPendingAdmissions <= 0 || q.MaxPendingPerSender <= 0 {
		return errors.New("a pending quota must bound how many events may wait")
	}
	if q.MaxPendingPerSender > q.MaxPendingAdmissions {
		return errors.New("a per-sender bound above the total bounds nothing")
	}
	if q.MaxPendingBytes <= 0 {
		return errors.New("a pending quota must bound how much may wait")
	}
	if q.MaxPendingAge <= 0 {
		return errors.New("a pending quota must bound how long an undecided event is kept")
	}
	return nil
}

// pendingCapacity reports whether one more event may wait.
//
// Expired records are not counted. They are removed by maintenance, and
// counting them would let a queue that is really empty refuse new events until
// the sweep ran.
func (j *Journal) pendingCapacity(senderEndpointID string, size int, now time.Time) error {
	entries, err := os.ReadDir(j.inboundRoot())
	if err != nil {
		return errors.New("read event journal")
	}
	seconds := uint64(now.Unix())
	total, forSender, bytes := 0, 0, size
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		record, err := readRecord(filepath.Join(j.inboundRoot(), entry.Name()))
		if err != nil || record.Admission != AdmissionPending {
			continue
		}
		if record.expired(j.quota, seconds) {
			continue
		}
		total++
		bytes += len(record.PayloadBase64)
		if record.SenderEndpointID == senderEndpointID {
			forSender++
		}
	}
	if total >= j.quota.MaxPendingAdmissions {
		return ErrPendingFull
	}
	if forSender >= j.quota.MaxPendingPerSender {
		return ErrPendingFull
	}
	if bytes > j.quota.MaxPendingBytes {
		return ErrPendingFull
	}
	return nil
}

// expired reports whether an undecided event has run out of time, either its
// own or the installation's.
func (r Record) expired(quota Quota, seconds uint64) bool {
	if r.EventExpiresAt != 0 && seconds >= r.EventExpiresAt {
		return true
	}
	age := uint64(quota.MaxPendingAge / time.Second)
	return r.ReceivedAtUnix != 0 && seconds >= r.ReceivedAtUnix+age
}

// ExpirePendingAdmissions refuses undecided events that ran out of time.
//
// They are recorded as refused rather than deleted. An owner who comes back to
// an empty queue should be able to see that something arrived and was never
// decided, and a sender who asks gets an answer instead of silence.
func (j *Journal) ExpirePendingAdmissions(now time.Time) (int, error) {
	if err := j.usable(); err != nil {
		return 0, err
	}
	if now.IsZero() || now.Unix() < 0 {
		return 0, errors.New("invalid expiry time")
	}
	j.mutex.Lock()
	defer j.mutex.Unlock()

	entries, err := os.ReadDir(j.inboundRoot())
	if err != nil {
		return 0, errors.New("read event journal")
	}
	seconds := uint64(now.Unix())
	expired := 0
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		path := filepath.Join(j.inboundRoot(), entry.Name())
		record, err := readRecord(path)
		if err != nil || record.Admission != AdmissionPending {
			continue
		}
		if !record.expired(j.quota, seconds) {
			continue
		}
		record.Admission = AdmissionDenied
		record.AdmissionAtUnix = seconds
		record.AdmissionCode = expiredCode
		record.Application = StateRejected
		record.RejectedAtUnix = seconds
		record.RejectionCode = expiredCode
		if _, err := j.commit(path, record); err != nil {
			return expired, err
		}
		expired++
	}
	return expired, nil
}

// receivedAt is when an entry arrived, as a time.
func (e Entry) receivedAt() time.Time { return time.Unix(int64(e.ReceivedAtUnix), 0) }
