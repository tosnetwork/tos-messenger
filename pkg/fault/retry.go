package fault

import "time"

// Retry schedule bounds. They are constants rather than configuration because
// a fleet whose members each choose their own backoff is a fleet that can
// synchronise into a thundering herd against one Relay.
const (
	// TransientBase is the first delay for a condition expected to pass.
	TransientBase = time.Second
	// TransientCap bounds transient backoff.
	TransientCap = 5 * time.Minute
	// TransientAttempts bounds how many times a transient failure is retried.
	TransientAttempts = 8

	// RefreshBase is the first delay before resolving state again.
	RefreshBase = 5 * time.Second
	// RefreshCap bounds refresh backoff.
	RefreshCap = 15 * time.Minute
	// RefreshAttempts bounds how many times state is resolved again.
	RefreshAttempts = 4
)

// Retry is what a caller should do next.
type Retry struct {
	// Disposition is the classification the decision came from.
	Disposition Disposition
	// Allowed reports whether the caller may try again on a timer.
	Allowed bool
	// After is how long to wait when Allowed.
	After time.Duration
	// Final reports that no future attempt can succeed. It is distinct from
	// Allowed being false: an approval hold is not final, it is waiting.
	Final bool
	// ResolveFirst reports that the caller must obtain current state before
	// the next attempt, rather than repeating the same request.
	ResolveFirst bool
}

// Next returns the retry decision for a failure on a given attempt, where the
// first attempt is 1.
func Next(err error, attempt int) Retry {
	return NextCode(CodeOf(err), attempt)
}

// NextCode returns the retry decision for a code.
func NextCode(code Code, attempt int) Retry {
	if attempt < 1 {
		attempt = 1
	}
	disposition := DispositionOf(code)
	switch disposition {
	case Transient:
		if attempt > TransientAttempts {
			return Retry{Disposition: disposition, Final: true}
		}
		return Retry{
			Disposition: disposition,
			Allowed:     true,
			After:       backoff(TransientBase, TransientCap, attempt),
		}
	case Refresh:
		if attempt > RefreshAttempts {
			return Retry{Disposition: disposition, Final: true}
		}
		return Retry{
			Disposition:  disposition,
			Allowed:      true,
			After:        backoff(RefreshBase, RefreshCap, attempt),
			ResolveFirst: true,
		}
	case Approval:
		// Not allowed and not final: the attempt resumes when a decision
		// arrives, and a timer would only ask the same person again.
		return Retry{Disposition: disposition}
	default:
		return Retry{Disposition: Permanent, Final: true}
	}
}

// backoff doubles from base to cap. Callers add their own jitter: spreading a
// fleet is a deployment concern, and keeping this function deterministic is
// what makes the schedule testable.
func backoff(base, cap time.Duration, attempt int) time.Duration {
	delay := base
	for index := 1; index < attempt; index++ {
		if delay > cap/2 {
			return cap
		}
		delay *= 2
	}
	if delay > cap {
		return cap
	}
	return delay
}
