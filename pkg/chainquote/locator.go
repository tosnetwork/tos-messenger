package chainquote

import (
	"errors"
	"sync"
)

// MapLocator is an in-memory EscrowLocator: it remembers where each commitment's
// escrow lives and which capability class it was agreed under.
//
// It is populated by whatever prepares and funds an escrow -- the entry a
// commitment maps to is written when its escrow address is known, which is not
// something the chain can be asked for by commitment. Persisting that mapping
// across restarts, and driving it from the funding flow, is follow-on wiring;
// this type is the minimal, concurrency-safe store the resolver reads from.
type MapLocator struct {
	mutex   sync.RWMutex
	entries map[string]escrowEntry
}

type escrowEntry struct {
	address string
	class   string
}

// NewMapLocator returns an empty locator.
func NewMapLocator() *MapLocator {
	return &MapLocator{entries: map[string]escrowEntry{}}
}

// Record binds a commitment to the escrow that holds it and the capability
// class it was agreed under. A commitment may be recorded once; a second,
// differing record is refused rather than silently overwriting where a
// commitment's escrow is, which would let a later write redirect an earlier
// agreement's settlement.
func (l *MapLocator) Record(commitment, escrowAddress, capabilityClass string) error {
	if l == nil {
		return errors.New("no locator")
	}
	if commitment == "" || escrowAddress == "" {
		return errors.New("a commitment and its escrow address are both required")
	}
	if capabilityClass == "" {
		return errors.New("a capability class is required")
	}
	l.mutex.Lock()
	defer l.mutex.Unlock()
	if existing, found := l.entries[commitment]; found {
		if existing.address != escrowAddress || existing.class != capabilityClass {
			return errors.New("this commitment is already bound to a different escrow")
		}
		return nil
	}
	l.entries[commitment] = escrowEntry{address: escrowAddress, class: capabilityClass}
	return nil
}

// LocateEscrow implements EscrowLocator.
func (l *MapLocator) LocateEscrow(commitment string) (string, string, bool, error) {
	if l == nil {
		return "", "", false, errors.New("no locator")
	}
	l.mutex.RLock()
	defer l.mutex.RUnlock()
	entry, found := l.entries[commitment]
	if !found {
		return "", "", false, nil
	}
	return entry.address, entry.class, true, nil
}
