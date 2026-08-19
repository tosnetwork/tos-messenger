package negotiation

import (
	"errors"
	"sync"
)

// Budget is what several negotiations draw on at once.
//
// A mandate bounds one exchange. An Agent talking to five providers about the
// same job has five mandates and one wallet, and five conversations each
// inside their own ceiling can still agree to more than the owner has. The
// budget is where that is caught, and it is caught at the moment a negotiation
// says yes rather than at the moment money moves, because by then five yeses
// already exist.
type Budget struct {
	mutex    sync.Mutex
	total    Amount
	spent    Amount
	reserved map[string]Amount
}

// NewBudget opens a budget for one asset.
func NewBudget(total Amount) (*Budget, error) {
	if err := total.Validate(); err != nil {
		return nil, err
	}
	return &Budget{
		total:    total,
		spent:    Amount{Asset: total.Asset, Decimals: total.Decimals},
		reserved: make(map[string]Amount),
	}, nil
}

// Reserve holds an amount for one negotiation.
//
// Reserving twice for the same negotiation replaces the earlier hold rather
// than adding to it, so a renegotiated price does not leak the old one.
func (b *Budget) Reserve(negotiationID string, amount Amount) error {
	if b == nil {
		return errors.New("no budget")
	}
	if negotiationID == "" {
		return errors.New("a reservation needs a negotiation")
	}
	if err := amount.Validate(); err != nil {
		return err
	}
	b.mutex.Lock()
	defer b.mutex.Unlock()
	if !amount.SameAsset(b.total) {
		return errors.New("a reservation in another asset cannot be drawn on this budget")
	}
	committed := b.spent.Units
	for id, held := range b.reserved {
		if id == negotiationID {
			continue
		}
		committed += held.Units
		if committed < held.Units {
			return errors.New("budget overflows")
		}
	}
	if committed+amount.Units < committed {
		return errors.New("budget overflows")
	}
	if committed+amount.Units > b.total.Units {
		return errors.New("the owner's budget cannot cover this alongside what is already held")
	}
	b.reserved[negotiationID] = amount
	return nil
}

// Release gives back what a negotiation was holding.
func (b *Budget) Release(negotiationID string) {
	if b == nil {
		return
	}
	b.mutex.Lock()
	defer b.mutex.Unlock()
	delete(b.reserved, negotiationID)
}

// Commit turns a hold into a spend.
func (b *Budget) Commit(negotiationID string) error {
	if b == nil {
		return errors.New("no budget")
	}
	b.mutex.Lock()
	defer b.mutex.Unlock()
	held, found := b.reserved[negotiationID]
	if !found {
		return errors.New("this negotiation holds nothing to commit")
	}
	sum := b.spent.Units + held.Units
	if sum < b.spent.Units || sum > b.total.Units {
		return errors.New("committing this would exceed the owner's budget")
	}
	b.spent = Amount{Asset: b.total.Asset, Units: sum, Decimals: b.total.Decimals}
	delete(b.reserved, negotiationID)
	return nil
}

// Remaining reports what is neither spent nor held.
func (b *Budget) Remaining() Amount {
	if b == nil {
		return Amount{}
	}
	b.mutex.Lock()
	defer b.mutex.Unlock()
	used := b.spent.Units
	for _, held := range b.reserved {
		used += held.Units
	}
	if used > b.total.Units {
		return Amount{Asset: b.total.Asset, Decimals: b.total.Decimals}
	}
	return Amount{Asset: b.total.Asset, Units: b.total.Units - used, Decimals: b.total.Decimals}
}

// Spent reports what has been committed.
func (b *Budget) Spent() Amount {
	if b == nil {
		return Amount{}
	}
	b.mutex.Lock()
	defer b.mutex.Unlock()
	return b.spent
}
