package negotiation

import (
	"errors"
	"sort"
	"sync"
)

// MaxReservations bounds how many negotiations may hold part of one budget at
// once. An unbounded set is an unbounded record and an unbounded restart.
const MaxReservations = 256

// ErrBudgetExceeded reports that a reservation or commitment would carry the
// budget past its total. It is a result a caller acts on -- escalating the
// spend to the owner rather than auto-authorising it -- not a durability
// failure, so it is a sentinel the caller can tell apart from a write error.
var ErrBudgetExceeded = errors.New("this would commit more than the budget allows")

// BudgetState is everything a budget needs to be reconstructed.
//
// It is written whole rather than as a delta. A delta applied halfway leaves a
// ledger nobody can reconcile, and this set is small and bounded, so there is
// nothing to gain by making the durable form clever.
type BudgetState struct {
	Total    Money
	Spent    Money
	Reserved map[string]Money
}

// Ledger is where a budget's reservations survive a restart.
//
// It is required. A budget that lived only in memory would forget every hold
// when the process ended: the spend would return to zero and several
// negotiations could commit against the same money again, which is precisely
// the outcome the budget exists to prevent, arriving by way of an ordinary
// restart rather than an attack.
type Ledger interface {
	Load() (BudgetState, bool, error)
	Record(state BudgetState) error
}

// Budget is what several negotiations draw on at once.
//
// A mandate bounds one exchange. An Agent talking to five providers about the
// same job has five mandates and one wallet, and five conversations each
// inside their own ceiling can still agree to more than the owner has. The
// budget is where that is caught, and it is caught at the moment a negotiation
// says yes rather than at the moment money moves, because by then five yeses
// already exist.
//
// It is not a balance. What can actually be spent is decided by the wallet and
// by finalized chain state; this is a stricter local ceiling on top of that,
// and it is never the authority on funds.
type Budget struct {
	mutex    sync.Mutex
	ledger   Ledger
	total    Money
	spent    Money
	reserved map[string]Money
}

// OpenBudget opens a budget for one asset, restoring whatever the ledger holds.
func OpenBudget(total Money, ledger Ledger) (*Budget, error) {
	if err := total.Validate(); err != nil {
		return nil, err
	}
	if ledger == nil {
		return nil, errors.New("a budget needs somewhere to survive a restart")
	}
	budget := &Budget{
		ledger: ledger, total: total, spent: total.Zero(),
		reserved: make(map[string]Money),
	}
	stored, found, err := ledger.Load()
	if err != nil {
		return nil, err
	}
	if !found {
		return budget, budget.record()
	}
	if !stored.Total.Equal(total) {
		// The owner changed the ceiling while holds were outstanding. Silently
		// adopting either number would either strand reservations or quietly
		// raise what was authorised, so the caller is told instead.
		return nil, errors.New("this budget was opened before with a different total")
	}
	budget.spent = stored.Spent
	for id, amount := range stored.Reserved {
		budget.reserved[id] = amount
	}
	return budget, nil
}

// Reserve holds an amount for one negotiation.
//
// Reserving twice for the same negotiation replaces the earlier hold rather
// than adding to it, so a renegotiated price does not leak the old one.
func (b *Budget) Reserve(negotiationID string, amount Money) error {
	if b == nil {
		return errors.New("no budget")
	}
	if negotiationID == "" || len(negotiationID) > 128 {
		return errors.New("invalid negotiation identifier")
	}
	if err := amount.Validate(); err != nil {
		return err
	}
	if !amount.SameAsset(b.total) {
		return errors.New("this amount is in an asset the budget does not hold")
	}
	b.mutex.Lock()
	defer b.mutex.Unlock()

	if _, held := b.reserved[negotiationID]; !held && len(b.reserved) >= MaxReservations {
		return errors.New("this budget holds as many reservations as it may")
	}
	previous, held := b.reserved[negotiationID]
	b.reserved[negotiationID] = amount
	committed, err := b.committedLocked()
	if err != nil {
		b.restore(negotiationID, previous, held)
		return err
	}
	within, err := committed.AtMost(b.total)
	if err != nil {
		b.restore(negotiationID, previous, held)
		return err
	}
	if !within {
		b.restore(negotiationID, previous, held)
		return ErrBudgetExceeded
	}
	if err := b.record(); err != nil {
		b.restore(negotiationID, previous, held)
		return err
	}
	return nil
}

func (b *Budget) restore(negotiationID string, previous Money, held bool) {
	if held {
		b.reserved[negotiationID] = previous
		return
	}
	delete(b.reserved, negotiationID)
}

// Release drops a hold.
func (b *Budget) Release(negotiationID string) error {
	if b == nil {
		return errors.New("no budget")
	}
	b.mutex.Lock()
	defer b.mutex.Unlock()
	previous, held := b.reserved[negotiationID]
	if !held {
		return nil
	}
	delete(b.reserved, negotiationID)
	if err := b.record(); err != nil {
		b.reserved[negotiationID] = previous
		return err
	}
	return nil
}

// Commit turns a hold into a spend.
//
// The hold becomes permanent here rather than when money moves, because the
// commitment is what the owner authorised and the movement is a consequence of
// it. Releasing after a commitment would let the same budget back the next one.
func (b *Budget) Commit(negotiationID string) error {
	if b == nil {
		return errors.New("no budget")
	}
	b.mutex.Lock()
	defer b.mutex.Unlock()
	amount, held := b.reserved[negotiationID]
	if !held {
		return errors.New("this negotiation holds no reservation")
	}
	spent, err := b.spent.Add(amount)
	if err != nil {
		return err
	}
	within, err := spent.AtMost(b.total)
	if err != nil {
		return err
	}
	if !within {
		return ErrBudgetExceeded
	}
	previousSpent := b.spent
	b.spent = spent
	delete(b.reserved, negotiationID)
	if err := b.record(); err != nil {
		b.spent = previousSpent
		b.reserved[negotiationID] = amount
		return err
	}
	return nil
}

// Remaining is what is left after spending and current holds.
func (b *Budget) Remaining() (Money, error) {
	if b == nil {
		return Money{}, errors.New("no budget")
	}
	b.mutex.Lock()
	defer b.mutex.Unlock()
	committed, err := b.committedLocked()
	if err != nil {
		return Money{}, err
	}
	left, err := b.total.Int()
	if err != nil {
		return Money{}, err
	}
	used, err := committed.Int()
	if err != nil {
		return Money{}, err
	}
	return NewMoney(b.total.Asset, left.Sub(left, used))
}

// Spent is what has been committed.
func (b *Budget) Spent() Money {
	if b == nil {
		return Money{}
	}
	b.mutex.Lock()
	defer b.mutex.Unlock()
	return b.spent
}

// Reserved reports the hold one negotiation carries.
func (b *Budget) Reserved(negotiationID string) (Money, bool) {
	if b == nil {
		return Money{}, false
	}
	b.mutex.Lock()
	defer b.mutex.Unlock()
	amount, held := b.reserved[negotiationID]
	return amount, held
}

func (b *Budget) committedLocked() (Money, error) {
	total := b.spent
	identifiers := make([]string, 0, len(b.reserved))
	for id := range b.reserved {
		identifiers = append(identifiers, id)
	}
	sort.Strings(identifiers)
	for _, id := range identifiers {
		sum, err := total.Add(b.reserved[id])
		if err != nil {
			return Money{}, err
		}
		total = sum
	}
	return total, nil
}

func (b *Budget) record() error {
	reserved := make(map[string]Money, len(b.reserved))
	for id, amount := range b.reserved {
		reserved[id] = amount
	}
	return b.ledger.Record(BudgetState{Total: b.total, Spent: b.spent, Reserved: reserved})
}
