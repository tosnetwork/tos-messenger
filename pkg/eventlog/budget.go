package eventlog

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"regexp"

	"github.com/tosnetwork/tos-messenger/internal/canon"
	"github.com/tosnetwork/tos-messenger/pkg/negotiation"
)

const (
	budgetDir = "budgets"

	// BudgetSchema is the on-disk schema of one budget ledger.
	BudgetSchema = "tos.messaging.budget-ledger.v1"
)

var budgetPattern = regexp.MustCompile(`^bgt_[0-9a-f]{64}$`)

// BudgetRecord is one budget's durable state.
//
// It holds the whole reservation set rather than a log of changes. The set is
// bounded and small, and a partially applied change is a ledger nobody can
// reconcile: an owner asking what their Agent has committed needs an answer,
// not a replay.
type BudgetRecord struct {
	Schema   string            `json:"schema"`
	BudgetID string            `json:"budget_id"`
	Asset    StoredAsset       `json:"asset"`
	Total    string            `json:"total_atomic"`
	Spent    string            `json:"spent_atomic"`
	Reserved map[string]string `json:"reserved_atomic,omitempty"`
}

// StoredAsset is an asset identity as it is written down.
type StoredAsset struct {
	Workchain      int32  `json:"workchain"`
	AccountID      string `json:"master_account_id"`
	MasterCodeHash string `json:"master_code_hash"`
	WalletCodeHash string `json:"wallet_code_hash"`
	Decimals       uint32 `json:"decimals"`
}

// BudgetID derives the identifier of the budget for one asset.
//
// One installation holds one budget per asset. Deriving the identifier from
// the asset rather than letting a caller choose it means two callers cannot
// open two budgets over the same money and each believe they hold all of it.
func BudgetID(asset negotiation.Asset) (string, error) {
	if err := asset.Validate(); err != nil {
		return "", err
	}
	buffer := bytes.NewBufferString(canon.DomainBudget)
	canon.Uint32(buffer, uint32(asset.Workchain))
	canon.Text(buffer, asset.AccountID)
	canon.Text(buffer, asset.MasterCodeHash)
	canon.Text(buffer, asset.WalletCodeHash)
	canon.Uint32(buffer, asset.Decimals)
	digest := canon.Digest(buffer.Bytes())
	return "bgt_" + digest[len("sha256:"):], nil
}

// BudgetLedger is the durable half of one budget.
type BudgetLedger struct {
	journal  *Journal
	budgetID string
	asset    negotiation.Asset
}

// OpenBudgetLedger returns the ledger for one asset's budget.
func (j *Journal) OpenBudgetLedger(asset negotiation.Asset) (*BudgetLedger, error) {
	if err := j.usable(); err != nil {
		return nil, err
	}
	budgetID, err := BudgetID(asset)
	if err != nil {
		return nil, err
	}
	return &BudgetLedger{journal: j, budgetID: budgetID, asset: asset}, nil
}

// Load implements negotiation.Ledger.
func (l *BudgetLedger) Load() (negotiation.BudgetState, bool, error) {
	if l == nil {
		return negotiation.BudgetState{}, false, errors.New("no budget ledger")
	}
	if err := l.journal.usable(); err != nil {
		return negotiation.BudgetState{}, false, err
	}
	l.journal.mutex.Lock()
	defer l.journal.mutex.Unlock()

	raw, err := os.ReadFile(l.path())
	if errors.Is(err, os.ErrNotExist) {
		return negotiation.BudgetState{}, false, nil
	}
	if err != nil {
		return negotiation.BudgetState{}, false, errors.New("read budget ledger")
	}
	if len(raw) > MaxRecordBytes {
		return negotiation.BudgetState{}, false, errors.New("budget ledger exceeds its bound")
	}
	var record BudgetRecord
	if err := json.Unmarshal(raw, &record); err != nil {
		return negotiation.BudgetState{}, false, errors.New("invalid budget ledger")
	}
	if record.Schema != BudgetSchema || record.BudgetID != l.budgetID {
		return negotiation.BudgetState{}, false, errors.New("budget ledger describes another budget")
	}
	asset := negotiation.Asset{
		Workchain: record.Asset.Workchain, AccountID: record.Asset.AccountID,
		MasterCodeHash: record.Asset.MasterCodeHash, WalletCodeHash: record.Asset.WalletCodeHash,
		Decimals: record.Asset.Decimals,
	}
	if !asset.Same(l.asset) {
		return negotiation.BudgetState{}, false, errors.New("budget ledger holds another asset")
	}
	state := negotiation.BudgetState{
		Total:    negotiation.Money{Asset: asset, Atomic: record.Total},
		Spent:    negotiation.Money{Asset: asset, Atomic: record.Spent},
		Reserved: make(map[string]negotiation.Money, len(record.Reserved)),
	}
	if err := state.Total.Validate(); err != nil {
		return negotiation.BudgetState{}, false, err
	}
	if err := state.Spent.Validate(); err != nil {
		return negotiation.BudgetState{}, false, err
	}
	if len(record.Reserved) > negotiation.MaxReservations {
		return negotiation.BudgetState{}, false, errors.New("budget ledger holds more reservations than it may")
	}
	for id, atomic := range record.Reserved {
		amount := negotiation.Money{Asset: asset, Atomic: atomic}
		if err := amount.Validate(); err != nil {
			return negotiation.BudgetState{}, false, err
		}
		state.Reserved[id] = amount
	}
	return state, true, nil
}

// Record implements negotiation.Ledger.
func (l *BudgetLedger) Record(state negotiation.BudgetState) error {
	if l == nil {
		return errors.New("no budget ledger")
	}
	if err := l.journal.usable(); err != nil {
		return err
	}
	if !state.Total.Asset.Same(l.asset) {
		return errors.New("this budget holds another asset")
	}
	record := BudgetRecord{
		Schema: BudgetSchema, BudgetID: l.budgetID,
		Asset: StoredAsset{
			Workchain: l.asset.Workchain, AccountID: l.asset.AccountID,
			MasterCodeHash: l.asset.MasterCodeHash, WalletCodeHash: l.asset.WalletCodeHash,
			Decimals: l.asset.Decimals,
		},
		Total: state.Total.Atomic, Spent: state.Spent.Atomic,
		Reserved: make(map[string]string, len(state.Reserved)),
	}
	for id, amount := range state.Reserved {
		record.Reserved[id] = amount.Atomic
	}
	encoded, err := json.Marshal(record)
	if err != nil {
		return err
	}
	l.journal.mutex.Lock()
	defer l.journal.mutex.Unlock()
	return l.journal.replace(l.path(), encoded)
}

func (l *BudgetLedger) path() string {
	return filepath.Join(l.journal.root, budgetDir, l.budgetID[len("bgt_"):]+".json")
}
