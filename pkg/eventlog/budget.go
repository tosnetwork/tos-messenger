package eventlog

import (
	"bytes"
	"encoding/json"
	"errors"
	"math/big"
	"os"
	"path/filepath"
	"regexp"

	"github.com/tosnetwork/tos-messenger/internal/canon"
	"github.com/tosnetwork/tos-messenger/pkg/negotiation"
)

const (
	budgetDir = "budgets"
	// mandateBudgetDir keeps per-mandate budgets apart from the per-asset ones.
	// The two are reconciled by different rules -- a per-asset budget's holds are
	// keyed by the negotiation that took them, a per-mandate budget's by the
	// economic execution -- so they must never share a directory a single
	// reconciler would sweep.
	mandateBudgetDir = "mandate-budgets"

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

// StoredAsset is an asset identity as it is written down. The network is part
// of it: the same contract tuple on another network is a different asset, and a
// ledger that omitted the network would let two networks share one budget.
type StoredAsset struct {
	NetworkID       string `json:"network_id"`
	GenesisRootHash string `json:"genesis_root_hash"`
	GenesisFileHash string `json:"genesis_file_hash"`
	Workchain       int32  `json:"workchain"`
	AccountID       string `json:"master_account_id"`
	MasterCodeHash  string `json:"master_code_hash"`
	WalletCodeHash  string `json:"wallet_code_hash"`
	Decimals        uint32 `json:"decimals"`
}

// BudgetID derives the identifier of the optional global budget for one asset.
//
// This budget is the optional global asset-risk ceiling. It no longer carries a
// mandate's MaxTotal: a mandate's durable total lives in the per-mandate budget
// (see MandateBudgetID), because one asset serves many mandates and a shared
// per-asset total would let distinct mandates draw each other's ceiling down.
// Deriving the identifier from the asset rather than letting a caller choose it
// means two callers cannot open two budgets over the same money and each believe
// they hold all of it.
func BudgetID(asset negotiation.Asset) (string, error) {
	if err := asset.Validate(); err != nil {
		return "", err
	}
	buffer := bytes.NewBufferString(canon.DomainBudget)
	canon.Text(buffer, asset.Network.ID)
	canon.Text(buffer, asset.Network.GenesisRootHash)
	canon.Text(buffer, asset.Network.GenesisFileHash)
	canon.Uint32(buffer, uint32(asset.Workchain))
	canon.Text(buffer, asset.AccountID)
	canon.Text(buffer, asset.MasterCodeHash)
	canon.Text(buffer, asset.WalletCodeHash)
	canon.Uint32(buffer, asset.Decimals)
	digest := canon.Digest(buffer.Bytes())
	return "bgt_" + digest[len("sha256:"):], nil
}

// MandateBudgetID derives the identifier of one mandate's budget.
//
// The mandate scopes it: the preimage folds in the mandate the ceiling belongs
// to as well as the asset, so two mandates over the same asset derive two
// budgets and neither can spend the other's total down. This is the budget that
// carries a mandate's MaxTotal; the per-asset BudgetID is a separate, optional
// global ceiling.
func MandateBudgetID(mandateID string, asset negotiation.Asset) (string, error) {
	if mandateID == "" || len(mandateID) > 128 {
		return "", errors.New("a mandate budget needs the mandate that bounds it")
	}
	if err := asset.Validate(); err != nil {
		return "", err
	}
	buffer := bytes.NewBufferString(canon.DomainMandateBudget)
	canon.Text(buffer, mandateID)
	canon.Text(buffer, asset.Network.ID)
	canon.Text(buffer, asset.Network.GenesisRootHash)
	canon.Text(buffer, asset.Network.GenesisFileHash)
	canon.Uint32(buffer, uint32(asset.Workchain))
	canon.Text(buffer, asset.AccountID)
	canon.Text(buffer, asset.MasterCodeHash)
	canon.Text(buffer, asset.WalletCodeHash)
	canon.Uint32(buffer, asset.Decimals)
	digest := canon.Digest(buffer.Bytes())
	return "mbg_" + digest[len("sha256:"):], nil
}

// BudgetLedger is the durable half of one budget.
//
// dir names the directory the record lives under and stem names the file within
// it, so the per-asset and per-mandate budgets reuse this same machinery while
// keeping their records in separate directories with separate reconciliation
// rules.
type BudgetLedger struct {
	journal  *Journal
	budgetID string
	dir      string
	stem     string
	asset    negotiation.Asset
}

// OpenBudgetLedger returns the ledger for one asset's optional global budget.
//
// This is the optional global asset-risk ceiling, not the carrier of any
// mandate's MaxTotal. Use OpenMandateBudgetLedger to bound one mandate's total.
func (j *Journal) OpenBudgetLedger(asset negotiation.Asset) (*BudgetLedger, error) {
	if err := j.usable(); err != nil {
		return nil, err
	}
	budgetID, err := BudgetID(asset)
	if err != nil {
		return nil, err
	}
	return &BudgetLedger{
		journal: j, budgetID: budgetID, dir: budgetDir,
		stem: budgetID[len("bgt_"):], asset: asset,
	}, nil
}

// OpenMandateBudgetLedger returns the ledger for one mandate's budget.
//
// The durable identity and path fold in the mandate, so two mandates never
// share one budget. This is the budget that carries a mandate's MaxTotal.
func (j *Journal) OpenMandateBudgetLedger(mandateID string, asset negotiation.Asset) (*BudgetLedger, error) {
	if err := j.usable(); err != nil {
		return nil, err
	}
	budgetID, err := MandateBudgetID(mandateID, asset)
	if err != nil {
		return nil, err
	}
	return &BudgetLedger{
		journal: j, budgetID: budgetID, dir: mandateBudgetDir,
		stem: budgetID[len("mbg_"):], asset: asset,
	}, nil
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
		Network: negotiation.Network{
			ID:              record.Asset.NetworkID,
			GenesisRootHash: record.Asset.GenesisRootHash,
			GenesisFileHash: record.Asset.GenesisFileHash,
		},
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
			NetworkID:       l.asset.Network.ID,
			GenesisRootHash: l.asset.Network.GenesisRootHash,
			GenesisFileHash: l.asset.Network.GenesisFileHash,
			Workchain:       l.asset.Workchain, AccountID: l.asset.AccountID,
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
	return filepath.Join(l.journal.root, l.dir, l.stem+".json")
}

// reconcileCommerce repairs the seam between budgets and negotiations after a
// crash.
//
// The two are separate records, so a crash between writing one and the other
// is possible; what makes it recoverable is that every transition writes them
// in an order whose intermediate shape names its own repair. A reservation is
// keyed by the negotiation that took it, so each one is checked against the
// exchange it belongs to:
//
//   - the exchange is settled without finalizing -- the hold goes back;
//   - the exchange is finalized -- the hold becomes the spend it was about to
//     become when the crash hit;
//   - the exchange never reached agreement, or does not exist -- the hold was
//     written before the agreement it backs, and the agreement never landed,
//     so it goes back;
//   - the exchange stands agreed or canonicalising -- the hold is right where
//     it should be.
//
// The reverse orphan -- an agreed exchange with no hold -- cannot arise from
// these orderings, which is why no repair for it exists: re-reserving here
// could exceed a ceiling that has moved on, and marking the exchange failed
// would end an agreement the owner may have approved. The orderings are chosen
// so that ambiguity never has to be resolved.
func (j *Journal) reconcileCommerce() error {
	entries, err := os.ReadDir(filepath.Join(j.root, budgetDir))
	if err != nil {
		return errors.New("read budget directory")
	}
	store := &NegotiationStore{journal: j}
	for _, entry := range entries {
		if entry.IsDir() || filepath.Ext(entry.Name()) != ".json" {
			continue
		}
		if err := j.reconcileBudgetFile(store, filepath.Join(j.root, budgetDir, entry.Name())); err != nil {
			return err
		}
	}
	return nil
}

func (j *Journal) reconcileBudgetFile(store *NegotiationStore, path string) error {
	raw, err := os.ReadFile(path)
	if err != nil {
		return errors.New("read budget ledger")
	}
	var record BudgetRecord
	if err := json.Unmarshal(raw, &record); err != nil || record.Schema != BudgetSchema {
		// A ledger this journal cannot read is not silently rewritten; opening
		// the budget will refuse it and say so.
		return nil
	}
	changed := false
	for id, atomic := range record.Reserved {
		disposition, err := j.holdDisposition(store, id)
		if err != nil {
			return err
		}
		switch disposition {
		case holdStands:
			continue
		case holdReturns:
			delete(record.Reserved, id)
			changed = true
		case holdBecomesSpend:
			spent, ok := new(big.Int).SetString(record.Spent, 10)
			amount, okAmount := new(big.Int).SetString(atomic, 10)
			if !ok || !okAmount {
				return errors.New("budget ledger holds a non-numeric amount")
			}
			record.Spent = spent.Add(spent, amount).String()
			delete(record.Reserved, id)
			changed = true
		}
	}
	if !changed {
		return nil
	}
	encoded, err := json.Marshal(record)
	if err != nil {
		return err
	}
	return j.replace(path, encoded)
}

type disposition int

const (
	holdStands disposition = iota
	holdReturns
	holdBecomesSpend
)

func (j *Journal) holdDisposition(store *NegotiationStore, negotiationID string) (disposition, error) {
	path, err := store.path(negotiationID)
	if err != nil {
		// A hold keyed by an identifier no negotiation could carry backs
		// nothing; it goes back.
		return holdReturns, nil
	}
	snapshot, found, err := store.read(path)
	if err != nil {
		return holdStands, err
	}
	if !found {
		return holdReturns, nil
	}
	switch negotiation.State(snapshot.State) {
	case negotiation.StateIntentAgreed, negotiation.StateCanonicalizationPending:
		return holdStands, nil
	case negotiation.StateFinalized:
		return holdBecomesSpend, nil
	default:
		return holdReturns, nil
	}
}
