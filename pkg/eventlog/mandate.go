package eventlog

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"time"

	"github.com/tosnetwork/tos-messenger/internal/canon"
)

const (
	mandateDir = "mandates"

	// MandateSchema is the on-disk schema of one stored mandate.
	MandateSchema = "tos.messaging.mandate-record.v1"

	// MaxMandates bounds how many standing authorisations one installation
	// holds. An owner who cannot enumerate what they authorised has not
	// authorised anything they could withdraw.
	MaxMandates = 64
)

var mandatePattern = regexp.MustCompile(`^mdt_[0-9a-f]{64}$`)

// ErrMandateUnknown reports that no mandate exists under an identifier.
var ErrMandateUnknown = errors.New("no such mandate")

// ErrMandateRevoked reports a mandate the owner has withdrawn.
var ErrMandateRevoked = errors.New("this mandate was withdrawn")

// ErrMandatesFull reports that the store is at its bound.
var ErrMandatesFull = errors.New("this installation holds as many mandates as it may")

// StoredMandate is one standing authorisation the owner placed.
//
// The mandate is stored as its fields rather than as an opaque blob, because
// the owner has to be able to read back what they authorised. A record only a
// program can interpret is a permission nobody can review.
type StoredMandate struct {
	Schema          string `json:"schema"`
	MandateID       string `json:"mandate_id"`
	Objective       string `json:"objective"`
	Authority       string `json:"authority"`
	CapabilityClass string `json:"capability_class"`
	// Asset names the asset the way the chain does. A ticker is a label; two
	// contracts may both answer to one, and an authorisation that named its
	// asset by ticker could be satisfied with a different token. The network is
	// part of the identity: the same contract tuple exists on other TOS
	// networks, and an authorisation that omitted it could be spent elsewhere.
	AssetNetworkID       string `json:"asset_network_id"`
	AssetGenesisRootHash string `json:"asset_genesis_root_hash"`
	AssetGenesisFileHash string `json:"asset_genesis_file_hash"`
	Workchain            int32  `json:"asset_workchain"`
	AssetAccountID       string `json:"asset_master_account_id"`
	AssetMasterCodeHash  string `json:"asset_master_code_hash"`
	AssetWalletCodeHash  string `json:"asset_wallet_code_hash"`
	AssetDecimals        uint32 `json:"asset_decimals"`
	MaxTotalAtomic       string `json:"max_total_atomic"`
	ApprovalAboveAtomic  string `json:"approval_above_atomic"`
	MaxCounteroffers     uint32 `json:"max_counteroffers"`
	ExpiresAtUnix        uint64 `json:"expires_at_unix"`
	PlacedAtUnix         uint64 `json:"placed_at_unix"`
	RevokedAtUnix        uint64 `json:"revoked_at_unix,omitempty"`
}

// Live reports whether a mandate may still authorise anything.
func (m StoredMandate) Live(now time.Time) bool {
	return m.RevokedAtUnix == 0 && m.ExpiresAtUnix > uint64(now.Unix())
}

// MandateID derives the identifier of a stored mandate from its terms.
//
// It is content addressed so that the identifier a runtime names is the
// authorisation the owner placed, rather than a handle that could be pointed
// at something else later. Withdrawing a mandate and placing a different one
// produces a different identifier, and a runtime holding the old one finds
// nothing.
func MandateID(mandate StoredMandate) (string, error) {
	if err := validateStoredMandate(mandate); err != nil {
		return "", err
	}
	buffer := bytes.NewBufferString(canon.DomainMandate)
	canon.Text(buffer, mandate.Objective)
	canon.Text(buffer, mandate.Authority)
	canon.Text(buffer, mandate.CapabilityClass)
	canon.Text(buffer, mandate.AssetNetworkID)
	canon.Text(buffer, mandate.AssetGenesisRootHash)
	canon.Text(buffer, mandate.AssetGenesisFileHash)
	canon.Uint32(buffer, uint32(mandate.Workchain))
	canon.Text(buffer, mandate.AssetAccountID)
	canon.Text(buffer, mandate.AssetMasterCodeHash)
	canon.Text(buffer, mandate.AssetWalletCodeHash)
	canon.Uint32(buffer, mandate.AssetDecimals)
	canon.Text(buffer, mandate.MaxTotalAtomic)
	canon.Text(buffer, mandate.ApprovalAboveAtomic)
	canon.Uint32(buffer, mandate.MaxCounteroffers)
	canon.Uint64(buffer, mandate.ExpiresAtUnix)
	digest := canon.Digest(buffer.Bytes())
	return "mdt_" + digest[len("sha256:"):], nil
}

// PlaceMandate records a standing authorisation.
//
// Placing the same mandate twice is the same authorisation and does not renew
// a withdrawal: an identifier derived from the terms means a revoked mandate
// cannot be brought back by asking for it again. The owner places a different
// one, which is a different identifier and a decision they made deliberately.
func (j *Journal) PlaceMandate(mandate StoredMandate, now time.Time) (StoredMandate, error) {
	if err := j.usable(); err != nil {
		return StoredMandate{}, err
	}
	if now.IsZero() || now.Unix() < 0 {
		return StoredMandate{}, errors.New("invalid mandate time")
	}
	identifier, err := MandateID(mandate)
	if err != nil {
		return StoredMandate{}, err
	}
	j.mutex.Lock()
	defer j.mutex.Unlock()

	existing, found, err := j.readMandate(identifier)
	if err != nil {
		return StoredMandate{}, err
	}
	if found {
		return existing, nil
	}
	held, err := j.countMandates()
	if err != nil {
		return StoredMandate{}, err
	}
	if held >= MaxMandates {
		return StoredMandate{}, ErrMandatesFull
	}
	mandate.Schema = MandateSchema
	mandate.MandateID = identifier
	mandate.PlacedAtUnix = uint64(now.Unix())
	mandate.RevokedAtUnix = 0
	return j.commitMandate(mandate)
}

// RevokeMandate withdraws one.
//
// A withdrawn mandate is kept rather than deleted. An owner asking what an
// Agent was allowed to do last week needs the answer to survive the withdrawal.
func (j *Journal) RevokeMandate(mandateID string, now time.Time) (StoredMandate, error) {
	if err := j.usable(); err != nil {
		return StoredMandate{}, err
	}
	if !mandatePattern.MatchString(mandateID) {
		return StoredMandate{}, errors.New("invalid mandate identifier")
	}
	if now.IsZero() || now.Unix() < 0 {
		return StoredMandate{}, errors.New("invalid mandate time")
	}
	j.mutex.Lock()
	defer j.mutex.Unlock()

	mandate, found, err := j.readMandate(mandateID)
	if err != nil {
		return StoredMandate{}, err
	}
	if !found {
		return StoredMandate{}, ErrMandateUnknown
	}
	if mandate.RevokedAtUnix != 0 {
		return mandate, nil
	}
	mandate.RevokedAtUnix = uint64(now.Unix())
	return j.commitMandate(mandate)
}

// ListMandates returns every mandate this installation holds, withdrawn ones
// included, in a stable order.
func (j *Journal) ListMandates() ([]StoredMandate, error) {
	if err := j.usable(); err != nil {
		return nil, err
	}
	j.mutex.Lock()
	defer j.mutex.Unlock()
	return j.readMandates()
}

// LookupMandate returns one mandate.
func (j *Journal) LookupMandate(mandateID string) (StoredMandate, bool, error) {
	if err := j.usable(); err != nil {
		return StoredMandate{}, false, err
	}
	if !mandatePattern.MatchString(mandateID) {
		return StoredMandate{}, false, errors.New("invalid mandate identifier")
	}
	j.mutex.Lock()
	defer j.mutex.Unlock()
	return j.readMandate(mandateID)
}

func (j *Journal) countMandates() (int, error) {
	mandates, err := j.readMandates()
	if err != nil {
		return 0, err
	}
	live := 0
	for _, mandate := range mandates {
		if mandate.RevokedAtUnix == 0 {
			live++
		}
	}
	return live, nil
}

func (j *Journal) readMandates() ([]StoredMandate, error) {
	entries, err := os.ReadDir(j.mandateRoot())
	if err != nil {
		return nil, errors.New("read mandate directory")
	}
	mandates := make([]StoredMandate, 0, len(entries))
	for _, entry := range entries {
		if entry.IsDir() || filepath.Ext(entry.Name()) != ".json" {
			continue
		}
		mandate, found, err := j.readMandate("mdt_" + entry.Name()[:len(entry.Name())-len(".json")])
		if err != nil || !found {
			continue
		}
		mandates = append(mandates, mandate)
	}
	sort.Slice(mandates, func(i, k int) bool {
		if mandates[i].PlacedAtUnix != mandates[k].PlacedAtUnix {
			return mandates[i].PlacedAtUnix < mandates[k].PlacedAtUnix
		}
		return mandates[i].MandateID < mandates[k].MandateID
	})
	return mandates, nil
}

func (j *Journal) readMandate(mandateID string) (StoredMandate, bool, error) {
	raw, err := os.ReadFile(j.mandatePath(mandateID))
	if errors.Is(err, os.ErrNotExist) {
		return StoredMandate{}, false, nil
	}
	if err != nil {
		return StoredMandate{}, false, errors.New("read mandate record")
	}
	if len(raw) > MaxRecordBytes {
		return StoredMandate{}, false, errors.New("mandate record exceeds its bound")
	}
	var mandate StoredMandate
	if err := json.Unmarshal(raw, &mandate); err != nil {
		return StoredMandate{}, false, errors.New("invalid mandate record")
	}
	if mandate.Schema != MandateSchema || mandate.MandateID != mandateID {
		return StoredMandate{}, false, errors.New("mandate record does not describe this mandate")
	}
	// The identifier commits the terms, so a record whose terms no longer
	// derive it has been edited on disk and is not the owner's decision.
	derived, err := MandateID(mandate)
	if err != nil || derived != mandateID {
		return StoredMandate{}, false, errors.New("mandate record does not match its identifier")
	}
	return mandate, true, nil
}

func (j *Journal) commitMandate(mandate StoredMandate) (StoredMandate, error) {
	encoded, err := json.Marshal(mandate)
	if err != nil {
		return StoredMandate{}, err
	}
	if err := j.replace(j.mandatePath(mandate.MandateID), encoded); err != nil {
		return StoredMandate{}, err
	}
	return mandate, nil
}

func (j *Journal) mandateRoot() string { return filepath.Join(j.root, mandateDir) }

func (j *Journal) mandatePath(mandateID string) string {
	return filepath.Join(j.root, mandateDir, mandateID[len("mdt_"):]+".json")
}

func validateStoredMandate(mandate StoredMandate) error {
	if mandate.Objective == "" || len(mandate.Objective) > MaxApprovalSummaryBytes {
		return errors.New("a mandate must say what it is for")
	}
	if mandate.Authority == "" || len(mandate.Authority) > 64 {
		return errors.New("a mandate must name its authority")
	}
	if mandate.CapabilityClass == "" || len(mandate.CapabilityClass) > 128 {
		return errors.New("a mandate must name what may be bought")
	}
	if mandate.AssetAccountID == "" || mandate.AssetMasterCodeHash == "" ||
		mandate.AssetWalletCodeHash == "" {
		return errors.New("a mandate must name its asset the way the chain does")
	}
	if mandate.AssetNetworkID == "" || len(mandate.AssetNetworkID) > 128 ||
		!canon.HashPattern.MatchString(mandate.AssetGenesisRootHash) ||
		!canon.HashPattern.MatchString(mandate.AssetGenesisFileHash) {
		return errors.New("a mandate must name the network its asset lives on")
	}
	if mandate.MaxTotalAtomic == "" || mandate.ApprovalAboveAtomic == "" {
		return errors.New("a mandate must name its ceiling and its approval point")
	}
	if mandate.ExpiresAtUnix == 0 {
		return errors.New("a mandate must expire")
	}
	return nil
}
