package negotiation

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"

	nativev1 "github.com/tosnetwork/tos-service-protocol/gen/tos/service/v1"
)

// SnapshotSchema is the strict schema of a persisted negotiation.
const SnapshotSchema = "tos.messaging.negotiation-state.v1"

// Store is where a negotiation survives a restart.
//
// It is required, for the same reason the budget's ledger is. A negotiation
// that lived only in memory would lose its state at the moment a process ended
// while its budget hold stayed on the books: the money would be spoken for by
// an exchange nobody could find, and the owner's approval -- the part that took
// a person -- would have to be asked for again.
type Store interface {
	Save(snapshot Snapshot) error
}

// Snapshot is a negotiation's durable state.
//
// The mandate is referenced by digest rather than copied. A copy could outlive
// the authority it describes: an owner who withdrew a mandate would find the
// exchange it authorised continuing from a snapshot that still carried it.
type Snapshot struct {
	Schema              string `json:"schema"`
	ID                  string `json:"negotiation_id"`
	ConversationID      string `json:"conversation_id"`
	CounterpartyAgentID string `json:"counterparty_agent_id"`
	MandateDigest       string `json:"mandate_digest"`
	// Network is the TOS network the exchange is bound to. It survives a restart
	// so a restored negotiation keeps checking a finalized quote against the
	// network it expected, rather than losing the binding and accepting a quote
	// from anywhere.
	Network *nativev1.NetworkDomain `json:"network"`

	State         string `json:"state"`
	Generation    uint64 `json:"generation"`
	Counteroffers uint32 `json:"counteroffers"`
	NeedsApproval bool   `json:"needs_owner_approval"`

	OnTable *Terms `json:"on_table,omitempty"`
	Agreed  *Terms `json:"agreed,omitempty"`

	Approval   *Approval `json:"owner_approval,omitempty"`
	Commitment string    `json:"commitment,omitempty"`
	// Quote is the finalized Accepted Quote a finalized negotiation was
	// committed against. It is persisted whole: without it a restart would find
	// a finalized state and a commitment but no evidence of what was committed,
	// so Committed() would be true while Quote() was false -- a finalisation the
	// installation can no longer show.
	Quote   *VerifiedAcceptedQuote `json:"finalized_quote,omitempty"`
	Failure string                 `json:"failure,omitempty"`
}

// Snapshot returns what has to survive.
func (n *Negotiation) Snapshot() (Snapshot, error) {
	if n == nil {
		return Snapshot{}, errors.New("no negotiation")
	}
	mandateDigest, err := n.Mandate.Digest()
	if err != nil {
		return Snapshot{}, err
	}
	snapshot := Snapshot{
		Schema: SnapshotSchema, ID: n.ID, ConversationID: n.ConversationID,
		CounterpartyAgentID: n.CounterpartyAgentID, MandateDigest: mandateDigest,
		Network: cloneNetwork(n.network),
		State:   string(n.state), Generation: n.generation, Counteroffers: n.counteroffers,
		NeedsApproval: n.needsApproval, Commitment: n.commitment, Failure: n.failure,
	}
	if n.onTable != nil {
		onTable := *n.onTable
		snapshot.OnTable = &onTable
	}
	if n.agreed != nil {
		agreed := *n.agreed
		snapshot.Agreed = &agreed
	}
	if n.approval != nil {
		approval := *n.approval
		snapshot.Approval = &approval
	}
	if n.quote != nil {
		quote := *n.quote
		snapshot.Quote = &quote
	}
	return snapshot, nil
}

// Restore rebuilds a negotiation from what was written down.
//
// The mandate is supplied by the caller and checked against the digest the
// snapshot carries. That is what makes a withdrawn or replaced authority
// visible: the exchange does not resume under the mandate it remembers, it
// resumes under the one that exists now, or not at all.
func Restore(snapshot Snapshot, mandate Mandate, budget *Budget, store Store) (*Negotiation, error) {
	if err := snapshot.Validate(); err != nil {
		return nil, err
	}
	digest, err := mandate.Digest()
	if err != nil {
		return nil, err
	}
	if digest != snapshot.MandateDigest {
		return nil, errors.New("this negotiation was authorised by a mandate that no longer stands")
	}
	// The digest above already commits the mandate's asset network, but the
	// binding is restated against the snapshot's own network so a snapshot whose
	// two halves disagree is refused rather than resumed.
	bound, err := NetworkFromDomain(snapshot.Network)
	if err != nil {
		return nil, err
	}
	if !mandate.MaxTotal.Asset.Network.Same(bound) {
		return nil, errors.New("the mandate is priced on a network this negotiation is not bound to")
	}
	if mandate.Authority == AuthorityCommit && budget == nil {
		return nil, errors.New("a mandate that may commit needs a budget to commit against")
	}
	if store == nil {
		return nil, errors.New("a negotiation needs somewhere to survive a restart")
	}
	instance := &Negotiation{
		ID: snapshot.ID, ConversationID: snapshot.ConversationID,
		CounterpartyAgentID: snapshot.CounterpartyAgentID, Mandate: mandate,
		network: cloneNetwork(snapshot.Network),
		state:   State(snapshot.State), generation: snapshot.Generation,
		counteroffers: snapshot.Counteroffers, needsApproval: snapshot.NeedsApproval,
		commitment: snapshot.Commitment, failure: snapshot.Failure,
		budget: budget, store: store,
	}
	if snapshot.OnTable != nil {
		onTable := *snapshot.OnTable
		instance.onTable = &onTable
	}
	if snapshot.Agreed != nil {
		agreed := *snapshot.Agreed
		instance.agreed = &agreed
	}
	if snapshot.Approval != nil {
		approval := *snapshot.Approval
		instance.approval = &approval
	}
	if snapshot.Quote != nil {
		quote := *snapshot.Quote
		instance.quote = &quote
	}
	return instance, nil
}

var states = map[State]struct{}{
	StateDiscussing: {}, StateProposalPending: {}, StateCounterproposalPending: {},
	StateIntentAgreed: {}, StateCanonicalizationPending: {}, StateFinalized: {},
	StateRejected: {}, StateWithdrawn: {}, StateExpired: {},
}

// Validate enforces a snapshot that describes something.
func (s Snapshot) Validate() error {
	if s.Schema != SnapshotSchema {
		return errors.New("unsupported negotiation snapshot schema")
	}
	if s.ID == "" || len(s.ID) > 128 {
		return errors.New("snapshot names no negotiation")
	}
	if _, known := states[State(s.State)]; !known {
		return errors.New("snapshot carries a state this build does not know")
	}
	if s.MandateDigest == "" {
		return errors.New("snapshot names no mandate")
	}
	// A snapshot must carry the network its exchange is bound to, fully
	// identified, or a restored negotiation would lose the binding and accept a
	// finalized quote from any network.
	if err := validateNetworkDomain(s.Network); err != nil {
		return errors.New("snapshot names no network")
	}
	// Every set of terms a snapshot carries must be priced on the network the
	// exchange is bound to. The terms digest commits the asset's network, so a
	// snapshot whose terms name another network is carrying a digest no
	// commitment this exchange accepts could ever answer to; refusing it here
	// means a store edit cannot smuggle a foreign purchase into a resumed
	// negotiation.
	bound, err := NetworkFromDomain(s.Network)
	if err != nil {
		return errors.New("snapshot names no network")
	}
	for _, terms := range []*Terms{s.OnTable, s.Agreed} {
		if terms == nil {
			continue
		}
		if err := terms.Validate(); err != nil {
			return err
		}
		if !terms.Price.Asset.Network.Same(bound) {
			return errors.New("snapshot carries terms priced on a network the negotiation is not bound to")
		}
	}
	// An approval that outran the generation it was given at would be an
	// approval for terms that no longer exist.
	if s.Approval != nil && s.Approval.Generation > s.Generation {
		return errors.New("snapshot carries an approval from a later version of itself")
	}
	if State(s.State) == StateFinalized {
		if s.Commitment == "" {
			return errors.New("a finalized negotiation carries no commitment")
		}
		// A finalized negotiation must carry the quote it was committed against,
		// and that quote must be the one the commitment names -- otherwise a
		// restart would report a commitment it cannot substantiate.
		if s.Quote == nil {
			return errors.New("a finalized negotiation carries no quote evidence")
		}
		if err := s.Quote.Validate(); err != nil {
			return err
		}
		if s.Quote.Commitment != s.Commitment {
			return errors.New("the finalized quote does not match the commitment")
		}
		if !s.Quote.Terms.Price.Asset.Network.Same(bound) {
			return errors.New("the finalized quote is priced on a network the negotiation is not bound to")
		}
	}
	return nil
}

// EncodeSnapshotJSON returns the durable form.
func EncodeSnapshotJSON(snapshot Snapshot) ([]byte, error) {
	if err := snapshot.Validate(); err != nil {
		return nil, err
	}
	return json.Marshal(snapshot)
}

// DecodeSnapshotJSON parses one, refusing unknown fields and trailing data.
func DecodeSnapshotJSON(raw []byte) (Snapshot, error) {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	var snapshot Snapshot
	if err := decoder.Decode(&snapshot); err != nil {
		return Snapshot{}, err
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return Snapshot{}, errors.New("negotiation snapshot has trailing JSON")
	}
	if err := snapshot.Validate(); err != nil {
		return Snapshot{}, err
	}
	return snapshot, nil
}
