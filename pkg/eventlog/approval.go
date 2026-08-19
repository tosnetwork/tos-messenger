package eventlog

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sort"
	"time"

	"github.com/tosnetwork/tos-messenger/internal/ids"
	"github.com/tosnetwork/tos-messenger/pkg/negotiation"
)

const (
	approvalDir = "approvals"

	// ApprovalSchema is the on-disk schema of one action approval.
	ApprovalSchema = "tos.messaging.action-approval.v1"

	// MaxApprovalsPerListing bounds one listing of waiting decisions.
	MaxApprovalsPerListing = 64
	// MaxPendingActions bounds how many decisions may await the owner at once.
	// The runtime asks for these, and a runtime in a loop would otherwise fill
	// the queue and the disk behind it as readily as a stranger would.
	MaxPendingActions = 128
	// MaxApprovalSummaryBytes bounds the description an owner is shown.
	MaxApprovalSummaryBytes = 512
	// MaxApprovalOrigins bounds the provenance one request may carry.
	MaxApprovalOrigins = 32
)

// ApprovalState is where one request for an owner decision has got to.
//
// There is no state for "granted and used again". An approval is spent the
// first time the action it names is performed, because an approval that could
// be presented twice would authorise the second occurrence of an action the
// owner saw once.
type ApprovalState string

const (
	// ApprovalPending is waiting for the owner.
	ApprovalPending ApprovalState = "pending"
	// ApprovalGranted is decided and not yet spent.
	ApprovalGranted ApprovalState = "granted"
	// ApprovalSpent means the action it authorised was performed.
	ApprovalSpent ApprovalState = "spent"
	// ApprovalDenied is refused.
	ApprovalDenied ApprovalState = "denied"
)

// ErrApprovalUnknown reports that no request exists for an action.
var ErrApprovalUnknown = errors.New("no approval request for this action")

// ErrApprovalDecided reports an attempt to decide a request that is already
// settled. An owner's decision is not revisited by whoever asked for it.
var ErrApprovalDecided = errors.New("this approval was already decided")

// ErrApprovalNotGranted reports an attempt to spend an approval that was not
// granted, or was granted and already spent.
var ErrApprovalNotGranted = errors.New("this action is not authorised")

// ApprovalOrigin is one piece of received content behind a request.
//
// It is stored with the request rather than looked up when the owner reads it.
// An approval prompt assembled from state that may have changed since the
// request would be showing the owner a different question than the one that
// was asked.
type ApprovalOrigin struct {
	AgentID    string `json:"agent_id"`
	EndpointID string `json:"messaging_endpoint_id"`
	// DeviceID and ReceivedAtUnix are part of the provenance the action
	// identifier commits, so they are stored: without them the owner cannot
	// reproduce the identifier they are signing, and a record that dropped them
	// would show a different provenance than the one the identifier was derived
	// from.
	DeviceID       string `json:"device_id"`
	EventID        string `json:"event_id"`
	ConversationID string `json:"conversation_id"`
	Kind           string `json:"event_kind"`
	ReceivedAtUnix uint64 `json:"received_at_unix"`
}

// ApprovalRequest is what the runtime asks the owner to decide.
type ApprovalRequest struct {
	// ActionID commits what the action is. The approval is an approval of that
	// action: a different action derives a different identifier and finds no
	// approval waiting for it.
	ActionID string
	Effect   string
	Summary  string
	Reason   string
	Origins  []ApprovalOrigin
	// Terms are the exact structured purchase, present for a spend. They are
	// persisted so the owner is shown the real amount, asset, provider, and
	// expiry from typed state rather than the runtime's summary, and so the
	// identifier can be recomputed and checked against what is being signed.
	Terms   *negotiation.Terms
	AskedAt uint64
}

// Approval is the durable state of one request.
type Approval struct {
	Schema        string             `json:"schema"`
	ActionID      string             `json:"action_id"`
	Effect        string             `json:"effect"`
	Summary       string             `json:"summary"`
	Reason        string             `json:"reason"`
	Origins       []ApprovalOrigin   `json:"origins,omitempty"`
	Terms         *negotiation.Terms `json:"terms,omitempty"`
	State         ApprovalState      `json:"state"`
	AskedAtUnix   uint64             `json:"asked_at_unix"`
	DecidedAtUnix uint64             `json:"decided_at_unix,omitempty"`
	SpentAtUnix   uint64             `json:"spent_at_unix,omitempty"`
	DenialReason  string             `json:"denial_reason,omitempty"`
}

// RequestApproval durably records that an action is waiting for a person.
//
// Asking twice for the same action is not an error and does not reset the
// request: the identifier is content addressed, so a repeat is the same
// question, and a runtime that retried would otherwise be able to clear a
// denial by asking again.
func (j *Journal) RequestApproval(request ApprovalRequest) (Approval, error) {
	if err := j.usable(); err != nil {
		return Approval{}, err
	}
	if err := validateApprovalRequest(request); err != nil {
		return Approval{}, err
	}
	j.mutex.Lock()
	defer j.mutex.Unlock()

	existing, found, err := j.readApproval(request.ActionID)
	if err != nil {
		return Approval{}, err
	}
	if found {
		return existing, nil
	}
	waiting, err := j.countPendingApprovals(request.AskedAt)
	if err != nil {
		return Approval{}, err
	}
	if waiting >= MaxPendingActions {
		return Approval{}, ErrPendingFull
	}
	approval := Approval{
		Schema: ApprovalSchema, ActionID: request.ActionID, Effect: request.Effect,
		Summary: request.Summary, Reason: request.Reason, Origins: request.Origins,
		Terms: request.Terms, State: ApprovalPending, AskedAtUnix: request.AskedAt,
	}
	return j.commitApproval(approval)
}

// ListPendingApprovals returns the decisions waiting for the owner, oldest
// first: a queue an owner works through in the order the questions were asked
// is one they can finish.
func (j *Journal) ListPendingApprovals(now time.Time, limit int) ([]Approval, error) {
	if err := j.usable(); err != nil {
		return nil, err
	}
	if limit <= 0 || limit > MaxApprovalsPerListing {
		limit = MaxApprovalsPerListing
	}
	j.mutex.Lock()
	defer j.mutex.Unlock()

	entries, err := os.ReadDir(j.approvalRoot())
	if err != nil {
		return nil, errors.New("read approval directory")
	}
	waiting := make([]Approval, 0, len(entries))
	for _, entry := range entries {
		if entry.IsDir() || filepath.Ext(entry.Name()) != ".json" {
			continue
		}
		approval, found, err := j.readApproval("act_" + entry.Name()[:len(entry.Name())-len(".json")])
		if err != nil || !found {
			continue
		}
		if approval.State != ApprovalPending {
			continue
		}
		// A request nobody decided within the window is not still pending.
		if j.approvalExpired(approval, uint64(now.Unix())) {
			continue
		}
		waiting = append(waiting, approval)
	}
	sort.Slice(waiting, func(i, j int) bool {
		if waiting[i].AskedAtUnix != waiting[j].AskedAtUnix {
			return waiting[i].AskedAtUnix < waiting[j].AskedAtUnix
		}
		return waiting[i].ActionID < waiting[j].ActionID
	})
	if len(waiting) > limit {
		waiting = waiting[:limit]
	}
	return waiting, nil
}

// GrantAction records the owner authorising one action.
func (j *Journal) GrantAction(actionID string, now time.Time) (Approval, error) {
	return j.decideApproval(actionID, ApprovalGranted, "", now)
}

// DenyAction records the owner refusing one action.
func (j *Journal) DenyAction(actionID, reason string, now time.Time) (Approval, error) {
	if reason == "" || len(reason) > MaxApprovalSummaryBytes {
		return Approval{}, errors.New("a refusal must say why")
	}
	return j.decideApproval(actionID, ApprovalDenied, reason, now)
}

// SpendApproval consumes a granted approval.
//
// It is what the runtime calls immediately before performing the action, and
// it is the reason a granted approval cannot authorise the same action twice.
// The transition is durable before the action happens, so a crash between the
// two loses the permission rather than reusing it.
func (j *Journal) SpendApproval(actionID string, now time.Time) (Approval, error) {
	if err := j.usable(); err != nil {
		return Approval{}, err
	}
	if !ids.Action.MatchString(actionID) {
		return Approval{}, errors.New("invalid action identifier")
	}
	if now.IsZero() || now.Unix() < 0 {
		return Approval{}, errors.New("invalid approval time")
	}
	j.mutex.Lock()
	defer j.mutex.Unlock()

	approval, found, err := j.readApproval(actionID)
	if err != nil {
		return Approval{}, err
	}
	if !found {
		return Approval{}, ErrApprovalUnknown
	}
	if approval.State != ApprovalGranted {
		return Approval{}, ErrApprovalNotGranted
	}
	approval.State = ApprovalSpent
	approval.SpentAtUnix = uint64(now.Unix())
	return j.commitApproval(approval)
}

// LookupApproval returns the state of one request.
func (j *Journal) LookupApproval(actionID string) (Approval, bool, error) {
	if err := j.usable(); err != nil {
		return Approval{}, false, err
	}
	if !ids.Action.MatchString(actionID) {
		return Approval{}, false, errors.New("invalid action identifier")
	}
	j.mutex.Lock()
	defer j.mutex.Unlock()
	return j.readApproval(actionID)
}

func (j *Journal) decideApproval(actionID string, state ApprovalState, reason string, now time.Time) (Approval, error) {
	if err := j.usable(); err != nil {
		return Approval{}, err
	}
	if !ids.Action.MatchString(actionID) {
		return Approval{}, errors.New("invalid action identifier")
	}
	if now.IsZero() || now.Unix() < 0 {
		return Approval{}, errors.New("invalid approval time")
	}
	j.mutex.Lock()
	defer j.mutex.Unlock()

	approval, found, err := j.readApproval(actionID)
	if err != nil {
		return Approval{}, err
	}
	if !found {
		return Approval{}, ErrApprovalUnknown
	}
	if approval.State != ApprovalPending {
		return Approval{}, ErrApprovalDecided
	}
	approval.State = state
	approval.DecidedAtUnix = uint64(now.Unix())
	approval.DenialReason = reason
	return j.commitApproval(approval)
}

func (j *Journal) readApproval(actionID string) (Approval, bool, error) {
	raw, err := os.ReadFile(j.approvalPath(actionID))
	if errors.Is(err, os.ErrNotExist) {
		return Approval{}, false, nil
	}
	if err != nil {
		return Approval{}, false, errors.New("read approval record")
	}
	if len(raw) > MaxRecordBytes {
		return Approval{}, false, errors.New("approval record exceeds its bound")
	}
	var approval Approval
	if err := json.Unmarshal(raw, &approval); err != nil {
		return Approval{}, false, errors.New("invalid approval record")
	}
	if approval.Schema != ApprovalSchema || approval.ActionID != actionID {
		return Approval{}, false, errors.New("approval record does not describe this action")
	}
	return approval, true, nil
}

func (j *Journal) commitApproval(approval Approval) (Approval, error) {
	encoded, err := json.Marshal(approval)
	if err != nil {
		return Approval{}, err
	}
	if err := j.replace(j.approvalPath(approval.ActionID), encoded); err != nil {
		return Approval{}, err
	}
	return approval, nil
}

func (j *Journal) approvalRoot() string { return filepath.Join(j.root, approvalDir) }

func (j *Journal) approvalPath(actionID string) string {
	return filepath.Join(j.root, approvalDir, actionID[len("act_"):]+".json")
}

func validateApprovalRequest(request ApprovalRequest) error {
	if !ids.Action.MatchString(request.ActionID) {
		return errors.New("invalid action identifier")
	}
	if request.Effect == "" || len(request.Effect) > 64 {
		return errors.New("an approval request must name an effect")
	}
	if request.Summary == "" || len(request.Summary) > MaxApprovalSummaryBytes {
		return errors.New("an approval request must describe itself")
	}
	if request.Reason == "" || len(request.Reason) > MaxApprovalSummaryBytes {
		return errors.New("an approval request must say why it is being asked")
	}
	if request.AskedAt == 0 {
		return errors.New("an approval request has no time")
	}
	if len(request.Origins) > MaxApprovalOrigins {
		return errors.New("an approval request cites more content than an owner could review")
	}
	for _, origin := range request.Origins {
		if !ids.Agent.MatchString(origin.AgentID) || !ids.Endpoint.MatchString(origin.EndpointID) ||
			!ids.Event.MatchString(origin.EventID) || !ids.Conversation.MatchString(origin.ConversationID) {
			return errors.New("an approval request cites content it cannot identify")
		}
		// The device is part of the provenance the action identifier commits, so
		// it has to be a real device identifier, not an empty one that would make
		// the stored provenance disagree with the identifier.
		if origin.DeviceID != "" && !ids.Device.MatchString(origin.DeviceID) {
			return errors.New("an approval request cites content from an unidentifiable device")
		}
		if origin.Kind == "" || len(origin.Kind) > 128 {
			return errors.New("an approval request cites content with no kind")
		}
	}
	// A spend is a purchase, and a purchase the owner cannot see in structured
	// form is one they cannot verify. The terms are required for a spend and are
	// validated whenever they are present, so a stored purchase is always a
	// complete one.
	if request.Effect == "spend" && request.Terms == nil {
		return errors.New("a spend approval must carry the structured purchase it is for")
	}
	if request.Terms != nil {
		if err := request.Terms.Validate(); err != nil {
			return err
		}
	}
	return nil
}

// approvalExpired reports whether a request has run out of time. It uses the
// same window as an undecided inbound event: a decision nobody made in a week
// is not one that is still being made.
func (j *Journal) approvalExpired(approval Approval, seconds uint64) bool {
	age := uint64(j.quota.MaxPendingAge / time.Second)
	return approval.AskedAtUnix != 0 && seconds >= approval.AskedAtUnix+age
}

func (j *Journal) countPendingApprovals(seconds uint64) (int, error) {
	entries, err := os.ReadDir(j.approvalRoot())
	if err != nil {
		return 0, errors.New("read approval directory")
	}
	waiting := 0
	for _, entry := range entries {
		if entry.IsDir() || filepath.Ext(entry.Name()) != ".json" {
			continue
		}
		approval, found, err := j.readApproval("act_" + entry.Name()[:len(entry.Name())-len(".json")])
		if err != nil || !found || approval.State != ApprovalPending {
			continue
		}
		if j.approvalExpired(approval, seconds) {
			continue
		}
		waiting++
	}
	return waiting, nil
}

// ExpirePendingApprovals refuses decisions nobody made in time.
//
// They are recorded as denied rather than deleted, for the same reason an
// expired inbound event is: an owner returning to an empty queue should be
// able to see that something was asked and never answered.
func (j *Journal) ExpirePendingApprovals(now time.Time) (int, error) {
	if err := j.usable(); err != nil {
		return 0, err
	}
	if now.IsZero() || now.Unix() < 0 {
		return 0, errors.New("invalid expiry time")
	}
	j.mutex.Lock()
	defer j.mutex.Unlock()

	entries, err := os.ReadDir(j.approvalRoot())
	if err != nil {
		return 0, errors.New("read approval directory")
	}
	seconds := uint64(now.Unix())
	expired := 0
	for _, entry := range entries {
		if entry.IsDir() || filepath.Ext(entry.Name()) != ".json" {
			continue
		}
		actionID := "act_" + entry.Name()[:len(entry.Name())-len(".json")]
		approval, found, err := j.readApproval(actionID)
		if err != nil || !found || approval.State != ApprovalPending {
			continue
		}
		if !j.approvalExpired(approval, seconds) {
			continue
		}
		approval.State = ApprovalDenied
		approval.DecidedAtUnix = seconds
		approval.DenialReason = "nobody decided within the window this installation keeps requests for"
		if _, err := j.commitApproval(approval); err != nil {
			return expired, err
		}
		expired++
	}
	return expired, nil
}

// RecordAutoAuthorization records a policy decision the way an owner decision
// is recorded: durably, and spendable once.
//
// It exists for actions the policy allows without a person -- today, a spend
// inside the owner's mandate. Returning a bare "yes" for those would make the
// one automatic case weaker than the human one: an approval an owner grants is
// consumed by the action it authorises, and a policy's grant has to be too, or
// a runtime could execute the same authorised spend as many times as it asked.
// The identifier commits the terms, so a second occurrence of the same
// purchase is a replay by definition and finds its grant already spent.
func (j *Journal) RecordAutoAuthorization(request ApprovalRequest) (Approval, error) {
	if err := j.usable(); err != nil {
		return Approval{}, err
	}
	if err := validateApprovalRequest(request); err != nil {
		return Approval{}, err
	}
	j.mutex.Lock()
	defer j.mutex.Unlock()

	existing, found, err := j.readApproval(request.ActionID)
	if err != nil {
		return Approval{}, err
	}
	if found {
		// Already recorded -- possibly already spent. Asking again does not
		// mint a second execution.
		return existing, nil
	}
	approval := Approval{
		Schema: ApprovalSchema, ActionID: request.ActionID, Effect: request.Effect,
		Summary: request.Summary, Reason: request.Reason, Origins: request.Origins,
		Terms: request.Terms, State: ApprovalGranted, AskedAtUnix: request.AskedAt, DecidedAtUnix: request.AskedAt,
	}
	return j.commitApproval(approval)
}
