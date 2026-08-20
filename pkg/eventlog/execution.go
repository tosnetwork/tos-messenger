package eventlog

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"regexp"
	"time"

	"github.com/tosnetwork/tos-messenger/internal/ids"
)

const (
	executionDir     = "executions"
	toolExecutionDir = "tool-executions"

	// ExecutionClaimSchema is the on-disk schema of one economic-execution
	// claim.
	ExecutionClaimSchema     = "tos.messaging.economic-execution-claim.v1"
	ToolExecutionClaimSchema = "tos.messaging.tool-execution-claim.v1"
)

var executionIDPattern = regexp.MustCompile(`^eex_[0-9a-f]{64}$`)
var toolExecutionIDPattern = regexp.MustCompile(`^idem_[0-9a-f]{64}$`)

// ExecutionClaim binds one economic execution to the action that first
// authorised it.
type ExecutionClaim struct {
	Schema        string `json:"schema"`
	ExecutionID   string `json:"execution_id"`
	ActionID      string `json:"action_id"`
	ClaimedAtUnix uint64 `json:"claimed_at_unix"`
}

// ClaimEconomicExecution binds an economic execution to the action that first
// authorised it, once.
//
// The binding is durable and taken before the authorisation it guards is
// recorded, so a crash between the two leaves a claim with no authorisation --
// which the same action recovers by re-claiming and finding itself bound -- and
// never an authorisation a different, re-described action could claim a second
// time. A caller that finds a different action already bound to this execution
// is looking at the same purchase authorised another way, and must not
// authorise it again.
func (j *Journal) ClaimEconomicExecution(executionID, actionID string, now time.Time) (boundActionID string, fresh bool, err error) {
	return j.claimExecution(executionDir, ExecutionClaimSchema, executionID, actionID, now, executionIDPattern)
}

// ClaimToolExecution binds a runtime idempotency key to the first action that
// used it. Rewording the action cannot turn one tool invocation into a fresh
// grant, while the same action can recover an interrupted request.
func (j *Journal) ClaimToolExecution(idempotencyKey, actionID string, now time.Time) (boundActionID string, fresh bool, err error) {
	return j.claimExecution(toolExecutionDir, ToolExecutionClaimSchema, idempotencyKey, actionID, now, toolExecutionIDPattern)
}

func (j *Journal) claimExecution(directory, schema, executionID, actionID string, now time.Time, pattern *regexp.Regexp) (boundActionID string, fresh bool, err error) {
	if err := j.usable(); err != nil {
		return "", false, err
	}
	if !pattern.MatchString(executionID) {
		return "", false, errors.New("invalid execution identifier")
	}
	if !ids.Action.MatchString(actionID) {
		return "", false, errors.New("invalid action identifier")
	}
	if now.IsZero() || now.Unix() < 0 {
		return "", false, errors.New("invalid time")
	}
	j.mutex.Lock()
	defer j.mutex.Unlock()

	existing, found, err := j.readExecutionClaim(directory, schema, executionID)
	if err != nil {
		return "", false, err
	}
	if found {
		return existing.ActionID, false, nil
	}
	claim := ExecutionClaim{
		Schema: schema, ExecutionID: executionID,
		ActionID: actionID, ClaimedAtUnix: uint64(now.Unix()),
	}
	encoded, err := json.Marshal(claim)
	if err != nil {
		return "", false, err
	}
	if err := j.replace(j.executionPath(directory, executionID), encoded); err != nil {
		return "", false, err
	}
	return actionID, true, nil
}

// LookupEconomicExecution returns the action an economic execution is bound to.
func (j *Journal) LookupEconomicExecution(executionID string) (ExecutionClaim, bool, error) {
	if err := j.usable(); err != nil {
		return ExecutionClaim{}, false, err
	}
	if !executionIDPattern.MatchString(executionID) {
		return ExecutionClaim{}, false, errors.New("invalid economic execution identifier")
	}
	j.mutex.Lock()
	defer j.mutex.Unlock()
	return j.readExecutionClaim(executionDir, ExecutionClaimSchema, executionID)
}

// LookupToolExecution returns the action bound to one tool idempotency key.
func (j *Journal) LookupToolExecution(idempotencyKey string) (ExecutionClaim, bool, error) {
	if err := j.usable(); err != nil {
		return ExecutionClaim{}, false, err
	}
	if !toolExecutionIDPattern.MatchString(idempotencyKey) {
		return ExecutionClaim{}, false, errors.New("invalid tool execution identifier")
	}
	j.mutex.Lock()
	defer j.mutex.Unlock()
	return j.readExecutionClaim(toolExecutionDir, ToolExecutionClaimSchema, idempotencyKey)
}

func (j *Journal) readExecutionClaim(directory, schema, executionID string) (ExecutionClaim, bool, error) {
	raw, err := os.ReadFile(j.executionPath(directory, executionID))
	if errors.Is(err, os.ErrNotExist) {
		return ExecutionClaim{}, false, nil
	}
	if err != nil {
		return ExecutionClaim{}, false, errors.New("read execution claim")
	}
	if len(raw) > MaxRecordBytes {
		return ExecutionClaim{}, false, errors.New("execution claim exceeds its bound")
	}
	var claim ExecutionClaim
	if err := json.Unmarshal(raw, &claim); err != nil {
		return ExecutionClaim{}, false, errors.New("invalid execution claim")
	}
	if claim.Schema != schema || claim.ExecutionID != executionID {
		return ExecutionClaim{}, false, errors.New("execution claim describes another execution")
	}
	return claim, true, nil
}

func (j *Journal) executionPath(directory, executionID string) string {
	offset := len("eex_")
	if directory == toolExecutionDir {
		offset = len("idem_")
	}
	return filepath.Join(j.root, directory, executionID[offset:]+".json")
}
