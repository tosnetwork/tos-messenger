package eventlog

// MLSController is the crash-consistency boundary between an RFC 9420 Driver
// and MLSLedger. Driver output is never returned to the caller until its next
// opaque state is durable. Callers may therefore publish a returned Commit,
// Welcome, ciphertext, or plaintext without risking state reuse after restart.

import (
	"bytes"
	"errors"
	"time"

	"github.com/tosnetwork/tos-messenger/internal/canon"
	"github.com/tosnetwork/tos-messenger/pkg/group"
)

type MLSController struct {
	ledger  *MLSLedger
	driver  group.Driver
	inspect group.StateInspector
	now     func() time.Time
}

func NewMLSController(ledger *MLSLedger, driver group.Driver, now func() time.Time) (*MLSController, error) {
	inspector, ok := driver.(group.StateInspector)
	if ledger == nil || driver == nil || !ok || driver.CipherSuite() != group.MLSCipherSuite {
		return nil, errors.New("invalid MLS controller dependencies")
	}
	if now == nil {
		now = time.Now
	}
	return &MLSController{ledger: ledger, driver: driver, inspect: inspector, now: now}, nil
}

func (c *MLSController) Join(binding group.State, expectedGroupID, identityState, welcome []byte, keyPackageRef string) error {
	state, err := c.driver.Join(identityState, welcome)
	if err != nil {
		return err
	}
	if err := c.checkState(state, expectedGroupID, binding.Clock.MLSEpoch); err != nil {
		return err
	}
	return c.ledger.InstallWelcome(binding, state, keyPackageRef, canon.Digest(welcome), c.now())
}

func (c *MLSController) CreateFounder(binding group.State, identityState, ownKeyPackage, groupID []byte, keyPackageRef string) error {
	provisioner, ok := c.driver.(group.ProvisioningDriver)
	if !ok {
		return errors.New("MLS driver cannot provision groups")
	}
	state, err := provisioner.CreateGroup(identityState, ownKeyPackage, groupID)
	if err != nil {
		return err
	}
	if err := c.checkState(state, groupID, binding.Clock.MLSEpoch); err != nil {
		return err
	}
	return c.ledger.InstallFounder(binding, state, keyPackageRef, c.now())
}

// Commit accepts a transition template with both commit-reference fields empty.
// The reference cannot be predicted before OpenMLS creates the randomized
// commit; the controller derives it from the exact wire bytes, validates the
// completed transition, and returns that durable transition to the caller.
func (c *MLSController) Commit(transition group.Transition, operations []group.LeafOperation) (group.Transition, []byte, map[string][]byte, error) {
	if transition.CommitRef != "" || transition.Next.AcceptedCommitRef != "" {
		return group.Transition{}, nil, nil, errors.New("MLS commit template already has a reference")
	}
	record, state, err := c.current(transition.Prior.RoomID)
	if err != nil {
		return group.Transition{}, nil, nil, err
	}
	if !sameGroupState(record.Binding(), transition.Prior) {
		return group.Transition{}, nil, nil, ErrMLSFork
	}
	nextState, commit, welcomes, err := c.driver.Commit(state, operations)
	if err != nil {
		return group.Transition{}, nil, nil, err
	}
	transition.CommitRef = canon.Digest(commit)
	transition.Next.AcceptedCommitRef = transition.CommitRef
	priorInfo, err := c.inspect.Inspect(state)
	if err != nil {
		return group.Transition{}, nil, nil, err
	}
	if err := c.checkState(nextState, priorInfo.GroupID, transition.Next.Clock.MLSEpoch); err != nil {
		return group.Transition{}, nil, nil, err
	}
	if err := group.ValidateTransition(transition); err != nil {
		return group.Transition{}, nil, nil, err
	}
	if _, err := c.ledger.AdvanceFrom(transition, record.StateDigest, nextState, c.now()); err != nil {
		return group.Transition{}, nil, nil, err
	}
	return transition, commit, welcomes, nil
}

func (c *MLSController) Apply(transition group.Transition, commit []byte) error {
	if err := group.ValidateTransition(transition); err != nil {
		return err
	}
	if canon.Digest(commit) != transition.CommitRef {
		return errors.New("MLS commit reference mismatch")
	}
	record, state, err := c.current(transition.Prior.RoomID)
	if err != nil {
		return err
	}
	if !sameGroupState(record.Binding(), transition.Prior) {
		return ErrMLSFork
	}
	next, err := c.driver.Apply(state, commit)
	if err != nil {
		return err
	}
	priorInfo, err := c.inspect.Inspect(state)
	if err != nil {
		return err
	}
	if err := c.checkState(next, priorInfo.GroupID, transition.Next.Clock.MLSEpoch); err != nil {
		return err
	}
	_, err = c.ledger.AdvanceFrom(transition, record.StateDigest, next, c.now())
	return err
}

func (c *MLSController) Seal(roomID string, aad, plaintext []byte) ([]byte, error) {
	record, state, err := c.current(roomID)
	if err != nil {
		return nil, err
	}
	next, message, err := c.driver.Seal(state, aad, plaintext)
	if err != nil {
		return nil, err
	}
	priorInfo, err := c.inspect.Inspect(state)
	if err != nil {
		return nil, err
	}
	if err := c.checkState(next, priorInfo.GroupID, record.MLSEpoch); err != nil {
		return nil, err
	}
	changed, err := c.ledger.Ratchet(roomID, record.StateDigest, next, c.now())
	if err != nil {
		return nil, err
	}
	if !changed {
		return nil, errors.New("MLS send did not advance private state")
	}
	return message, nil
}

func (c *MLSController) Open(roomID string, aad, message []byte) ([]byte, error) {
	record, state, err := c.current(roomID)
	if err != nil {
		return nil, err
	}
	next, plaintext, err := c.driver.Open(state, aad, message)
	if err != nil {
		return nil, err
	}
	priorInfo, err := c.inspect.Inspect(state)
	if err != nil {
		return nil, err
	}
	if err := c.checkState(next, priorInfo.GroupID, record.MLSEpoch); err != nil {
		return nil, err
	}
	changed, err := c.ledger.Ratchet(roomID, record.StateDigest, next, c.now())
	if err != nil {
		return nil, err
	}
	if !changed {
		return nil, errors.New("MLS receive did not advance private state")
	}
	return plaintext, nil
}

func (c *MLSController) checkState(state, expectedGroupID []byte, expectedEpoch uint64) error {
	if len(expectedGroupID) == 0 {
		return errors.New("missing expected MLS group id")
	}
	info, err := c.inspect.Inspect(state)
	if err != nil {
		return err
	}
	if !bytes.Equal(info.GroupID, expectedGroupID) || info.Epoch != expectedEpoch {
		return errors.New("MLS state does not match room binding")
	}
	return nil
}

func (c *MLSController) current(roomID string) (MLSRecord, []byte, error) {
	record, found, err := c.ledger.Current(roomID)
	if err != nil {
		return MLSRecord{}, nil, err
	}
	if !found {
		return MLSRecord{}, nil, errors.New("MLS room has no installed state")
	}
	state, err := record.State()
	return record, state, err
}
