// Package ownercontrol provides the transport-neutral, deduplicated command
// sink for Trusted Capability and Owner Control V1. Authentication and policy
// resolution are injected; Messenger never treats device authentication alone
// as business authorization.
package ownercontrol

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"sort"
	"strings"

	commerce "github.com/tosnetwork/tos-service-protocol/pkg/agentcommerce"
	trusted "github.com/tosnetwork/tos-service-protocol/pkg/trustedcapability"
)

type Authorizer interface {
	VerifyOwnerCommand(context.Context, AuthenticatedPrincipal, trusted.OwnerCommandEffectV1, trusted.OwnerCommandAuthorizationAttemptV1, SubmissionEvidence) error
	VerifyOwnerCommandQuery(context.Context, AuthenticatedPrincipal, []byte, []byte) error
}
type RecoveryAuthorizer interface {
	VerifyOwnerCommandRecovery(context.Context, AuthenticatedPrincipal, trusted.OwnerCommandEffectV1, trusted.OwnerCommandAuthorizationAttemptV1, SubmissionEvidence) error
}
type EffectSink interface {
	ApplyOwnerCommand(context.Context, AuthenticatedPrincipal, trusted.OwnerCommandEffectV1, trusted.OwnerCommandAuthorizationAttemptV1, SubmissionEvidence, []byte) (resultRevision uint64, evidence []trusted.ImmutableObjectReferenceV1, err error)
	ReconcileOwnerCommand(context.Context, AuthenticatedPrincipal, trusted.OwnerCommandEffectV1, trusted.OwnerCommandAuthorizationAttemptV1, SubmissionEvidence, []byte) (state string, resultRevision uint64, evidence []trusted.ImmutableObjectReferenceV1, err error)
}

type SubmissionEvidence struct {
	Parameters                []byte                                 `json:"parameters"`
	SemanticConfirmation      trusted.SemanticConfirmationV1         `json:"semantic_confirmation"`
	CommandLeaseObject        trusted.ProfileObjectV1                `json:"command_lease_object"`
	CommandLeaseAuthorization trusted.ProfileAuthorizationEnvelopeV1 `json:"command_lease_authorization"`
	AllowedCommandKinds       []string                               `json:"allowed_command_kinds"`
}

type AuthenticatedPrincipal struct {
	DomainKind           uint8
	DomainID             []byte
	OwnerID              []byte
	Audience             string
	SessionDigest        []byte
	ChannelBindingDigest []byte
	MayReadEvidence      bool
}

type SinkAuthorityResolver interface {
	CurrentOwnerCommandSink(context.Context) (authorityID []byte, clusterEpoch uint64, err error)
}

type Record struct {
	Principal            AuthenticatedPrincipal
	Effect               trusted.OwnerCommandEffectV1
	Attempt              trusted.OwnerCommandAuthorizationAttemptV1
	Evidence             SubmissionEvidence
	AuthorizationHistory []AuthorizationRecord
	FencingToken         []byte
	Resolution           trusted.OwnerCommandResolutionV1
}

type AuthorizationRecord struct {
	Principal     AuthenticatedPrincipal
	Attempt       trusted.OwnerCommandAuthorizationAttemptV1
	Evidence      SubmissionEvidence
	AttemptDigest []byte
}

type TrustedTimeObservation struct {
	UnixSeconds    uint64
	Epoch          uint64
	EvidenceDigest []byte
}

type TrustedTimeSource interface {
	ObserveTrustedTime(context.Context) (TrustedTimeObservation, error)
}

// CommandJournal is a durable, linearizable sink journal shared by every
// replica in a resolution namespace. Begin must atomically return the prior
// record or persist prepared before reporting inserted=true. Implementations
// must not acknowledge before durable quorum/fsync according to deployment.
type CommandJournal interface {
	Begin(context.Context, []byte, []byte, Record, TrustedTimeObservation) (prior Record, fencingToken []byte, inserted bool, err error)
	AttachAuthorization(context.Context, []byte, []byte, Record, TrustedTimeObservation) error
	Transition(context.Context, []byte, []byte, string, Record, TrustedTimeObservation) error
	Get(context.Context, []byte, []byte) (Record, bool, error)
	MultiHostSafe() bool
}
type Service struct {
	authorizer    Authorizer
	sink          EffectSink
	sinkID        []byte
	clock         TrustedTimeSource
	journal       CommandJournal
	sinkAuthority SinkAuthorityResolver
	multiHost     bool
}

func New(authorizer Authorizer, sink EffectSink, journal CommandJournal, sinkAuthority SinkAuthorityResolver, sinkID []byte, multiHost bool, clock TrustedTimeSource) (*Service, error) {
	if authorizer == nil || sink == nil || journal == nil || sinkAuthority == nil || len(sinkID) == 0 || clock == nil || multiHost && !journal.MultiHostSafe() {
		return nil, errors.New("owner command service is incomplete")
	}
	return &Service{authorizer: authorizer, sink: sink, sinkID: append([]byte(nil), sinkID...), clock: clock, journal: journal, sinkAuthority: sinkAuthority, multiHost: multiHost}, nil
}

func (service *Service) Submit(ctx context.Context, principal AuthenticatedPrincipal, effect trusted.OwnerCommandEffectV1, attempt trusted.OwnerCommandAuthorizationAttemptV1, evidence SubmissionEvidence) (trusted.OwnerCommandResolutionV1, error) {
	if service == nil || ctx == nil {
		return trusted.OwnerCommandResolutionV1{}, errors.New("owner command service unavailable")
	}
	timeObservation, err := service.clock.ObserveTrustedTime(ctx)
	if err != nil || timeObservation.UnixSeconds == 0 || timeObservation.Epoch == 0 || len(timeObservation.EvidenceDigest) != 32 {
		return trusted.OwnerCommandResolutionV1{}, errors.New("trusted owner-command time is unavailable")
	}
	now := timeObservation.UnixSeconds
	if err := trusted.ValidateOwnerCommandEffect(effect); err != nil {
		return trusted.OwnerCommandResolutionV1{}, err
	}
	effectObject, err := trusted.NewObject(trusted.DomainKind(effect.DomainKind), effect.DomainID, "owner-command-effect", effect)
	if err != nil {
		return trusted.OwnerCommandResolutionV1{}, err
	}
	effectBytes, err := trusted.EncodeObject(effectObject)
	if err != nil {
		return trusted.OwnerCommandResolutionV1{}, err
	}
	sum, err := trusted.ObjectDigest(effectObject)
	if err != nil {
		return trusted.OwnerCommandResolutionV1{}, err
	}
	parameterDigest := sha256.Sum256(evidence.Parameters)
	leaseDigest, leaseErr := trusted.ObjectDigest(evidence.CommandLeaseObject)
	classesDigest, classesErr := OwnerCommandClassSetDigest(evidence.AllowedCommandKinds)
	if leaseErr != nil || classesErr != nil || !bytes.Equal(parameterDigest[:], effect.ExactParameterDigest) || !bytes.Equal(leaseDigest, attempt.CommandLeaseDigest) {
		return trusted.OwnerCommandResolutionV1{}, errors.New("owner command evidence is incomplete or does not match its digests")
	}
	if !containsCommandKind(evidence.AllowedCommandKinds, effect.CommandKind) {
		return trusted.OwnerCommandResolutionV1{}, errors.New("owner command class set does not permit the command")
	}
	wantAction, wantRequest, err := DeriveOwnerCommandIdentity(effect, sum, effectBytes, parameterDigest[:], leaseDigest, classesDigest)
	if err != nil {
		return trusted.OwnerCommandResolutionV1{}, err
	}
	predicateDigest, predicateErr := trusted.OwnerCommandAuthorizationPredicateSetDigest(effect)
	confirmationDigest, confirmationErr := trusted.SemanticConfirmationDigest(evidence.SemanticConfirmation)
	if predicateErr != nil || confirmationErr != nil || !bytes.Equal(predicateDigest, effect.AuthorityPredicateSetDigest) ||
		!bytes.Equal(confirmationDigest, effect.SemanticConfirmationDigest) {
		return trusted.OwnerCommandResolutionV1{}, errors.New("owner command confirmation or authorization predicate set is invalid")
	}
	priorRecord, existingExact, journalErr := service.journal.Get(ctx, effect.ResolutionNamespace, wantAction)
	if journalErr != nil {
		return trusted.OwnerCommandResolutionV1{}, journalErr
	}
	if existingExact && (!bytes.Equal(priorRecord.Attempt.ExactRequestDigest, wantRequest) || !bytes.Equal(priorRecord.Resolution.EffectDigest, sum)) {
		return trusted.OwnerCommandResolutionV1{}, errors.New("owner command Action identity conflict")
	}
	confirmationTime := now
	if existingExact && now >= effect.ExpiresAtUnix {
		confirmationTime = effect.CreatedAtUnix
	}
	if trusted.ValidateSemanticConfirmation(evidence.SemanticConfirmation, effect, wantAction, confirmationTime) != nil {
		return trusted.OwnerCommandResolutionV1{}, errors.New("owner command semantic confirmation is invalid")
	}
	if !bytes.Equal(sum, attempt.CommandEffectDigest) || !bytes.Equal(wantAction, attempt.ActionID) || !bytes.Equal(wantRequest, attempt.ExactRequestDigest) ||
		now < effect.CreatedAtUnix || !existingExact && now >= effect.ExpiresAtUnix || now < attempt.AttemptedAtUnix || now >= attempt.ExpiresAtUnix || len(effect.ResolutionNamespace) != 32 {
		return trusted.OwnerCommandResolutionV1{}, errors.New("owner command binding or validity is invalid")
	}
	if principal.DomainKind != effect.DomainKind || !bytes.Equal(principal.DomainID, effect.DomainID) || !bytes.Equal(principal.OwnerID, effect.OwnerID) || principal.Audience == "" ||
		len(principal.ChannelBindingDigest) != sha256.Size || !bytes.Equal(principal.SessionDigest, attempt.DeviceSessionDigest) {
		return trusted.OwnerCommandResolutionV1{}, errors.New("owner command principal scope mismatch")
	}
	if existingExact {
		recoveryAuthorizer, ok := service.authorizer.(RecoveryAuthorizer)
		if !ok {
			return trusted.OwnerCommandResolutionV1{}, errors.New("owner command authorizer does not support authenticated recovery")
		}
		if err := recoveryAuthorizer.VerifyOwnerCommandRecovery(ctx, principal, effect, attempt, evidence); err != nil {
			return trusted.OwnerCommandResolutionV1{}, err
		}
	} else if err := service.authorizer.VerifyOwnerCommand(ctx, principal, effect, attempt, evidence); err != nil {
		return trusted.OwnerCommandResolutionV1{}, err
	}
	currentSink, currentEpoch, err := service.sinkAuthority.CurrentOwnerCommandSink(ctx)
	if err != nil || !bytes.Equal(currentSink, effect.SinkAuthorityID) || !bytes.Equal(currentSink, service.sinkID) ||
		!sinkEpochAdmits(effect.SinkClusterEpoch, currentEpoch, existingExact) {
		return trusted.OwnerCommandResolutionV1{}, errors.New("owner command targets a stale sink authority")
	}
	if existingExact {
		prior := priorRecord
		if bytes.Equal(prior.Attempt.ExactRequestDigest, attempt.ExactRequestDigest) && bytes.Equal(prior.Resolution.EffectDigest, sum) {
			if prior.Resolution.State == "prepared" || prior.Resolution.State == "admitted" || prior.Resolution.State == "submitted" || prior.Resolution.State == "ambiguous" {
				updated, attachErr := service.attachAuthorization(ctx, effect.ResolutionNamespace, prior, principal, attempt, evidence, timeObservation)
				if attachErr != nil {
					return trusted.OwnerCommandResolutionV1{}, attachErr
				}
				return service.recover(ctx, effect.ResolutionNamespace, updated)
			}
			return redactResolution(prior.Resolution, principal.MayReadEvidence), nil
		}
		return trusted.OwnerCommandResolutionV1{}, errors.New("owner command Action identity conflict")
	}
	prepared := trusted.OwnerCommandResolutionV1{State: "prepared", EffectDigest: sum, ActionID: attempt.ActionID, ExactRequestDigest: attempt.ExactRequestDigest, TargetPriorRevision: effect.ExpectedTargetRevision, SinkIdentity: service.sinkID, EffectReferences: []trusted.ImmutableObjectReferenceV1{}, ObservedAtUnix: now}
	initialAuthorization, err := authorizationRecord(principal, attempt, evidence, effect)
	if err != nil {
		return trusted.OwnerCommandResolutionV1{}, err
	}
	preparedRecord := Record{Principal: principal, Effect: effect, Attempt: attempt, Evidence: evidence, AuthorizationHistory: []AuthorizationRecord{initialAuthorization}, Resolution: prepared}
	prior, fencingToken, inserted, err := service.journal.Begin(ctx, effect.ResolutionNamespace, attempt.ActionID, preparedRecord, timeObservation)
	if err != nil {
		return trusted.OwnerCommandResolutionV1{}, err
	}
	if !inserted {
		if bytes.Equal(prior.Attempt.ExactRequestDigest, attempt.ExactRequestDigest) && bytes.Equal(prior.Resolution.EffectDigest, sum) {
			return redactResolution(prior.Resolution, principal.MayReadEvidence), nil
		}
		return trusted.OwnerCommandResolutionV1{}, errors.New("owner command concurrent Action identity conflict")
	}
	currentSink, currentEpoch, err = service.sinkAuthority.CurrentOwnerCommandSink(ctx)
	if err != nil || !bytes.Equal(currentSink, effect.SinkAuthorityID) || currentEpoch != effect.SinkClusterEpoch {
		fenceErr := errors.New("owner command sink fence was lost before apply")
		resolution, terminalErr := service.storeTerminal(ctx, effect, attempt, evidence, sum, "prepared", "rejected", 0, nil, "ERR_NOT_SUBMITTED")
		return resolution, errors.Join(fenceErr, terminalErr)
	}
	admitted := prepared
	admitted.State = "admitted"
	admitted.ObservedAtUnix = timeObservation.UnixSeconds
	if err := service.journal.Transition(ctx, effect.ResolutionNamespace, attempt.ActionID, "prepared",
		Record{Principal: principal, Effect: effect, Attempt: attempt, Evidence: evidence, AuthorizationHistory: preparedRecord.AuthorizationHistory, Resolution: admitted}, timeObservation); err != nil {
		return trusted.OwnerCommandResolutionV1{}, err
	}
	revision, effectReferences, applyErr := service.sink.ApplyOwnerCommand(ctx, principal, effect, attempt, evidence, fencingToken)
	if applyErr != nil {
		result, storeErr := service.storeTerminal(ctx, effect, attempt, evidence, sum, "admitted", "ambiguous", 0, nil, "ERR_AMBIGUOUS")
		if storeErr != nil {
			return trusted.OwnerCommandResolutionV1{}, errors.Join(applyErr, storeErr)
		}
		return result, applyErr
	}
	return service.storeTerminal(ctx, effect, attempt, evidence, sum, "admitted", "applied", revision, effectReferences, "")
}

func (service *Service) Resolve(ctx context.Context, principal AuthenticatedPrincipal, namespace, actionID []byte) (trusted.OwnerCommandResolutionV1, error) {
	if err := service.authorizer.VerifyOwnerCommandQuery(ctx, principal, namespace, actionID); err != nil {
		return trusted.OwnerCommandResolutionV1{}, err
	}
	value, ok, err := service.journal.Get(ctx, namespace, actionID)
	if err != nil {
		return trusted.OwnerCommandResolutionV1{}, err
	}
	if !ok {
		return trusted.OwnerCommandResolutionV1{State: "unknown"}, nil
	}
	return redactResolution(value.Resolution, principal.MayReadEvidence), nil
}

func (service *Service) storeTerminal(ctx context.Context, effect trusted.OwnerCommandEffectV1, attempt trusted.OwnerCommandAuthorizationAttemptV1, submission SubmissionEvidence, digest []byte, expectedState, state string, revision uint64, evidence []trusted.ImmutableObjectReferenceV1, code string) (trusted.OwnerCommandResolutionV1, error) {
	timeObservation, err := service.clock.ObserveTrustedTime(ctx)
	if err != nil || timeObservation.UnixSeconds == 0 || timeObservation.Epoch == 0 || len(timeObservation.EvidenceDigest) != 32 {
		return trusted.OwnerCommandResolutionV1{}, errors.New("trusted owner-command time is unavailable during resolution")
	}
	now := timeObservation.UnixSeconds
	attemptObject, _ := trusted.NewObject(trusted.DomainKind(effect.DomainKind), effect.DomainID, "owner-command-attempt", attempt)
	attemptDigest, _ := trusted.ObjectDigest(attemptObject)
	var resultRevision *uint64
	if revision > 0 {
		resultRevision = &revision
	}
	var errorCode *string
	if code != "" {
		errorCode = &code
	}
	resolution := trusted.OwnerCommandResolutionV1{State: state, EffectDigest: digest, AcceptedAttemptDigest: &attemptDigest, ActionID: attempt.ActionID, ExactRequestDigest: attempt.ExactRequestDigest, TargetPriorRevision: effect.ExpectedTargetRevision, TargetResultRevision: resultRevision, SinkIdentity: service.sinkID, EffectReferences: evidence, ErrorCode: errorCode, ObservedAtUnix: now}
	prior, ok, getErr := service.journal.Get(ctx, effect.ResolutionNamespace, attempt.ActionID)
	if getErr != nil || !ok {
		return trusted.OwnerCommandResolutionV1{}, errors.Join(errors.New("owner command principal journal is unavailable"), getErr)
	}
	if err := service.journal.Transition(ctx, effect.ResolutionNamespace, attempt.ActionID, expectedState, Record{Principal: prior.Principal, Effect: effect, Attempt: attempt, Evidence: submission, AuthorizationHistory: prior.AuthorizationHistory, Resolution: resolution}, timeObservation); err != nil {
		return trusted.OwnerCommandResolutionV1{}, err
	}
	return resolution, nil
}

func (service *Service) recover(ctx context.Context, namespace []byte, prior Record) (trusted.OwnerCommandResolutionV1, error) {
	currentSink, epoch, err := service.sinkAuthority.CurrentOwnerCommandSink(ctx)
	if err != nil || !bytes.Equal(currentSink, prior.Effect.SinkAuthorityID) || !bytes.Equal(currentSink, service.sinkID) ||
		!sinkEpochAdmits(prior.Effect.SinkClusterEpoch, epoch, true) {
		return trusted.OwnerCommandResolutionV1{}, errors.New("cannot reconcile under stale sink fence")
	}
	timeObservation, timeErr := service.clock.ObserveTrustedTime(ctx)
	if timeErr != nil {
		return trusted.OwnerCommandResolutionV1{}, timeErr
	}
	_, token, _, err := service.journal.Begin(ctx, namespace, prior.Attempt.ActionID, prior, timeObservation)
	if err != nil {
		return trusted.OwnerCommandResolutionV1{}, err
	}
	if len(prior.Principal.ChannelBindingDigest) != sha256.Size {
		return prior.Resolution, errors.New("cannot reconcile without the transport-authenticated channel binding")
	}
	// A prepared record is durably known to precede the admitted transition and
	// therefore cannot have reached ApplyOwnerCommand. Close it without asking a
	// sink to infer execution from an operation it never received.
	if prior.Resolution.State == "prepared" {
		return service.storeTerminal(ctx, prior.Effect, prior.Attempt, prior.Evidence, prior.Resolution.EffectDigest, "prepared", "rejected", 0, nil, "ERR_NOT_SUBMITTED")
	}
	state, revision, evidence, reconcileErr := service.sink.ReconcileOwnerCommand(ctx, prior.Principal, prior.Effect, prior.Attempt, prior.Evidence, token)
	if reconcileErr != nil || state != "applied" && state != "rejected" && state != "conflict" {
		return prior.Resolution, errors.Join(errors.New("owner command remains ambiguous"), reconcileErr)
	}
	return service.storeTerminal(ctx, prior.Effect, prior.Attempt, prior.Evidence, prior.Resolution.EffectDigest, prior.Resolution.State, state, revision, evidence, "")
}

// A new semantic command is admitted only at the exact epoch frozen in its
// effect. Recovery is different: the same stable sink identity may move to a
// strictly newer epoch after failover, while the shared journal's fencing token
// prevents the superseded replica from reconciling the retained Action.
func sinkEpochAdmits(effectEpoch, currentEpoch uint64, recovery bool) bool {
	if recovery {
		return currentEpoch >= effectEpoch
	}
	return currentEpoch == effectEpoch
}

func (service *Service) attachAuthorization(ctx context.Context, namespace []byte, prior Record, principal AuthenticatedPrincipal, attempt trusted.OwnerCommandAuthorizationAttemptV1, evidence SubmissionEvidence, observed TrustedTimeObservation) (Record, error) {
	record, err := authorizationRecord(principal, attempt, evidence, prior.Effect)
	if err != nil {
		return Record{}, err
	}
	for _, existing := range prior.AuthorizationHistory {
		if bytes.Equal(existing.AttemptDigest, record.AttemptDigest) {
			return prior, nil
		}
	}
	prior.Principal, prior.Attempt, prior.Evidence = principal, attempt, evidence
	prior.AuthorizationHistory = append(prior.AuthorizationHistory, record)
	if err := service.journal.AttachAuthorization(ctx, namespace, attempt.ActionID, prior, observed); err != nil {
		return Record{}, err
	}
	return prior, nil
}

func authorizationRecord(principal AuthenticatedPrincipal, attempt trusted.OwnerCommandAuthorizationAttemptV1, evidence SubmissionEvidence, effect trusted.OwnerCommandEffectV1) (AuthorizationRecord, error) {
	object, err := trusted.NewObject(trusted.DomainKind(effect.DomainKind), effect.DomainID, "owner-command-attempt", attempt)
	if err != nil {
		return AuthorizationRecord{}, err
	}
	digest, err := trusted.ObjectDigest(object)
	if err != nil {
		return AuthorizationRecord{}, err
	}
	return AuthorizationRecord{Principal: principal, Attempt: attempt, Evidence: evidence, AttemptDigest: digest}, nil
}

func redactResolution(value trusted.OwnerCommandResolutionV1, evidence bool) trusted.OwnerCommandResolutionV1 {
	if !evidence {
		value.EffectReferences = []trusted.ImmutableObjectReferenceV1{}
		value.AuthorityEvidenceDigest = nil
	}
	return value
}

// DeriveOwnerCommandIdentity is shared by clients and the sink, but the sink
// always recomputes it. It prevents a retry or takeover from choosing a fresh
// semantic identity for the same command effect.
func DeriveOwnerCommandIdentity(effect trusted.OwnerCommandEffectV1, _ []byte, effectBytes, parameterDigest, _, _ []byte) ([]byte, []byte, error) {
	agentID := "owner-scope"
	if effect.AgentID != nil {
		agentID = hex.EncodeToString(*effect.AgentID)
	}
	action, _, err := commerce.DeriveStableActionID("owner.command.submit", map[string]commerce.SemanticValue{
		"owner_id": commerce.ID(hex.EncodeToString(effect.OwnerID)), "agent_id": commerce.ID(agentID),
		"resolution_namespace": commerce.Digest32("sha256:" + hex.EncodeToString(effect.ResolutionNamespace)),
		"command_kind":         commerce.Kind(effect.CommandKind), "target_object_kind": commerce.Kind(effect.TargetObjectKind),
		"target_object_id":         commerce.ID(hex.EncodeToString(effect.TargetObjectID)),
		"exact_parameter_digest":   commerce.Digest32("sha256:" + hex.EncodeToString(effect.ExactParameterDigest)),
		"governing_policy_digest":  commerce.Digest32("sha256:" + hex.EncodeToString(effect.PolicyDigest)),
		"expected_target_revision": commerce.U64(effect.ExpectedTargetRevision),
		"command_instance_id":      commerce.ID(hex.EncodeToString(effect.CommandInstanceID)),
	})
	if err != nil {
		return nil, nil, err
	}
	exactRequest, err := trusted.MarshalBody(struct {
		EffectBytes     []byte `cbor:"1,keyasint"`
		ParameterDigest []byte `cbor:"2,keyasint"`
	}{effectBytes, parameterDigest})
	if err != nil {
		return nil, nil, err
	}
	request, err := commerce.ExactRequestDigest(exactRequest)
	if err != nil {
		return nil, nil, err
	}
	return parseDigest(action), parseDigest(request), nil
}

func OwnerCommandClassSetDigest(kinds []string) ([]byte, error) {
	if len(kinds) == 0 || len(kinds) > len(trusted.OwnerCommandKindsV1) {
		return nil, errors.New("owner command class set is empty or oversized")
	}
	copyKinds := append([]string(nil), kinds...)
	sort.Strings(copyKinds)
	for i, kind := range copyKinds {
		if i > 0 && kind == copyKinds[i-1] {
			return nil, errors.New("duplicate owner command class")
		}
		index := sort.SearchStrings(trusted.OwnerCommandKindsV1, kind)
		if index == len(trusted.OwnerCommandKindsV1) || trusted.OwnerCommandKindsV1[index] != kind {
			return nil, errors.New("unknown owner command class")
		}
	}
	wire, err := trusted.MarshalBody(copyKinds)
	if err != nil {
		return nil, err
	}
	sum := sha256.Sum256(append([]byte("tos.owner-command-class-set.v1\x00"), wire...))
	return sum[:], nil
}

func containsCommandKind(kinds []string, wanted string) bool {
	for _, kind := range kinds {
		if kind == wanted {
			return true
		}
	}
	return false
}

func parseDigest(value string) []byte {
	raw, _ := hex.DecodeString(strings.TrimPrefix(value, "sha256:"))
	return raw
}
