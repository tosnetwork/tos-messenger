package ownercontrol

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"testing"

	trusted "github.com/tosnetwork/tos-service-protocol/pkg/trustedcapability"
)

type auth struct{}

func (auth) VerifyOwnerCommand(context.Context, AuthenticatedPrincipal, trusted.OwnerCommandEffectV1, trusted.OwnerCommandAuthorizationAttemptV1, SubmissionEvidence) error {
	return nil
}
func (auth) VerifyOwnerCommandRecovery(context.Context, AuthenticatedPrincipal, trusted.OwnerCommandEffectV1, trusted.OwnerCommandAuthorizationAttemptV1, SubmissionEvidence) error {
	return nil
}

type crashAfterApplySink struct {
	token   []byte
	applied bool
}

type mutableSinkAuthority struct{ epoch uint64 }

func (authority *mutableSinkAuthority) CurrentOwnerCommandSink(context.Context) ([]byte, uint64, error) {
	return []byte("sink"), authority.epoch, nil
}

func (s *crashAfterApplySink) ApplyOwnerCommand(_ context.Context, _ AuthenticatedPrincipal, _ trusted.OwnerCommandEffectV1, _ trusted.OwnerCommandAuthorizationAttemptV1, _ SubmissionEvidence, token []byte) (uint64, []trusted.ImmutableObjectReferenceV1, error) {
	s.token, s.applied = append([]byte(nil), token...), true
	return 0, nil, errors.New("injected crash after apply")
}
func (s *crashAfterApplySink) ReconcileOwnerCommand(_ context.Context, _ AuthenticatedPrincipal, _ trusted.OwnerCommandEffectV1, _ trusted.OwnerCommandAuthorizationAttemptV1, _ SubmissionEvidence, token []byte) (string, uint64, []trusted.ImmutableObjectReferenceV1, error) {
	if !s.applied || !bytes.Equal(token, s.token) {
		return "conflict", 0, nil, errors.New("fencing token changed")
	}
	return "applied", 2, nil, nil
}

func TestCrashAfterApplyRecoversWithOriginalFencingToken(t *testing.T) {
	authority := &memoryJournalAuthority{installation: bytes.Repeat([]byte{7}, 32)}
	root := t.TempDir()
	journal, err := OpenFileJournal(root, authority)
	if err != nil {
		t.Fatal(err)
	}
	target := &crashAfterApplySink{}
	sinkFence := &mutableSinkAuthority{epoch: 1}
	service, err := New(auth{}, target, journal, sinkFence, []byte("sink"), false, trustedClock{100})
	if err != nil {
		t.Fatal(err)
	}
	agent := []byte("agent")
	effect := trusted.OwnerCommandEffectV1{SchemaVersion: 1, DomainKind: 2, DomainID: []byte("domain"), OwnerID: []byte("owner"), AgentID: &agent, CommandKind: "owner.pause",
		CommandInstanceID: bytes.Repeat([]byte{1}, 16), TargetObjectKind: "agent", TargetObjectID: agent, SinkAuthorityID: []byte("sink"), SinkClusterEpoch: 1,
		ResolutionNamespace: bytes.Repeat([]byte{1}, 32), ControlScopeGeneration: 1, ExpectedTargetRevision: 1, PolicyRevision: 1, PolicyDigest: bytes.Repeat([]byte{3}, 32),
		SemanticConfirmationDigest: bytes.Repeat([]byte{4}, 32), AuthorityPredicateSetDigest: bytes.Repeat([]byte{5}, 32), CreatedAtUnix: 90, ExpiresAtUnix: 200}
	effect, evidence, digest, action, request, leaseDigest := finalizeTestCommand(t, effect)
	attempt := testAuthorizationAttempt(digest, action, request, leaseDigest)
	principal := AuthenticatedPrincipal{DomainKind: 2, DomainID: effect.DomainID, OwnerID: effect.OwnerID, Audience: "test", SessionDigest: attempt.DeviceSessionDigest, ChannelBindingDigest: bytes.Repeat([]byte{8}, sha256.Size)}
	if _, err := service.Submit(context.Background(), principal, effect, attempt, evidence); err == nil {
		t.Fatal("crash injection was not observed")
	}
	if err := journal.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := OpenFileJournal(root, authority)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	// Legitimate failover advances the epoch but retains the stable sink
	// identity and shared journal fencing domain.
	sinkFence.epoch = 2
	restarted, _ := New(auth{}, target, reopened, sinkFence, []byte("sink"), false, trustedClock{101})
	resolution, err := restarted.Submit(context.Background(), principal, effect, attempt, evidence)
	if err != nil || resolution.State != "applied" {
		t.Fatalf("resolution=%+v err=%v", resolution, err)
	}
}

func TestReplacementDeviceAttachesFreshAuthorizationWithoutChangingAction(t *testing.T) {
	authority := &memoryJournalAuthority{installation: bytes.Repeat([]byte{17}, 32)}
	journal, err := OpenFileJournal(t.TempDir(), authority)
	if err != nil {
		t.Fatal(err)
	}
	defer journal.Close()
	target := &crashAfterApplySink{}
	service, err := New(auth{}, target, journal, sinkAuthority{}, []byte("sink"), false, trustedClock{100})
	if err != nil {
		t.Fatal(err)
	}
	agent := []byte("agent")
	effect := trusted.OwnerCommandEffectV1{SchemaVersion: 1, DomainKind: 2, DomainID: []byte("domain"), OwnerID: []byte("owner"), AgentID: &agent, CommandKind: "owner.pause",
		CommandInstanceID: bytes.Repeat([]byte{7}, 16), TargetObjectKind: "agent", TargetObjectID: agent, SinkAuthorityID: []byte("sink"), SinkClusterEpoch: 1,
		ResolutionNamespace: bytes.Repeat([]byte{2}, 32), ControlScopeGeneration: 1, ExpectedTargetRevision: 1, PolicyRevision: 1, PolicyDigest: bytes.Repeat([]byte{3}, 32),
		SemanticConfirmationDigest: bytes.Repeat([]byte{4}, 32), AuthorityPredicateSetDigest: bytes.Repeat([]byte{5}, 32), CreatedAtUnix: 90, ExpiresAtUnix: 200}
	effect, evidence, effectDigest, actionID, requestDigest, leaseDigest := finalizeTestCommand(t, effect)
	firstAttempt := testAuthorizationAttempt(effectDigest, actionID, requestDigest, leaseDigest)
	first := AuthenticatedPrincipal{DomainKind: 2, DomainID: effect.DomainID, OwnerID: effect.OwnerID, Audience: "test", SessionDigest: firstAttempt.DeviceSessionDigest, ChannelBindingDigest: bytes.Repeat([]byte{6}, 32)}
	if _, err := service.Submit(context.Background(), first, effect, firstAttempt, evidence); err == nil {
		t.Fatal("crash injection was not observed")
	}
	var lease trusted.OwnerCommandLeaseV1
	if err := trusted.DecodeBody(evidence.CommandLeaseObject, "owner-command-lease", &lease); err != nil {
		t.Fatal(err)
	}
	lease.DeviceSessionDigest = bytes.Repeat([]byte{18}, 32)
	lease.LeaseID = bytes.Repeat([]byte{19}, 32)
	evidence2 := evidence
	evidence2.CommandLeaseObject, err = trusted.NewObject(trusted.DomainOwnerLocal, effect.DomainID, "owner-command-lease", lease)
	if err != nil {
		t.Fatal(err)
	}
	leaseDigest2, _ := trusted.ObjectDigest(evidence2.CommandLeaseObject)
	effectObject, _ := trusted.NewObject(trusted.DomainOwnerLocal, effect.DomainID, "owner-command-effect", effect)
	effectBytes, _ := trusted.EncodeObject(effectObject)
	parameterDigest := sha256.Sum256(evidence2.Parameters)
	classesDigest, _ := OwnerCommandClassSetDigest(evidence2.AllowedCommandKinds)
	action2, request2, err := DeriveOwnerCommandIdentity(effect, effectDigest, effectBytes, parameterDigest[:], leaseDigest2, classesDigest)
	if err != nil || !bytes.Equal(action2, actionID) || !bytes.Equal(request2, requestDigest) {
		t.Fatalf("replacement authorization changed semantic identity: %x %x %v", action2, request2, err)
	}
	secondAttempt := testAuthorizationAttempt(effectDigest, action2, request2, leaseDigest2)
	secondAttempt.DeviceSessionDigest = lease.DeviceSessionDigest
	// Recovery is authenticated by the fresh attempt and channel even after the
	// immutable effect/confirmation window has ended.
	service.clock = trustedClock{250}
	secondAttempt.AttemptedAtUnix, secondAttempt.ExpiresAtUnix = 240, 300
	second := AuthenticatedPrincipal{DomainKind: 2, DomainID: effect.DomainID, OwnerID: effect.OwnerID, Audience: "test", SessionDigest: secondAttempt.DeviceSessionDigest, ChannelBindingDigest: bytes.Repeat([]byte{20}, 32)}
	resolution, err := service.Submit(context.Background(), second, effect, secondAttempt, evidence2)
	if err != nil || resolution.State != "applied" {
		t.Fatalf("replacement recovery resolution=%+v err=%v", resolution, err)
	}
	record, ok, err := journal.Get(context.Background(), effect.ResolutionNamespace, actionID)
	if err != nil || !ok || len(record.AuthorizationHistory) != 2 || !bytes.Equal(record.Principal.ChannelBindingDigest, second.ChannelBindingDigest) {
		t.Fatalf("authorization history was not retained: ok=%v count=%d err=%v", ok, len(record.AuthorizationHistory), err)
	}
}

func TestServicePersistsAppliedWithFileJournal(t *testing.T) {
	authority := &memoryJournalAuthority{installation: bytes.Repeat([]byte{8}, 32)}
	journal, err := OpenFileJournal(t.TempDir(), authority)
	if err != nil {
		t.Fatal(err)
	}
	defer journal.Close()
	target := &sink{}
	service, err := New(auth{}, target, journal, sinkAuthority{}, []byte("sink"), false, trustedClock{100})
	if err != nil {
		t.Fatal(err)
	}
	agent := []byte("agent")
	effect := trusted.OwnerCommandEffectV1{SchemaVersion: 1, DomainKind: uint8(trusted.DomainOwnerLocal), DomainID: []byte("domain"), OwnerID: []byte("owner"), AgentID: &agent,
		CommandKind: "owner.pause", CommandInstanceID: bytes.Repeat([]byte{2}, 16), TargetObjectKind: "agent", TargetObjectID: agent,
		ResolutionNamespace: bytes.Repeat([]byte{1}, 32), SinkAuthorityID: []byte("sink"), SinkClusterEpoch: 1, ControlScopeGeneration: 1,
		ExpectedTargetRevision: 1, PolicyRevision: 1, PolicyDigest: bytes.Repeat([]byte{3}, 32),
		SemanticConfirmationDigest: bytes.Repeat([]byte{4}, 32), AuthorityPredicateSetDigest: bytes.Repeat([]byte{5}, 32), CreatedAtUnix: 90, ExpiresAtUnix: 200}
	effect, evidence, digest, actionID, requestDigest, leaseDigest := finalizeTestCommand(t, effect)
	attempt := testAuthorizationAttempt(digest, actionID, requestDigest, leaseDigest)
	principal := AuthenticatedPrincipal{DomainKind: effect.DomainKind, DomainID: effect.DomainID, OwnerID: effect.OwnerID, Audience: "test", SessionDigest: attempt.DeviceSessionDigest, ChannelBindingDigest: bytes.Repeat([]byte{8}, sha256.Size)}
	resolution, err := service.Submit(context.Background(), principal, effect, attempt, evidence)
	if err != nil || resolution.State != "applied" || target.calls != 1 {
		t.Fatalf("resolution=%+v calls=%d err=%v", resolution, target.calls, err)
	}
}
func (auth) VerifyOwnerCommandQuery(context.Context, AuthenticatedPrincipal, []byte, []byte) error {
	return nil
}

type sink struct{ calls int }

type memoryJournal struct{ records map[string]Record }

func (journal *memoryJournal) key(namespace, action []byte) string {
	return string(namespace) + "\x00" + string(action)
}
func (journal *memoryJournal) Begin(_ context.Context, namespace, action []byte, value Record, _ TrustedTimeObservation) (Record, []byte, bool, error) {
	key := journal.key(namespace, action)
	if prior, ok := journal.records[key]; ok {
		return prior, []byte("fence"), false, nil
	}
	journal.records[key] = value
	return Record{}, []byte("fence"), true, nil
}
func (journal *memoryJournal) Transition(_ context.Context, namespace, action []byte, _ string, value Record, _ TrustedTimeObservation) error {
	journal.records[journal.key(namespace, action)] = value
	return nil
}
func (journal *memoryJournal) AttachAuthorization(_ context.Context, namespace, action []byte, value Record, _ TrustedTimeObservation) error {
	journal.records[journal.key(namespace, action)] = value
	return nil
}
func (journal *memoryJournal) MultiHostSafe() bool { return true }
func (journal *memoryJournal) Get(_ context.Context, namespace, action []byte) (Record, bool, error) {
	value, ok := journal.records[journal.key(namespace, action)]
	return value, ok, nil
}

func (s *sink) ApplyOwnerCommand(context.Context, AuthenticatedPrincipal, trusted.OwnerCommandEffectV1, trusted.OwnerCommandAuthorizationAttemptV1, SubmissionEvidence, []byte) (uint64, []trusted.ImmutableObjectReferenceV1, error) {
	s.calls++
	return 2, nil, nil
}
func (s *sink) ReconcileOwnerCommand(context.Context, AuthenticatedPrincipal, trusted.OwnerCommandEffectV1, trusted.OwnerCommandAuthorizationAttemptV1, SubmissionEvidence, []byte) (string, uint64, []trusted.ImmutableObjectReferenceV1, error) {
	return "applied", 2, nil, nil
}

type sinkAuthority struct{}
type trustedClock struct{ at uint64 }

func (clock trustedClock) ObserveTrustedTime(context.Context) (TrustedTimeObservation, error) {
	return TrustedTimeObservation{UnixSeconds: clock.at, Epoch: 1, EvidenceDigest: bytes.Repeat([]byte{9}, 32)}, nil
}

func (sinkAuthority) CurrentOwnerCommandSink(context.Context) ([]byte, uint64, error) {
	return []byte("sink"), 1, nil
}

func TestSinkEpochAdmissionAndRecoveryRules(t *testing.T) {
	if sinkEpochAdmits(1, 2, false) {
		t.Fatal("a new command was admitted under a superseded effect epoch")
	}
	if !sinkEpochAdmits(1, 2, true) {
		t.Fatal("retained Action recovery did not survive monotonic sink failover")
	}
	if sinkEpochAdmits(2, 1, true) {
		t.Fatal("retained Action recovery accepted sink epoch rollback")
	}
}

func TestServiceDeduplicatesSameAction(t *testing.T) {
	target := &sink{}
	service, err := New(auth{}, target, &memoryJournal{records: map[string]Record{}}, sinkAuthority{}, []byte("sink"), false, trustedClock{100})
	if err != nil {
		t.Fatal(err)
	}
	agent := []byte("agent")
	effect := trusted.OwnerCommandEffectV1{SchemaVersion: 1, DomainKind: uint8(trusted.DomainOwnerLocal), DomainID: []byte("domain"), OwnerID: []byte("owner"), AgentID: &agent,
		CommandKind: "owner.pause", CommandInstanceID: bytes.Repeat([]byte{3}, 16), TargetObjectKind: "agent", TargetObjectID: agent,
		ResolutionNamespace: bytes.Repeat([]byte{1}, 32), SinkAuthorityID: []byte("sink"), SinkClusterEpoch: 1, ControlScopeGeneration: 1,
		ExpectedTargetRevision: 1, PolicyRevision: 1, PolicyDigest: bytes.Repeat([]byte{3}, 32),
		SemanticConfirmationDigest: bytes.Repeat([]byte{4}, 32), AuthorityPredicateSetDigest: bytes.Repeat([]byte{5}, 32), CreatedAtUnix: 90, ExpiresAtUnix: 200}
	effect, evidence, digest, actionID, requestDigest, leaseDigest := finalizeTestCommand(t, effect)
	attempt := testAuthorizationAttempt(digest, actionID, requestDigest, leaseDigest)
	principal := AuthenticatedPrincipal{DomainKind: effect.DomainKind, DomainID: effect.DomainID, OwnerID: effect.OwnerID, Audience: "test", SessionDigest: attempt.DeviceSessionDigest, ChannelBindingDigest: bytes.Repeat([]byte{8}, sha256.Size)}
	if _, err = service.Submit(context.Background(), principal, effect, attempt, evidence); err != nil {
		t.Fatal(err)
	}
	if _, err = service.Submit(context.Background(), principal, effect, attempt, evidence); err != nil {
		t.Fatal(err)
	}
	if target.calls != 1 {
		t.Fatalf("calls=%d", target.calls)
	}
}

func testSubmissionEvidence(t *testing.T, effect trusted.OwnerCommandEffectV1) (SubmissionEvidence, []byte, []byte, []byte) {
	t.Helper()
	parameters := []byte{0xa1, 0x01, 0x01}
	parameterDigest := sha256.Sum256(parameters)
	classes := []string{effect.CommandKind}
	classesDigest, err := OwnerCommandClassSetDigest(classes)
	if err != nil {
		t.Fatal(err)
	}
	lease := trusted.OwnerCommandLeaseV1{SchemaVersion: 1, LeaseID: []byte("lease-1234567890"), DomainKind: effect.DomainKind, DomainID: effect.DomainID, OwnerID: effect.OwnerID,
		DeviceSessionDigest:         bytes.Repeat([]byte{9}, sha256.Size),
		AllowedCommandClassesDigest: classesDigest, Audience: "test", SinkAuthorityID: effect.SinkAuthorityID, SinkClusterEpoch: effect.SinkClusterEpoch,
		ControlScopeGeneration: effect.ControlScopeGeneration, PolicyRevision: effect.PolicyRevision, PolicyDigest: effect.PolicyDigest, AuthorityEpoch: 1, NotBeforeUnix: 90, ExpiresAtUnix: 200}
	leaseObject, err := trusted.NewObject(trusted.DomainOwnerLocal, effect.DomainID, "owner-command-lease", lease)
	if err != nil {
		t.Fatal(err)
	}
	leaseDigest, err := trusted.ObjectDigest(leaseObject)
	if err != nil {
		t.Fatal(err)
	}
	return SubmissionEvidence{Parameters: parameters, CommandLeaseObject: leaseObject, AllowedCommandKinds: classes}, leaseDigest, parameterDigest[:], classesDigest
}

func testAuthorizationAttempt(effectDigest, actionID, requestDigest, leaseDigest []byte) trusted.OwnerCommandAuthorizationAttemptV1 {
	return trusted.OwnerCommandAuthorizationAttemptV1{
		CommandEffectDigest:         effectDigest,
		ActionID:                    actionID,
		ExactRequestDigest:          requestDigest,
		DeviceSessionDigest:         bytes.Repeat([]byte{9}, sha256.Size),
		SessionGeneration:           1,
		SessionRevocationGeneration: 1,
		AuthorityEpoch:              1,
		CommandLeaseDigest:          leaseDigest,
		AuthorizationEnvelopes:      []trusted.ProfileAuthorizationEnvelopeV1{},
		AttemptedAtUnix:             100,
		ExpiresAtUnix:               200,
	}
}

func finalizeTestCommand(t *testing.T, effect trusted.OwnerCommandEffectV1) (trusted.OwnerCommandEffectV1, SubmissionEvidence, []byte, []byte, []byte, []byte) {
	t.Helper()
	if effect.Extensions == nil {
		effect.Extensions = [][]byte{}
	}
	evidence, leaseDigest, parameterDigest, classesDigest := testSubmissionEvidence(t, effect)
	effect.ExactParameterDigest = parameterDigest
	predicateDigest, err := trusted.OwnerCommandAuthorizationPredicateSetDigest(effect)
	if err != nil {
		t.Fatal(err)
	}
	effect.AuthorityPredicateSetDigest = predicateDigest
	provisional, err := trusted.NewObject(trusted.DomainKind(effect.DomainKind), effect.DomainID, "owner-command-effect", effect)
	if err != nil {
		t.Fatal(err)
	}
	provisionalBytes, _ := trusted.EncodeObject(provisional)
	provisionalDigest, _ := trusted.ObjectDigest(provisional)
	action, _, err := DeriveOwnerCommandIdentity(effect, provisionalDigest, provisionalBytes, parameterDigest, leaseDigest, classesDigest)
	if err != nil {
		t.Fatal(err)
	}
	profile, _ := trusted.OwnerCommandAuthorizationPredicateSet(effect)
	risk := "bounded"
	if profile.RequireIndependentApprover {
		risk = "high"
	}
	evidence.SemanticConfirmation = trusted.SemanticConfirmationV1{DisplayProfileURI: trusted.OwnerCommandConfirmationProfileV1, DisplayProfileVersion: 1,
		RiskClass: risk, DomainID: effect.DomainID, OwnerID: effect.OwnerID, ActionID: action, CommandKind: effect.CommandKind,
		Target: effect.TargetObjectKind + ":" + hex.EncodeToString(effect.TargetObjectID), PermissionDelta: []byte{}, PolicyDelta: []byte{},
		CriticalParameters: [][]byte{effect.ExactParameterDigest, effect.PolicyDigest, effect.TargetObjectID}, ExpiresAtUnix: effect.ExpiresAtUnix}
	effect.SemanticConfirmationDigest, err = trusted.SemanticConfirmationDigest(evidence.SemanticConfirmation)
	if err != nil {
		t.Fatal(err)
	}
	object, err := trusted.NewObject(trusted.DomainKind(effect.DomainKind), effect.DomainID, "owner-command-effect", effect)
	if err != nil {
		t.Fatal(err)
	}
	wire, _ := trusted.EncodeObject(object)
	digest, _ := trusted.ObjectDigest(object)
	action, request, err := DeriveOwnerCommandIdentity(effect, digest, wire, parameterDigest, leaseDigest, classesDigest)
	if err != nil {
		t.Fatal(err)
	}
	return effect, evidence, digest, action, request, leaseDigest
}
