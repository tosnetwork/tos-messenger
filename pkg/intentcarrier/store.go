// Package intentcarrier implements the Messenger public-channel carrier
// profile. It deliberately uses a different append-only journal and action
// store from the service Gateway carrier. Carrier observations are hints;
// signed Intent objects remain the only portable discovery evidence.
package intentcarrier

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/tosnetwork/tos-messenger/internal/dirlock"
	"github.com/tosnetwork/tos-messenger/pkg/economicaction"
	commerce "github.com/tosnetwork/tos-service-protocol/pkg/agentcommerce"
	"github.com/tosnetwork/tos-service-protocol/pkg/codec"
)

const (
	MaxObjectBytes = 2 << 20
	MaxPageResults = 1000
	journalSchema  = "tos.messaging.intent-carrier-journal.v1"
)

type Query struct {
	Modes          []commerce.IntentMode
	SubjectClasses []commerce.SubjectClass
	TaxonomyPrefix string
	Keywords       []string
	Limit          uint32
	AfterSequence  uint64
}

type IntentResult struct {
	Intent             commerce.SignedAgentIntent `json:"intent"`
	IntentDigest       string                     `json:"intent_digest"`
	AuthorizationLevel string                     `json:"authorization_level"`
	StoredAtUnix       uint64                     `json:"stored_at_unix"`
	CarrierSequence    uint64                     `json:"carrier_sequence"`
}

type WithdrawalResult struct {
	Withdrawal       commerce.SignedAgentIntentWithdrawal `json:"withdrawal"`
	WithdrawalDigest string                               `json:"withdrawal_digest"`
	StoredAtUnix     uint64                               `json:"stored_at_unix"`
	CarrierSequence  uint64                               `json:"carrier_sequence"`
}

type Operation struct {
	Kind            string            `json:"kind"`
	CarrierSequence uint64            `json:"carrier_sequence"`
	Intent          *IntentResult     `json:"intent,omitempty"`
	Withdrawal      *WithdrawalResult `json:"withdrawal,omitempty"`
}

type Page struct {
	CarrierID  string         `json:"carrier_id"`
	Results    []IntentResult `json:"results"`
	Operations []Operation    `json:"operations"`
	Next       string         `json:"next_cursor,omitempty"`
}

type journal struct {
	Schema            string            `json:"schema"`
	NextSequence      uint64            `json:"next_sequence"`
	Operations        []Operation       `json:"operations"`
	ConsumedChallenge map[string]string `json:"consumed_challenges"`
}

type Store struct {
	mu              sync.Mutex
	root            string
	carrierID       string
	maxEntries      uint32
	maxActorEntries uint32
	now             func() time.Time
	lock            *dirlock.Lock
	key             ed25519.PrivateKey
	actions         *economicaction.Store
	doc             journal
}

func Open(root, carrierID string, maxEntries, maxActorEntries uint32, authorities map[string]ed25519.PublicKey) (*Store, error) {
	if !filepath.IsAbs(root) || filepath.Clean(root) != root || carrierID == "" || maxEntries == 0 || maxEntries > 1_000_000 ||
		maxActorEntries == 0 || maxActorEntries > maxEntries || len(authorities) == 0 {
		return nil, errors.New("Messenger Intent Carrier configuration is invalid")
	}
	if err := os.MkdirAll(root, 0o700); err != nil {
		return nil, err
	}
	info, err := os.Lstat(root)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0o077 != 0 {
		return nil, errors.New("Messenger Intent Carrier state directory is not private")
	}
	lock, err := dirlock.Acquire(root, ".intent-carrier.lock")
	if err != nil {
		return nil, err
	}
	store := &Store{root: root, carrierID: carrierID, maxEntries: maxEntries, maxActorEntries: maxActorEntries,
		now: time.Now, lock: lock, doc: journal{Schema: journalSchema, NextSequence: 1, ConsumedChallenge: map[string]string{}}}
	if store.key, err = loadOrCreateKey(filepath.Join(root, "intent-carrier-admission.key")); err != nil {
		_ = lock.Close()
		return nil, err
	}
	if store.actions, err = economicaction.Open(root, authorities); err != nil {
		_ = lock.Close()
		return nil, err
	}
	if err := store.load(); err != nil {
		_ = lock.Close()
		return nil, err
	}
	return store, nil
}

func (s *Store) Close() error {
	if s == nil {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	for i := range s.key {
		s.key[i] = 0
	}
	if s.lock == nil {
		return nil
	}
	err := s.lock.Close()
	s.lock = nil
	return err
}

func (s *Store) IssueAdmission(operationKind, actorID, audience string, declaredBytes uint64) (commerce.SignedOperationAdmissionChallenge, error) {
	if s == nil || (operationKind != "publication.publish" && operationKind != "publication.withdraw") || actorID == "" || audience == "" ||
		declaredBytes == 0 || declaredBytes > MaxObjectBytes {
		return commerce.SignedOperationAdmissionChallenge{}, errors.New("Messenger Carrier admission request is invalid")
	}
	resource, err := commerce.AdmissionResourceVectorDigest(operationKind, declaredBytes,
		map[string]uint64{"index_entries": 1, "retained_bytes": declaredBytes})
	if err != nil {
		return commerce.SignedOperationAdmissionChallenge{}, err
	}
	now := s.now().UTC()
	return commerce.NewOperationAdmissionChallenge(commerce.OperationAdmissionChallengeBody{SchemaVersion: 1,
		ProfileURI: "tos.operation-admission.hashcash.v1", CarrierID: s.carrierID, ActorID: actorID, OperationKind: operationKind,
		Audience: audience, DeclaredBytes: declaredBytes, ResourceVectorDigest: resource, DifficultyBits: 12,
		IssuedAtUnix: uint64(now.Unix()), ExpiresAtUnix: uint64(now.Add(2 * time.Minute).Unix())}, s.key)
}

func (s *Store) Publish(intent commerce.SignedAgentIntent, proof commerce.OperationAdmissionProof,
	action commerce.AuthorizedAction, fence commerce.WriterFence) (IntentResult, commerce.ActionResolution, error) {
	if s == nil {
		return IntentResult{}, commerce.ActionResolution{}, errors.New("Messenger Carrier is unavailable")
	}
	now := s.now().UTC()
	if err := commerce.VerifyIntent(intent, selfSignatureResolver{}, now); err != nil {
		return IntentResult{}, commerce.ActionResolution{}, err
	}
	digest, err := commerce.IntentBodyDigest(intent.Body)
	if err != nil {
		return IntentResult{}, commerce.ActionResolution{}, err
	}
	exact, err := codec.Marshal(intent)
	if err != nil || len(exact) > MaxObjectBytes {
		return IntentResult{}, commerce.ActionResolution{}, errors.New("signed Intent is oversized")
	}
	opDigest, err := codec.Digest("tos.agent-intent-publication-operation.v1", intent)
	if err != nil {
		return IntentResult{}, commerce.ActionResolution{}, err
	}
	fields := map[string]commerce.SemanticValue{"owner_id": commerce.ID(action.OwnerID), "agent_id": commerce.ID(action.AgentID),
		"carrier_id": commerce.ID(s.carrierID), "intent_object_id": commerce.ID(intent.Body.ObjectID),
		"revision": commerce.U64(intent.Body.Revision), "operation_digest": commerce.Digest32(opDigest)}
	resolution, err := s.actions.Admit(action, fence, fields, exact, now)
	if err != nil {
		return IntentResult{}, resolution, err
	}
	if resolution.State == commerce.ActionAccepted || resolution.State == commerce.ActionTerminal {
		result, getErr := s.Get(digest)
		return result, resolution, getErr
	}
	if err := s.verifyAdmission(proof, "publication.publish", intent.Body.IssuerAgentID, intent.Body.Audience, uint64(len(exact))); err != nil {
		return IntentResult{}, resolution, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if found, ok := s.findIntentLocked(digest); ok {
		if err := s.consumeLocked(proof.ChallengeDigest, digest); err != nil {
			return IntentResult{}, resolution, err
		}
		resolution, err = s.actions.Accept(action.StableActionID, action.ExactRequestDigest, digest)
		return found, resolution, err
	}
	if len(s.doc.Operations) >= int(s.maxEntries) || s.actorCountLocked(intent.Body.IssuerAgentID) >= s.maxActorEntries {
		return IntentResult{}, resolution, errors.New("Messenger Carrier retention quota reached")
	}
	// Quota rejection must not consume the short-lived proof.  The publisher
	// may retry the exact operation after an operator raises capacity, while a
	// successfully admitted operation still consumes the proof atomically with
	// the append below.
	if err := s.consumeLocked(proof.ChallengeDigest, digest); err != nil {
		return IntentResult{}, resolution, err
	}
	result := IntentResult{Intent: intent, IntentDigest: digest, AuthorizationLevel: "self-signature+messenger-channel-admission",
		StoredAtUnix: uint64(now.Unix()), CarrierSequence: s.doc.NextSequence}
	s.doc.NextSequence++
	s.doc.Operations = append(s.doc.Operations, Operation{Kind: "intent", CarrierSequence: result.CarrierSequence, Intent: &result})
	if err := s.persistLocked(); err != nil {
		s.doc.Operations = s.doc.Operations[:len(s.doc.Operations)-1]
		s.doc.NextSequence--
		delete(s.doc.ConsumedChallenge, proof.ChallengeDigest)
		return IntentResult{}, resolution, err
	}
	resolution, err = s.actions.Accept(action.StableActionID, action.ExactRequestDigest, digest)
	return result, resolution, err
}

func (s *Store) Withdraw(withdrawal commerce.SignedAgentIntentWithdrawal, proof commerce.OperationAdmissionProof,
	action commerce.AuthorizedAction, fence commerce.WriterFence) (commerce.ActionResolution, error) {
	if s == nil {
		return commerce.ActionResolution{}, errors.New("Messenger Carrier is unavailable")
	}
	now := s.now().UTC()
	if err := commerce.VerifyIntentWithdrawal(withdrawal, selfSignatureResolver{}, now); err != nil {
		return commerce.ActionResolution{}, err
	}
	s.mu.Lock()
	prior, ok := s.findIntentLocked(withdrawal.Body.IntentDigest)
	s.mu.Unlock()
	if !ok || prior.Intent.Body.IssuerAgentID != withdrawal.Body.IssuerAgentID || prior.Intent.Body.ObjectID != withdrawal.Body.ObjectID ||
		prior.Intent.Body.Revision != withdrawal.Body.IntentRevision || prior.Intent.Body.NetworkID != withdrawal.Body.NetworkID || prior.Intent.Body.Audience != withdrawal.Body.Audience {
		return commerce.ActionResolution{}, errors.New("withdrawal does not bind a retained Intent revision")
	}
	exact, err := codec.Marshal(withdrawal)
	if err != nil || len(exact) > MaxObjectBytes {
		return commerce.ActionResolution{}, errors.New("signed withdrawal is oversized")
	}
	opDigest, err := codec.Digest("tos.agent-intent-withdrawal-operation.v1", withdrawal)
	if err != nil {
		return commerce.ActionResolution{}, err
	}
	fields := map[string]commerce.SemanticValue{"owner_id": commerce.ID(action.OwnerID), "agent_id": commerce.ID(action.AgentID),
		"carrier_id": commerce.ID(s.carrierID), "intent_object_id": commerce.ID(withdrawal.Body.ObjectID),
		"withdrawn_revision": commerce.U64(withdrawal.Body.IntentRevision), "withdrawal_operation_digest": commerce.Digest32(opDigest)}
	resolution, err := s.actions.Admit(action, fence, fields, exact, now)
	if err != nil || resolution.State == commerce.ActionAccepted || resolution.State == commerce.ActionTerminal {
		return resolution, err
	}
	if err := s.verifyAdmission(proof, "publication.withdraw", withdrawal.Body.IssuerAgentID, withdrawal.Body.Audience, uint64(len(exact))); err != nil {
		return resolution, err
	}
	digest, _ := commerce.IntentWithdrawalDigest(withdrawal.Body)
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.consumeLocked(proof.ChallengeDigest, digest); err != nil {
		return resolution, err
	}
	for _, operation := range s.doc.Operations {
		if operation.Withdrawal != nil && operation.Withdrawal.Withdrawal.Body.IntentDigest == withdrawal.Body.IntentDigest {
			if operation.Withdrawal.WithdrawalDigest != digest {
				return resolution, errors.New("conflicting withdrawal for Intent revision")
			}
			return s.actions.Accept(action.StableActionID, action.ExactRequestDigest, digest)
		}
	}
	result := WithdrawalResult{Withdrawal: withdrawal, WithdrawalDigest: digest, StoredAtUnix: uint64(now.Unix()), CarrierSequence: s.doc.NextSequence}
	s.doc.NextSequence++
	s.doc.Operations = append(s.doc.Operations, Operation{Kind: "withdrawal", CarrierSequence: result.CarrierSequence, Withdrawal: &result})
	if err := s.persistLocked(); err != nil {
		s.doc.Operations = s.doc.Operations[:len(s.doc.Operations)-1]
		s.doc.NextSequence--
		delete(s.doc.ConsumedChallenge, proof.ChallengeDigest)
		return resolution, err
	}
	return s.actions.Accept(action.StableActionID, action.ExactRequestDigest, digest)
}

func (s *Store) ResolveAction(actionID, requestDigest string) (commerce.ActionResolution, error) {
	if s == nil {
		return commerce.ActionResolution{}, errors.New("Messenger Carrier is unavailable")
	}
	return s.actions.Resolve(actionID, requestDigest)
}

func (s *Store) Get(digest string) (IntentResult, error) {
	if !canonicalDigest(digest) {
		return IntentResult{}, errors.New("Intent digest is invalid")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	result, ok := s.findIntentLocked(digest)
	if !ok {
		return IntentResult{}, os.ErrNotExist
	}
	return result, nil
}

func (s *Store) Search(query Query) (Page, error) {
	if s == nil || query.Limit == 0 || query.Limit > MaxPageResults || len(query.Keywords) > 32 || len(query.Modes) > 16 || len(query.SubjectClasses) > 16 {
		return Page{}, errors.New("Messenger Carrier query is invalid or unbounded")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	withdrawn := map[string]bool{}
	for _, operation := range s.doc.Operations {
		if operation.Withdrawal != nil {
			withdrawn[operation.Withdrawal.Withdrawal.Body.IntentDigest] = true
		}
	}
	page := Page{CarrierID: s.carrierID, Results: []IntentResult{}, Operations: []Operation{}}
	now := s.now().UTC()
	for _, operation := range s.doc.Operations {
		if operation.CarrierSequence <= query.AfterSequence {
			continue
		}
		if operation.Intent != nil {
			if withdrawn[operation.Intent.IntentDigest] || !now.Before(time.Unix(int64(operation.Intent.Intent.Body.ExpiresAtUnix), 0)) ||
				!matches(operation.Intent.Intent.Body.Payload.DiscoveryCard, query) {
				continue
			}
			page.Results = append(page.Results, *operation.Intent)
		}
		page.Operations = append(page.Operations, operation)
		if len(page.Operations) == int(query.Limit) {
			page.Next = "seq:" + strconv.FormatUint(operation.CarrierSequence, 10)
			break
		}
	}
	return page, nil
}

func (s *Store) Subscribe(ctx context.Context, query Query, wait time.Duration) (Page, error) {
	if ctx == nil || wait < 0 || wait > 25*time.Second {
		return Page{}, errors.New("Messenger Carrier subscription wait is invalid")
	}
	deadline := time.NewTimer(wait)
	defer deadline.Stop()
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()
	for {
		page, err := s.Search(query)
		if err != nil || len(page.Operations) > 0 || wait == 0 {
			return page, err
		}
		select {
		case <-ctx.Done():
			return Page{}, ctx.Err()
		case <-deadline.C:
			return Page{CarrierID: s.carrierID, Results: []IntentResult{}, Operations: []Operation{}}, nil
		case <-ticker.C:
		}
	}
}

func (s *Store) verifyAdmission(proof commerce.OperationAdmissionProof, kind, actor, audience string, size uint64) error {
	resource, err := commerce.AdmissionResourceVectorDigest(kind, size, map[string]uint64{"index_entries": 1, "retained_bytes": size})
	if err != nil || proof.Challenge.Body.CarrierID != s.carrierID ||
		commerce.VerifyOperationAdmission(proof, s.key.Public().(ed25519.PublicKey), actor, kind, audience, size, resource, s.now().UTC()) != nil {
		return errors.New("Messenger Carrier admission proof is invalid")
	}
	return nil
}

func (s *Store) consumeLocked(challengeDigest, objectDigest string) error {
	if prior := s.doc.ConsumedChallenge[challengeDigest]; prior != "" {
		return errors.New("Messenger Carrier admission challenge was already consumed")
	}
	s.doc.ConsumedChallenge[challengeDigest] = objectDigest
	return nil
}

func (s *Store) actorCountLocked(actor string) uint32 {
	var count uint32
	for _, operation := range s.doc.Operations {
		if operation.Intent != nil && operation.Intent.Intent.Body.IssuerAgentID == actor {
			count++
		}
	}
	return count
}

func (s *Store) findIntentLocked(digest string) (IntentResult, bool) {
	for _, operation := range s.doc.Operations {
		if operation.Intent != nil && operation.Intent.IntentDigest == digest {
			return *operation.Intent, true
		}
	}
	return IntentResult{}, false
}

func (s *Store) load() error {
	path := filepath.Join(s.root, "intent-carrier-journal-v1.json")
	raw, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return s.persistLocked()
	}
	if err != nil || len(raw) == 0 || len(raw) > 512<<20 {
		return errors.New("Messenger Carrier journal is unavailable or oversized")
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&s.doc) != nil || s.doc.Schema != journalSchema || s.doc.NextSequence == 0 || s.doc.ConsumedChallenge == nil || requireEOF(decoder) != nil {
		return errors.New("Messenger Carrier journal is corrupt")
	}
	var previous uint64
	for _, operation := range s.doc.Operations {
		if operation.CarrierSequence <= previous || operation.CarrierSequence >= s.doc.NextSequence ||
			(operation.Intent == nil) == (operation.Withdrawal == nil) {
			return errors.New("Messenger Carrier journal has invalid ordering")
		}
		previous = operation.CarrierSequence
	}
	return nil
}

func (s *Store) persistLocked() error {
	raw, err := json.Marshal(s.doc)
	if err != nil {
		return err
	}
	temporary, err := os.CreateTemp(s.root, ".intent-carrier-journal-*")
	if err != nil {
		return err
	}
	name := temporary.Name()
	defer os.Remove(name)
	if err := temporary.Chmod(0o600); err != nil {
		_ = temporary.Close()
		return err
	}
	if _, err = temporary.Write(raw); err == nil {
		err = temporary.Sync()
	}
	if closeErr := temporary.Close(); err == nil {
		err = closeErr
	}
	if err == nil {
		err = os.Rename(name, filepath.Join(s.root, "intent-carrier-journal-v1.json"))
	}
	return err
}

func loadOrCreateKey(path string) (ed25519.PrivateKey, error) {
	raw, err := os.ReadFile(path)
	if err == nil {
		info, statErr := os.Lstat(path)
		if statErr != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm() != 0o600 || len(raw) != ed25519.PrivateKeySize {
			return nil, errors.New("Messenger Carrier admission key is invalid")
		}
		return ed25519.PrivateKey(append([]byte(nil), raw...)), nil
	}
	if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return nil, err
	}
	if _, err = file.Write(key); err == nil {
		err = file.Sync()
	}
	if closeErr := file.Close(); err == nil {
		err = closeErr
	}
	return key, err
}

type selfSignatureResolver struct{}

func (selfSignatureResolver) AuthorizeIntentKey(string, ed25519.PublicKey, time.Time) error {
	return nil
}

func matches(card commerce.DiscoveryCard, query Query) bool {
	if len(query.Modes) > 0 && !modeIntersection(card.IntentModes, query.Modes) ||
		len(query.SubjectClasses) > 0 && !classIntersection(card.SubjectClasses, query.SubjectClasses) {
		return false
	}
	if query.TaxonomyPrefix != "" {
		found := false
		for _, taxonomy := range card.TaxonomyPaths {
			if strings.HasPrefix(taxonomy, query.TaxonomyPrefix) {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	for _, wanted := range query.Keywords {
		found := false
		for _, keyword := range card.Keywords {
			if keyword.Text == wanted {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	return true
}

func modeIntersection(left, right []commerce.IntentMode) bool {
	for _, a := range left {
		for _, b := range right {
			if a == b {
				return true
			}
		}
	}
	return false
}

func classIntersection(left, right []commerce.SubjectClass) bool {
	for _, a := range left {
		for _, b := range right {
			if a == b {
				return true
			}
		}
	}
	return false
}

func canonicalDigest(value string) bool {
	if len(value) != 71 || !strings.HasPrefix(value, "sha256:") {
		return false
	}
	for _, r := range value[7:] {
		if !(r >= '0' && r <= '9' || r >= 'a' && r <= 'f') {
			return false
		}
	}
	return true
}

func requireEOF(decoder *json.Decoder) error {
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return errors.New("trailing JSON")
	}
	return nil
}

// StableOperations returns a sequence-ordered copy for operator diagnostics.
func (s *Store) StableOperations() []Operation {
	s.mu.Lock()
	defer s.mu.Unlock()
	result := append([]Operation(nil), s.doc.Operations...)
	sort.Slice(result, func(i, j int) bool { return result[i].CarrierSequence < result[j].CarrierSequence })
	return result
}
