// Package economicaction is the Messenger-owned admission boundary for
// economic side effects. The coordinator's Unix-socket access is not
// authority: every send must carry a current signed writer fence and the exact
// released semantic identity material, and the daemon persists generation
// high-water before transmitting anything.
package economicaction

import (
	"bytes"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"
	"time"

	commerce "github.com/tosnetwork/tos-service-protocol/pkg/agentcommerce"
)

const schema = "tos.messaging.economic-action-store.v1"

var ErrStaleWriter = errors.New("economic action writer generation is stale")

type authorityResolver struct{ keys map[string]ed25519.PublicKey }

func (r authorityResolver) AuthorizeFenceKey(id string, key ed25519.PublicKey, _ time.Time) error {
	want, ok := r.keys[id]
	if !ok || !ed25519.PublicKey(key).Equal(want) {
		return errors.New("writer fence authority is not operator-pinned")
	}
	return nil
}

type document struct {
	Schema         string                               `json:"schema"`
	HighWater      map[string]uint64                    `json:"writer_high_water"`
	FenceHighWater map[string]string                    `json:"writer_fence_high_water"`
	Actions        map[string]commerce.ActionResolution `json:"actions"`
}

type Store struct {
	mu       sync.Mutex
	path     string
	resolver authorityResolver
	doc      document
}

// Open creates or validates a store under the already single-writer daemon
// state directory. authorities are operator configuration, never request data.
func Open(stateDir string, authorities map[string]ed25519.PublicKey) (*Store, error) {
	if !filepath.IsAbs(stateDir) || len(authorities) == 0 {
		return nil, errors.New("economic action store configuration is invalid")
	}
	keys := make(map[string]ed25519.PublicKey, len(authorities))
	for id, key := range authorities {
		if id == "" || len(key) != ed25519.PublicKeySize {
			return nil, errors.New("economic action authority is invalid")
		}
		keys[id] = append(ed25519.PublicKey(nil), key...)
	}
	store := &Store{path: filepath.Join(stateDir, "economic-actions-v1.json"), resolver: authorityResolver{keys: keys},
		doc: document{Schema: schema, HighWater: map[string]uint64{}, FenceHighWater: map[string]string{}, Actions: map[string]commerce.ActionResolution{}}}
	if info, statErr := os.Lstat(store.path); statErr == nil && (!info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm() != 0o600 || info.Size() <= 0 || info.Size() > 64<<20) {
		return nil, errors.New("economic action store is not an owner-only bounded regular file")
	}
	raw, err := os.ReadFile(store.path)
	if errors.Is(err, os.ErrNotExist) {
		return store, store.persistLocked()
	}
	if err != nil {
		return nil, err
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&store.doc); err != nil || store.doc.Schema != schema || store.doc.HighWater == nil || store.doc.Actions == nil {
		return nil, errors.New("economic action store is corrupt")
	}
	if store.doc.FenceHighWater == nil {
		store.doc.FenceHighWater = map[string]string{}
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return nil, errors.New("economic action store has trailing data")
	}
	for id, resolution := range store.doc.Actions {
		if id != resolution.StableActionID || commerce.ValidateActionResolution(resolution) != nil {
			return nil, errors.New("economic action store contains an invalid resolution")
		}
	}
	return store, nil
}

// Admit verifies and durably records the generation and exact request before
// the network send. An exact retry returns the prior state; a semantic-ID
// collision or stale generation never reaches the sender.
func (s *Store) Admit(action commerce.AuthorizedAction, fence commerce.WriterFence,
	fields map[string]commerce.SemanticValue, exactRequest []byte, now time.Time) (commerce.ActionResolution, error) {
	if s == nil {
		return commerce.ActionResolution{}, errors.New("economic action store is unavailable")
	}
	if err := commerce.VerifyAuthorizedAction(action, fields, exactRequest, fence, s.resolver, now.UTC()); err != nil {
		return commerce.ActionResolution{}, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	key := action.OwnerID + "\x00" + action.AgentID
	fenceDigest, err := commerce.WriterFenceDigest(fence)
	if err != nil {
		return commerce.ActionResolution{}, err
	}
	if action.WriterGeneration < s.doc.HighWater[key] {
		return commerce.ActionResolution{}, ErrStaleWriter
	}
	if action.WriterGeneration == s.doc.HighWater[key] && s.doc.FenceHighWater[key] != "" && s.doc.FenceHighWater[key] != fenceDigest {
		return commerce.ActionResolution{}, errors.New("writer generation equivocates between two authority fences")
	}
	if prior, ok := s.doc.Actions[action.StableActionID]; ok {
		if prior.ExactRequestDigest != action.ExactRequestDigest {
			return commerce.ActionResolution{StableActionID: action.StableActionID, ExactRequestDigest: action.ExactRequestDigest,
				State: commerce.ActionConflict, StateRevision: prior.StateRevision + 1}, nil
		}
		return prior, nil
	}
	if len(s.doc.Actions) >= 1_000_000 {
		return commerce.ActionResolution{}, errors.New("economic action store capacity reached")
	}
	priorGeneration, priorFence := s.doc.HighWater[key], s.doc.FenceHighWater[key]
	if action.WriterGeneration > priorGeneration || priorFence == "" {
		s.doc.HighWater[key], s.doc.FenceHighWater[key] = action.WriterGeneration, fenceDigest
	}
	resolution := commerce.ActionResolution{StableActionID: action.StableActionID, ExactRequestDigest: action.ExactRequestDigest,
		State: commerce.ActionPrepared, StateRevision: 1}
	s.doc.Actions[action.StableActionID] = resolution
	if err := s.persistLocked(); err != nil {
		delete(s.doc.Actions, action.StableActionID)
		s.doc.HighWater[key], s.doc.FenceHighWater[key] = priorGeneration, priorFence
		return commerce.ActionResolution{}, err
	}
	return resolution, nil
}

func (s *Store) Submit(stableID, requestDigest string) (commerce.ActionResolution, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	prior, ok := s.doc.Actions[stableID]
	if !ok || prior.ExactRequestDigest != requestDigest {
		return commerce.ActionResolution{}, errors.New("economic action was not prepared")
	}
	if prior.State == commerce.ActionSubmitted || prior.State == commerce.ActionAccepted {
		return prior, nil
	}
	if prior.State != commerce.ActionPrepared {
		return commerce.ActionResolution{}, errors.New("economic action cannot be submitted")
	}
	original := prior
	prior.State, prior.StateRevision = commerce.ActionSubmitted, prior.StateRevision+1
	s.doc.Actions[stableID] = prior
	if err := s.persistLocked(); err != nil {
		s.doc.Actions[stableID] = original
		return commerce.ActionResolution{}, err
	}
	return prior, nil
}

func (s *Store) Resolve(stableID, requestDigest string) (commerce.ActionResolution, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	prior, ok := s.doc.Actions[stableID]
	if !ok {
		return commerce.ActionResolution{StableActionID: stableID, ExactRequestDigest: requestDigest,
			State: commerce.ActionUnknown, StateRevision: 1}, nil
	}
	if prior.ExactRequestDigest != requestDigest {
		return commerce.ActionResolution{StableActionID: stableID, ExactRequestDigest: requestDigest,
			State: commerce.ActionConflict, StateRevision: prior.StateRevision + 1}, nil
	}
	return prior, nil
}

func (s *Store) Accept(stableID, requestDigest, eventID string) (commerce.ActionResolution, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	prior, ok := s.doc.Actions[stableID]
	if !ok || prior.ExactRequestDigest != requestDigest {
		return commerce.ActionResolution{}, errors.New("economic action was not prepared")
	}
	if prior.State == commerce.ActionAccepted {
		if prior.SinkReference != eventID {
			return commerce.ActionResolution{}, errors.New("economic action has conflicting sink evidence")
		}
		return prior, nil
	}
	if prior.State != commerce.ActionPrepared && prior.State != commerce.ActionSubmitted {
		return commerce.ActionResolution{}, errors.New("economic action cannot become accepted")
	}
	original := prior
	prior.State, prior.SinkReference, prior.StateRevision = commerce.ActionAccepted, eventID, prior.StateRevision+1
	if err := commerce.ValidateActionResolution(prior); err != nil {
		return commerce.ActionResolution{}, err
	}
	s.doc.Actions[stableID] = prior
	if err := s.persistLocked(); err != nil {
		s.doc.Actions[stableID] = original
		return commerce.ActionResolution{}, err
	}
	return prior, nil
}

func (s *Store) persistLocked() error {
	raw, err := json.Marshal(s.doc)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(s.path), 0700); err != nil {
		return err
	}
	temporary, err := os.CreateTemp(filepath.Dir(s.path), ".economic-actions-*")
	if err != nil {
		return err
	}
	temporaryName := temporary.Name()
	ok := false
	defer func() {
		_ = temporary.Close()
		if !ok {
			_ = os.Remove(temporaryName)
		}
	}()
	if err := temporary.Chmod(0600); err != nil {
		return err
	}
	if _, err := temporary.Write(append(raw, '\n')); err != nil {
		return err
	}
	if err := temporary.Sync(); err != nil {
		return fmt.Errorf("sync economic action store: %w", err)
	}
	if err := temporary.Close(); err != nil {
		return fmt.Errorf("close economic action store: %w", err)
	}
	if err := os.Rename(temporaryName, s.path); err != nil {
		return err
	}
	directory, err := os.Open(filepath.Dir(s.path))
	if err != nil {
		return err
	}
	err = directory.Sync()
	_ = directory.Close()
	ok = err == nil
	return err
}

// ParseAuthorityKey decodes the strict operator configuration form.
func ParseAuthorityKey(encoded string) (ed25519.PublicKey, error) {
	raw, err := hex.DecodeString(encoded)
	if err != nil || len(raw) != ed25519.PublicKeySize {
		return nil, errors.New("economic authority public key is invalid")
	}
	return ed25519.PublicKey(raw), nil
}
