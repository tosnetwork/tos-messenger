// Package conformance refutes candidate group-key-agreement schemes.
//
// Every check establishes the absence of a property, never its presence. A
// scheme that lets a removed member reach the next epoch's secret definitively
// does not re-key on removal; a scheme whose joiner shares a secret with the
// epoch before it joined definitively leaks the room's past. Passing every
// check means a candidate cleared a floor, not that it is sound: the properties
// here are structural -- who is addressed, which epoch a view reaches, whether
// a commit matches its membership -- and structure is necessary, not
// sufficient. Selecting a construction still requires cryptographic review of
// the secrecy the structure is supposed to carry, which no black-box harness
// provides.
//
// The harness survives a bad candidate: a scheme that panics or returns
// nonsense is reported as a failed check rather than taking the run down.
package conformance

import (
	"bytes"
	"errors"
	"fmt"

	"github.com/tosnetwork/tos-messenger/pkg/group"
	"github.com/tosnetwork/tos-messenger/pkg/room"
)

// Check is one property and what the candidate did about it.
type Check struct {
	Name   string `json:"name"`
	Passed bool   `json:"passed"`
	Detail string `json:"detail,omitempty"`
}

// Result is a complete run.
type Result struct {
	AlgorithmID string  `json:"algorithm_id"`
	Checks      []Check `json:"checks"`
}

// Failed returns the checks the candidate did not satisfy.
func (r Result) Failed() []Check {
	var failed []Check
	for _, check := range r.Checks {
		if !check.Passed {
			failed = append(failed, check)
		}
	}
	return failed
}

// Passed reports whether every check held.
func (r Result) Passed() bool { return len(r.Failed()) == 0 }

// Names of the properties this harness can refute.
const (
	CheckAlgorithmIdentifier = "algorithm-identifier"
	CheckFoundingAgreement   = "founding-agreement"
	CheckEpochAdvance        = "epoch-advance"
	CheckMembershipBound     = "membership-bound"
	CheckRemovalReKeys       = "removal-re-keys"
	CheckJoinerHasNoPast     = "joiner-has-no-past"
	CheckForgedCommitRefused = "forged-commit-refused"
	CheckSecretBounded       = "secret-bounded"
	CheckViewPortable        = "view-portable"
)

// Verify runs every check against a candidate scheme.
func Verify(scheme group.Scheme) Result {
	if scheme == nil {
		return Result{Checks: []Check{{Name: CheckAlgorithmIdentifier, Detail: "no scheme supplied"}}}
	}
	result := Result{AlgorithmID: safeAlgorithmID(scheme)}
	checks := []struct {
		name string
		run  func(group.Scheme) error
	}{
		{CheckAlgorithmIdentifier, checkAlgorithmIdentifier},
		{CheckFoundingAgreement, checkFoundingAgreement},
		{CheckEpochAdvance, checkEpochAdvance},
		{CheckMembershipBound, checkMembershipBound},
		{CheckRemovalReKeys, checkRemovalReKeys},
		{CheckJoinerHasNoPast, checkJoinerHasNoPast},
		{CheckForgedCommitRefused, checkForgedCommitRefused},
		{CheckSecretBounded, checkSecretBounded},
		{CheckViewPortable, checkViewPortable},
	}
	for _, item := range checks {
		err := guard(func() error { return item.run(scheme) })
		check := Check{Name: item.name, Passed: err == nil}
		if err != nil {
			check.Detail = err.Error()
		}
		result.Checks = append(result.Checks, check)
	}
	return result
}

// guard turns a panicking candidate into a failed check.
func guard(run func() error) (err error) {
	defer func() {
		if recovered := recover(); recovered != nil {
			err = fmt.Errorf("candidate panicked: %v", recovered)
		}
	}()
	return run()
}

func safeAlgorithmID(scheme group.Scheme) (id string) {
	defer func() { _ = recover() }()
	return scheme.AlgorithmID()
}

// The identities and rooms the scenarios are built from.
const (
	roomID = "room_" + "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
)

func member(seed byte) string {
	body := make([]byte, 64)
	for i := range body {
		body[i] = "0123456789abcdef"[seed%16]
	}
	// Vary the first byte so seeds produce distinct identifiers.
	body[0] = "0123456789abcdef"[(seed/16)%16]
	body[1] = "0123456789abcdef"[seed%16]
	return "agent_" + string(body)
}

func founding(members ...string) (room.Membership, error) {
	return room.Found(roomID, members)
}

// scenario is a founded group with the founder's view already established and
// the other founders joined, so a check can start from a live epoch 1.
type scenario struct {
	scheme     group.Scheme
	membership room.Membership
	founder    string
	views      map[string]group.View
}

func newScenario(scheme group.Scheme, members ...string) (*scenario, error) {
	membership, err := founding(members...)
	if err != nil {
		return nil, err
	}
	founder := membership.Members[0]
	founderView, commit, err := scheme.Create(founder, membership)
	if err != nil {
		return nil, fmt.Errorf("create: %w", err)
	}
	if err := commit.Validate(); err != nil {
		return nil, fmt.Errorf("founding commit is not well formed: %w", err)
	}
	views := map[string]group.View{founder: founderView}
	for _, m := range membership.Members {
		if m == founder {
			continue
		}
		view, err := scheme.Join(m, commit)
		if err != nil {
			return nil, fmt.Errorf("join %s: %w", m, err)
		}
		views[m] = view
	}
	return &scenario{scheme: scheme, membership: membership, founder: founder, views: views}, nil
}

// secret reads one member's epoch secret.
func (s *scenario) secret(memberID string) ([]byte, error) {
	view, ok := s.views[memberID]
	if !ok {
		return nil, fmt.Errorf("no view for %s", memberID)
	}
	return s.scheme.EpochSecret(view)
}

// advance drives a membership change: the founder commits it, every continuing
// member applies it, and every newly added member joins. It returns the commit
// so a check can also feed it to a removed member.
func (s *scenario) advance(next room.Membership) (group.Commit, error) {
	priorMembers := s.membership.Members
	founderView, commit, err := s.scheme.Commit(s.views[s.founder], next)
	if err != nil {
		return group.Commit{}, fmt.Errorf("commit: %w", err)
	}
	if err := commit.Validate(); err != nil {
		return group.Commit{}, fmt.Errorf("commit is not well formed: %w", err)
	}
	newViews := map[string]group.View{s.founder: founderView}
	priorSet := asSet(priorMembers)
	for _, m := range next.Members {
		if m == s.founder {
			continue
		}
		if _, continuing := priorSet[m]; continuing {
			view, err := s.scheme.Apply(s.views[m], commit)
			if err != nil {
				return group.Commit{}, fmt.Errorf("apply for %s: %w", m, err)
			}
			newViews[m] = view
			continue
		}
		view, err := s.scheme.Join(m, commit)
		if err != nil {
			return group.Commit{}, fmt.Errorf("join for %s: %w", m, err)
		}
		newViews[m] = view
	}
	s.membership = next
	s.views = newViews
	return commit, nil
}

func checkAlgorithmIdentifier(scheme group.Scheme) error {
	id := scheme.AlgorithmID()
	if id == "" {
		return errors.New("scheme has no algorithm identifier")
	}
	if scheme.AlgorithmID() != id {
		return errors.New("algorithm identifier is not stable")
	}
	return nil
}

// Every current member of an epoch derives the same secret.
func checkFoundingAgreement(scheme group.Scheme) error {
	sc, err := newScenario(scheme, member(1), member(2), member(3))
	if err != nil {
		return err
	}
	return allAgree(sc, sc.membership.Members)
}

// A membership change moves the epoch and the secret with it.
func checkEpochAdvance(scheme group.Scheme) error {
	sc, err := newScenario(scheme, member(1), member(2))
	if err != nil {
		return err
	}
	before, err := sc.secret(sc.founder)
	if err != nil {
		return err
	}
	next, err := sc.membership.Add([]string{member(3)})
	if err != nil {
		return err
	}
	if _, err := sc.advance(next); err != nil {
		return err
	}
	after, err := sc.secret(sc.founder)
	if err != nil {
		return err
	}
	if bytes.Equal(before, after) {
		return errors.New("the epoch secret did not change with the membership")
	}
	return allAgree(sc, sc.membership.Members)
}

// A commit that lies about its membership -- a digest that does not reproduce
// from its members -- is refused.
func checkMembershipBound(scheme group.Scheme) error {
	sc, err := newScenario(scheme, member(1), member(2), member(3))
	if err != nil {
		return err
	}
	next, err := sc.membership.Add([]string{member(4)})
	if err != nil {
		return err
	}
	_, commit, err := scheme.Commit(sc.views[sc.founder], next)
	if err != nil {
		return fmt.Errorf("commit: %w", err)
	}
	tampered := commit
	tampered.MembershipDigest = tampered.MembershipDigest[:len(tampered.MembershipDigest)-1] + "0"
	if tampered.MembershipDigest == commit.MembershipDigest {
		tampered.MembershipDigest = commit.MembershipDigest[:len(commit.MembershipDigest)-1] + "1"
	}
	// A continuing member must refuse the tampered commit.
	if _, err := scheme.Apply(sc.views[member(2)], tampered); err == nil {
		return errors.New("a commit whose digest does not match its members was applied")
	}
	return nil
}

// A member removed at an epoch cannot apply the commit that removed them and
// cannot reach the epoch it produced.
func checkRemovalReKeys(scheme group.Scheme) error {
	sc, err := newScenario(scheme, member(1), member(2), member(3))
	if err != nil {
		return err
	}
	removed := member(3)
	removedView := sc.views[removed]
	next, err := sc.membership.Remove([]string{removed})
	if err != nil {
		return err
	}
	commit, err := sc.advance(next)
	if err != nil {
		return err
	}
	// The removed member, still holding its pre-removal view, is refused.
	if _, err := scheme.Apply(removedView, commit); err == nil {
		return errors.New("a removed member applied the commit that removed it")
	}
	// And the secret the removed member still holds is not the new one.
	stale, err := scheme.EpochSecret(removedView)
	if err != nil {
		return err
	}
	current, err := sc.secret(sc.founder)
	if err != nil {
		return err
	}
	if bytes.Equal(stale, current) {
		return errors.New("a removed member's retained secret still opens the new epoch")
	}
	return allAgree(sc, sc.membership.Members)
}

// A member added at an epoch reaches that epoch's secret and not the one
// before it: joining a room does not hand over its past.
func checkJoinerHasNoPast(scheme group.Scheme) error {
	sc, err := newScenario(scheme, member(1), member(2))
	if err != nil {
		return err
	}
	past, err := sc.secret(sc.founder)
	if err != nil {
		return err
	}
	joiner := member(3)
	next, err := sc.membership.Add([]string{joiner})
	if err != nil {
		return err
	}
	if _, err := sc.advance(next); err != nil {
		return err
	}
	joined, err := sc.secret(joiner)
	if err != nil {
		return err
	}
	current, err := sc.secret(sc.founder)
	if err != nil {
		return err
	}
	if !bytes.Equal(joined, current) {
		return errors.New("a joiner did not reach the epoch it joined")
	}
	if bytes.Equal(joined, past) {
		return errors.New("a joiner shares the secret of an epoch before it joined")
	}
	return nil
}

// A commit no member produced -- a fabricated payload -- is refused.
func checkForgedCommitRefused(scheme group.Scheme) error {
	sc, err := newScenario(scheme, member(1), member(2), member(3))
	if err != nil {
		return err
	}
	next, err := sc.membership.Add([]string{member(4)})
	if err != nil {
		return err
	}
	forged := group.Commit{
		RoomID:           next.RoomID,
		Epoch:            next.Epoch,
		MembershipDigest: next.Digest,
		Members:          next.Members,
		Payload:          []byte("this payload was not produced by any member"),
	}
	if _, err := scheme.Apply(sc.views[member(2)], forged); err == nil {
		return errors.New("a fabricated commit was applied")
	}
	return nil
}

// An epoch secret is at least a key's worth of bytes.
func checkSecretBounded(scheme group.Scheme) error {
	sc, err := newScenario(scheme, member(1), member(2))
	if err != nil {
		return err
	}
	secret, err := sc.secret(sc.founder)
	if err != nil {
		return err
	}
	if len(secret) < group.MinEpochSecretBytes {
		return fmt.Errorf("epoch secret is %d bytes, below the %d-byte floor", len(secret), group.MinEpochSecretBytes)
	}
	return nil
}

// A view survives being persisted and reloaded: it is bytes a caller can store.
func checkViewPortable(scheme group.Scheme) error {
	sc, err := newScenario(scheme, member(1), member(2))
	if err != nil {
		return err
	}
	view := sc.views[sc.founder]
	reloaded := group.View(append([]byte(nil), view...))
	before, err := scheme.EpochSecret(view)
	if err != nil {
		return err
	}
	after, err := scheme.EpochSecret(reloaded)
	if err != nil {
		return fmt.Errorf("a reloaded view was unusable: %w", err)
	}
	if !bytes.Equal(before, after) {
		return errors.New("a reloaded view produced a different secret")
	}
	return nil
}

// allAgree checks that every listed member derives the same secret.
func allAgree(sc *scenario, members []string) error {
	var reference []byte
	for _, m := range members {
		secret, err := sc.secret(m)
		if err != nil {
			return err
		}
		if len(reference) == 0 {
			reference = secret
			continue
		}
		if !bytes.Equal(reference, secret) {
			return fmt.Errorf("members disagree about the epoch secret (%s differs)", m)
		}
	}
	return nil
}

func asSet(members []string) map[string]struct{} {
	set := make(map[string]struct{}, len(members))
	for _, m := range members {
		set[m] = struct{}{}
	}
	return set
}
