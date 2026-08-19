package conformance

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"errors"
	"sort"
	"testing"

	"github.com/tosnetwork/tos-messenger/pkg/group"
	"github.com/tosnetwork/tos-messenger/pkg/room"
)

// example is NOT cryptography and must never be used for anything. It is a
// structural stand-in: it re-keys on every membership change by drawing a fresh
// group seed and distributing it, in the clear, to exactly the epoch's members.
// The secrecy a real scheme would provide is absent; what is present is the
// protocol structure the harness checks -- who is addressed, which epoch a view
// reaches, whether a commit matches its membership. It exists to prove the
// harness passes a scheme built to satisfy those properties.
type example struct{}

func (example) AlgorithmID() string { return "tos.messaging.group.example.v1" }

type exampleView struct {
	RoomID  string   `json:"room_id"`
	Epoch   uint64   `json:"epoch"`
	Self    string   `json:"self"`
	Members []string `json:"members"`
	Seed    []byte   `json:"seed"`
}

// welcome is the commit payload: the epoch's seed, addressed to each member
// other than the committer. A member not addressed cannot reach the seed.
type welcome struct {
	Seeds map[string][]byte `json:"seeds"`
}

func encodeView(v exampleView) group.View {
	encoded, err := json.Marshal(v)
	if err != nil {
		panic(err) // test double only
	}
	return encoded
}

func decodeView(raw group.View) (exampleView, error) {
	var v exampleView
	if err := json.Unmarshal(raw, &v); err != nil || len(v.Seed) == 0 || v.Self == "" {
		return exampleView{}, group.ErrViewUnusable
	}
	return v, nil
}

func freshSeed() []byte {
	seed := make([]byte, 32)
	if _, err := rand.Read(seed); err != nil {
		panic(err) // test double only
	}
	return seed
}

// distribute builds a commit that carries seed to every member but the
// committer.
func distribute(membership room.Membership, committer string, seed []byte) (group.Commit, error) {
	seeds := map[string][]byte{}
	for _, m := range membership.Members {
		if m == committer {
			continue
		}
		seeds[m] = append([]byte(nil), seed...)
	}
	payload, err := json.Marshal(welcome{Seeds: seeds})
	if err != nil {
		return group.Commit{}, err
	}
	commit := group.Commit{
		RoomID:           membership.RoomID,
		Epoch:            membership.Epoch,
		MembershipDigest: membership.Digest,
		Members:          membership.Members,
		Payload:          payload,
	}
	return commit, commit.Validate()
}

func (example) Create(self string, founding room.Membership) (group.View, group.Commit, error) {
	if !founding.Contains(self) {
		return nil, group.Commit{}, errors.New("founder is not a member")
	}
	seed := freshSeed()
	commit, err := distribute(founding, self, seed)
	if err != nil {
		return nil, group.Commit{}, err
	}
	view := encodeView(exampleView{
		RoomID: founding.RoomID, Epoch: founding.Epoch, Self: self,
		Members: founding.Members, Seed: seed,
	})
	return view, commit, nil
}

func (example) Commit(raw group.View, next room.Membership) (group.View, group.Commit, error) {
	view, err := decodeView(raw)
	if err != nil {
		return nil, group.Commit{}, err
	}
	if next.RoomID != view.RoomID {
		return nil, group.Commit{}, errors.New("commit crosses rooms")
	}
	if next.Epoch <= view.Epoch {
		return nil, group.Commit{}, errors.New("commit does not advance the epoch")
	}
	if !next.Contains(view.Self) {
		return nil, group.Commit{}, errors.New("a committer cannot remove itself")
	}
	seed := freshSeed()
	commit, err := distribute(next, view.Self, seed)
	if err != nil {
		return nil, group.Commit{}, err
	}
	out := encodeView(exampleView{
		RoomID: next.RoomID, Epoch: next.Epoch, Self: view.Self,
		Members: next.Members, Seed: seed,
	})
	return out, commit, nil
}

func (example) Apply(raw group.View, commit group.Commit) (group.View, error) {
	view, err := decodeView(raw)
	if err != nil {
		return nil, err
	}
	if err := commit.Validate(); err != nil {
		return nil, err
	}
	if commit.RoomID != view.RoomID {
		return nil, group.ErrCommitUnauthentic
	}
	if commit.Epoch <= view.Epoch {
		return nil, errors.New("commit does not advance the epoch")
	}
	return joinFrom(view.Self, commit)
}

func (example) Join(self string, commit group.Commit) (group.View, error) {
	if err := commit.Validate(); err != nil {
		return nil, err
	}
	return joinFrom(self, commit)
}

func joinFrom(self string, commit group.Commit) (group.View, error) {
	if !contains(commit.Members, self) {
		return nil, group.ErrNotAMember
	}
	var w welcome
	if err := json.Unmarshal(commit.Payload, &w); err != nil {
		return nil, group.ErrCommitUnauthentic
	}
	seed, addressed := w.Seeds[self]
	if !addressed || len(seed) == 0 {
		return nil, group.ErrNotAMember
	}
	return encodeView(exampleView{
		RoomID: commit.RoomID, Epoch: commit.Epoch, Self: self,
		Members: commit.Members, Seed: seed,
	}), nil
}

func (example) EpochSecret(raw group.View) ([]byte, error) {
	view, err := decodeView(raw)
	if err != nil {
		return nil, err
	}
	members := append([]string(nil), view.Members...)
	sort.Strings(members)
	// A plain, deliberately non-protocol prefix: this double reserves no
	// namespace in the canonical domain registry, because it is not a scheme
	// anything would encode against.
	buffer := bytes.NewBufferString("group-example-epoch-secret|")
	buffer.Write(view.Seed)
	buffer.WriteString(view.RoomID)
	var epoch [8]byte
	binary.BigEndian.PutUint64(epoch[:], view.Epoch)
	buffer.Write(epoch[:])
	for _, m := range members {
		buffer.WriteString(m)
		buffer.WriteByte(0)
	}
	sum := sha256.Sum256(buffer.Bytes())
	return sum[:], nil
}

func contains(list []string, value string) bool {
	for _, item := range list {
		if item == value {
			return true
		}
	}
	return false
}

// The reference example clears every check. A harness that never passes a
// well-built scheme is as useless as one that never fails a broken one.
func TestExampleSchemePasses(t *testing.T) {
	result := Verify(example{})
	if !result.Passed() {
		for _, failed := range result.Failed() {
			t.Errorf("the example scheme failed %s: %s", failed.Name, failed.Detail)
		}
	}
	if len(result.Checks) == 0 {
		t.Fatal("no checks ran")
	}
}

// A nil scheme is a failed run, not a panic.
func TestNilScheme(t *testing.T) {
	if Verify(nil).Passed() {
		t.Fatal("a nil scheme passed")
	}
}

// The doubles below are each broken in one named way. The harness must report
// that breakage; a harness that passes all of them has never been shown to
// discriminate.

// addressesRemoved re-keys but hands the new seed to everyone who applies,
// membership be damned -- so a removed member can still apply the removal.
type acceptsAnyApply struct{ example }

func (acceptsAnyApply) Apply(_ group.View, commit group.Commit) (group.View, error) {
	// Ignore who the caller is and whether they are addressed: derive a view
	// from the commit for anyone. This is exactly the removal defect.
	seed := sha256.Sum256(commit.Payload)
	return encodeView(exampleView{
		RoomID: commit.RoomID, Epoch: commit.Epoch, Self: "anyone",
		Members: commit.Members, Seed: seed[:],
	}), nil
}

// frozenSecret never lets the secret change: it returns a constant.
type frozenSecret struct{ example }

func (frozenSecret) EpochSecret(_ group.View) ([]byte, error) {
	return bytes.Repeat([]byte{0x5a}, 32), nil
}

// shortSecret returns a secret below the byte floor.
type shortSecret struct{ example }

func (shortSecret) EpochSecret(raw group.View) ([]byte, error) {
	secret, err := example{}.EpochSecret(raw)
	if err != nil {
		return nil, err
	}
	return secret[:8], nil
}

// skipsMembershipCheck applies a commit without checking that its digest
// matches its members.
type skipsMembershipCheck struct{ example }

func (skipsMembershipCheck) Apply(raw group.View, commit group.Commit) (group.View, error) {
	view, err := decodeView(raw)
	if err != nil {
		return nil, err
	}
	// No commit.Validate(): a lied-about membership sails through.
	return joinFrom(view.Self, commit)
}

// panicsOnCommit dies when asked to advance.
type panicsOnCommit struct{ example }

func (panicsOnCommit) Commit(_ group.View, _ room.Membership) (group.View, group.Commit, error) {
	panic("this candidate is broken")
}

func TestHarnessCatchesBrokenSchemes(t *testing.T) {
	cases := []struct {
		name   string
		scheme group.Scheme
		expect string
	}{
		{"accepts-any-apply", acceptsAnyApply{}, CheckRemovalReKeys},
		{"frozen-secret", frozenSecret{}, CheckEpochAdvance},
		{"short-secret", shortSecret{}, CheckSecretBounded},
		{"skips-membership-check", skipsMembershipCheck{}, CheckMembershipBound},
		{"panics-on-commit", panicsOnCommit{}, CheckEpochAdvance},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			result := Verify(tc.scheme)
			if result.Passed() {
				t.Fatalf("%s passed the harness but is broken", tc.name)
			}
			found := false
			for _, failed := range result.Failed() {
				if failed.Name == tc.expect {
					found = true
				}
			}
			if !found {
				t.Fatalf("%s did not fail the expected check %q; failures: %v",
					tc.name, tc.expect, result.Failed())
			}
		})
	}
}
