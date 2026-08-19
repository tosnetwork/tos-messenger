package room

import (
	"strings"
	"testing"

	"github.com/tosnetwork/tos-messenger/internal/canon"
)

var testRoom = "room_" + strings.Repeat("a", 64)

func agent(seed byte) string {
	return "agent_" + strings.Repeat(string("0123456789abcdef"[seed%16]), 64)
}

func mustFound(t *testing.T, members ...string) Membership {
	t.Helper()
	m, err := Found(testRoom, members)
	if err != nil {
		t.Fatalf("found: %v", err)
	}
	return m
}

// A founding membership is epoch 1 with a sorted, deduplicated member set and a
// digest that matches its members.
func TestFoundIsEpochOne(t *testing.T) {
	m := mustFound(t, agent(3), agent(1), agent(2))
	if m.Epoch != 1 {
		t.Fatalf("first epoch is %d, want 1", m.Epoch)
	}
	if len(m.Members) != 3 {
		t.Fatalf("member count %d, want 3", len(m.Members))
	}
	for i := 1; i < len(m.Members); i++ {
		if m.Members[i-1] >= m.Members[i] {
			t.Fatalf("members are not sorted: %v", m.Members)
		}
	}
	digest, err := Digest(testRoom, 1, m.Members)
	if err != nil {
		t.Fatalf("digest: %v", err)
	}
	if m.Digest != digest || !canon.ValidDigest(m.Digest) {
		t.Fatalf("digest %q does not match members", m.Digest)
	}
}

func TestFoundRejectsEmptyAndInvalid(t *testing.T) {
	if _, err := Found(testRoom, nil); err == nil {
		t.Fatal("an empty room was founded")
	}
	if _, err := Found("room_short", []string{agent(1)}); err == nil {
		t.Fatal("an invalid room id was accepted")
	}
	if _, err := Found(testRoom, []string{"not-an-agent"}); err == nil {
		t.Fatal("a non-agent member was accepted")
	}
	if _, err := Found(testRoom, []string{agent(1), agent(1)}); err == nil {
		t.Fatal("a duplicate founder was accepted")
	}
}

// Adding advances the epoch by exactly one and changes the digest.
func TestAddAdvancesEpoch(t *testing.T) {
	m := mustFound(t, agent(1), agent(2))
	next, err := m.Add([]string{agent(3)})
	if err != nil {
		t.Fatalf("add: %v", err)
	}
	if next.Epoch != 2 {
		t.Fatalf("epoch %d, want 2", next.Epoch)
	}
	if !next.Contains(agent(3)) {
		t.Fatal("the added member is absent")
	}
	if next.Digest == m.Digest {
		t.Fatal("the digest did not change with membership")
	}
	// The prior membership is untouched: a transition returns a successor.
	if m.Epoch != 1 || m.Contains(agent(3)) {
		t.Fatal("the prior membership was mutated")
	}
}

func TestAddRejectsDuplicateAndEmpty(t *testing.T) {
	m := mustFound(t, agent(1), agent(2))
	if _, err := m.Add([]string{agent(1)}); err == nil {
		t.Fatal("a member already present was added again")
	}
	if _, err := m.Add(nil); err == nil {
		t.Fatal("an empty add advanced the epoch")
	}
	if _, err := m.Add([]string{agent(3), agent(3)}); err == nil {
		t.Fatal("a duplicate within one add was accepted")
	}
}

// Removing advances the epoch, and a removed member can be added back at a
// later epoch -- membership is an Agent, not a permanently revoked key.
func TestRemoveThenReAdd(t *testing.T) {
	m := mustFound(t, agent(1), agent(2), agent(3))
	removed, err := m.Remove([]string{agent(2)})
	if err != nil {
		t.Fatalf("remove: %v", err)
	}
	if removed.Epoch != 2 || removed.Contains(agent(2)) {
		t.Fatalf("removal did not take: epoch %d", removed.Epoch)
	}
	readded, err := removed.Add([]string{agent(2)})
	if err != nil {
		t.Fatalf("re-add: %v", err)
	}
	if readded.Epoch != 3 || !readded.Contains(agent(2)) {
		t.Fatal("a removed member could not return")
	}
}

func TestRemoveRejectsAbsentAndLastMember(t *testing.T) {
	m := mustFound(t, agent(1), agent(2))
	if _, err := m.Remove([]string{agent(9)}); err == nil {
		t.Fatal("a member not present was removed")
	}
	if _, err := m.Remove(nil); err == nil {
		t.Fatal("an empty removal advanced the epoch")
	}
	if _, err := m.Remove([]string{agent(1), agent(2)}); err == nil {
		t.Fatal("the room was emptied")
	}
}

// Re-adding a removed member reproduces an earlier member set but at a higher
// epoch, and the digest differs because the epoch is inside the preimage. This
// is what stops an old membership being replayed as a current one.
func TestSameMembersDifferentEpochDifferentDigest(t *testing.T) {
	first, err := Digest(testRoom, 2, []string{agent(1), agent(2)})
	if err != nil {
		t.Fatalf("digest: %v", err)
	}
	second, err := Digest(testRoom, 5, []string{agent(1), agent(2)})
	if err != nil {
		t.Fatalf("digest: %v", err)
	}
	if first == second {
		t.Fatal("two epochs with the same members share a digest")
	}
}

// The digest does not depend on the order members are named in.
func TestDigestIsOrderIndependent(t *testing.T) {
	a, err := Digest(testRoom, 1, []string{agent(1), agent(2), agent(3)})
	if err != nil {
		t.Fatalf("digest: %v", err)
	}
	b, err := Digest(testRoom, 1, []string{agent(3), agent(1), agent(2)})
	if err != nil {
		t.Fatalf("digest: %v", err)
	}
	if a != b {
		t.Fatal("digest depends on member order")
	}
}

// Announce and VerifyCommit are inverses: a room's own commit verifies against
// its membership, and a commit with a swapped digest is refused.
func TestAnnounceRoundTrips(t *testing.T) {
	m := mustFound(t, agent(1), agent(2))
	commitment, err := m.Announce()
	if err != nil {
		t.Fatalf("announce: %v", err)
	}
	if commitment.Epoch != m.Epoch || commitment.MemberCount != 2 {
		t.Fatalf("commit does not describe the membership: %+v", commitment)
	}
	if err := m.VerifyCommit(commitment); err != nil {
		t.Fatalf("a room's own commit failed to verify: %v", err)
	}
	tampered := commitment
	tampered.MembershipDigest = canon.Digest([]byte("forged"))
	if err := m.VerifyCommit(tampered); err == nil {
		t.Fatal("a commit with a forged digest verified")
	}
	wrongEpoch := commitment
	wrongEpoch.Epoch = 9
	if err := m.VerifyCommit(wrongEpoch); err == nil {
		t.Fatal("a commit naming another epoch verified")
	}
}

// A membership whose digest was tampered without recomputing is unusable.
func TestTamperedMembershipIsUnusable(t *testing.T) {
	m := mustFound(t, agent(1), agent(2))
	m.Members = append(m.Members, agent(3)) // digest no longer matches
	if _, err := m.Add([]string{agent(4)}); err == nil {
		t.Fatal("a transition from a tampered membership succeeded")
	}
	if _, err := m.Announce(); err == nil {
		t.Fatal("a tampered membership announced")
	}
}

// The member bound is enforced.
func TestRoomFull(t *testing.T) {
	members := make([]string, 0, MaxMembers)
	// Distinct valid agent ids: vary a 64-hex-char body deterministically.
	for i := 0; i < MaxMembers; i++ {
		members = append(members, distinctAgent(i))
	}
	m, err := Found(testRoom, members)
	if err != nil {
		t.Fatalf("found at capacity: %v", err)
	}
	if _, err := m.Add([]string{distinctAgent(MaxMembers)}); err != ErrRoomFull {
		t.Fatalf("add past capacity returned %v, want ErrRoomFull", err)
	}
}

func distinctAgent(i int) string {
	const hexdigits = "0123456789abcdef"
	body := make([]byte, 64)
	for j := 0; j < 64; j++ {
		body[j] = hexdigits[(i>>(uint(j%16)*0))%16]
	}
	// Encode i across the first several nibbles so ids are distinct.
	v := i
	for j := 0; j < 16; j++ {
		body[j] = hexdigits[v&0xf]
		v >>= 4
	}
	for j := 16; j < 64; j++ {
		body[j] = 'a'
	}
	return "agent_" + string(body)
}
