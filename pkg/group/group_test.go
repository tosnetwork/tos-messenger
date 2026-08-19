package group

import (
	"strings"
	"testing"

	"github.com/tosnetwork/tos-messenger/pkg/room"
)

func testMembership(t *testing.T) room.Membership {
	t.Helper()
	roomID := "room_" + strings.Repeat("a", 64)
	members := []string{
		"agent_" + strings.Repeat("1", 64),
		"agent_" + strings.Repeat("2", 64),
	}
	membership, err := room.Found(roomID, members)
	if err != nil {
		t.Fatalf("found: %v", err)
	}
	return membership
}

func validCommit(t *testing.T) Commit {
	t.Helper()
	m := testMembership(t)
	return Commit{
		RoomID:           m.RoomID,
		Epoch:            m.Epoch,
		MembershipDigest: m.Digest,
		Members:          m.Members,
		Payload:          []byte("distribution material"),
	}
}

// A commit whose digest reproduces from its members and that carries material
// is well formed.
func TestCommitValidateAccepts(t *testing.T) {
	if err := validCommit(t).Validate(); err != nil {
		t.Fatalf("a well-formed commit was refused: %v", err)
	}
}

// A commit whose declared digest does not reproduce from its members is
// distributing one membership under another's name.
func TestCommitValidateRejectsMismatchedDigest(t *testing.T) {
	commit := validCommit(t)
	commit.MembershipDigest = "sha256:" + strings.Repeat("0", 64)
	if err := commit.Validate(); err == nil {
		t.Fatal("a commit whose digest does not match its members was accepted")
	}
}

// The zero-trust surface: each missing or malformed field fails closed.
func TestCommitValidateRejectsMalformed(t *testing.T) {
	cases := map[string]func(*Commit){
		"bad room":       func(c *Commit) { c.RoomID = "room_short" },
		"zero epoch":     func(c *Commit) { c.Epoch = 0 },
		"no members":     func(c *Commit) { c.Members = nil },
		"no payload":     func(c *Commit) { c.Payload = nil },
		"swapped member": func(c *Commit) { c.Members = []string{"agent_" + strings.Repeat("9", 64)} },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			commit := validCommit(t)
			mutate(&commit)
			if err := commit.Validate(); err == nil {
				t.Fatalf("a commit with %q was accepted", name)
			}
		})
	}
}
