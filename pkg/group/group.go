// Package group is the contract a group-key-agreement scheme must satisfy, and
// nothing more. It selects no construction and implements no cryptography, for
// the same reason pkg/e2ee does not: choosing the scheme that re-keys a private
// room on every membership change is a protocol-freeze decision, and a scheme
// written here would be a second opinion about a choice that is not this
// repository's to make.
//
// What the package fixes is the shape of the agreement and the properties a
// candidate is refuted against. A room's membership already advances in epochs
// (see pkg/room): each add or remove produces a new epoch and a commitment over
// the member set. A group-key scheme rides those epochs -- every epoch has a
// secret that exactly its members can derive, a member removed at an epoch
// cannot derive the next one, and a member added at an epoch cannot derive the
// previous ones. The membership state machine says who is in the room; the
// scheme says what only they can read.
//
// The refutation harness in the conformance subpackage establishes the absence
// of these properties, never their presence. A scheme that lets a removed
// member reach the next epoch's secret definitively does not re-key on removal.
// The converse does not follow: clearing the harness is a floor, not soundness,
// and selecting a construction still requires cryptographic review the harness
// cannot substitute for.
package group

import (
	"errors"

	"github.com/tosnetwork/tos-messenger/pkg/room"
)

// MinEpochSecretBytes is the shortest an epoch secret may be. A secret shorter
// than this is not a key a scheme could have derived; it is an uninitialised
// field, and it fails closed.
const MinEpochSecretBytes = 16

var (
	// ErrViewUnusable reports a view that cannot be read: absent, malformed, or
	// from a scheme that does not recognise it.
	ErrViewUnusable = errors.New("group view is unusable")

	// ErrNotAMember reports an operation by an identity the epoch it targets
	// does not contain -- a removed member applying the commit that removed
	// them, or a stranger applying any commit.
	ErrNotAMember = errors.New("this identity is not a member of the epoch")

	// ErrCommitUnauthentic reports a commit that does not match the membership
	// it declares, or that no member could have produced.
	ErrCommitUnauthentic = errors.New("group commit is not authentic")
)

// View is one member's private group state at one epoch. It is opaque to
// everyone but the scheme that produced it; a caller persists it and hands it
// back, exactly as with an end-to-end session state.
type View []byte

// Commit is what a member broadcasts when it advances the room to a new
// membership epoch. It carries the public membership (so any recipient can
// check it against the room's own commitment) and scheme-opaque material that
// lets exactly the epoch's members -- and no one else -- reach the new secret.
//
// The membership fields are not the scheme's to interpret loosely: a conforming
// scheme refuses a commit whose declared digest does not reproduce from its
// members, so a commit cannot claim one membership while distributing another.
type Commit struct {
	// RoomID, Epoch, MembershipDigest, and Members restate the room membership
	// commitment this epoch corresponds to.
	RoomID           string
	Epoch            uint64
	MembershipDigest string
	Members          []string
	// Payload is the scheme's own distribution material. It is opaque here.
	Payload []byte
}

// Validate checks the membership envelope of a commit, independent of any
// scheme. It is what lets a recipient reject a commit that lies about its
// membership before a scheme ever inspects the payload.
func (c Commit) Validate() error {
	if !room.ValidRoomID(c.RoomID) {
		return errors.New("commit names no room")
	}
	if c.Epoch == 0 {
		return errors.New("commit names no epoch")
	}
	if len(c.Members) == 0 {
		return errors.New("commit names no members")
	}
	if len(c.Payload) == 0 {
		return errors.New("commit carries no distribution material")
	}
	// The declared digest must reproduce from the declared members, or the
	// commit is distributing one membership under another's name.
	digest, err := room.Digest(c.RoomID, c.Epoch, c.Members)
	if err != nil {
		return err
	}
	if digest != c.MembershipDigest {
		return ErrCommitUnauthentic
	}
	return nil
}

// Scheme is a group-key-agreement construction. Every method is deterministic
// given its inputs except where a scheme draws fresh key material, which it may
// do inside Create and Commit only.
type Scheme interface {
	// AlgorithmID is the frozen identifier of the construction. It must be
	// stable for the lifetime of the value.
	AlgorithmID() string

	// Create returns the founding member's view at the room's first epoch and
	// the commit that welcomes the other founding members. The membership is the
	// room's founding commitment; self must be one of its members. Founding is
	// not symmetric: one member draws the group's first secret and distributes
	// it, and the others reach it through Join, because two members each drawing
	// their own first secret would never agree.
	Create(self string, founding room.Membership) (View, Commit, error)

	// Commit advances a member's view to a new membership epoch and returns the
	// commit the other members apply. next must be the successor membership the
	// room state machine produced; the caller, not the scheme, decides the
	// delta.
	Commit(view View, next room.Membership) (View, Commit, error)

	// Apply advances an existing member's view by a commit another member
	// produced. A member the commit's epoch does not contain is refused with
	// ErrNotAMember, which is what makes a removal take effect.
	Apply(view View, commit Commit) (View, error)

	// Join builds a newly added member's first view from the commit that added
	// them. The resulting view reaches the commit's epoch and no earlier one,
	// which is what keeps a joiner from reading the room's past.
	Join(self string, commit Commit) (View, error)

	// EpochSecret returns the shared secret of the view's current epoch. Every
	// member of that epoch returns the same bytes; no other epoch's members do.
	EpochSecret(view View) ([]byte, error)
}
