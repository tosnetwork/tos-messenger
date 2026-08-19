package negotiation

import (
	"errors"
	"regexp"
	"time"

	"github.com/tosnetwork/tos-messenger/internal/ids"
)

// Authority separates what an Agent may do from what it may only propose.
//
// The levels are not a hierarchy an Agent climbs by arguing well. They are set
// by the owner before the conversation starts, and the only way up is a new
// mandate.
type Authority string

const (
	// AuthorityConverse permits talking and nothing else.
	AuthorityConverse Authority = "conversation"
	// AuthorityPropose permits making non-binding offers.
	AuthorityPropose Authority = "proposal"
	// AuthorityCommit permits producing the exact terms a canonical action
	// would carry. It still does not sign or fund anything.
	AuthorityCommit Authority = "commit"
)

var authorities = map[Authority]struct{}{
	AuthorityConverse: {}, AuthorityPropose: {}, AuthorityCommit: {},
}

// MaxCounteroffers bounds what any mandate may permit. A negotiation that can
// run forever is one an unattended Agent can be kept in indefinitely.
const MaxCounteroffers = 32

var capabilityClassPattern = regexp.MustCompile(`^[a-z][a-z0-9]*(\.[a-z0-9]+)*$`)

// Mandate is what the owner permitted before the conversation began.
//
// It is the reason an Agent can negotiate unattended. Every bound in it is one
// the Agent cannot move: it may counter an offer above the ceiling, and it may
// not raise the ceiling, because the ceiling is not part of the negotiation.
type Mandate struct {
	Objective string `json:"objective"`
	// Authority is the highest level this mandate grants.
	Authority Authority `json:"authority"`
	// CapabilityClass restricts what may be bought.
	CapabilityClass string `json:"capability_class"`
	// MaxTotal is the ceiling. Terms above it are outside the mandate whatever
	// the counterparty says about them.
	MaxTotal Amount `json:"max_total"`
	// ApprovalAbove is the point past which the owner decides personally. It
	// must not exceed the ceiling, or it would describe an approval that could
	// never be reached.
	ApprovalAbove Amount `json:"approval_above"`
	// MaxCounteroffers bounds how long the exchange may run.
	MaxCounteroffers uint32 `json:"max_counteroffers"`
	ExpiresAtUnix    uint64 `json:"expires_at_unix"`
}

// Validate enforces a mandate that can actually decide anything.
func (m Mandate) Validate() error {
	if m.Objective == "" || len(m.Objective) > 512 {
		return errors.New("a mandate needs an objective")
	}
	if _, known := authorities[m.Authority]; !known {
		return errors.New("invalid mandate authority")
	}
	if !capabilityClassPattern.MatchString(m.CapabilityClass) || len(m.CapabilityClass) > 64 {
		return errors.New("invalid mandate capability class")
	}
	if err := m.MaxTotal.Validate(); err != nil {
		return err
	}
	if err := m.ApprovalAbove.Validate(); err != nil {
		return err
	}
	if !m.MaxTotal.SameAsset(m.ApprovalAbove) {
		return errors.New("a mandate's ceiling and approval point must use one asset")
	}
	within, err := m.ApprovalAbove.AtMost(m.MaxTotal)
	if err != nil {
		return err
	}
	if !within {
		return errors.New("a mandate's approval point is above its own ceiling")
	}
	if m.MaxCounteroffers == 0 || m.MaxCounteroffers > MaxCounteroffers {
		return errors.New("invalid mandate counteroffer bound")
	}
	if m.ExpiresAtUnix == 0 {
		return errors.New("a mandate must expire")
	}
	return nil
}

// Live reports whether a mandate is still in force.
func (m Mandate) Live(now time.Time) error {
	if err := m.Validate(); err != nil {
		return err
	}
	if now.IsZero() || now.Unix() < 0 {
		return errors.New("invalid mandate time")
	}
	if uint64(now.Unix()) >= m.ExpiresAtUnix {
		return errors.New("mandate has expired")
	}
	return nil
}

// Permits reports whether terms are inside the mandate, and whether the owner
// must decide personally.
//
// A caller receives both answers together on purpose. Asking whether terms are
// permitted and separately whether approval is needed invites a caller to act
// on the first answer and forget the second.
func (m Mandate) Permits(terms Terms, now time.Time) (needsApproval bool, err error) {
	if err := m.Live(now); err != nil {
		return false, err
	}
	if err := terms.Validate(); err != nil {
		return false, err
	}
	if m.Authority != AuthorityCommit {
		return false, errors.New("this mandate does not permit committing to terms")
	}
	if terms.CapabilityClass != m.CapabilityClass {
		return false, errors.New("terms are for a capability class the mandate does not cover")
	}
	within, err := terms.Total.AtMost(m.MaxTotal)
	if err != nil {
		return false, err
	}
	if !within {
		return false, errors.New("terms exceed the mandate ceiling")
	}
	if terms.NotAfterUnix > m.ExpiresAtUnix {
		return false, errors.New("terms outlive the mandate that permits them")
	}
	above, err := m.ApprovalAbove.AtMost(terms.Total)
	if err != nil {
		return false, err
	}
	// Equal to the approval point counts as reaching it: a threshold nobody
	// can land exactly on is a threshold with an off-by-one in it.
	return above, nil
}

// Terms are the exact commercial and execution terms a commitment would carry.
//
// Every field is one a canonical action must reproduce. A term left out here
// is a term somebody downstream would have to infer, and inference is what
// this layer exists to prevent.
type Terms struct {
	CapabilityID      string `json:"capability_id"`
	CapabilityVersion string `json:"capability_version"`
	CapabilityClass   string `json:"capability_class"`
	Total             Amount `json:"total"`
	NotAfterUnix      uint64 `json:"not_after_unix"`
}

// Validate enforces that terms are complete.
func (t Terms) Validate() error {
	if !ids.Capability.MatchString(t.CapabilityID) {
		return errors.New("terms name no capability")
	}
	if t.CapabilityVersion == "" || len(t.CapabilityVersion) > 64 {
		return errors.New("terms name no capability version")
	}
	if !capabilityClassPattern.MatchString(t.CapabilityClass) {
		return errors.New("terms name no capability class")
	}
	if err := t.Total.Validate(); err != nil {
		return err
	}
	if t.NotAfterUnix == 0 {
		return errors.New("terms must expire")
	}
	return nil
}

// Equal reports whether two sets of terms are the same in every field.
func (t Terms) Equal(other Terms) bool {
	return t.CapabilityID == other.CapabilityID &&
		t.CapabilityVersion == other.CapabilityVersion &&
		t.CapabilityClass == other.CapabilityClass &&
		t.Total.Equal(other.Total) &&
		t.NotAfterUnix == other.NotAfterUnix
}
