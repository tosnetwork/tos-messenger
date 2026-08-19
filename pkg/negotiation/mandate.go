package negotiation

import (
	"bytes"
	"errors"
	"time"

	"github.com/tosnetwork/tos-messenger/internal/canon"
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
	MaxTotal Money `json:"max_total"`
	// ApprovalAbove is the point past which the owner decides personally. It
	// must not exceed the ceiling, or it would describe an approval that could
	// never be reached.
	ApprovalAbove Money `json:"approval_above"`
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

// Permits reports whether terms fall inside a mandate, and whether the owner
// still has to decide personally.
//
// It answers with two values rather than one because "outside what was
// authorised" and "authorised but worth a person's attention" are different
// situations with different remedies. The first ends the exchange; the second
// pauses it.
// Permits judges terms at the conversational level: whether an authority above
// bare conversation may agree to them in principle. It does not authorise a
// commitment; agreeing to terms is not owing them. Use PermitsCommit for the
// boundary where value can actually move.
func (m Mandate) Permits(terms Terms, now time.Time) (needsApproval bool, err error) {
	return m.permits(terms, now, false)
}

// PermitsCommit judges terms at the commitment level: it requires the mandate to
// grant AuthorityCommit, because producing the exact terms a canonical action
// carries -- or authorising a spend against them -- is the one act a proposal
// authority must not reach. A mandate that may only propose is refused here even
// though the same terms would pass Permits.
func (m Mandate) PermitsCommit(terms Terms, now time.Time) (needsApproval bool, err error) {
	return m.permits(terms, now, true)
}

func (m Mandate) permits(terms Terms, now time.Time, requireCommit bool) (needsApproval bool, err error) {
	if err := m.Live(now); err != nil {
		return false, err
	}
	if err := terms.Validate(); err != nil {
		return false, err
	}
	// A mandate that grants only conversation permits no terms at all. It is
	// not a small mandate; it is permission to talk.
	if m.Authority == AuthorityConverse {
		return false, errors.New("this mandate permits conversation and nothing else")
	}
	// A proposal authority may agree to terms in conversation but may never
	// commit them: canonicalisation, finalisation, and spend all pass through
	// PermitsCommit, which is the only caller that sets this.
	if requireCommit && m.Authority != AuthorityCommit {
		return false, errors.New("this mandate may propose but not commit")
	}
	if terms.CapabilityClass != m.CapabilityClass {
		return false, errors.New("these terms buy something the mandate does not cover")
	}
	if !terms.Price.SameAsset(m.MaxTotal) {
		return false, errors.New("these terms are priced in an asset the mandate does not name")
	}
	within, err := terms.Price.AtMost(m.MaxTotal)
	if err != nil {
		return false, err
	}
	if !within {
		return false, errors.New("these terms are above the mandate's ceiling")
	}
	if uint64(now.Unix()) >= terms.NotAfterUnix {
		return false, errors.New("these terms have already expired")
	}
	// Terms that outlive the authority they were agreed under would be a
	// commitment the owner never gave.
	if terms.NotAfterUnix > m.ExpiresAtUnix {
		return false, errors.New("these terms outlive the mandate that permits them")
	}
	under, err := terms.Price.AtMost(m.ApprovalAbove)
	if err != nil {
		return false, err
	}
	return !under, nil
}

// CanonicalBytes returns the preimage that identifies one mandate.
func (m Mandate) CanonicalBytes() ([]byte, error) {
	if err := m.Validate(); err != nil {
		return nil, err
	}
	buffer := bytes.NewBufferString(canon.DomainMandate)
	canon.Text(buffer, m.Objective)
	canon.Text(buffer, string(m.Authority))
	canon.Text(buffer, m.CapabilityClass)
	m.MaxTotal.canonical(buffer)
	m.ApprovalAbove.canonical(buffer)
	canon.Uint32(buffer, m.MaxCounteroffers)
	canon.Uint64(buffer, m.ExpiresAtUnix)
	return buffer.Bytes(), nil
}

// Digest identifies one mandate.
//
// An owner approval is bound to it, so an authority replaced after the fact
// cannot carry the decision that was made under the old one.
func (m Mandate) Digest() (string, error) {
	preimage, err := m.CanonicalBytes()
	if err != nil {
		return "", err
	}
	return canon.Digest(preimage), nil
}
