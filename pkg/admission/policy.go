// Package admission decides whether a decrypted inbound event may reach an
// Agent runtime.
//
// This is the lower half of the context firewall. It establishes that an event
// came from the party it claims, inside the scope that party was delegated,
// within its own validity window, past the recipient's inbox policy, and that
// it has not already been delivered. What it deliberately does not do is
// decide what the content means: marking remote text as untrusted, refusing to
// let it reach an instruction channel, and routing side effects through owner
// approval belong to the runtime, and putting them here would imply this
// package had judged the content safe.
//
// A valid signature proves origin, not safety. Nothing in this package should
// ever be read as saying otherwise.
package admission

import (
	"bytes"
	"errors"

	"github.com/tosnetwork/tos-messenger/internal/canon"
	"github.com/tosnetwork/tos-messenger/pkg/fault"
)

// Admission is what a recipient's inbox policy says about a sender.
type Admission string

const (
	// AdmitAllow lets the event through to the remaining checks.
	AdmitAllow Admission = "allow"
	// AdmitRequireAdmission refuses an unknown sender that has not satisfied
	// the published inbox policy, and tells them so, because a sender who
	// cannot learn what is required cannot satisfy it.
	AdmitRequireAdmission Admission = "require-admission"
	// AdmitHoldForApproval keeps the event for an owner decision. The sender
	// is told nothing that distinguishes this from a refusal.
	AdmitHoldForApproval Admission = "hold-for-approval"
	// AdmitInviteOrHold lets the gate satisfy first contact with a valid
	// one-time invite; without one, the event waits for the owner.
	AdmitInviteOrHold Admission = "invite-or-hold"
	// AdmitDeny refuses the sender outright.
	AdmitDeny Admission = "deny"
)

// InboxRule is the closed set of admission rules this build implements.
type InboxRule string

const (
	// RuleOpen admits every sender. A zero-cost open inbox is a supported
	// configuration, not a placeholder: any admission cost has to remain
	// optional, or a recipient who wants to be reachable by strangers has no
	// way to say so.
	RuleOpen InboxRule = "open-inbox"
	// RuleAllowList admits known contacts and denies anyone blocked.
	RuleAllowList InboxRule = "allow-list"
)

// UnknownSenderRule is what happens to a sender the roster does not name.
type UnknownSenderRule string

const (
	// TellThem refuses and says what the inbox requires, because a sender who
	// cannot learn what is required cannot satisfy it.
	TellThem UnknownSenderRule = "require-admission"
	// AskTheOwner keeps the event for an owner decision.
	AskTheOwner UnknownSenderRule = "hold-for-approval"
	// InviteOrAskOwner is the v1 default: an invitation admits one event and
	// every other unknown sender waits for an owner decision.
	InviteOrAskOwner UnknownSenderRule = "invite-or-hold"
)

// InboxPolicyDocument is the published description of an inbox policy.
//
// It is what the digest is computed from and what the evaluator is built from,
// which is the point. When a policy could declare its own digest, an
// implementation could answer "allow everyone" while publishing the identity
// of an invite-only inbox, and the check would pass: the digest would be
// testing whether an implementation agreed with itself.
type InboxPolicyDocument struct {
	Rule InboxRule
	// Unknown applies to an allow list only.
	Unknown UnknownSenderRule
}

// Validate enforces a document this build can evaluate.
func (d InboxPolicyDocument) Validate() error {
	switch d.Rule {
	case RuleOpen:
		if d.Unknown != "" {
			return errors.New("an open inbox has no rule for unknown senders")
		}
		return nil
	case RuleAllowList:
		if d.Unknown != TellThem && d.Unknown != AskTheOwner && d.Unknown != InviteOrAskOwner {
			return errors.New("an allow list must say what happens to an unknown sender")
		}
		return nil
	default:
		return errors.New("this build does not implement that inbox rule")
	}
}

// Digest is the published identity of a policy.
//
// It commits the rule a sender has to satisfy, not the recipient's roster. A
// digest that changed whenever a contact was added would force the descriptor
// to be republished on every change, and the pattern of those republications
// would leak the roster the policy exists to keep private.
func (d InboxPolicyDocument) Digest() (string, error) {
	if err := d.Validate(); err != nil {
		return "", err
	}
	buffer := bytes.NewBufferString(canon.DomainInboxPolicy)
	canon.Text(buffer, string(d.Rule))
	canon.Text(buffer, string(d.Unknown))
	return canon.Digest(buffer.Bytes()), nil
}

// Roster is the recipient's private contact list.
//
// It is deliberately not part of the document and not part of the digest. Who
// a recipient knows is theirs; what a stranger must do to reach them is
// public.
type Roster struct {
	Known   map[string]struct{}
	Blocked map[string]struct{}
}

// ContactPolicy is a document and the roster it is evaluated against.
//
// It is a closed type rather than an interface. An interface here would let
// any package supply a pair of methods where one says what the policy is and
// the other says what it does, and nothing could make those two agree. Adding
// a rule means adding it to this build, where the digest and the behaviour are
// derived from the same document.
type ContactPolicy struct {
	document InboxPolicyDocument
	roster   Roster
	digest   string
}

// NewContactPolicy builds the evaluator for one published document.
func NewContactPolicy(document InboxPolicyDocument, roster Roster) (ContactPolicy, error) {
	digest, err := document.Digest()
	if err != nil {
		return ContactPolicy{}, err
	}
	return ContactPolicy{document: document, roster: roster, digest: digest}, nil
}

// OpenInbox is the policy that admits everyone.
func OpenInbox() ContactPolicy {
	policy, err := NewContactPolicy(InboxPolicyDocument{Rule: RuleOpen}, Roster{})
	if err != nil {
		panic("the open inbox document is not valid: " + err.Error())
	}
	return policy
}

// Digest returns the published identity of this policy.
func (p ContactPolicy) Digest() string { return p.digest }

// Document returns what was published.
func (p ContactPolicy) Document() InboxPolicyDocument { return p.document }

// Configured reports whether this policy was built rather than zero-valued.
func (p ContactPolicy) Configured() bool { return p.digest != "" }

// Admits reports how an event from one Agent should be treated.
//
// It is given the sender's Agent identifier and the event kind, and nothing
// else: a policy that could read the content would be making a content
// judgement this layer is not entitled to make.
func (p ContactPolicy) Admits(senderAgentID string, _ string) Admission {
	if p.document.Rule == RuleOpen {
		return AdmitAllow
	}
	if _, blocked := p.roster.Blocked[senderAgentID]; blocked {
		return AdmitDeny
	}
	if _, known := p.roster.Known[senderAgentID]; known {
		return AdmitAllow
	}
	if p.document.Unknown == AskTheOwner {
		return AdmitHoldForApproval
	}
	if p.document.Unknown == InviteOrAskOwner {
		return AdmitInviteOrHold
	}
	return AdmitRequireAdmission
}

// codeFor maps a policy answer to its failure code.
func codeFor(admission Admission) (fault.Code, error) {
	switch admission {
	case AdmitRequireAdmission:
		return fault.CodeAdmissionRequired, nil
	case AdmitHoldForApproval:
		return fault.CodeApprovalRequired, nil
	case AdmitDeny:
		// A denied sender learns only that they were refused. Telling them
		// they are blocked confirms the recipient knows who they are.
		return fault.CodeRejected, nil
	default:
		return "", errors.New("policy returned an unknown admission")
	}
}
