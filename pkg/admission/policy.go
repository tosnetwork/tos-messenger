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
	// AdmitDeny refuses the sender outright.
	AdmitDeny Admission = "deny"
)

// ContactPolicy is the recipient's inbox admission policy.
//
// The mechanism is settled here; the parameters are not. What an unknown
// sender must present, whether that is a bond, an invite token, or nothing at
// all, is an open protocol-freeze decision. This package's contribution is
// that a policy is always consulted and that its answer is honoured, not what
// any particular policy says.
type ContactPolicy interface {
	// Admits reports how an event from one Agent should be treated. It is
	// given the sender's Agent identifier and the event kind, and nothing
	// else: a policy that could read the content would be making a content
	// judgement this layer is not entitled to make.
	Admits(senderAgentID string, kind string) Admission

	// Digest is the published identity of this policy. The recipient commits
	// it in its delegation and republishes it in its descriptor, and the gate
	// refuses to run if the policy in memory does not answer to the digest the
	// network was told about. Without that check the published digest is a
	// decoration: an installation could advertise one policy and enforce
	// another, and nothing would notice.
	//
	// It commits the rule a sender has to satisfy, not the recipient's roster.
	// A digest that changed whenever a contact was added would force the
	// descriptor to be republished on every change, and the pattern of those
	// republications would leak the roster the policy exists to keep private.
	Digest() string
}

// policyDigest derives the published identity of a policy from its rule and
// the parameters a sender would have to satisfy.
func policyDigest(rule string, parameters ...string) string {
	buffer := bytes.NewBufferString(canon.DomainInboxPolicy)
	canon.Text(buffer, rule)
	canon.Uint64(buffer, uint64(len(parameters)))
	for _, parameter := range parameters {
		canon.Text(buffer, parameter)
	}
	return canon.Digest(buffer.Bytes())
}

// OpenInbox admits every sender.
//
// A zero-cost open inbox is a supported configuration, not a placeholder. Any
// admission cost has to remain optional, or a recipient who wants to be
// reachable by strangers has no way to say so.
type OpenInbox struct{}

// Admits implements ContactPolicy.
func (OpenInbox) Admits(string, string) Admission { return AdmitAllow }

// Digest implements ContactPolicy.
func (OpenInbox) Digest() string { return policyDigest("open-inbox") }

// AllowList admits known contacts, holds unknown senders for an owner
// decision, and denies anyone explicitly blocked.
//
// It is the invite-only mode the first demonstration is expected to use, which
// exists so that the demonstration does not depend on an economic admission
// profile that is still gated.
type AllowList struct {
	Known   map[string]struct{}
	Blocked map[string]struct{}
	// HoldUnknown keeps an unknown sender for an owner decision instead of
	// refusing them. With it false, an unknown sender is told what the inbox
	// requires.
	HoldUnknown bool
}

// Admits implements ContactPolicy.
func (a AllowList) Admits(senderAgentID string, _ string) Admission {
	if _, blocked := a.Blocked[senderAgentID]; blocked {
		return AdmitDeny
	}
	if _, known := a.Known[senderAgentID]; known {
		return AdmitAllow
	}
	if a.HoldUnknown {
		return AdmitHoldForApproval
	}
	return AdmitRequireAdmission
}

// Digest implements ContactPolicy.
//
// The entries are deliberately not committed. What a sender must satisfy is
// "be known to this recipient", and that rule does not change when the roster
// does.
func (a AllowList) Digest() string {
	unknown := "require-admission"
	if a.HoldUnknown {
		unknown = "hold-for-approval"
	}
	return policyDigest("allow-list", unknown)
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
