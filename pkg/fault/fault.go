// Package fault defines the Messenger's typed failures and what a caller may
// do about them.
//
// Two decisions are encoded here that a per-call-site error string cannot
// carry. The first is the retry disposition: whether an attempt can ever
// succeed again, whether it needs fresh state first, and whether it is waiting
// on a person rather than on time. The second is peer visibility.
//
// An error code returned to a stranger is an oracle. A sender who can tell
// "not authentic" from "already delivered" learns what reached the recipient;
// one who can tell "no such mailbox" from "refused" learns who exists. Some
// codes must still be returned, because a sender who cannot learn why they
// were refused cannot fix it, and the admission model depends on them being
// able to. So visibility is a property of the code, decided once, and
// everything that is not visible collapses into a single indistinguishable
// refusal.
package fault

import "errors"

// Disposition is what a caller may do after a failure.
type Disposition string

const (
	// Permanent means no repetition of this attempt can succeed.
	Permanent Disposition = "permanent"
	// Transient means the condition is expected to pass on its own.
	Transient Disposition = "transient"
	// Refresh means a retry is possible only after resolving current state
	// again: a new delegation, a new descriptor, a new session, or an
	// admission commitment the sender has yet to make.
	Refresh Disposition = "refresh-state"
	// Approval means the attempt is waiting on an owner decision. It is never
	// retried on a timer, because a timer would ask a person the same question
	// repeatedly; it resumes when the decision arrives.
	Approval Disposition = "await-approval"
)

// Code is a typed failure.
type Code string

// Authority and identity.
const (
	// CodeNetworkMismatch reports an object from another network domain.
	CodeNetworkMismatch Code = "network-mismatch"
	// CodeDelegationUncommitted reports a delegation the finalized Agent does
	// not commit.
	CodeDelegationUncommitted Code = "delegation-uncommitted"
	// CodeDelegationExpired reports a delegation outside its window.
	CodeDelegationExpired Code = "delegation-expired"
	// CodeAgentTombstoned reports a revoked Agent.
	CodeAgentTombstoned Code = "agent-tombstoned"
	// CodeDeviceRevoked reports a sending device removed from its endpoint's
	// published set. It is peer-visible and permanent: a well-behaved sender
	// whose device was legitimately retired needs to learn it is retired, and
	// a device that comes back does so under a fresh key, which is a fresh
	// identifier, not a retried one.
	CodeDeviceRevoked Code = "device-revoked"
	// CodeSignatureInvalid reports a signature that is not from the key the
	// delegation authorizes.
	CodeSignatureInvalid Code = "signature-invalid"
	// CodeSenderMismatch reports an event whose declared sender is not the
	// party the delegation covers. It is impersonation inside an otherwise
	// authenticated channel, which is a different failure from a bad
	// signature.
	CodeSenderMismatch Code = "sender-mismatch"
)

// Discovery.
const (
	// CodeDescriptorExpired reports a Contact Descriptor past its expiry.
	CodeDescriptorExpired Code = "descriptor-expired"
	// CodeDescriptorUnbound reports a descriptor its delegation does not
	// authorize.
	CodeDescriptorUnbound Code = "descriptor-unbound"
	// CodeLocatorStale reports a DHT value that no longer resolves.
	CodeLocatorStale Code = "locator-stale"
	// CodeNoRouteAdvertised reports an endpoint with no usable route.
	CodeNoRouteAdvertised Code = "no-route-advertised"
)

// Transport.
const (
	// CodeUnreachable reports an endpoint that could not be reached.
	CodeUnreachable Code = "unreachable"
	// CodeTimeout reports an attempt that ran out of time.
	CodeTimeout Code = "timeout"
	// CodeRateLimited reports a caller sending faster than permitted.
	CodeRateLimited Code = "rate-limited"
	// CodeOversized reports an object beyond a published bound.
	CodeOversized Code = "oversized"
)

// Session and encryption.
const (
	// CodeNotAuthentic reports a ciphertext that failed authentication.
	CodeNotAuthentic Code = "not-authentic"
	// CodeReplayed reports an event already delivered.
	CodeReplayed Code = "replayed"
	// CodeSessionExpired reports a session past its permitted lifetime.
	CodeSessionExpired Code = "session-expired"
	// CodeSuiteUnsupported reports a suite this endpoint does not implement.
	CodeSuiteUnsupported Code = "suite-unsupported"
)

// Policy and admission.
const (
	// CodeClassNotDelegated reports an event class outside the delegated scope.
	CodeClassNotDelegated Code = "class-not-delegated"
	// CodeAdmissionRequired reports an inbox policy the sender has not
	// satisfied.
	CodeAdmissionRequired Code = "admission-required"
	// CodeUnknownEventKind reports a kind this build does not recognise.
	CodeUnknownEventKind Code = "unknown-event-kind"
	// CodeNotARoomMember reports an event addressed to a room whose sender this
	// installation does not hold as a member of that room at its current epoch.
	// It is peer-visible and a refresh, not permanent: a sender removed since
	// they last synchronised needs to learn it, and one this installation has
	// simply not caught up to can be re-admitted once it has, so the remedy is
	// to reconcile membership rather than to give up.
	CodeNotARoomMember Code = "not-a-room-member"
	// CodeContentTooLarge reports content beyond the accepted bound.
	CodeContentTooLarge Code = "content-too-large"
	// CodePayloadMalformed reports a body that is not what its own kind says
	// it is. It is peer-visible because it is a fact about the sender's own
	// message: withholding it would leave a correct implementation unable to
	// tell a rejection from a network fault.
	CodePayloadMalformed Code = "payload-malformed"
	// CodeEventOutsideWindow reports an event past its own expiry or dated far
	// enough ahead that no honest clock explains it.
	CodeEventOutsideWindow Code = "event-outside-window"
	// CodeApprovalRequired reports an event held for an owner decision.
	CodeApprovalRequired Code = "approval-required"
)

// Storage.
const (
	// CodeRelayFull reports a Relay with no room.
	CodeRelayFull Code = "relay-full"
	// CodeRetentionExceeded reports a retention request beyond what is offered.
	CodeRetentionExceeded Code = "retention-exceeded"
	// CodeQuotaExceeded reports an exhausted quota.
	CodeQuotaExceeded Code = "quota-exceeded"
)

// Internal and generic.
const (
	// CodeInternal reports a local failure that says nothing about the peer.
	CodeInternal Code = "internal"
	// CodeRejected is what a peer is told when the real code would leak. It is
	// deliberately uninformative and is never used internally.
	CodeRejected Code = "rejected"
)

// spec is the fixed classification of one code.
type spec struct {
	disposition Disposition
	peerVisible bool
	retryHint   bool
}

// registry classifies every code exactly once.
//
// Visibility is the judgement in this table. A code is visible when a
// legitimate sender needs it to correct their own request, and hidden when
// knowing it would tell them something about the recipient they could not
// otherwise learn: whether an event arrived, whether a person is looking at
// it, or whether an address is in use.
var registry = map[Code]spec{
	CodeNetworkMismatch:       {Permanent, true, false},
	CodeDelegationUncommitted: {Refresh, true, false},
	CodeDelegationExpired:     {Refresh, true, false},
	CodeAgentTombstoned:       {Permanent, true, false},
	CodeDeviceRevoked:         {Permanent, true, false},
	CodeSignatureInvalid:      {Permanent, true, false},
	CodeSenderMismatch:        {Permanent, true, false},

	CodeDescriptorExpired: {Refresh, true, false},
	CodeDescriptorUnbound: {Permanent, true, false},
	CodeLocatorStale:      {Refresh, false, false},
	CodeNoRouteAdvertised: {Permanent, true, false},

	CodeUnreachable: {Transient, false, false},
	CodeTimeout:     {Transient, false, false},
	CodeRateLimited: {Transient, true, true},
	CodeOversized:   {Permanent, true, false},

	// Authentication and replay outcomes stay hidden. A sender able to
	// separate them can use the endpoint as a delivery oracle.
	CodeNotAuthentic:     {Permanent, false, false},
	CodeReplayed:         {Permanent, false, false},
	CodeSessionExpired:   {Refresh, true, false},
	CodeSuiteUnsupported: {Permanent, true, false},

	CodeClassNotDelegated:  {Permanent, true, false},
	CodeAdmissionRequired:  {Refresh, true, true},
	CodeUnknownEventKind:   {Permanent, true, false},
	CodeNotARoomMember:     {Refresh, true, false},
	CodeContentTooLarge:    {Permanent, true, false},
	CodePayloadMalformed:   {Permanent, true, false},
	CodeEventOutsideWindow: {Permanent, true, false},
	// Telling a sender that a person is deciding confirms the event arrived
	// and was read by policy, so the owner's queue stays invisible.
	CodeApprovalRequired: {Approval, false, false},

	CodeRelayFull:         {Transient, true, true},
	CodeRetentionExceeded: {Permanent, true, false},
	CodeQuotaExceeded:     {Transient, true, true},

	CodeInternal: {Transient, false, false},
	CodeRejected: {Permanent, true, false},
}

// Codes returns every classified code.
func Codes() []Code {
	codes := make([]Code, 0, len(registry))
	for code := range registry {
		codes = append(codes, code)
	}
	return codes
}

// Known reports whether a code is classified. An unclassified code is a
// programming error, never a value accepted from a wire.
func Known(code Code) bool {
	_, found := registry[code]
	return found
}

// DispositionOf returns the retry disposition of a code. An unknown code is
// treated as permanent: a failure nobody classified is not one to retry
// blindly.
func DispositionOf(code Code) Disposition {
	if classification, found := registry[code]; found {
		return classification.disposition
	}
	return Permanent
}

// PeerVisible reports whether a code may be returned to the sender.
func PeerVisible(code Code) bool {
	classification, found := registry[code]
	return found && classification.peerVisible
}

// Fault is a typed failure with local detail.
type Fault struct {
	Code   Code
	Detail string
	cause  error
}

// New builds a fault. Detail is for local logs and never leaves the process
// through Peer.
func New(code Code, detail string) *Fault {
	return &Fault{Code: code, Detail: detail}
}

// Wrap attaches a code to an underlying error.
func Wrap(code Code, cause error) *Fault {
	detail := ""
	if cause != nil {
		detail = cause.Error()
	}
	return &Fault{Code: code, Detail: detail, cause: cause}
}

func (f *Fault) Error() string {
	if f == nil {
		return "<nil fault>"
	}
	if f.Detail == "" {
		return string(f.Code)
	}
	return string(f.Code) + ": " + f.Detail
}

// Unwrap exposes the underlying cause to errors.Is and errors.As.
func (f *Fault) Unwrap() error {
	if f == nil {
		return nil
	}
	return f.cause
}

// Is matches faults by code, so a caller can test for a condition without
// depending on how it was produced.
func (f *Fault) Is(target error) bool {
	other, ok := target.(*Fault)
	return ok && f != nil && other != nil && f.Code == other.Code
}

// Of extracts a fault from an error chain.
func Of(err error) (*Fault, bool) {
	var fault *Fault
	if errors.As(err, &fault) {
		return fault, true
	}
	return nil, false
}

// CodeOf returns the code of an error, or CodeInternal for anything
// unclassified. An untyped error is a local defect, and treating it as
// internal keeps it out of a peer's view.
func CodeOf(err error) Code {
	if fault, ok := Of(err); ok {
		return fault.Code
	}
	return CodeInternal
}
