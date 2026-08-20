// Package e2ee defines the contract a candidate end-to-end encryption profile
// must satisfy, and the bindings that tie one ciphertext to one conversation.
//
// It carries a concrete default candidate, but that candidate remains a
// protocol-freeze decision: its presence is implementation evidence, not owner
// ratification. The package invents no cipher, MAC, signature, or ratchet. It
// fixes what the candidate provides, what a ciphertext is bound to, what
// published material commits, how a candidate is refuted, and how session
// state survives a crash.
//
// The last of those is why the interface is a pure state transition rather
// than a mutable session object. A session that advances in memory has two
// truths, the one in memory and the one on disk, and every crash decides which
// survives. Returning the next state alongside the result makes the caller
// commit both together, and lets this repository state the commit order
// instead of discovering it from whichever library is chosen.
//
// The conformance harness can only refute. A suite that fails a check
// definitively lacks the property; a suite that passes every check has cleared
// a floor, not earned an approval. Selection still requires cryptographic
// review.
package e2ee

import (
	"errors"
	"regexp"
)

// MaxCiphertextOverheadBytes bounds how much a suite may add to a plaintext.
// Every message pays this on every hop and every Relay stores it, so an
// unbounded expansion is a protocol cost, not an implementation detail.
const MaxCiphertextOverheadBytes = 512

// MaxSessionStateBytes bounds one persisted session state. State is committed
// on the critical path of every message, so a suite whose state grows without
// limit would make every send slower than the last.
const MaxSessionStateBytes = 256 << 10

// AlgorithmPattern matches a frozen suite identifier. A suite that cannot name
// itself cannot be negotiated, deprecated, or upgraded.
var AlgorithmPattern = regexp.MustCompile(`^tos\.messaging\.e2ee\.[a-z0-9-]{1,32}\.v[0-9]{1,3}$`)

// Errors a suite must return rather than inventing its own semantics. A caller
// distinguishes a replayed message from a corrupt one, and a rejected binding
// from either.
var (
	// ErrReplayed reports a ciphertext this state has already opened.
	ErrReplayed = errors.New("message was already opened")
	// ErrNotAuthentic reports a ciphertext that failed authentication, whether
	// because it was altered or because its binding does not match.
	ErrNotAuthentic = errors.New("message is not authentic for this binding")
	// ErrSessionExpired reports a session past its permitted lifetime.
	ErrSessionExpired = errors.New("session has expired")
	// ErrStateUnusable reports state a suite cannot interpret, including state
	// written by a version it does not understand.
	ErrStateUnusable = errors.New("session state is unusable")
)

// State is one session's complete persisted state.
//
// It is opaque, and it is everything the suite needs to continue: keys,
// ratchet position, skipped-message keys, and replay bookkeeping. A state that
// omitted replay bookkeeping would let a restart re-accept a message the
// session had already opened.
type State []byte

// Suite is a candidate cryptographic profile.
//
// Establishment is asynchronous by construction: an initiator starts from
// published material alone, because the recipient of a first message is
// usually offline. A suite that requires both parties online cannot serve this
// Messenger.
type Suite interface {
	// AlgorithmID returns the frozen suite identifier. It must be stable for
	// the lifetime of the value.
	AlgorithmID() string

	// NewPrekeyMaterial produces the public material an endpoint publishes and
	// the private state that answers it.
	NewPrekeyMaterial() (public []byte, private []byte, err error)

	// Initiate starts a session using this device's private prekey material and
	// the peer's published material. Requiring both is the possession proof
	// behind the identities in the binding; published material alone would let
	// anyone initiate while claiming to be any delegated endpoint.
	Initiate(private []byte, peerPublic []byte, binding []byte) (State, []byte, error)

	// Accept completes a session from an initial message and the initiator's
	// independently fetched, endpoint-signed published material.
	Accept(private []byte, peerPublic []byte, initial []byte, binding []byte) (State, error)

	// Seal encrypts under a binding and returns the state that must be durable
	// before the ciphertext is released.
	Seal(state State, plaintext []byte, binding []byte) (ciphertext []byte, next State, err error)

	// Open decrypts under a binding and returns the state that must be durable
	// before the plaintext is acted on.
	Open(state State, ciphertext []byte, binding []byte) (plaintext []byte, next State, err error)

	// KeyMaterial returns the part of a state an attacker obtains when they
	// take the device: keys, without replay bookkeeping.
	//
	// It exists so a compromise check cannot be satisfied by retaining a list
	// of what was already seen. Whether an implementation kept such a list has
	// no bearing on whether past traffic is readable, and a suite whose
	// persisted state was accepted as the attacker's view could appear to
	// protect a backlog it does not protect.
	//
	// Production code has no reason to call this.
	KeyMaterial(state State) (State, error)
}

// CommitOrder documents the order in which a caller must make things durable.
//
// The two directions commit in opposite orders, and each order is decided by
// what a crash between the two writes would cost.
//
//	Inbound:  the event record first, then the session state.
//	  A crash between them leaves the event durable and the state behind. The
//	  same ciphertext opens again to the same next state, so nothing is lost.
//	  The other order consumes the message key and then loses the event, and
//	  no retry can recover it: the peer's copy no longer opens.
//
//	Outbound: the session state first, then the ciphertext.
//	  A crash between them advances the state and loses the ciphertext, so the
//	  message is sealed again from the new state under a fresh key. The other
//	  order leaves a released ciphertext with the state rolled back, and the
//	  next seal reuses a message key and nonce, which is the one failure a
//	  ratchet cannot absorb.
//
// The plaintext is queued before it is sealed, so re-sealing after a crash has
// something to seal.
const CommitOrder = "inbound: event then state; outbound: state then ciphertext"

// ValidateAlgorithmID reports whether a suite identifier is well formed.
func ValidateAlgorithmID(algorithm string) error {
	if !AlgorithmPattern.MatchString(algorithm) {
		return errors.New("invalid end-to-end encryption algorithm identifier")
	}
	return nil
}

// ValidateState enforces the bounds every persisted state must respect.
func ValidateState(state State) error {
	if len(state) == 0 {
		return ErrStateUnusable
	}
	if len(state) > MaxSessionStateBytes {
		return errors.New("session state exceeds its bound")
	}
	return nil
}
