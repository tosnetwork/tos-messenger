// Package e2ee defines the contract a candidate end-to-end encryption profile
// must satisfy, and the bindings that tie one ciphertext to one conversation.
//
// It contains no cryptography. The suite is a protocol-freeze decision, and
// the architecture is explicit that no new cipher, MAC, signature, or ratchet
// construction may be invented on the way there. What can be settled before
// that decision is everything around it: what the suite must provide, what a
// ciphertext is bound to, and how a candidate is refuted.
//
// The conformance harness in the conformance subpackage can only refute. A
// suite that fails a check definitively lacks the property; a suite that
// passes every check has cleared a floor, not earned an approval. Selection
// still requires cryptographic review.
package e2ee

import (
	"errors"
	"regexp"
)

// MaxCiphertextOverheadBytes bounds how much a suite may add to a plaintext.
// Every message pays this on every hop and every Relay stores it, so an
// unbounded expansion is a protocol cost, not an implementation detail.
const MaxCiphertextOverheadBytes = 512

// AlgorithmPattern matches a frozen suite identifier. A suite that cannot name
// itself cannot be negotiated, deprecated, or upgraded.
var AlgorithmPattern = regexp.MustCompile(`^tos\.messaging\.e2ee\.[a-z0-9-]{1,32}\.v[0-9]{1,3}$`)

// Errors a Session must return rather than inventing its own semantics. A
// caller distinguishes a replayed message from a corrupt one, and a rejected
// binding from either.
var (
	// ErrReplayed reports a ciphertext this session has already opened.
	ErrReplayed = errors.New("message was already opened")
	// ErrNotAuthentic reports a ciphertext that failed authentication, whether
	// because it was altered or because its binding does not match.
	ErrNotAuthentic = errors.New("message is not authentic for this binding")
	// ErrSessionExpired reports a session past its permitted lifetime.
	ErrSessionExpired = errors.New("session has expired")
)

// Suite is a candidate cryptographic profile.
//
// The interface is deliberately shaped around asynchronous establishment: an
// initiator must be able to start from published material alone, because the
// recipient of a first message is usually offline. A suite that requires both
// parties online cannot serve this Messenger.
type Suite interface {
	// AlgorithmID returns the frozen suite identifier. It must be stable for
	// the lifetime of the value.
	AlgorithmID() string

	// NewPrekeyMaterial produces the public material an endpoint publishes and
	// the private state that answers it.
	NewPrekeyMaterial() (public []byte, private []byte, err error)

	// Initiate starts a session against published material while the peer is
	// offline, returning the session and the initial message the peer needs.
	Initiate(peerPublic []byte, binding []byte) (Session, []byte, error)

	// Accept completes a session from an initial message.
	Accept(private []byte, initial []byte, binding []byte) (Session, error)
}

// Session is one established end-to-end encrypted session.
type Session interface {
	// Seal encrypts a plaintext under a binding.
	Seal(plaintext []byte, binding []byte) ([]byte, error)

	// Open decrypts a ciphertext under a binding. It returns ErrReplayed for a
	// message it has already opened and ErrNotAuthentic for anything that
	// fails authentication.
	Open(ciphertext []byte, binding []byte) ([]byte, error)

	// Snapshot exports the secret state an attacker obtains when they take the
	// device: key material and nothing else.
	//
	// It must exclude replay bookkeeping and any record of past messages. An
	// attacker who steals a device gets the keys; whether the implementation
	// also kept a list of what it had already seen has no bearing on whether
	// past traffic is readable, and a snapshot that carried that list would
	// let a suite appear to protect past traffic when it does not.
	//
	// Production code has no reason to call this. It exists so that a
	// conformance run can simulate a compromise.
	Snapshot() ([]byte, error)

	// Restore reconstitutes a session from snapshot material alone.
	Restore(snapshot []byte) (Session, error)
}

// ValidateAlgorithmID reports whether a suite identifier is well formed.
func ValidateAlgorithmID(algorithm string) error {
	if !AlgorithmPattern.MatchString(algorithm) {
		return errors.New("invalid end-to-end encryption algorithm identifier")
	}
	return nil
}
