// Package conformance refutes candidate end-to-end encryption suites.
//
// Every check here can only establish the absence of a property. A suite that
// opens a ciphertext under the wrong binding definitively does not bind; a
// suite that opens past traffic from a stolen snapshot definitively has no
// forward secrecy. The converse does not follow: passing every check means a
// candidate has cleared a floor, not that it is sound. Selecting a suite still
// requires cryptographic review of the construction itself, which no black-box
// harness can substitute for.
//
// The harness is written to survive a bad candidate. A suite that returns
// nonsense, blocks on nothing, or panics is reported as a failure rather than
// taking the run down with it.
package conformance

import (
	"bytes"
	"errors"
	"fmt"
	"strings"

	"github.com/tosnetwork/tos-messenger/pkg/e2ee"
)

// Check is one property and what the candidate did about it.
type Check struct {
	Name   string `json:"name"`
	Passed bool   `json:"passed"`
	Detail string `json:"detail,omitempty"`
}

// Result is a complete run.
type Result struct {
	AlgorithmID string  `json:"algorithm_id"`
	Checks      []Check `json:"checks"`
}

// Failed returns the checks the candidate did not satisfy.
func (r Result) Failed() []Check {
	var failed []Check
	for _, check := range r.Checks {
		if !check.Passed {
			failed = append(failed, check)
		}
	}
	return failed
}

// Passed reports whether every check held.
func (r Result) Passed() bool {
	return len(r.Failed()) == 0
}

// Names of the properties this harness can refute.
const (
	CheckAlgorithmIdentifier = "algorithm-identifier"
	CheckAsyncEstablishment  = "asynchronous-establishment"
	CheckReverseDirection    = "reverse-direction"
	CheckBindingEnforced     = "binding-enforced"
	CheckTamperDetected      = "tamper-detected"
	CheckReplayRejected      = "replay-rejected"
	CheckOutOfOrder          = "out-of-order-delivery"
	CheckBoundedExpansion    = "bounded-expansion"
	CheckPastTrafficSealed   = "past-traffic-sealed-after-compromise"
	CheckPostCompromise      = "post-compromise-recovery"
)

// Verify runs every check against a candidate suite.
func Verify(suite e2ee.Suite, binding e2ee.Binding) Result {
	result := Result{}
	if suite == nil {
		return Result{Checks: []Check{{Name: CheckAlgorithmIdentifier, Detail: "no suite supplied"}}}
	}
	result.AlgorithmID = safeAlgorithmID(suite)
	if err := binding.Validate(); err != nil {
		return Result{AlgorithmID: result.AlgorithmID, Checks: []Check{
			{Name: CheckBindingEnforced, Detail: "binding is invalid: " + err.Error()},
		}}
	}
	checks := []struct {
		name string
		run  func(e2ee.Suite, e2ee.Binding) error
	}{
		{CheckAlgorithmIdentifier, checkAlgorithmIdentifier},
		{CheckAsyncEstablishment, checkAsyncEstablishment},
		{CheckReverseDirection, checkReverseDirection},
		{CheckBindingEnforced, checkBindingEnforced},
		{CheckTamperDetected, checkTamperDetected},
		{CheckReplayRejected, checkReplayRejected},
		{CheckOutOfOrder, checkOutOfOrder},
		{CheckBoundedExpansion, checkBoundedExpansion},
		{CheckPastTrafficSealed, checkPastTrafficSealed},
		{CheckPostCompromise, checkPostCompromise},
	}
	for _, item := range checks {
		err := guard(func() error { return item.run(suite, binding) })
		check := Check{Name: item.name, Passed: err == nil}
		if err != nil {
			check.Detail = err.Error()
		}
		result.Checks = append(result.Checks, check)
	}
	return result
}

// guard turns a panicking candidate into a failed check.
func guard(run func() error) (err error) {
	defer func() {
		if recovered := recover(); recovered != nil {
			err = fmt.Errorf("candidate panicked: %v", recovered)
		}
	}()
	return run()
}

func safeAlgorithmID(suite e2ee.Suite) string {
	identifier := ""
	_ = guard(func() error {
		identifier = suite.AlgorithmID()
		return nil
	})
	return identifier
}

type pair struct {
	initiator e2ee.Session
	acceptor  e2ee.Session
	binding   e2ee.Binding
	reply     e2ee.Binding
}

// establish performs the asynchronous handshake the Messenger depends on: the
// initiator starts from published material alone.
func establish(suite e2ee.Suite, binding e2ee.Binding) (pair, error) {
	forward, err := binding.Bytes()
	if err != nil {
		return pair{}, err
	}
	public, private, err := suite.NewPrekeyMaterial()
	if err != nil {
		return pair{}, errors.New("prekey material: " + err.Error())
	}
	if len(public) == 0 {
		return pair{}, errors.New("published prekey material is empty")
	}
	initiator, initial, err := suite.Initiate(public, forward)
	if err != nil {
		return pair{}, errors.New("initiate: " + err.Error())
	}
	if initiator == nil {
		return pair{}, errors.New("initiate returned no session")
	}
	acceptor, err := suite.Accept(private, initial, forward)
	if err != nil {
		return pair{}, errors.New("accept: " + err.Error())
	}
	if acceptor == nil {
		return pair{}, errors.New("accept returned no session")
	}
	return pair{initiator: initiator, acceptor: acceptor, binding: binding, reply: binding.Reply()}, nil
}

func (p pair) send(plaintext []byte) ([]byte, error) {
	forward, err := p.binding.Bytes()
	if err != nil {
		return nil, err
	}
	return p.initiator.Seal(plaintext, forward)
}

func (p pair) receive(ciphertext []byte) ([]byte, error) {
	forward, err := p.binding.Bytes()
	if err != nil {
		return nil, err
	}
	return p.acceptor.Open(ciphertext, forward)
}

func checkAlgorithmIdentifier(suite e2ee.Suite, _ e2ee.Binding) error {
	identifier := suite.AlgorithmID()
	if err := e2ee.ValidateAlgorithmID(identifier); err != nil {
		return err
	}
	if suite.AlgorithmID() != identifier {
		return errors.New("algorithm identifier is not stable")
	}
	return nil
}

func checkAsyncEstablishment(suite e2ee.Suite, binding e2ee.Binding) error {
	sessions, err := establish(suite, binding)
	if err != nil {
		return err
	}
	plaintext := []byte("first contact while the recipient is offline")
	ciphertext, err := sessions.send(plaintext)
	if err != nil {
		return errors.New("seal: " + err.Error())
	}
	if bytes.Contains(ciphertext, plaintext) {
		return errors.New("ciphertext contains its plaintext")
	}
	opened, err := sessions.receive(ciphertext)
	if err != nil {
		return errors.New("open: " + err.Error())
	}
	if !bytes.Equal(opened, plaintext) {
		return errors.New("opened plaintext does not match")
	}
	return nil
}

func checkReverseDirection(suite e2ee.Suite, binding e2ee.Binding) error {
	sessions, err := establish(suite, binding)
	if err != nil {
		return err
	}
	// Many designs require the initiator's first message before the acceptor
	// can answer, so the exchange is driven in order.
	ciphertext, err := sessions.send([]byte("request"))
	if err != nil {
		return errors.New("seal: " + err.Error())
	}
	if _, err := sessions.receive(ciphertext); err != nil {
		return errors.New("open: " + err.Error())
	}
	reply, err := sessions.reply.Bytes()
	if err != nil {
		return err
	}
	plaintext := []byte("response")
	answer, err := sessions.acceptor.Seal(plaintext, reply)
	if err != nil {
		return errors.New("seal reply: " + err.Error())
	}
	opened, err := sessions.initiator.Open(answer, reply)
	if err != nil {
		return errors.New("open reply: " + err.Error())
	}
	if !bytes.Equal(opened, plaintext) {
		return errors.New("opened reply does not match")
	}
	return nil
}

// checkBindingEnforced lifts a ciphertext into another conversation. A suite
// that opens it lets a Relay or a peer move messages between contexts.
func checkBindingEnforced(suite e2ee.Suite, binding e2ee.Binding) error {
	sessions, err := establish(suite, binding)
	if err != nil {
		return err
	}
	ciphertext, err := sessions.send([]byte("bound to one conversation"))
	if err != nil {
		return errors.New("seal: " + err.Error())
	}
	foreign := binding
	foreign.ConversationID = "conv_" + strings.Repeat("9", 64)
	foreignBytes, err := foreign.Bytes()
	if err != nil {
		return err
	}
	if _, err := sessions.acceptor.Open(ciphertext, foreignBytes); err == nil {
		return errors.New("a ciphertext opened under a different conversation")
	}
	return nil
}

func checkTamperDetected(suite e2ee.Suite, binding e2ee.Binding) error {
	sessions, err := establish(suite, binding)
	if err != nil {
		return err
	}
	ciphertext, err := sessions.send([]byte("integrity matters"))
	if err != nil {
		return errors.New("seal: " + err.Error())
	}
	for index := range ciphertext {
		altered := append([]byte(nil), ciphertext...)
		altered[index] ^= 0x01
		if _, err := sessions.receive(altered); err == nil {
			return fmt.Errorf("a ciphertext altered at byte %d still opened", index)
		}
	}
	return nil
}

func checkReplayRejected(suite e2ee.Suite, binding e2ee.Binding) error {
	sessions, err := establish(suite, binding)
	if err != nil {
		return err
	}
	ciphertext, err := sessions.send([]byte("deliver once"))
	if err != nil {
		return errors.New("seal: " + err.Error())
	}
	if _, err := sessions.receive(ciphertext); err != nil {
		return errors.New("open: " + err.Error())
	}
	if _, err := sessions.receive(ciphertext); err == nil {
		return errors.New("a redelivered ciphertext opened a second time")
	} else if !errors.Is(err, e2ee.ErrReplayed) {
		return errors.New("a replay was refused without reporting ErrReplayed: " + err.Error())
	}
	return nil
}

// checkOutOfOrder delivers a later message first. Transport delivery is at
// least once and in no particular order, so a suite that requires strict order
// cannot be used over a Relay.
func checkOutOfOrder(suite e2ee.Suite, binding e2ee.Binding) error {
	sessions, err := establish(suite, binding)
	if err != nil {
		return err
	}
	plaintexts := [][]byte{[]byte("one"), []byte("two"), []byte("three")}
	ciphertexts := make([][]byte, 0, len(plaintexts))
	for _, plaintext := range plaintexts {
		ciphertext, err := sessions.send(plaintext)
		if err != nil {
			return errors.New("seal: " + err.Error())
		}
		ciphertexts = append(ciphertexts, ciphertext)
	}
	for _, index := range []int{2, 0, 1} {
		opened, err := sessions.receive(ciphertexts[index])
		if err != nil {
			return fmt.Errorf("message %d did not open out of order: %v", index, err)
		}
		if !bytes.Equal(opened, plaintexts[index]) {
			return fmt.Errorf("message %d opened as the wrong plaintext", index)
		}
	}
	return nil
}

func checkBoundedExpansion(suite e2ee.Suite, binding e2ee.Binding) error {
	sessions, err := establish(suite, binding)
	if err != nil {
		return err
	}
	for _, size := range []int{0, 1, 1024, 64 << 10} {
		plaintext := make([]byte, size)
		for index := range plaintext {
			plaintext[index] = byte(index)
		}
		ciphertext, err := sessions.send(plaintext)
		if err != nil {
			return errors.New("seal: " + err.Error())
		}
		if overhead := len(ciphertext) - len(plaintext); overhead > e2ee.MaxCiphertextOverheadBytes {
			return fmt.Errorf("a %d byte plaintext expanded by %d bytes", size, overhead)
		}
	}
	return nil
}

// checkPastTrafficSealed takes the receiver's key material after it has
// already read a message, and tries to read that message again from the
// material alone. A suite whose keys survive their own use offers no forward
// secrecy: whoever takes the device reads the backlog.
func checkPastTrafficSealed(suite e2ee.Suite, binding e2ee.Binding) error {
	sessions, err := establish(suite, binding)
	if err != nil {
		return err
	}
	first, err := sessions.send([]byte("older message"))
	if err != nil {
		return errors.New("seal: " + err.Error())
	}
	if _, err := sessions.receive(first); err != nil {
		return errors.New("open: " + err.Error())
	}
	for index := 0; index < 4; index++ {
		later, err := sessions.send([]byte("later message"))
		if err != nil {
			return errors.New("seal: " + err.Error())
		}
		if _, err := sessions.receive(later); err != nil {
			return errors.New("open: " + err.Error())
		}
	}
	snapshot, err := sessions.acceptor.Snapshot()
	if err != nil {
		return errors.New("snapshot: " + err.Error())
	}
	stolen, err := sessions.acceptor.Restore(snapshot)
	if err != nil {
		return errors.New("restore: " + err.Error())
	}
	if stolen == nil {
		return errors.New("restore returned no session")
	}
	forward, err := binding.Bytes()
	if err != nil {
		return err
	}
	if _, err := stolen.Open(first, forward); err == nil {
		return errors.New("stolen key material read a message that had already been delivered")
	}
	return nil
}

// checkPostCompromise leaks the receiver's state, lets both parties exchange
// fresh messages, and then tries the leaked state against a new message. A
// suite that never renews its keys leaves a single theft permanent.
func checkPostCompromise(suite e2ee.Suite, binding e2ee.Binding) error {
	sessions, err := establish(suite, binding)
	if err != nil {
		return err
	}
	opening, err := sessions.send([]byte("before the compromise"))
	if err != nil {
		return errors.New("seal: " + err.Error())
	}
	if _, err := sessions.receive(opening); err != nil {
		return errors.New("open: " + err.Error())
	}
	snapshot, err := sessions.acceptor.Snapshot()
	if err != nil {
		return errors.New("snapshot: " + err.Error())
	}
	stolen, err := sessions.acceptor.Restore(snapshot)
	if err != nil {
		return errors.New("restore: " + err.Error())
	}

	// A full round trip in both directions is what gives a ratcheting design
	// the chance to renew its keys.
	reply, err := sessions.reply.Bytes()
	if err != nil {
		return err
	}
	forward, err := binding.Bytes()
	if err != nil {
		return err
	}
	for round := 0; round < 3; round++ {
		answer, err := sessions.acceptor.Seal([]byte("recovering"), reply)
		if err != nil {
			return errors.New("seal reply: " + err.Error())
		}
		if _, err := sessions.initiator.Open(answer, reply); err != nil {
			return errors.New("open reply: " + err.Error())
		}
		forwardCiphertext, err := sessions.initiator.Seal([]byte("recovering"), forward)
		if err != nil {
			return errors.New("seal: " + err.Error())
		}
		if _, err := sessions.acceptor.Open(forwardCiphertext, forward); err != nil {
			return errors.New("open: " + err.Error())
		}
	}

	fresh, err := sessions.initiator.Seal([]byte("after recovery"), forward)
	if err != nil {
		return errors.New("seal: " + err.Error())
	}
	if _, err := stolen.Open(fresh, forward); err == nil {
		return errors.New("stolen key material still read traffic sent after a full exchange")
	}
	return nil
}
