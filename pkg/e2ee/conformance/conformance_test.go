package conformance

import (
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"sort"
	"strings"
	"testing"

	"github.com/tosnetwork/tos-messenger/pkg/e2ee"
	nativev1 "github.com/tosnetwork/tos-service-protocol/gen/tos/service/v1"
)

// The doubles below are NOT cryptography and must never be used for anything.
// They exist to prove the harness discriminates: each one is broken in one
// named way, and the test asserts that the harness reports exactly that
// breakage and nothing else. A harness that has never rejected anything is a
// harness nobody has tested.

type double struct {
	algorithm     string
	ignoreBinding bool
	allowReplay   bool
	panicOnSeal   bool
}

func (d double) AlgorithmID() string { return d.algorithm }

func (d double) NewPrekeyMaterial() ([]byte, []byte, error) {
	material := sha256.Sum256([]byte("test double material"))
	return material[:], material[:], nil
}

func (d double) Initiate(peerPublic []byte, _ []byte) (e2ee.Session, []byte, error) {
	return &doubleSession{key: append([]byte(nil), peerPublic...), suite: d, seen: map[uint64]bool{}}, []byte("initial"), nil
}

func (d double) Accept(private []byte, _ []byte, _ []byte) (e2ee.Session, error) {
	return &doubleSession{key: append([]byte(nil), private...), suite: d, seen: map[uint64]bool{}}, nil
}

type doubleSession struct {
	key     []byte
	suite   double
	counter uint64
	seen    map[uint64]bool
}

func (s *doubleSession) stream(counter uint64, length int) []byte {
	out := make([]byte, 0, length+sha256.Size)
	for block := 0; len(out) < length; block++ {
		var header [16]byte
		binary.BigEndian.PutUint64(header[:8], counter)
		binary.BigEndian.PutUint64(header[8:], uint64(block))
		sum := sha256.Sum256(append(append([]byte(nil), s.key...), header[:]...))
		out = append(out, sum[:]...)
	}
	return out[:length]
}

func (s *doubleSession) tag(counter uint64, body, binding []byte) []byte {
	var header [8]byte
	binary.BigEndian.PutUint64(header[:], counter)
	input := append([]byte(nil), s.key...)
	input = append(input, header[:]...)
	input = append(input, body...)
	if !s.suite.ignoreBinding {
		input = append(input, binding...)
	}
	sum := sha256.Sum256(input)
	return sum[:16]
}

func (s *doubleSession) Seal(plaintext, binding []byte) ([]byte, error) {
	if s.suite.panicOnSeal {
		panic("this candidate is broken")
	}
	counter := s.counter
	s.counter++
	body := append([]byte(nil), plaintext...)
	keystream := s.stream(counter, len(body))
	for index := range body {
		body[index] ^= keystream[index]
	}
	out := make([]byte, 8)
	binary.BigEndian.PutUint64(out, counter)
	out = append(out, s.tag(counter, body, binding)...)
	return append(out, body...), nil
}

func (s *doubleSession) Open(ciphertext, binding []byte) ([]byte, error) {
	if len(ciphertext) < 24 {
		return nil, e2ee.ErrNotAuthentic
	}
	counter := binary.BigEndian.Uint64(ciphertext[:8])
	body := ciphertext[24:]
	expected := s.tag(counter, body, binding)
	if len(expected) != 16 || string(expected) != string(ciphertext[8:24]) {
		return nil, e2ee.ErrNotAuthentic
	}
	if !s.suite.allowReplay && s.seen[counter] {
		return nil, e2ee.ErrReplayed
	}
	s.seen[counter] = true
	plaintext := append([]byte(nil), body...)
	keystream := s.stream(counter, len(plaintext))
	for index := range plaintext {
		plaintext[index] ^= keystream[index]
	}
	return plaintext, nil
}

// Snapshot exports key material only, which is what an attacker taking the
// device obtains.
func (s *doubleSession) Snapshot() ([]byte, error) {
	return append([]byte(nil), s.key...), nil
}

func (s *doubleSession) Restore(snapshot []byte) (e2ee.Session, error) {
	if len(snapshot) == 0 {
		return nil, errors.New("empty snapshot")
	}
	return &doubleSession{key: append([]byte(nil), snapshot...), suite: s.suite, seen: map[uint64]bool{}}, nil
}

func testBinding() e2ee.Binding {
	return e2ee.Binding{
		Network: &nativev1.NetworkDomain{
			NetworkId:       "tos-local",
			GenesisRootHash: strings.Repeat("a", 64),
			GenesisFileHash: strings.Repeat("b", 64),
		},
		AlgorithmID:         "tos.messaging.e2ee.test-double.v1",
		ConversationID:      "conv_" + strings.Repeat("1", 64),
		SenderAgentID:       "agent_" + strings.Repeat("2", 64),
		SenderEndpointID:    "mep_" + strings.Repeat("3", 64),
		SenderDeviceID:      "dev_" + strings.Repeat("4", 64),
		RecipientAgentID:    "agent_" + strings.Repeat("5", 64),
		RecipientEndpointID: "mep_" + strings.Repeat("6", 64),
		RecipientDeviceID:   "dev_" + strings.Repeat("7", 64),
	}
}

func failedNames(result Result) []string {
	names := make([]string, 0, len(result.Checks))
	for _, check := range result.Failed() {
		names = append(names, check.Name)
	}
	sort.Strings(names)
	return names
}

func assertFailures(t *testing.T, result Result, expected ...string) {
	t.Helper()
	sort.Strings(expected)
	got := failedNames(result)
	if len(got) != len(expected) {
		t.Fatalf("expected failures %v, got %v", expected, got)
	}
	for index := range got {
		if got[index] != expected[index] {
			t.Fatalf("expected failures %v, got %v", expected, got)
		}
	}
}

// A suite whose keys never change passes every mechanical check and still
// leaves a single device theft permanent. That is the whole reason the
// compromise checks exist.
func TestStaticKeysFailOnlyTheCompromiseChecks(t *testing.T) {
	result := Verify(double{algorithm: "tos.messaging.e2ee.test-double.v1"}, testBinding())
	if result.AlgorithmID != "tos.messaging.e2ee.test-double.v1" {
		t.Fatalf("unexpected algorithm identifier: %q", result.AlgorithmID)
	}
	if result.Passed() {
		t.Fatal("a static-key candidate must not pass")
	}
	assertFailures(t, result, CheckPastTrafficSealed, CheckPostCompromise)
}

func TestUnboundCiphertextIsCaught(t *testing.T) {
	result := Verify(double{algorithm: "tos.messaging.e2ee.test-double.v1", ignoreBinding: true}, testBinding())
	assertFailures(t, result, CheckBindingEnforced, CheckPastTrafficSealed, CheckPostCompromise)
}

func TestMissingReplayProtectionIsCaught(t *testing.T) {
	result := Verify(double{algorithm: "tos.messaging.e2ee.test-double.v1", allowReplay: true}, testBinding())
	assertFailures(t, result, CheckReplayRejected, CheckPastTrafficSealed, CheckPostCompromise)
}

func TestUnnamedSuiteIsCaught(t *testing.T) {
	result := Verify(double{algorithm: "homegrown"}, testBinding())
	names := failedNames(result)
	found := false
	for _, name := range names {
		if name == CheckAlgorithmIdentifier {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected the algorithm identifier to be refused, failures were %v", names)
	}
}

// A candidate that crashes must be reported, not propagated.
func TestPanickingCandidateIsReported(t *testing.T) {
	result := Verify(double{algorithm: "tos.messaging.e2ee.test-double.v1", panicOnSeal: true}, testBinding())
	if result.Passed() {
		t.Fatal("a panicking candidate must not pass")
	}
	for _, check := range result.Failed() {
		if check.Name == CheckAsyncEstablishment && !strings.Contains(check.Detail, "panicked") {
			t.Fatalf("expected the panic to be reported, got %q", check.Detail)
		}
	}
}

func TestHarnessRefusesUnusableInput(t *testing.T) {
	if Verify(nil, testBinding()).Passed() {
		t.Fatal("a missing suite must not pass")
	}
	invalid := testBinding()
	invalid.ConversationID = "conv_bad"
	result := Verify(double{algorithm: "tos.messaging.e2ee.test-double.v1"}, invalid)
	if result.Passed() || len(result.Checks) != 1 {
		t.Fatalf("an invalid binding must stop the run, got %d checks", len(result.Checks))
	}
}

func TestEveryCheckRuns(t *testing.T) {
	result := Verify(double{algorithm: "tos.messaging.e2ee.test-double.v1"}, testBinding())
	expected := []string{
		CheckAlgorithmIdentifier, CheckAsyncEstablishment, CheckReverseDirection,
		CheckBindingEnforced, CheckTamperDetected, CheckReplayRejected,
		CheckOutOfOrder, CheckBoundedExpansion, CheckPastTrafficSealed, CheckPostCompromise,
	}
	if len(result.Checks) != len(expected) {
		t.Fatalf("expected %d checks, got %d", len(expected), len(result.Checks))
	}
	seen := map[string]bool{}
	for _, check := range result.Checks {
		seen[check.Name] = true
	}
	for _, name := range expected {
		if !seen[name] {
			t.Fatalf("check %q never ran", name)
		}
	}
}
