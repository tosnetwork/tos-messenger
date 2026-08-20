package conformance

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"sync/atomic"
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
	ignorePeer    bool
	allowReplay   bool
	panicOnSeal   bool
}

// doubleState is the persisted state: key material plus the replay bookkeeping
// that has to survive a restart.
type doubleState struct {
	Key  []byte   `json:"key"`
	Send uint64   `json:"send"`
	Seen []uint64 `json:"seen,omitempty"`
}

var doubleMaterialCounter atomic.Uint64

func encodeState(state doubleState) e2ee.State {
	encoded, err := json.Marshal(state)
	if err != nil {
		panic(err)
	}
	return encoded
}

func decodeState(raw e2ee.State) (doubleState, error) {
	var state doubleState
	if err := json.Unmarshal(raw, &state); err != nil || len(state.Key) == 0 {
		return doubleState{}, e2ee.ErrStateUnusable
	}
	return state, nil
}

func (d double) AlgorithmID() string { return d.algorithm }

func (d double) NewPrekeyMaterial() ([]byte, []byte, error) {
	sequence := doubleMaterialCounter.Add(1)
	material := sha256.Sum256([]byte(fmt.Sprintf("test double material %d", sequence)))
	return material[:], material[:], nil
}

func (d double) Initiate(private []byte, peerPublic []byte, _ []byte) (e2ee.State, []byte, error) {
	if d.ignorePeer {
		return encodeState(doubleState{Key: append([]byte(nil), peerPublic...)}), []byte("initial"), nil
	}
	key := sha256.Sum256(append(append([]byte(nil), private...), peerPublic...))
	return encodeState(doubleState{Key: key[:]}), []byte("initial"), nil
}

func (d double) Accept(private []byte, peerPublic []byte, _ []byte, _ []byte) (e2ee.State, error) {
	if d.ignorePeer {
		return encodeState(doubleState{Key: append([]byte(nil), private...)}), nil
	}
	key := sha256.Sum256(append(append([]byte(nil), peerPublic...), private...))
	return encodeState(doubleState{Key: key[:]}), nil
}

func (d double) KeyMaterial(raw e2ee.State) (e2ee.State, error) {
	state, err := decodeState(raw)
	if err != nil {
		return nil, err
	}
	// Keys only: what someone taking the device obtains, without the record of
	// what had already been seen.
	return encodeState(doubleState{Key: state.Key, Send: state.Send}), nil
}

func (d double) Seal(raw e2ee.State, plaintext, binding []byte) ([]byte, e2ee.State, error) {
	if d.panicOnSeal {
		panic("this candidate is broken")
	}
	state, err := decodeState(raw)
	if err != nil {
		return nil, nil, err
	}
	counter := state.Send
	state.Send++
	body := append([]byte(nil), plaintext...)
	keystream := stream(state.Key, counter, len(body))
	for index := range body {
		body[index] ^= keystream[index]
	}
	out := make([]byte, 8)
	binary.BigEndian.PutUint64(out, counter)
	out = append(out, d.tag(state.Key, counter, body, binding)...)
	return append(out, body...), encodeState(state), nil
}

func (d double) Open(raw e2ee.State, ciphertext, binding []byte) ([]byte, e2ee.State, error) {
	state, err := decodeState(raw)
	if err != nil {
		return nil, nil, err
	}
	if len(ciphertext) < 24 {
		return nil, nil, e2ee.ErrNotAuthentic
	}
	counter := binary.BigEndian.Uint64(ciphertext[:8])
	body := ciphertext[24:]
	if string(d.tag(state.Key, counter, body, binding)) != string(ciphertext[8:24]) {
		return nil, nil, e2ee.ErrNotAuthentic
	}
	if !d.allowReplay {
		for _, seen := range state.Seen {
			if seen == counter {
				return nil, nil, e2ee.ErrReplayed
			}
		}
		state.Seen = append(state.Seen, counter)
	}
	plaintext := append([]byte(nil), body...)
	keystream := stream(state.Key, counter, len(plaintext))
	for index := range plaintext {
		plaintext[index] ^= keystream[index]
	}
	return plaintext, encodeState(state), nil
}

func (d double) tag(key []byte, counter uint64, body, binding []byte) []byte {
	var header [8]byte
	binary.BigEndian.PutUint64(header[:], counter)
	input := append([]byte(nil), key...)
	input = append(input, header[:]...)
	input = append(input, body...)
	if !d.ignoreBinding {
		input = append(input, binding...)
	}
	sum := sha256.Sum256(input)
	return sum[:16]
}

func stream(key []byte, counter uint64, length int) []byte {
	out := make([]byte, 0, length+sha256.Size)
	for block := 0; len(out) < length; block++ {
		var header [16]byte
		binary.BigEndian.PutUint64(header[:8], counter)
		binary.BigEndian.PutUint64(header[8:], uint64(block))
		sum := sha256.Sum256(append(append([]byte(nil), key...), header[:]...))
		out = append(out, sum[:]...)
	}
	return out[:length]
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
// leaves a single device theft permanent.
func TestStaticKeysFailOnlyTheCompromiseChecks(t *testing.T) {
	result := Verify(double{algorithm: "tos.messaging.e2ee.test-double.v1"}, testBinding())
	if result.AlgorithmID != "tos.messaging.e2ee.test-double.v1" {
		t.Fatalf("unexpected algorithm identifier: %q", result.AlgorithmID)
	}
	assertFailures(t, result, CheckPastTrafficSealed, CheckPostCompromise)
}

func TestUnboundCiphertextIsCaught(t *testing.T) {
	result := Verify(double{algorithm: "tos.messaging.e2ee.test-double.v1", ignoreBinding: true}, testBinding())
	assertFailures(t, result, CheckBindingEnforced, CheckPastTrafficSealed, CheckPostCompromise)
}

func TestUnauthenticatedPeerIsCaught(t *testing.T) {
	result := Verify(double{algorithm: "tos.messaging.e2ee.test-double.v1", ignorePeer: true}, testBinding())
	assertFailures(t, result, CheckPeerAuthentication, CheckPastTrafficSealed, CheckPostCompromise)
}

// Replay protection that does not live in the persisted state fails twice:
// within a session and across a restart.
func TestMissingReplayProtectionIsCaught(t *testing.T) {
	result := Verify(double{algorithm: "tos.messaging.e2ee.test-double.v1", allowReplay: true}, testBinding())
	assertFailures(t, result, CheckReplayRejected, CheckReplaySurvivesState,
		CheckPastTrafficSealed, CheckPostCompromise)
}

func TestUnnamedSuiteIsCaught(t *testing.T) {
	result := Verify(double{algorithm: "homegrown"}, testBinding())
	found := false
	for _, name := range failedNames(result) {
		if name == CheckAlgorithmIdentifier {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected the algorithm identifier to be refused, failures were %v", failedNames(result))
	}
}

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
		CheckAlgorithmIdentifier, CheckAsyncEstablishment, CheckPeerAuthentication, CheckReverseDirection,
		CheckBindingEnforced, CheckTamperDetected, CheckReplayRejected,
		CheckOutOfOrder, CheckBoundedExpansion, CheckStatePortable, CheckStateBounded,
		CheckReplaySurvivesState, CheckPastTrafficSealed, CheckPostCompromise,
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
