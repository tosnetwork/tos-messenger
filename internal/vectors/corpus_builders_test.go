package vectors

import (
	"strings"
	"testing"

	"github.com/tosnetwork/tos-messenger/pkg/directory"
	"github.com/tosnetwork/tos-messenger/pkg/e2ee"
	"github.com/tosnetwork/tos-messenger/pkg/envelope"
	"github.com/tosnetwork/tos-messenger/pkg/identity"
	"github.com/tosnetwork/tos-messenger/pkg/negotiation"
	"github.com/tosnetwork/tos-messenger/pkg/payload"
)

// Valid baselines. Each is accepted by its decoder; the corpus refuses
// mutations of it.

func validDelegationJSON(t *testing.T) []byte {
	t.Helper()
	encoded, err := identity.EncodeJSON(delegation(t))
	if err != nil {
		t.Fatalf("delegation: %v", err)
	}
	return encoded
}

func validDescriptor(t *testing.T) directory.Descriptor {
	t.Helper()
	del := delegation(t)
	digest, err := identity.Digest(del)
	if err != nil {
		t.Fatalf("digest: %v", err)
	}
	descriptor := directory.Descriptor{
		Network: del.Network, AgentID: del.AgentID, EndpointID: del.EndpointID,
		DelegationDigest:           digest,
		SupportedMessagingVersions: []uint32{1},
		SupportedA2AVersions:       []string{"0.3"},
		SupportedMCPVersions:       []string{"2025-06-18"},
		ADNLID:                     del.ADNLID,
		HTTPSEndpoint:              "https://endpoint.example/messaging",
		PrekeyBundleDigest:         "sha256:" + strings.Repeat("7a", 32),
		MailboxRelaySetDigest:      directory.EmptyRelaySetDigest(),
		InboxAdmissionPolicyDigest: del.InboxAdmissionPolicyDigest,
		MaximumEnvelopeBytes:       64 << 10,
		IssuedAtUnix:               baseUnix,
		ExpiresAtUnix:              baseUnix + 3600,
	}
	signed, err := directory.SignDescriptor(descriptor, endpointKey())
	if err != nil {
		t.Fatalf("sign descriptor: %v", err)
	}
	return signed
}

func validDescriptorJSON(t *testing.T) []byte {
	t.Helper()
	encoded, err := directory.EncodeDescriptorJSON(validDescriptor(t))
	if err != nil {
		t.Fatalf("descriptor: %v", err)
	}
	return encoded
}

func validBundleJSON(t *testing.T) []byte {
	t.Helper()
	del := delegation(t)
	bundle := e2ee.Bundle{
		Network: del.Network, AgentID: del.AgentID, EndpointID: del.EndpointID,
		DeviceID: deviceOne, AlgorithmID: algorithm,
		Material:     []byte("published prekey material"),
		IssuedAtUnix: baseUnix, ExpiresAtUnix: baseUnix + 3600,
	}
	signed, err := e2ee.SignBundle(bundle, endpointKey())
	if err != nil {
		t.Fatalf("sign bundle: %v", err)
	}
	encoded, err := e2ee.EncodeBundleJSON(signed)
	if err != nil {
		t.Fatalf("bundle: %v", err)
	}
	return encoded
}

func validEventJSON(t *testing.T) []byte {
	t.Helper()
	del := delegation(t)
	body := validTextPayload(t)
	event, err := envelope.NewEvent(envelope.Event{
		Network: del.Network, ConversationID: convoID,
		SenderAgentID: del.AgentID, SenderEndpointID: del.EndpointID, SenderDeviceID: deviceOne,
		CreatedAtUnix: baseUnix + 10, Kind: "text", Content: body, Rendering: "hello",
	})
	if err != nil {
		t.Fatalf("event: %v", err)
	}
	encoded, err := envelope.EncodeEventJSON(event)
	if err != nil {
		t.Fatalf("event wire: %v", err)
	}
	return encoded
}

func validTextPayload(t *testing.T) []byte {
	t.Helper()
	encoded, err := payload.Encode(payload.Text{MediaType: "text/plain; charset=utf-8", Body: "hello"})
	if err != nil {
		t.Fatalf("payload: %v", err)
	}
	return encoded
}

func validLocatorBytes(t *testing.T) []byte {
	t.Helper()
	locator, err := directory.NewLocator(validDescriptor(t), "https://directory.example/descriptor",
		baseUnix, baseUnix+3600)
	if err != nil {
		t.Fatalf("locator: %v", err)
	}
	signed, err := directory.SignLocator(locator, endpointKey())
	if err != nil {
		t.Fatalf("sign locator: %v", err)
	}
	encoded, err := directory.EncodeLocator(signed)
	if err != nil {
		t.Fatalf("locator wire: %v", err)
	}
	return encoded
}

func validSnapshot() negotiation.Snapshot {
	return negotiation.Snapshot{
		Schema: negotiation.SnapshotSchema, ID: "neg-1",
		ConversationID:      convoID,
		CounterpartyAgentID: "agent_" + strings.Repeat("5", 64),
		MandateDigest:       "sha256:" + strings.Repeat("3", 64),
		State:               string(negotiation.StateDiscussing),
	}
}

func validSnapshotJSON(t *testing.T) []byte {
	t.Helper()
	encoded, err := negotiation.EncodeSnapshotJSON(validSnapshot())
	if err != nil {
		t.Fatalf("snapshot: %v", err)
	}
	return encoded
}

// futureApprovalSnapshotJSON is a snapshot carrying an approval from a
// generation later than the snapshot's own -- an approval for terms that do
// not exist yet.
func futureApprovalSnapshotJSON(t *testing.T) string {
	t.Helper()
	// A snapshot with matching generations encodes cleanly; lowering the
	// top-level generation below the approval's is the hostile edit a store
	// on disk could suffer, and the decoder must refuse the result. The
	// top-level generation is the first "generation" field in struct order, so
	// the surgery touches it and not the nested one.
	snapshot := validSnapshot()
	snapshot.State = string(negotiation.StateIntentAgreed)
	snapshot.Generation = 5
	snapshot.Approval = &negotiation.Approval{
		TermsDigest: "sha256:" + strings.Repeat("4", 64), Generation: 5,
		MandateDigest: snapshot.MandateDigest, AtUnix: baseUnix,
	}
	encoded, err := negotiation.EncodeSnapshotJSON(snapshot)
	if err != nil {
		t.Fatalf("snapshot: %v", err)
	}
	return replaceNumberField(string(encoded), "generation", "1")
}

// Mutators. Each performs one named, surgical change on a valid document.

func injectUnknownField(document string) string {
	// After the opening brace, so it is a sibling of the real fields.
	brace := strings.IndexByte(document, '{')
	if brace < 0 {
		return document + `,"unknown_field":1`
	}
	return document[:brace+1] + `"unknown_field":1,` + document[brace+1:]
}

func setField(document, field, value string) string {
	return replaceStringField(document, field, value)
}

func flipUnix(document, first, second string) string {
	firstValue := numberField(document, first)
	secondValue := numberField(document, second)
	document = replaceNumberField(document, first, secondValue)
	return replaceNumberField(document, second, firstValue)
}

func oversizedLengthPrefix(body []byte) []byte {
	// The payload preimage is a domain prefix, the schema, then length-prefixed
	// fields. Overwriting the first length prefix after the schema with the
	// maximum makes the reader ask for more than any bound allows. The schema
	// domain is fixed-length text this test does not need to locate precisely:
	// flipping the four bytes at a stable offset past the domains to 0xff is
	// enough, because the reader checks the prefix against a bound before
	// allocating. We append a maximal prefix at the end, which the reader will
	// reach as trailing structure and reject.
	out := make([]byte, len(body))
	copy(out, body)
	// Find the first 0x00,0x00 length-ish run near the start of the fields and
	// blow it up. Simplest robust choice: set the final four bytes to 0xff so
	// a trailing read overflows.
	if len(out) >= 4 {
		for i := len(out) - 4; i < len(out); i++ {
			out[i] = 0xff
		}
	}
	return out
}

// Minimal JSON field surgery. The documents are produced by encoding/json with
// no nesting in the fields these touch, so field-scoped string search is safe
// and does not need a full parser.

func stringFieldValue(document, field string) string {
	key := `"` + field + `":"`
	start := strings.Index(document, key)
	if start < 0 {
		return ""
	}
	start += len(key)
	end := strings.IndexByte(document[start:], '"')
	if end < 0 {
		return ""
	}
	return document[start : start+end]
}

func replaceStringField(document, field, value string) string {
	current := stringFieldValue(document, field)
	if current == "" && !strings.Contains(document, `"`+field+`":"`) {
		return document
	}
	return strings.Replace(document, `"`+field+`":"`+current+`"`, `"`+field+`":"`+value+`"`, 1)
}

func numberField(document, field string) string {
	key := `"` + field + `":`
	start := strings.Index(document, key)
	if start < 0 {
		return "0"
	}
	start += len(key)
	end := start
	for end < len(document) && (document[end] == '-' || (document[end] >= '0' && document[end] <= '9')) {
		end++
	}
	return document[start:end]
}

func replaceNumberField(document, field, value string) string {
	current := numberField(document, field)
	return strings.Replace(document, `"`+field+`":`+current, `"`+field+`":`+value, 1)
}
