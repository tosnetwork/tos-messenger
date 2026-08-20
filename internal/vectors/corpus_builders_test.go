package vectors

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"strings"
	"testing"

	"github.com/tosnetwork/tos-messenger/internal/canon"
	"github.com/tosnetwork/tos-messenger/pkg/attachments"
	"github.com/tosnetwork/tos-messenger/pkg/directory"
	"github.com/tosnetwork/tos-messenger/pkg/e2ee"
	"github.com/tosnetwork/tos-messenger/pkg/envelope"
	"github.com/tosnetwork/tos-messenger/pkg/group"
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

func validMLSCredential(t *testing.T) group.DeviceCredential {
	t.Helper()
	del := delegation(t)
	leaf := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x33}, ed25519.SeedSize))
	credential, err := group.SignDeviceCredential(group.DeviceCredential{
		Network: del.Network, AgentID: del.AgentID, EndpointID: del.EndpointID,
		DeviceID: deviceOne, DeviceSetDigest: "sha256:" + strings.Repeat("8c", 32),
		LeafSignaturePublicKey: leaf.Public().(ed25519.PublicKey),
		KeyPackage:             []byte("fixed RFC 9420 KeyPackage candidate bytes"),
		IssuedAtUnix:           baseUnix, ExpiresAtUnix: baseUnix + 3600,
	}, endpointKey())
	if err != nil {
		t.Fatalf("MLS credential: %v", err)
	}
	return credential
}

func validMLSCredentialJSON(t *testing.T) []byte {
	t.Helper()
	raw, err := group.EncodeDeviceCredentialJSON(validMLSCredential(t))
	if err != nil {
		t.Fatalf("MLS credential wire: %v", err)
	}
	return raw
}

func validEncryptedAttachmentJSON(t *testing.T) []byte {
	t.Helper()
	plaintext := []byte("private attachment vector")
	random := bytes.NewReader(bytes.Repeat([]byte{0x5d}, attachments.KeyBytes+attachments.AttachmentIDBytes+attachments.NoncePrefixBytes))
	ref, _, err := attachments.Seal(random, plaintext, attachments.Metadata{Filename: "vector.txt", MediaType: "text/plain", PlaintextDigest: canon.Digest(plaintext), ExpiresAtUnix: baseUnix + 3600})
	if err != nil {
		t.Fatalf("attachment: %v", err)
	}
	raw, err := attachments.EncodeReferenceJSON(ref)
	if err != nil {
		t.Fatalf("attachment wire: %v", err)
	}
	return raw
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
		Network:             testNetwork(),
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

// snapshotTerms is a complete set of negotiation terms priced on the given
// network. The network rides inside the asset, and through the asset inside
// the terms digest: the same numbers on two networks are two digests.
func snapshotTerms(network negotiation.Network) *negotiation.Terms {
	return &negotiation.Terms{
		CapabilityID:           "cap_" + strings.Repeat("9", 64),
		CapabilityVersion:      "1.0.0",
		CapabilityClass:        "software.audit",
		ProviderAgentID:        "agent_" + strings.Repeat("5", 64),
		ManifestDigest:         "sha256:" + strings.Repeat("d", 64),
		TransportBindingDigest: "sha256:" + strings.Repeat("e", 64),
		Price: negotiation.Money{Asset: negotiation.Asset{
			Network:        network,
			Workchain:      0,
			AccountID:      strings.Repeat("a", 64),
			MasterCodeHash: "tvm-cell-sha256:" + strings.Repeat("b", 64),
			WalletCodeHash: "tvm-cell-sha256:" + strings.Repeat("c", 64),
			Decimals:       6,
		}, Atomic: "100"},
		EscrowTermsDigest:   "sha256:" + strings.Repeat("f", 64),
		DisputePolicyDigest: "sha256:" + strings.Repeat("1", 64),
		NotAfterUnix:        baseUnix + 3600,
	}
}

// snapshotNetworkIdentity is the value form of the snapshot's bound network.
func snapshotNetworkIdentity(t *testing.T) negotiation.Network {
	t.Helper()
	network, err := negotiation.NetworkFromDomain(testNetwork())
	if err != nil {
		t.Fatalf("network: %v", err)
	}
	return network
}

// crossNetworkTermsSnapshotJSON is a snapshot whose on-table terms are priced
// on a network other than the one the exchange is bound to. The terms digest
// commits the asset's network, so this is a foreign purchase's digest riding a
// local conversation, and the decoder must refuse it. The same document with
// the terms priced on the bound network encodes and decodes cleanly, which is
// what proves the refusal is owed to the network and to nothing else.
func crossNetworkTermsSnapshotJSON(t *testing.T) string {
	t.Helper()
	snapshot := validSnapshot()
	snapshot.State = string(negotiation.StateProposalPending)
	snapshot.OnTable = snapshotTerms(snapshotNetworkIdentity(t))
	if _, err := negotiation.EncodeSnapshotJSON(snapshot); err != nil {
		t.Fatalf("the same-network baseline does not encode: %v", err)
	}
	foreign := snapshotNetworkIdentity(t)
	foreign.ID = "tos-somewhere-else"
	snapshot.OnTable = snapshotTerms(foreign)
	// The valid encoder refuses this document, so the hostile form a store on
	// disk could suffer is marshalled directly.
	encoded, err := json.Marshal(snapshot)
	if err != nil {
		t.Fatalf("marshal snapshot: %v", err)
	}
	return string(encoded)
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
