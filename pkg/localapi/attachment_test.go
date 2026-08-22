package localapi

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"strings"
	"testing"
	"time"

	"github.com/tosnetwork/tos-messenger/internal/canon"
	"github.com/tosnetwork/tos-messenger/pkg/attachmentadmission"
	"github.com/tosnetwork/tos-messenger/pkg/attachments"
	"github.com/tosnetwork/tos-messenger/pkg/envelope"
	"github.com/tosnetwork/tos-messenger/pkg/firewall"
	"github.com/tosnetwork/tos-messenger/pkg/payload"
)

type fixedAttachmentAdmitter struct {
	result attachmentadmission.Result
	seen   chan envelope.Event
}

func (a *fixedAttachmentAdmitter) Admit(_ context.Context, event envelope.Event) (attachmentadmission.Result, error) {
	a.seen <- event
	return a.result, nil
}

func TestEncryptedAttachmentIsReservedAndOnlyAdmittedContentCrossesRuntimeAPI(t *testing.T) {
	h := newHarness(t)
	plaintext := []byte("scanner-admitted text\n")
	event, capabilityKey := attachmentEvent(t, plaintext)
	admitter := &fixedAttachmentAdmitter{seen: make(chan envelope.Event, 1), result: attachmentadmission.Result{
		Body: string(plaintext), Metadata: attachments.Metadata{Filename: "note.txt", MediaType: "text/plain",
			PlaintextDigest: canon.Digest(plaintext), ExpiresAtUnix: baseUnix + 3600},
		Report: attachments.AdmissionReport{Schema: attachments.AdmissionReportSchema,
			PlaintextDigest: canon.Digest(plaintext), SizeBytes: uint64(len(plaintext)), MediaType: "text/plain",
			Scans: []attachments.ScanVerdict{{ScannerID: "reference-text",
				ScannerDigest: "sha256:" + strings.Repeat("e", 64), Decision: attachments.ScanAllow,
				Resources: []attachments.ScanResourceEvidence{
					{Name: "clamscan", Digest: "sha256:" + strings.Repeat("1", 64)},
					{Name: "daily.cvd", Digest: "sha256:" + strings.Repeat("2", 64)},
				}}}},
	}}
	server, err := NewServer(Config{Journal: h.journal, Dispatcher: h.dispatcher, Policy: firewall.Default(),
		OwnerKey: testOwnerPublic(), LocalEndpointID: peerMEP, Now: func() time.Time { return h.clock },
		DeviceIDs: []string{senderDev, targetDev}, AttachmentAdmitter: admitter})
	if err != nil {
		t.Fatal(err)
	}
	h.server = server
	h.receive(t, event)

	if response := h.call(t, Request{Op: OpPending}); !response.OK || len(response.Events) != 0 {
		t.Fatalf("secret attachment appeared in general inbox: %+v", response)
	}
	if response := h.call(t, Request{Op: OpClaim, EventID: event.EventID, LeaseID: leaseID, LeaseSeconds: 60}); response.OK {
		t.Fatalf("general claim obtained secret attachment: %+v", response)
	}
	listing := h.call(t, Request{Op: OpPendingAttachments})
	if !listing.OK || len(listing.Attachments) != 1 || listing.Attachments[0].EventID != event.EventID {
		t.Fatalf("wrong attachment listing: %+v", listing)
	}
	claimed := h.call(t, Request{Op: OpClaimAttachment, EventID: event.EventID, LeaseID: leaseID, LeaseSeconds: 60})
	if !claimed.OK || claimed.Attachment == nil || claimed.Attachment.Body != string(plaintext) ||
		claimed.Attachment.PlaintextDigest != canon.Digest(plaintext) || len(claimed.Attachment.Scans) != 1 ||
		len(claimed.Attachment.Scans[0].Resources) != 2 ||
		claimed.Attachment.Scans[0].Resources[0].Name != "clamscan" ||
		claimed.Attachment.Scans[0].Resources[1].Digest != "sha256:"+strings.Repeat("2", 64) {
		t.Fatalf("wrong admitted attachment: %+v", claimed)
	}
	if seen := <-admitter.seen; seen.EventID != event.EventID {
		t.Fatalf("admitter saw another Event: %+v", seen)
	}
	wire, err := EncodeResponse(claimed)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(wire, []byte(hex.EncodeToString(capabilityKey))) || bytes.Contains(wire, []byte("key_hex")) ||
		bytes.Contains(wire, []byte("fetch_grant")) {
		t.Fatal("runtime response leaked attachment key material")
	}
	if response := h.call(t, Request{Op: OpComplete, EventID: event.EventID, LeaseID: leaseID}); !response.OK {
		t.Fatalf("complete admitted attachment: %+v", response)
	}
}

func attachmentEvent(t *testing.T, plaintext []byte) (envelope.Event, ed25519.PrivateKey) {
	t.Helper()
	ref, chunks, err := attachments.Seal(bytes.NewReader(bytes.Repeat([]byte{0x71},
		attachments.KeyBytes+attachments.AttachmentIDBytes+attachments.NoncePrefixBytes)), plaintext,
		attachments.Metadata{Filename: "note.txt", MediaType: "text/plain", PlaintextDigest: canon.Digest(plaintext),
			ExpiresAtUnix: baseUnix + 3600})
	if err != nil {
		t.Fatal(err)
	}
	referenceJSON, err := attachments.EncodeReferenceJSON(ref)
	if err != nil {
		t.Fatal(err)
	}
	manifestDigest, err := attachments.ManifestDigest(ref.Manifest)
	if err != nil {
		t.Fatal(err)
	}
	endpointKey := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x72}, ed25519.SeedSize))
	storageKey := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x73}, ed25519.SeedSize))
	capabilityKey := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x74}, ed25519.SeedSize))
	var ciphertextBytes uint64
	for _, chunk := range chunks {
		ciphertextBytes += uint64(len(chunk.Ciphertext))
	}
	grant, err := attachments.SignGrant(attachments.CapabilityGrant{NetworkID: testNetwork().NetworkId,
		GenesisRootHash: testNetwork().GenesisRootHash, GenesisFileHash: testNetwork().GenesisFileHash,
		AgentID: senderID, EndpointID: senderMEP,
		StoragePublicKeyHex:    hex.EncodeToString(storageKey.Public().(ed25519.PublicKey)),
		CapabilityPublicKeyHex: hex.EncodeToString(capabilityKey.Public().(ed25519.PublicKey)),
		ManifestDigest:         manifestDigest, ChunkDigests: append([]string(nil), ref.Manifest.ChunkDigests...),
		CiphertextBytes: ciphertextBytes, RetainUntilUnix: ref.Metadata.ExpiresAtUnix,
		Operations: []attachments.Operation{attachments.OperationFetch}, IssuedAtUnix: baseUnix,
		ExpiresAtUnix: ref.Metadata.ExpiresAtUnix}, endpointKey)
	if err != nil {
		t.Fatal(err)
	}
	grantJSON, err := attachments.EncodeGrantJSON(grant)
	if err != nil {
		t.Fatal(err)
	}
	locator, err := attachments.HTTPSLocator("https://attachments.example", manifestDigest)
	if err != nil {
		t.Fatal(err)
	}
	content, err := payload.Encode(payload.EncryptedAttachment{ManifestDigest: manifestDigest, ReferenceJSON: referenceJSON,
		Locator: locator, FetchGrantJSON: grantJSON, FetchCapabilityPrivateKeyHex: hex.EncodeToString(capabilityKey)})
	if err != nil {
		t.Fatal(err)
	}
	event, err := envelope.NewEvent(envelope.Event{Network: testNetwork(), ConversationID: convoID,
		SenderAgentID: senderID, SenderEndpointID: senderMEP, SenderDeviceID: senderDev,
		CreatedAtUnix: baseUnix + 1, ExpiresAtUnix: baseUnix + 3600, Kind: "artifact.encrypted", Content: content,
		AttachmentReferences: []string{manifestDigest}})
	if err != nil {
		t.Fatal(err)
	}
	return event, capabilityKey
}
