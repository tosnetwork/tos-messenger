package localapi

import (
	"context"
	"strings"
	"testing"

	"github.com/tosnetwork/tos-messenger/pkg/attachmentops"
)

type recordingAttachmentEmitter struct {
	begun   attachmentops.BeginRequest
	chunk   []byte
	upload  string
	index   uint32
	commits int
}

func (e *recordingAttachmentEmitter) Begin(request attachmentops.BeginRequest) (attachmentops.Progress, error) {
	e.begun = request
	return attachmentops.Progress{UploadID: "attup_" + strings.Repeat("a", 64)}, nil
}

func (e *recordingAttachmentEmitter) Append(upload string, index uint32, chunk []byte) (attachmentops.Progress, error) {
	e.upload, e.index, e.chunk = upload, index, append([]byte(nil), chunk...)
	return attachmentops.Progress{UploadID: upload, NextChunk: index + 1}, nil
}

func (e *recordingAttachmentEmitter) Commit(context.Context, string) (attachmentops.Progress, error) {
	e.commits++
	return attachmentops.Progress{Complete: true, EventID: "evt_" + strings.Repeat("b", 64)}, nil
}

func TestRuntimeStreamsOutboundAttachmentWithoutAuthorityFields(t *testing.T) {
	h := newHarness(t)
	emitter := new(recordingAttachmentEmitter)
	h.server.config.AttachmentEmitter = emitter
	roomID := "room_" + strings.Repeat("c", 64)
	begin := h.call(t, Request{Op: OpBeginOutboundAttachment, ConversationID: convoID, RoomID: roomID,
		ReplyToEventID: "evt_" + strings.Repeat("d", 64), MembershipEpoch: 9,
		IdempotencyKey: "idem_" + strings.Repeat("e", 64), SessionID: sessionID, RecipientEndpointID: peerMEP,
		Filename: "evidence.txt", MediaType: "text/plain", PlaintextDigest: "sha256:" + strings.Repeat("f", 64), PlaintextBytes: 5})
	if !begin.OK || begin.UploadID == "" || emitter.begun.Filename != "evidence.txt" || emitter.begun.MembershipEpoch != 9 {
		t.Fatalf("begin=%+v recorded=%+v", begin, emitter.begun)
	}
	appended := h.call(t, Request{Op: OpAppendOutboundAttachment, UploadID: begin.UploadID, Chunk: []byte("hello")})
	if !appended.OK || appended.NextChunk != 1 || string(emitter.chunk) != "hello" || emitter.index != 0 {
		t.Fatalf("append=%+v emitter=%+v", appended, emitter)
	}
	committed := h.call(t, Request{Op: OpCommitOutboundAttachment, UploadID: begin.UploadID})
	if !committed.OK || !committed.Complete || committed.EventID == "" || emitter.commits != 1 {
		t.Fatalf("commit=%+v count=%d", committed, emitter.commits)
	}
	if owner := h.callAs(t, PrincipalOwner, Request{Op: OpCommitOutboundAttachment, UploadID: begin.UploadID}); owner.OK {
		t.Fatal("owner socket acquired a runtime attachment operation")
	}
}

func TestOutboundAttachmentOperationsFailClosedWithoutOperatorResources(t *testing.T) {
	h := newHarness(t)
	response := h.call(t, Request{Op: OpBeginOutboundAttachment, ConversationID: convoID,
		IdempotencyKey: "idem_" + strings.Repeat("e", 64), SessionID: sessionID, RecipientEndpointID: peerMEP,
		Filename: "evidence.txt", MediaType: "text/plain", PlaintextDigest: "sha256:" + strings.Repeat("f", 64), PlaintextBytes: 5})
	if response.OK {
		t.Fatal("outbound attachment emission succeeded without operator resources")
	}
}
