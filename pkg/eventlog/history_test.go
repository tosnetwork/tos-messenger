package eventlog

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/tosnetwork/tos-messenger/internal/canon"
	"github.com/tosnetwork/tos-messenger/pkg/envelope"
	"github.com/tosnetwork/tos-messenger/pkg/payload"
	nativev1 "github.com/tosnetwork/tos-service-protocol/gen/tos/service/v1"
)

const (
	historyAgent    = "agent_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	historyEndpoint = "mep_bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	historySource   = "dev_1111111111111111111111111111111111111111111111111111111111111111"
	historyTarget   = "dev_2222222222222222222222222222222222222222222222222222222222222222"
	historyPeer     = "dev_3333333333333333333333333333333333333333333333333333333333333333"
	historyConvo    = "conv_4444444444444444444444444444444444444444444444444444444444444444"
)

func TestHistorySegmentsApplyIdempotentlyAndSurviveRestart(t *testing.T) {
	root := filepath.Join(t.TempDir(), "state")
	journal, err := Open(root)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Unix(1_800_000_100, 0)
	firstEvent := historicalText(t, 1_800_000_001, "first")
	secondEvent := historicalText(t, 1_800_000_002, "second")
	first := historySegmentEvent(t, payload.DeviceHistorySegment{SourceDeviceID: historySource,
		TargetDeviceID: historyTarget, ConversationID: historyConvo, Sequence: 1,
		Events: [][]byte{eventJSON(t, firstEvent)}}, 1_800_000_010)
	segment := decodeHistoryBody(t, first)
	if fresh, err := journal.ApplyHistorySegment(first, segment, historyAgent, historyEndpoint, historyTarget,
		[]string{historySource, historyTarget}, now); err != nil || !fresh {
		t.Fatalf("apply first: fresh=%v err=%v", fresh, err)
	}
	if fresh, err := journal.ApplyHistorySegment(first, segment, historyAgent, historyEndpoint, historyTarget,
		[]string{historySource, historyTarget}, now); err != nil || fresh {
		t.Fatalf("idempotent retry: fresh=%v err=%v", fresh, err)
	}
	second := historySegmentEvent(t, payload.DeviceHistorySegment{SourceDeviceID: historySource,
		TargetDeviceID: historyTarget, ConversationID: historyConvo, Sequence: 2,
		PreviousSegmentDigest: canon.Digest(first.Content), AfterCreatedAtUnix: firstEvent.CreatedAtUnix,
		AfterEventID: firstEvent.EventID, Events: [][]byte{eventJSON(t, secondEvent)}}, 1_800_000_011)
	if fresh, err := journal.ApplyHistorySegment(second, decodeHistoryBody(t, second), historyAgent, historyEndpoint,
		historyTarget, []string{historySource, historyTarget}, now); err != nil || !fresh {
		t.Fatalf("apply second: fresh=%v err=%v", fresh, err)
	}
	history, err := journal.History(historyConvo, 0)
	if err != nil || len(history) != 2 || history[0].EventID != firstEvent.EventID || history[1].EventID != secondEvent.EventID {
		t.Fatalf("history: %+v err=%v", history, err)
	}
	if err := journal.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := Open(root)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	history, err = reopened.History(historyConvo, 1)
	if err != nil || len(history) != 1 || history[0].EventID != secondEvent.EventID {
		t.Fatalf("restart/limit: %+v err=%v", history, err)
	}
}

func TestBuildHistorySegmentUsesStableDurableCursor(t *testing.T) {
	journal, _ := openJournal(t)
	now := time.Unix(1_800_000_100, 0)
	inboundEvent := historicalText(t, 1_800_000_001, "inbound applied")
	inboundRaw := eventJSON(t, inboundEvent)
	if _, _, err := journal.Accept(Entry{EventID: inboundEvent.EventID, SenderEndpointID: inboundEvent.SenderEndpointID,
		ConversationID: historyConvo, Payload: inboundRaw, Admission: AdmissionAdmitted,
		ReceivedAtUnix: inboundEvent.CreatedAtUnix}); err != nil {
		t.Fatal(err)
	}
	if _, err := journal.ClaimForApplication(inboundEvent.EventID, lease(0x91), now, time.Minute); err != nil {
		t.Fatal(err)
	}
	if _, err := journal.CompleteApplication(inboundEvent.EventID, lease(0x91), now); err != nil {
		t.Fatal(err)
	}
	outboundEvent := historicalText(t, 1_800_000_002, "outbound delivered")
	outboundEvent.SenderAgentID, outboundEvent.SenderEndpointID, outboundEvent.SenderDeviceID = historyAgent, historyEndpoint, historySource
	outboundEvent.EventID = ""
	var err error
	outboundEvent, err = envelope.NewEvent(outboundEvent)
	if err != nil {
		t.Fatal(err)
	}
	outboundRaw := eventJSON(t, outboundEvent)
	if _, _, err := journal.Enqueue(Outbound{EventID: outboundEvent.EventID, SessionID: session(0x92),
		RecipientEndpointID: "mep_" + strings.Repeat("9", 64), ConversationID: historyConvo,
		Payload: outboundRaw, CreatedAtUnix: outboundEvent.CreatedAtUnix, ExpiresAtUnix: outboundEvent.CreatedAtUnix + 3600}); err != nil {
		t.Fatal(err)
	}
	attemptID := claim(t, journal, outboundEvent.EventID, 0x92, now)
	if _, err := journal.Delivered(outboundEvent.EventID, attemptID, now); err != nil {
		t.Fatal(err)
	}
	queued := historicalText(t, 1_800_000_003, "not yet applied")
	if _, _, err := journal.Accept(Entry{EventID: queued.EventID, SenderEndpointID: queued.SenderEndpointID,
		ConversationID: historyConvo, Payload: eventJSON(t, queued), Admission: AdmissionAdmitted,
		ReceivedAtUnix: queued.CreatedAtUnix}); err != nil {
		t.Fatal(err)
	}

	first, err := journal.BuildHistorySegment(historySource, historyTarget, historyConvo, 1, "", 0, "", 1)
	if err != nil || len(first.Events) != 1 {
		t.Fatalf("first page: %+v err=%v", first, err)
	}
	firstDecoded, _ := envelope.DecodeEventJSON(first.Events[0])
	if firstDecoded.EventID != inboundEvent.EventID {
		t.Fatalf("unexpected first page: %s", firstDecoded.EventID)
	}
	firstContent, err := payload.Encode(first)
	if err != nil {
		t.Fatal(err)
	}
	second, err := journal.BuildHistorySegment(historySource, historyTarget, historyConvo, 2,
		canon.Digest(firstContent), firstDecoded.CreatedAtUnix, firstDecoded.EventID, 1)
	if err != nil || len(second.Events) != 1 {
		t.Fatalf("second page: %+v err=%v", second, err)
	}
	secondDecoded, _ := envelope.DecodeEventJSON(second.Events[0])
	if secondDecoded.EventID != outboundEvent.EventID {
		t.Fatalf("queued Event leaked or delivered Event was missed: %s", secondDecoded.EventID)
	}
	secondContent, _ := payload.Encode(second)
	if _, err := journal.BuildHistorySegment(historySource, historyTarget, historyConvo, 3,
		canon.Digest(secondContent), secondDecoded.CreatedAtUnix, secondDecoded.EventID, 1); !errors.Is(err, ErrHistoryExhausted) {
		t.Fatalf("exhausted cursor returned %v", err)
	}
}

func TestHistorySegmentRefusesGapSubstitutionAndUnsafeContent(t *testing.T) {
	journal, _ := openJournal(t)
	now := time.Unix(1_800_000_100, 0)
	event := historicalText(t, 1_800_000_001, "safe")
	base := payload.DeviceHistorySegment{SourceDeviceID: historySource, TargetDeviceID: historyTarget,
		ConversationID: historyConvo, Sequence: 2, PreviousSegmentDigest: "sha256:" + strings.Repeat("9", 64),
		AfterCreatedAtUnix: 1_800_000_000, AfterEventID: "evt_" + strings.Repeat("9", 64),
		Events: [][]byte{eventJSON(t, event)}}
	outer := historySegmentEvent(t, base, 1_800_000_010)
	if _, err := journal.ApplyHistorySegment(outer, base, historyAgent, historyEndpoint, historyTarget,
		[]string{historySource, historyTarget}, now); !errors.Is(err, ErrHistorySequence) {
		t.Fatalf("gap: %v", err)
	}
	base.Sequence, base.PreviousSegmentDigest, base.AfterCreatedAtUnix, base.AfterEventID = 1, "", 0, ""
	outer = historySegmentEvent(t, base, 1_800_000_010)
	if _, err := journal.ApplyHistorySegment(outer, base, historyAgent, historyEndpoint, historyPeer,
		[]string{historyPeer, historySource, historyTarget}, now); !errors.Is(err, ErrHistoryRoute) {
		t.Fatalf("target substitution: %v", err)
	}
	if _, err := journal.ApplyHistorySegment(outer, base, historyAgent, historyEndpoint, historyTarget,
		[]string{historyTarget}, now); !errors.Is(err, ErrHistoryDevice) {
		t.Fatalf("revoked source: %v", err)
	}

	roomEvent := event
	roomEvent.EventID = ""
	roomEvent.RoomID = "room_" + strings.Repeat("5", 64)
	roomEvent, err := envelope.NewEvent(roomEvent)
	if err != nil {
		t.Fatal(err)
	}
	base.Events = [][]byte{eventJSON(t, roomEvent)}
	outer = historySegmentEvent(t, base, 1_800_000_010)
	if _, err := journal.ApplyHistorySegment(outer, base, historyAgent, historyEndpoint, historyTarget,
		[]string{historySource, historyTarget}, now); !errors.Is(err, ErrHistoryContent) {
		t.Fatalf("room backfill: %v", err)
	}
}

func TestDeviceHistoryExportRefusesRoomRoute(t *testing.T) {
	journal, _ := openJournal(t)
	if _, err := journal.BuildHistorySegment(historySource, historyTarget,
		"room_"+strings.Repeat("5", 64), 1, "", 0, "", 1); err == nil ||
		err.Error() != "invalid history export request" {
		t.Fatalf("room identifier reached direct-history export: %v", err)
	}
}

func TestHistoryListingFailsClosedOnManifestDamageAndIgnoresOrphans(t *testing.T) {
	journal, root := openJournal(t)
	now := time.Unix(1_800_000_100, 0)
	event := historicalText(t, 1_800_000_001, "visible")
	segment := payload.DeviceHistorySegment{SourceDeviceID: historySource, TargetDeviceID: historyTarget,
		ConversationID: historyConvo, Sequence: 1, Events: [][]byte{eventJSON(t, event)}}
	outer := historySegmentEvent(t, segment, 1_800_000_010)
	if _, err := journal.ApplyHistorySegment(outer, segment, historyAgent, historyEndpoint, historyTarget,
		[]string{historySource, historyTarget}, now); err != nil {
		t.Fatal(err)
	}
	orphan := historicalText(t, 1_800_000_002, "orphan")
	if err := os.WriteFile(filepath.Join(root, historySyncDir, "objects", orphan.EventID[len("evt_"):]+".json"), eventJSON(t, orphan), 0o600); err != nil {
		t.Fatal(err)
	}
	history, err := journal.History(historyConvo, 0)
	if err != nil || len(history) != 1 || history[0].EventID != event.EventID {
		t.Fatalf("orphan became visible: %+v err=%v", history, err)
	}
	manifest := filepath.Join(root, historySyncDir, "chains", historyConvo[len("conv_"):],
		historySource[len("dev_"):]+"-"+historyTarget[len("dev_"):], "segments", "00000000000000000001.json")
	if err := os.WriteFile(manifest, []byte(`{"schema":"damaged"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := journal.History(historyConvo, 0); err == nil {
		t.Fatal("damaged committed manifest was skipped")
	}
}

func historyNetwork() *nativev1.NetworkDomain {
	return &nativev1.NetworkDomain{NetworkId: "tos-test", GenesisRootHash: strings.Repeat("a", 64), GenesisFileHash: strings.Repeat("b", 64)}
}

func historicalText(t *testing.T, created uint64, body string) envelope.Event {
	t.Helper()
	content, err := payload.Encode(payload.Text{MediaType: "text/plain; charset=utf-8", Body: body})
	if err != nil {
		t.Fatal(err)
	}
	event, err := envelope.NewEvent(envelope.Event{Network: historyNetwork(), ConversationID: historyConvo,
		SenderAgentID: "agent_" + strings.Repeat("6", 64), SenderEndpointID: "mep_" + strings.Repeat("7", 64),
		SenderDeviceID: "dev_" + strings.Repeat("8", 64), CreatedAtUnix: created, Kind: "text", Content: content})
	if err != nil {
		t.Fatal(err)
	}
	return event
}

func historySegmentEvent(t *testing.T, segment payload.DeviceHistorySegment, created uint64) envelope.Event {
	t.Helper()
	content, err := payload.Encode(segment)
	if err != nil {
		t.Fatal(err)
	}
	event, err := envelope.NewEvent(envelope.Event{Network: historyNetwork(), ConversationID: historyConvo,
		SenderAgentID: historyAgent, SenderEndpointID: historyEndpoint, SenderDeviceID: historySource,
		CreatedAtUnix: created, Kind: "device.history.segment", Content: content})
	if err != nil {
		t.Fatal(err)
	}
	return event
}

func eventJSON(t *testing.T, event envelope.Event) []byte {
	t.Helper()
	raw, err := envelope.EncodeEventJSON(event)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func decodeHistoryBody(t *testing.T, event envelope.Event) payload.DeviceHistorySegment {
	t.Helper()
	decoded, err := payload.Decode(event.Kind, event.Content)
	if err != nil {
		t.Fatal(err)
	}
	return decoded.(payload.DeviceHistorySegment)
}
