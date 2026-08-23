package envelope

import (
	"strings"
	"testing"

	"github.com/tosnetwork/tos-messenger/pkg/payload"
)

func giftEvent(t *testing.T) Event {
	t.Helper()
	content, err := payload.Encode(payload.GiftAddressRequest{CanonicalRequest: []byte{0xa1, 1}})
	if err != nil {
		t.Fatal(err)
	}
	event, err := NewEvent(Event{Network: testNetwork(), ConversationID: "conv_" + strings.Repeat("1", 64),
		SenderAgentID: "agent_" + strings.Repeat("2", 64), SenderEndpointID: "mep_" + strings.Repeat("3", 64),
		SenderDeviceID: "dev_" + strings.Repeat("4", 64), CreatedAtUnix: baseUnix, ExpiresAtUnix: baseUnix + 300,
		Kind: "agent.gift.address-request", Content: content})
	if err != nil {
		t.Fatal(err)
	}
	return event
}

func TestAgentGiftEventsAreDirectOpaqueAndHaveNoRenderingMetadata(t *testing.T) {
	event := giftEvent(t)
	if !RequiresEstablishedDirect(event.Kind) {
		t.Fatal("Gift event did not require established direct session")
	}
	if err := ValidateEvent(event); err != nil {
		t.Fatal(err)
	}
	room := event
	room.EventID = ""
	room.RoomID = "room_" + strings.Repeat("5", 64)
	if _, err := NewEvent(room); err == nil {
		t.Fatal("room Gift carriage accepted")
	}
	rendered := event
	rendered.EventID = ""
	rendered.Rendering = "1 TOS to an address"
	if _, err := NewEvent(rendered); err == nil {
		t.Fatal("Gift authority leaked into rendering")
	}
}
