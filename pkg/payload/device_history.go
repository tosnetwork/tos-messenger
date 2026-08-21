package payload

import (
	"bytes"
	"errors"

	"github.com/tosnetwork/tos-messenger/internal/canon"
	"github.com/tosnetwork/tos-messenger/internal/ids"
)

const (
	MaxHistoryEventsPerSegment = 16
	// MaxHistorySegmentEventBytes leaves room beneath the Event content bound
	// for canonical field/count/length framing.
	MaxHistorySegmentEventBytes = 96 << 10
)

// DeviceHistorySegment carries a bounded direct-conversation backfill from
// one currently authorized device to another. It is itself transported inside
// the existing authenticated pairwise Event/session; this body defines no
// second encryption or key-agreement protocol.
type DeviceHistorySegment struct {
	SourceDeviceID        string
	TargetDeviceID        string
	ConversationID        string
	Sequence              uint64
	PreviousSegmentDigest string
	AfterCreatedAtUnix    uint64
	AfterEventID          string
	Events                [][]byte
}

func (DeviceHistorySegment) Schema() string {
	return "tos.messaging.payload.device-history-segment.v1"
}

func (h DeviceHistorySegment) Validate() error {
	if !ids.Device.MatchString(h.SourceDeviceID) || !ids.Device.MatchString(h.TargetDeviceID) ||
		h.SourceDeviceID == h.TargetDeviceID {
		return errors.New("history segment needs two distinct device identifiers")
	}
	if !ids.Conversation.MatchString(h.ConversationID) {
		return errors.New("history segment has an invalid conversation")
	}
	if h.Sequence == 0 {
		return errors.New("history segment sequence must start at one")
	}
	if h.Sequence == 1 {
		if h.PreviousSegmentDigest != "" || h.AfterCreatedAtUnix != 0 || h.AfterEventID != "" {
			return errors.New("first history segment cannot name a predecessor or cursor")
		}
	} else if !canon.ValidDigest(h.PreviousSegmentDigest) || h.AfterCreatedAtUnix == 0 || !ids.Event.MatchString(h.AfterEventID) {
		return errors.New("history segment needs its exact predecessor and cursor")
	}
	if len(h.Events) == 0 || len(h.Events) > MaxHistoryEventsPerSegment {
		return errors.New("history segment event count is outside its bound")
	}
	total := 0
	for _, event := range h.Events {
		if len(event) == 0 || len(event) > MaxOpaqueBytes {
			return errors.New("history segment contains an invalid event")
		}
		total += len(event)
		if total > MaxHistorySegmentEventBytes {
			return errors.New("history segment exceeds its content bound")
		}
	}
	return nil
}

func (h DeviceHistorySegment) encode(buffer *bytes.Buffer) {
	canon.Text(buffer, h.SourceDeviceID)
	canon.Text(buffer, h.TargetDeviceID)
	canon.Text(buffer, h.ConversationID)
	canon.Uint64(buffer, h.Sequence)
	canon.Text(buffer, h.PreviousSegmentDigest)
	canon.Uint64(buffer, h.AfterCreatedAtUnix)
	canon.Text(buffer, h.AfterEventID)
	canon.Uint32(buffer, uint32(len(h.Events)))
	for _, event := range h.Events {
		canon.Bytes(buffer, event)
	}
}

func decodeDeviceHistorySegment(reader *canon.Reader) Payload {
	segment := DeviceHistorySegment{
		SourceDeviceID: reader.Text(MaxShortTextBytes), TargetDeviceID: reader.Text(MaxShortTextBytes),
		ConversationID: reader.Text(MaxShortTextBytes), Sequence: reader.Uint64(),
		PreviousSegmentDigest: reader.Text(MaxDigestBytes),
		AfterCreatedAtUnix:    reader.Uint64(), AfterEventID: reader.Text(MaxShortTextBytes),
	}
	count := reader.Count(MaxHistoryEventsPerSegment)
	segment.Events = make([][]byte, 0, count)
	for index := 0; index < count; index++ {
		segment.Events = append(segment.Events, reader.Bytes(MaxOpaqueBytes))
	}
	return segment
}
