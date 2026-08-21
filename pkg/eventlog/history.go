package eventlog

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"time"

	"github.com/tosnetwork/tos-messenger/internal/canon"
	"github.com/tosnetwork/tos-messenger/internal/ids"
	"github.com/tosnetwork/tos-messenger/internal/securefile"
	"github.com/tosnetwork/tos-messenger/pkg/envelope"
	"github.com/tosnetwork/tos-messenger/pkg/payload"
)

const (
	HistoryCheckpointSchema    = "tos.messaging.history-checkpoint.v1"
	HistoryManifestSchema      = "tos.messaging.history-manifest.v1"
	MaxHistorySegmentsPerChain = 4096
)

var (
	ErrHistorySequence  = errors.New("history segment does not extend the accepted chain")
	ErrHistoryRoute     = errors.New("history segment is not bound to this device route")
	ErrHistoryDevice    = errors.New("history segment names an unauthorized device")
	ErrHistoryContent   = errors.New("history segment contains ineligible content")
	ErrHistoryExhausted = errors.New("no direct history remains after the requested cursor")
)

type historyCheckpoint struct {
	Schema             string `json:"schema"`
	ConversationID     string `json:"conversation_id"`
	SourceDeviceID     string `json:"source_device_id"`
	TargetDeviceID     string `json:"target_device_id"`
	Sequence           uint64 `json:"sequence"`
	LastSegmentDigest  string `json:"last_segment_digest"`
	LastEventCreatedAt uint64 `json:"last_event_created_at_unix"`
	LastEventID        string `json:"last_event_id"`
	UpdatedAtUnix      uint64 `json:"updated_at_unix"`
}

type historyManifest struct {
	Schema                string   `json:"schema"`
	ConversationID        string   `json:"conversation_id"`
	SourceDeviceID        string   `json:"source_device_id"`
	TargetDeviceID        string   `json:"target_device_id"`
	Sequence              uint64   `json:"sequence"`
	PreviousSegmentDigest string   `json:"previous_segment_digest,omitempty"`
	AfterCreatedAtUnix    uint64   `json:"after_created_at_unix,omitempty"`
	AfterEventID          string   `json:"after_event_id,omitempty"`
	SegmentDigest         string   `json:"segment_digest"`
	EventIDs              []string `json:"event_ids"`
	EventDigests          []string `json:"event_digests"`
	AppliedAtUnix         uint64   `json:"applied_at_unix"`
}

// BuildHistorySegment deterministically pages durable direct-conversation
// history for another device. Only applied inbound Events and delivered
// outbound Events are eligible; queued, rejected, local-only, room, recursive
// history, and execution-only state never enter a segment.
func (j *Journal) BuildHistorySegment(sourceDeviceID, targetDeviceID, conversationID string,
	sequence uint64, previousSegmentDigest string, afterCreatedAt uint64, afterEventID string,
	limit int) (payload.DeviceHistorySegment, error) {
	if err := j.usable(); err != nil {
		return payload.DeviceHistorySegment{}, err
	}
	if limit == 0 {
		limit = payload.MaxHistoryEventsPerSegment
	}
	segment := payload.DeviceHistorySegment{SourceDeviceID: sourceDeviceID, TargetDeviceID: targetDeviceID,
		ConversationID: conversationID, Sequence: sequence, PreviousSegmentDigest: previousSegmentDigest,
		AfterCreatedAtUnix: afterCreatedAt, AfterEventID: afterEventID}
	validCursor := sequence == 1 && previousSegmentDigest == "" && afterCreatedAt == 0 && afterEventID == "" ||
		sequence > 1 && canon.ValidDigest(previousSegmentDigest) && afterCreatedAt > 0 && ids.Event.MatchString(afterEventID)
	if limit < 1 || limit > payload.MaxHistoryEventsPerSegment || !ids.Device.MatchString(sourceDeviceID) ||
		!ids.Device.MatchString(targetDeviceID) || sourceDeviceID == targetDeviceID ||
		!ids.Conversation.MatchString(conversationID) || !validCursor {
		return payload.DeviceHistorySegment{}, errors.New("invalid history export request")
	}

	j.mutex.Lock()
	defer j.mutex.Unlock()
	type candidate struct {
		event envelope.Event
		raw   []byte
	}
	byID := make(map[string]candidate)
	add := func(raw []byte) error {
		event, err := envelope.DecodeEventJSON(raw)
		if err != nil {
			return errors.New("decode durable Event for history export")
		}
		if event.ConversationID != conversationID || event.RoomID != "" || event.Kind == "device.history.segment" ||
			envelope.LocalOnly(event.Kind) || event.CreatedAtUnix < afterCreatedAt ||
			(event.CreatedAtUnix == afterCreatedAt && event.EventID <= afterEventID) {
			return nil
		}
		canonical, err := envelope.EncodeEventJSON(event)
		if err != nil {
			return err
		}
		if existing, found := byID[event.EventID]; found && !bytes.Equal(existing.raw, canonical) {
			return ErrConflict
		}
		byID[event.EventID] = candidate{event: event, raw: canonical}
		return nil
	}
	inbound, err := os.ReadDir(j.inboundRoot())
	if err != nil {
		return payload.DeviceHistorySegment{}, errors.New("read inbound history source")
	}
	for _, entry := range inbound {
		if entry.IsDir() {
			return payload.DeviceHistorySegment{}, errors.New("inbound history source contains a directory")
		}
		record, err := readRecord(filepath.Join(j.inboundRoot(), entry.Name()))
		if err != nil {
			return payload.DeviceHistorySegment{}, err
		}
		if record.ConversationID != conversationID || record.Admission != AdmissionAdmitted ||
			record.Application != StateApplied || !record.Deliverable() {
			continue
		}
		raw, err := record.Payload()
		if err != nil {
			return payload.DeviceHistorySegment{}, err
		}
		if err := add(raw); err != nil {
			return payload.DeviceHistorySegment{}, err
		}
	}
	outbound, err := os.ReadDir(j.outboundRoot())
	if err != nil {
		return payload.DeviceHistorySegment{}, errors.New("read outbound history source")
	}
	for _, entry := range outbound {
		if entry.IsDir() {
			return payload.DeviceHistorySegment{}, errors.New("outbound history source contains a directory")
		}
		delivery, err := readDelivery(j.deliveryPathForFile(entry.Name()))
		if err != nil {
			return payload.DeviceHistorySegment{}, err
		}
		if delivery.ConversationID != conversationID || delivery.State != StateDelivered {
			continue
		}
		raw, err := delivery.Payload()
		if err != nil {
			return payload.DeviceHistorySegment{}, err
		}
		if err := add(raw); err != nil {
			return payload.DeviceHistorySegment{}, err
		}
	}
	candidates := make([]candidate, 0, len(byID))
	for _, item := range byID {
		candidates = append(candidates, item)
	}
	sort.Slice(candidates, func(i, k int) bool {
		if candidates[i].event.CreatedAtUnix != candidates[k].event.CreatedAtUnix {
			return candidates[i].event.CreatedAtUnix < candidates[k].event.CreatedAtUnix
		}
		return candidates[i].event.EventID < candidates[k].event.EventID
	})
	bytesUsed := 0
	for _, item := range candidates {
		if len(segment.Events) == limit || bytesUsed+len(item.raw) > payload.MaxHistorySegmentEventBytes {
			break
		}
		segment.Events = append(segment.Events, append([]byte(nil), item.raw...))
		bytesUsed += len(item.raw)
	}
	if len(segment.Events) == 0 {
		return payload.DeviceHistorySegment{}, ErrHistoryExhausted
	}
	if err := segment.Validate(); err != nil {
		return payload.DeviceHistorySegment{}, err
	}
	return segment, nil
}

// ApplyHistorySegment durably imports display-only direct-conversation history
// from another currently authorized device of this same Endpoint. Imported
// Events never enter the inbound application journal, so replay cannot invoke
// the Agent loop, tools, approvals, Agent Packets, or commerce adapters.
func (j *Journal) ApplyHistorySegment(outer envelope.Event, segment payload.DeviceHistorySegment,
	localAgentID, localEndpointID, localDeviceID string, authorizedDeviceIDs []string, now time.Time) (bool, error) {
	if err := j.usable(); err != nil {
		return false, err
	}
	if now.IsZero() || now.Unix() < 0 {
		return false, errors.New("invalid history application time")
	}
	if err := validateHistoryEnvelope(outer, segment, localAgentID, localEndpointID, localDeviceID, authorizedDeviceIDs); err != nil {
		return false, err
	}
	events, raws, err := validateHistoryEvents(outer, segment)
	if err != nil {
		return false, err
	}
	segmentDigest := canon.Digest(outer.Content)

	j.mutex.Lock()
	defer j.mutex.Unlock()
	chain, err := j.ensureHistoryChain(segment)
	if err != nil {
		return false, err
	}
	checkpointPath := filepath.Join(chain, "checkpoint.json")
	checkpoint, found, err := readHistoryCheckpoint(checkpointPath, segment)
	if err != nil {
		return false, err
	}
	if found && segment.Sequence == checkpoint.Sequence && segmentDigest == checkpoint.LastSegmentDigest {
		return false, nil
	}
	if (!found && (segment.Sequence != 1 || segment.PreviousSegmentDigest != "")) ||
		(found && (segment.Sequence != checkpoint.Sequence+1 || segment.PreviousSegmentDigest != checkpoint.LastSegmentDigest)) {
		return false, ErrHistorySequence
	}
	if found && (segment.AfterCreatedAtUnix != checkpoint.LastEventCreatedAt || segment.AfterEventID != checkpoint.LastEventID) {
		return false, ErrHistorySequence
	}
	if segment.Sequence > MaxHistorySegmentsPerChain {
		return false, errors.New("history segment chain reached its bound")
	}

	objects := filepath.Join(j.root, historySyncDir, "objects")
	for index, event := range events {
		path := filepath.Join(objects, event.EventID[len("evt_"):]+".json")
		if err := putHistoryImmutable(path, raws[index]); err != nil {
			return false, err
		}
	}
	manifest := historyManifest{
		Schema: HistoryManifestSchema, ConversationID: segment.ConversationID,
		SourceDeviceID: segment.SourceDeviceID, TargetDeviceID: segment.TargetDeviceID,
		Sequence: segment.Sequence, PreviousSegmentDigest: segment.PreviousSegmentDigest,
		AfterCreatedAtUnix: segment.AfterCreatedAtUnix, AfterEventID: segment.AfterEventID,
		SegmentDigest: segmentDigest, AppliedAtUnix: uint64(now.Unix()),
	}
	for index, event := range events {
		manifest.EventIDs = append(manifest.EventIDs, event.EventID)
		manifest.EventDigests = append(manifest.EventDigests, canon.Digest(raws[index]))
	}
	manifestRaw, err := json.Marshal(manifest)
	if err != nil {
		return false, err
	}
	manifestPath := filepath.Join(chain, "segments", fmt.Sprintf("%020d.json", segment.Sequence))
	if err := putHistoryImmutable(manifestPath, manifestRaw); err != nil {
		return false, err
	}
	checkpoint = historyCheckpoint{Schema: HistoryCheckpointSchema, ConversationID: segment.ConversationID,
		SourceDeviceID: segment.SourceDeviceID, TargetDeviceID: segment.TargetDeviceID,
		Sequence: segment.Sequence, LastSegmentDigest: segmentDigest,
		LastEventCreatedAt: events[len(events)-1].CreatedAtUnix, LastEventID: events[len(events)-1].EventID,
		UpdatedAtUnix: uint64(now.Unix())}
	checkpointRaw, err := json.Marshal(checkpoint)
	if err != nil {
		return false, err
	}
	if err := j.replace(checkpointPath, checkpointRaw); err != nil {
		return false, err
	}
	return true, nil
}

// History returns only Events reachable from committed segment checkpoints.
// Orphan objects left by a crash or refused conflicting segment are invisible.
func (j *Journal) History(conversationID string, limit int) ([]envelope.Event, error) {
	if err := j.usable(); err != nil {
		return nil, err
	}
	if !ids.Conversation.MatchString(conversationID) || limit < 0 || limit > MaxHistorySegmentsPerChain*payload.MaxHistoryEventsPerSegment {
		return nil, errors.New("invalid history query")
	}
	j.mutex.Lock()
	defer j.mutex.Unlock()
	conversationRoot := filepath.Join(j.root, historySyncDir, "chains", conversationID[len("conv_"):])
	chains, err := os.ReadDir(conversationRoot)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, errors.New("read history chains")
	}
	byID := make(map[string]envelope.Event)
	for _, chain := range chains {
		if !chain.IsDir() {
			return nil, errors.New("history chain entry is not a directory")
		}
		chainPath := filepath.Join(conversationRoot, chain.Name())
		checkpoint, err := decodeHistoryCheckpointFile(filepath.Join(chainPath, "checkpoint.json"))
		if err != nil || checkpoint.ConversationID != conversationID {
			return nil, errors.New("invalid history checkpoint")
		}
		previousDigest := ""
		var previousCreated uint64
		previousEventID := ""
		for sequence := uint64(1); sequence <= checkpoint.Sequence; sequence++ {
			manifest, err := readHistoryManifest(filepath.Join(chainPath, "segments", fmt.Sprintf("%020d.json", sequence)), checkpoint)
			if err != nil {
				return nil, err
			}
			if manifest.Sequence != sequence || manifest.PreviousSegmentDigest != previousDigest ||
				manifest.AfterCreatedAtUnix != previousCreated || manifest.AfterEventID != previousEventID ||
				(sequence == checkpoint.Sequence && manifest.SegmentDigest != checkpoint.LastSegmentDigest) {
				return nil, errors.New("history manifest chain is inconsistent")
			}
			previousDigest = manifest.SegmentDigest
			for index, eventID := range manifest.EventIDs {
				raw, err := securefile.ReadBoundedRegular(filepath.Join(j.root, historySyncDir, "objects", eventID[len("evt_"):]+".json"), MaxRecordBytes)
				if err != nil {
					return nil, errors.New("read committed history object: " + err.Error())
				}
				if canon.Digest(raw) != manifest.EventDigests[index] {
					return nil, errors.New("history object does not match its committed manifest")
				}
				event, err := envelope.DecodeEventJSON(raw)
				if err != nil || event.EventID != eventID || event.ConversationID != conversationID {
					return nil, errors.New("invalid committed history object")
				}
				byID[eventID] = event
				previousCreated, previousEventID = event.CreatedAtUnix, event.EventID
			}
		}
		if previousCreated != checkpoint.LastEventCreatedAt || previousEventID != checkpoint.LastEventID {
			return nil, errors.New("history checkpoint cursor is inconsistent")
		}
	}
	result := make([]envelope.Event, 0, len(byID))
	for _, event := range byID {
		result = append(result, event)
	}
	sort.Slice(result, func(i, k int) bool {
		if result[i].CreatedAtUnix != result[k].CreatedAtUnix {
			return result[i].CreatedAtUnix < result[k].CreatedAtUnix
		}
		return result[i].EventID < result[k].EventID
	})
	if limit > 0 && len(result) > limit {
		result = result[len(result)-limit:]
	}
	return result, nil
}

func validateHistoryEnvelope(outer envelope.Event, segment payload.DeviceHistorySegment,
	localAgentID, localEndpointID, localDeviceID string, authorized []string) error {
	if err := envelope.ValidateEvent(outer); err != nil || segment.Validate() != nil {
		return fmt.Errorf("%w: invalid Event", ErrHistoryContent)
	}
	if outer.Kind != "device.history.segment" || outer.RoomID != "" || outer.ConversationID != segment.ConversationID ||
		outer.SenderAgentID != localAgentID || outer.SenderEndpointID != localEndpointID ||
		outer.SenderDeviceID != segment.SourceDeviceID || segment.TargetDeviceID != localDeviceID {
		return ErrHistoryRoute
	}
	foundSource, foundTarget := false, false
	for index, deviceID := range authorized {
		if !ids.Device.MatchString(deviceID) || index > 0 && authorized[index-1] >= deviceID {
			return fmt.Errorf("%w: configured roster is invalid", ErrHistoryDevice)
		}
		foundSource = foundSource || deviceID == segment.SourceDeviceID
		foundTarget = foundTarget || deviceID == segment.TargetDeviceID
	}
	if !foundSource || !foundTarget {
		return ErrHistoryDevice
	}
	return nil
}

func validateHistoryEvents(outer envelope.Event, segment payload.DeviceHistorySegment) ([]envelope.Event, [][]byte, error) {
	events := make([]envelope.Event, 0, len(segment.Events))
	raws := make([][]byte, 0, len(segment.Events))
	for _, raw := range segment.Events {
		event, err := envelope.DecodeEventJSON(raw)
		if err != nil || event.ConversationID != segment.ConversationID || event.RoomID != "" ||
			event.Kind == "device.history.segment" || envelope.LocalOnly(event.Kind) || !sameNetwork(event, outer) {
			return nil, nil, ErrHistoryContent
		}
		canonical, err := envelope.EncodeEventJSON(event)
		if err != nil {
			return nil, nil, err
		}
		if len(events) > 0 {
			previous := events[len(events)-1]
			if previous.CreatedAtUnix > event.CreatedAtUnix ||
				(previous.CreatedAtUnix == event.CreatedAtUnix && previous.EventID >= event.EventID) {
				return nil, nil, fmt.Errorf("%w: Events are not strictly ordered", ErrHistoryContent)
			}
		}
		if event.CreatedAtUnix < segment.AfterCreatedAtUnix ||
			(event.CreatedAtUnix == segment.AfterCreatedAtUnix && event.EventID <= segment.AfterEventID) {
			return nil, nil, fmt.Errorf("%w: Event does not follow the segment cursor", ErrHistoryContent)
		}
		events = append(events, event)
		raws = append(raws, canonical)
	}
	return events, raws, nil
}

func sameNetwork(first, second envelope.Event) bool {
	return first.Network != nil && second.Network != nil && first.Network.NetworkId == second.Network.NetworkId &&
		first.Network.GenesisRootHash == second.Network.GenesisRootHash && first.Network.GenesisFileHash == second.Network.GenesisFileHash
}

func (j *Journal) ensureHistoryChain(segment payload.DeviceHistorySegment) (string, error) {
	base := filepath.Join(j.root, historySyncDir)
	conversation := filepath.Join(base, "chains", segment.ConversationID[len("conv_"):])
	chain := filepath.Join(conversation, segment.SourceDeviceID[len("dev_"):]+"-"+segment.TargetDeviceID[len("dev_"):])
	for _, path := range []string{filepath.Join(base, "objects"), filepath.Join(base, "chains"), conversation, chain, filepath.Join(chain, "segments")} {
		if err := os.MkdirAll(path, 0o700); err != nil {
			return "", errors.New("create history directory")
		}
		info, err := os.Lstat(path)
		if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm() != 0o700 {
			return "", errors.New("history path is not a protected directory")
		}
	}
	return chain, nil
}

func readHistoryCheckpoint(path string, segment payload.DeviceHistorySegment) (historyCheckpoint, bool, error) {
	checkpoint, err := decodeHistoryCheckpointFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return historyCheckpoint{}, false, nil
	}
	if err != nil || checkpoint.ConversationID != segment.ConversationID || checkpoint.SourceDeviceID != segment.SourceDeviceID ||
		checkpoint.TargetDeviceID != segment.TargetDeviceID {
		return historyCheckpoint{}, false, errors.New("invalid history checkpoint")
	}
	return checkpoint, true, nil
}

func decodeHistoryCheckpointFile(path string) (historyCheckpoint, error) {
	if _, err := os.Lstat(path); err != nil {
		return historyCheckpoint{}, err
	}
	raw, err := securefile.ReadBoundedRegular(path, MaxRecordBytes)
	if err != nil {
		return historyCheckpoint{}, err
	}
	if len(raw) == 0 || len(raw) > MaxRecordBytes {
		return historyCheckpoint{}, errors.New("invalid history checkpoint size")
	}
	var checkpoint historyCheckpoint
	if err := decodeHistoryJSON(raw, &checkpoint); err != nil || checkpoint.Schema != HistoryCheckpointSchema ||
		!ids.Conversation.MatchString(checkpoint.ConversationID) || !ids.Device.MatchString(checkpoint.SourceDeviceID) ||
		!ids.Device.MatchString(checkpoint.TargetDeviceID) || checkpoint.Sequence == 0 ||
		!canon.ValidDigest(checkpoint.LastSegmentDigest) || checkpoint.LastEventCreatedAt == 0 ||
		!ids.Event.MatchString(checkpoint.LastEventID) || checkpoint.UpdatedAtUnix == 0 {
		return historyCheckpoint{}, errors.New("invalid history checkpoint")
	}
	return checkpoint, nil
}

func readHistoryManifest(path string, checkpoint historyCheckpoint) (historyManifest, error) {
	raw, err := securefile.ReadBoundedRegular(path, MaxRecordBytes)
	if err != nil || len(raw) == 0 || len(raw) > MaxRecordBytes {
		return historyManifest{}, errors.New("read history manifest")
	}
	var manifest historyManifest
	if err := decodeHistoryJSON(raw, &manifest); err != nil || manifest.Schema != HistoryManifestSchema ||
		manifest.ConversationID != checkpoint.ConversationID || manifest.SourceDeviceID != checkpoint.SourceDeviceID ||
		manifest.TargetDeviceID != checkpoint.TargetDeviceID || manifest.Sequence == 0 ||
		!canon.ValidDigest(manifest.SegmentDigest) || len(manifest.EventIDs) == 0 ||
		len(manifest.EventIDs) != len(manifest.EventDigests) || len(manifest.EventIDs) > payload.MaxHistoryEventsPerSegment {
		return historyManifest{}, errors.New("invalid history manifest")
	}
	for index, eventID := range manifest.EventIDs {
		if !ids.Event.MatchString(eventID) || !canon.ValidDigest(manifest.EventDigests[index]) {
			return historyManifest{}, errors.New("invalid history manifest Event")
		}
	}
	return manifest, nil
}

func putHistoryImmutable(path string, raw []byte) error {
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err == nil {
		if _, err := file.Write(raw); err != nil {
			_ = file.Close()
			_ = os.Remove(path)
			return errors.New("write immutable history object")
		}
		if err := file.Sync(); err != nil {
			_ = file.Close()
			_ = os.Remove(path)
			return errors.New("sync immutable history object")
		}
		if err := file.Close(); err != nil {
			_ = os.Remove(path)
			return err
		}
		return syncDirectory(filepath.Dir(path))
	}
	if !errors.Is(err, os.ErrExist) {
		return errors.New("create history object")
	}
	existing, err := securefile.ReadBoundedRegular(path, MaxRecordBytes)
	if err != nil || !bytes.Equal(existing, raw) {
		return errors.New("history content address contains conflicting bytes")
	}
	return nil
}

func decodeHistoryJSON(raw []byte, value any) error {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(value); err != nil {
		return err
	}
	if err := decoder.Decode(new(any)); !errors.Is(err, io.EOF) {
		return errors.New("history record has trailing JSON")
	}
	return nil
}
