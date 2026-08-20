package envelope

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"regexp"

	"github.com/tosnetwork/tos-messenger/internal/canon"
	"github.com/tosnetwork/tos-messenger/internal/ids"
	"github.com/tosnetwork/tos-messenger/pkg/identity"
	"github.com/tosnetwork/tos-messenger/pkg/payload"
	nativev1 "github.com/tosnetwork/tos-service-protocol/gen/tos/service/v1"
)

const (
	// EventSchema is the strict wire schema identifier.
	EventSchema = "tos.messaging.event.v1"

	// MaxContentBytes bounds one event body.
	MaxContentBytes = 128 << 10
	// MaxCausalParents bounds the causal reference set.
	MaxCausalParents = 16
	// MaxAttachmentReferences bounds the attachments one event may reference.
	MaxAttachmentReferences = 16
	// MaxRenderingBytes bounds the optional human presentation.
	MaxRenderingBytes = 4 << 10
)

var (
	conversationPattern = ids.Conversation
	eventPattern        = ids.Event
	devicePattern       = ids.Device
	roomPattern         = ids.Room
	threadPattern       = ids.Thread
	idempotencyPattern  = regexp.MustCompile(`^[0-9a-f]{64}$`)
	bindingPattern      = regexp.MustCompile(`^(?:sha256|tvm-cell-sha256):[0-9a-f]{64}$`)
)

// kindSpec is everything the protocol fixes about one event kind.
type kindSpec struct {
	class string
	// localOnly marks a kind that may only arrive over the owner's own local
	// interface and never from the network.
	localOnly bool
}

// eventKinds is the typed event set.
//
// The class is what a Messaging Endpoint delegation grants, so a kind with no
// entry here can never be admitted by scope: an unrecognised kind fails closed
// rather than inheriting a neighbour's authority.
//
// Approval appears twice on purpose. A counterparty attestation is a remote
// Agent telling us what it decided about its own side, which is information.
// An owner approval is this owner authorising an action here, which is
// authority. They were one kind, and a single loose check in a context
// firewall would then have let a remote Agent approve a local wallet or tool
// operation. Splitting them means the dangerous one is not expressible on the
// wire at all.
var eventKinds = map[string]kindSpec{
	"text":                {class: "text"},
	"conversation.invite": {class: "conversation"},
	"conversation.accept": {class: "conversation"},
	"presence.hint":       {class: "presence"},

	"agent.task.request":        {class: "agent.task"},
	"agent.task.progress":       {class: "agent.task"},
	"agent.task.result":         {class: "agent.task"},
	"agent.task.status.request": {class: "agent.task"},

	// Negotiation is conversation, not commitment. None of these create,
	// accept, or fund anything; they carry what the parties said they intend.
	"negotiation.proposal":        {class: "negotiation"},
	"negotiation.counterproposal": {class: "negotiation"},
	"negotiation.withdraw":        {class: "negotiation"},
	"negotiation.intent.accept":   {class: "negotiation"},
	"negotiation.intent.reject":   {class: "negotiation"},

	// What the other party says it decided.
	"counterparty.approval.request": {class: "counterparty.approval"},
	"counterparty.approval.granted": {class: "counterparty.approval"},
	"counterparty.approval.denied":  {class: "counterparty.approval"},

	// What this owner authorises here. Never accepted from the network.
	"owner.approval.grant": {class: "owner.approval", localOnly: true},
	"owner.approval.deny":  {class: "owner.approval", localOnly: true},

	"a2a.message": {class: "a2a"},
	"mcp.call":    {class: "mcp"},
	"mcp.result":  {class: "mcp"},

	"artifact.offer":     {class: "artifact"},
	"artifact.reference": {class: "artifact"},
	"artifact.encrypted": {class: "artifact"},

	"service.quote.reference":   {class: "service"},
	"service.escrow.reference":  {class: "service"},
	"service.receipt.reference": {class: "service"},

	"delivery.ack":    {class: "delivery"},
	"application.ack": {class: "application"},
	"read.ack":        {class: "read"},

	"room.invite":            {class: "room"},
	"room.membership.commit": {class: "room"},
	"room.message":           {class: "room"},
}

// Event is the inner typed object obtained after decryption.
//
// Authenticity comes from the end-to-end encrypted session, not from a field
// in this struct. A high-value control event may additionally carry an
// independently verifiable signature, which is a separate profile.
type Event struct {
	Network          *nativev1.NetworkDomain
	ConversationID   string
	EventID          string
	SenderAgentID    string
	SenderEndpointID string
	SenderDeviceID   string
	RoomID           string
	ThreadID         string
	ReplyToEventID   string
	CausalParents    []string
	CreatedAtUnix    uint64
	ExpiresAtUnix    uint64
	Kind             string
	// PayloadSchema names the structure of Content. It is fixed by the kind,
	// and carried explicitly so a decoder is reading a declared shape rather
	// than guessing one from a name.
	PayloadSchema  string
	IdempotencyKey string
	// Content is the structured payload. It is what automation reads.
	Content []byte
	// Rendering is an optional human presentation of the same event.
	//
	// It is presentation and never input. Where the two disagree the
	// difference is not a preference to resolve: a caller that let a model
	// choose which one to believe would have made the rendering authoritative
	// by another route.
	Rendering            string
	AttachmentReferences []string
	ServiceBinding       string
}

type wireEvent struct {
	Schema               string   `json:"schema"`
	NetworkID            string   `json:"network_id"`
	GenesisRootHash      string   `json:"genesis_root_hash"`
	GenesisFileHash      string   `json:"genesis_file_hash"`
	ConversationID       string   `json:"conversation_id"`
	EventID              string   `json:"event_id"`
	SenderAgentID        string   `json:"sender_agent_id"`
	SenderEndpointID     string   `json:"sender_messaging_endpoint_id"`
	SenderDeviceID       string   `json:"sender_device_id"`
	RoomID               string   `json:"room_id,omitempty"`
	ThreadID             string   `json:"thread_id,omitempty"`
	ReplyToEventID       string   `json:"reply_to_event_id,omitempty"`
	CausalParents        []string `json:"causal_parents,omitempty"`
	CreatedAtUnix        uint64   `json:"created_at_unix"`
	ExpiresAtUnix        uint64   `json:"expires_at_unix,omitempty"`
	Kind                 string   `json:"event_kind"`
	PayloadSchema        string   `json:"payload_schema"`
	IdempotencyKey       string   `json:"idempotency_key,omitempty"`
	ContentBase64        string   `json:"content_base64,omitempty"`
	Rendering            string   `json:"rendering,omitempty"`
	AttachmentReferences []string `json:"attachment_references,omitempty"`
	ServiceBinding       string   `json:"service_binding,omitempty"`
}

// ClassOf returns the delegated class of an event kind. An unknown kind has no
// class and therefore no scope.
func ClassOf(kind string) (string, bool) {
	spec, known := eventKinds[kind]
	return spec.class, known
}

// PayloadSchemaOf returns the structured payload schema a kind carries.
//
// The schema comes from the codec that actually parses the body, not from a
// second table kept in step by hand. A kind whose schema was declared in one
// place and implemented in another would eventually declare a contract nothing
// enforced.
func PayloadSchemaOf(kind string) (string, bool) {
	if _, known := eventKinds[kind]; !known {
		return "", false
	}
	return payload.SchemaFor(kind)
}

// LocalOnly reports whether a kind may only arrive over the owner's own local
// interface.
//
// A local-only kind carries authority rather than information, so it is not
// something a remote party may express. Callers on the network path refuse it
// outright rather than evaluating it and deciding it is not allowed.
func LocalOnly(kind string) bool {
	return eventKinds[kind].localOnly
}

// KnownKinds returns the recognised event kinds.
func KnownKinds() []string {
	kinds := make([]string, 0, len(eventKinds))
	for kind := range eventKinds {
		kinds = append(kinds, kind)
	}
	return kinds
}

// EventCanonicalBytes returns the preimage the Event ID commits to. The Event
// ID itself is excluded, because it is derived from this preimage.
func EventCanonicalBytes(event Event) ([]byte, error) {
	if err := validateEventFields(event); err != nil {
		return nil, err
	}
	buffer := bytes.NewBufferString(canon.DomainEventID)
	canon.Text(buffer, EventSchema)
	canon.Text(buffer, event.Network.NetworkId)
	canon.Text(buffer, event.Network.GenesisRootHash)
	canon.Text(buffer, event.Network.GenesisFileHash)
	canon.Text(buffer, event.ConversationID)
	canon.Text(buffer, event.SenderAgentID)
	canon.Text(buffer, event.SenderEndpointID)
	canon.Text(buffer, event.SenderDeviceID)
	canon.Text(buffer, event.RoomID)
	canon.Text(buffer, event.ThreadID)
	canon.Text(buffer, event.ReplyToEventID)
	canon.Uint32(buffer, uint32(len(event.CausalParents)))
	for _, parent := range event.CausalParents {
		canon.Text(buffer, parent)
	}
	canon.Uint64(buffer, event.CreatedAtUnix)
	canon.Uint64(buffer, event.ExpiresAtUnix)
	canon.Text(buffer, event.Kind)
	canon.Text(buffer, event.PayloadSchema)
	canon.Text(buffer, event.IdempotencyKey)
	canon.Bytes(buffer, event.Content)
	canon.Text(buffer, event.Rendering)
	canon.Uint32(buffer, uint32(len(event.AttachmentReferences)))
	for _, reference := range event.AttachmentReferences {
		canon.Text(buffer, reference)
	}
	canon.Text(buffer, event.ServiceBinding)
	return buffer.Bytes(), nil
}

// DeriveEventID content-addresses an event. Two peers that hold the same event
// compute the same identifier, and no peer can present different content under
// an identifier another peer already committed.
func DeriveEventID(event Event) (string, error) {
	preimage, err := EventCanonicalBytes(event)
	if err != nil {
		return "", err
	}
	digest := canon.Digest(preimage)
	return "evt_" + digest[len("sha256:"):], nil
}

// NewEvent completes an event by filling the schema its kind fixes and
// deriving its identifier.
func NewEvent(event Event) (Event, error) {
	event.EventID = ""
	if schema, known := payload.SchemaFor(event.Kind); known && event.PayloadSchema == "" {
		event.PayloadSchema = schema
	}
	eventID, err := DeriveEventID(event)
	if err != nil {
		return Event{}, err
	}
	event.EventID = eventID
	if err := ValidateEvent(event); err != nil {
		return Event{}, err
	}
	return event, nil
}

// EncodeEventJSON returns the plaintext transport representation. Callers
// encrypt the result; this package never places it on a wire itself.
func EncodeEventJSON(event Event) ([]byte, error) {
	if err := ValidateEvent(event); err != nil {
		return nil, err
	}
	value := wireEvent{
		Schema:               EventSchema,
		NetworkID:            event.Network.NetworkId,
		GenesisRootHash:      event.Network.GenesisRootHash,
		GenesisFileHash:      event.Network.GenesisFileHash,
		ConversationID:       event.ConversationID,
		EventID:              event.EventID,
		SenderAgentID:        event.SenderAgentID,
		SenderEndpointID:     event.SenderEndpointID,
		SenderDeviceID:       event.SenderDeviceID,
		RoomID:               event.RoomID,
		ThreadID:             event.ThreadID,
		ReplyToEventID:       event.ReplyToEventID,
		CausalParents:        event.CausalParents,
		CreatedAtUnix:        event.CreatedAtUnix,
		ExpiresAtUnix:        event.ExpiresAtUnix,
		Kind:                 event.Kind,
		PayloadSchema:        event.PayloadSchema,
		IdempotencyKey:       event.IdempotencyKey,
		Rendering:            event.Rendering,
		AttachmentReferences: event.AttachmentReferences,
		ServiceBinding:       event.ServiceBinding,
	}
	if len(event.Content) > 0 {
		value.ContentBase64 = base64.StdEncoding.EncodeToString(event.Content)
	}
	return json.Marshal(value)
}

// DecodeEventJSON rejects unknown fields, trailing data, unrecognised event
// kinds, and any event whose identifier does not match its content.
func DecodeEventJSON(raw []byte) (Event, error) {
	event, err := decodeEvent(raw)
	if err != nil {
		return Event{}, err
	}
	if _, known := ClassOf(event.Kind); !known {
		return Event{}, errors.New("unrecognised event kind")
	}
	return event, nil
}

// DecodeEventJSONForwardCompatible additionally admits an event kind this
// build does not recognise, for a caller whose policy explicitly allows
// forward compatibility.
//
// A forward-compatible event has no delegated class, so it must never be
// interpreted as a tool call, an approval, or a payment. It may be stored and
// displayed as an unknown event and nothing more.
func DecodeEventJSONForwardCompatible(raw []byte) (Event, error) {
	return decodeEvent(raw)
}

func decodeEvent(raw []byte) (Event, error) {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	var value wireEvent
	if err := decoder.Decode(&value); err != nil {
		return Event{}, err
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return Event{}, errors.New("event has trailing JSON")
	}
	if value.Schema != EventSchema {
		return Event{}, errors.New("unsupported event schema")
	}
	var content []byte
	if value.ContentBase64 != "" {
		decoded, err := base64.StdEncoding.Strict().DecodeString(value.ContentBase64)
		if err != nil {
			return Event{}, errors.New("invalid event content")
		}
		content = decoded
	}
	event := Event{
		Network: &nativev1.NetworkDomain{
			NetworkId:       value.NetworkID,
			GenesisRootHash: value.GenesisRootHash,
			GenesisFileHash: value.GenesisFileHash,
		},
		ConversationID:       value.ConversationID,
		EventID:              value.EventID,
		SenderAgentID:        value.SenderAgentID,
		SenderEndpointID:     value.SenderEndpointID,
		SenderDeviceID:       value.SenderDeviceID,
		RoomID:               value.RoomID,
		ThreadID:             value.ThreadID,
		ReplyToEventID:       value.ReplyToEventID,
		CausalParents:        value.CausalParents,
		CreatedAtUnix:        value.CreatedAtUnix,
		ExpiresAtUnix:        value.ExpiresAtUnix,
		Kind:                 value.Kind,
		PayloadSchema:        value.PayloadSchema,
		IdempotencyKey:       value.IdempotencyKey,
		Content:              content,
		Rendering:            value.Rendering,
		AttachmentReferences: value.AttachmentReferences,
		ServiceBinding:       value.ServiceBinding,
	}
	if err := ValidateEvent(event); err != nil {
		return Event{}, err
	}
	return event, nil
}

// ValidateEvent enforces every structural rule and re-derives the Event ID.
func ValidateEvent(event Event) error {
	if !eventPattern.MatchString(event.EventID) {
		return errors.New("invalid event identifier")
	}
	derived, err := DeriveEventID(event)
	if err != nil {
		return err
	}
	if event.EventID != derived {
		return errors.New("event identifier does not match its content")
	}
	return nil
}

// AdmittedBy reports whether a delegation grants the sender's endpoint the
// class of this event, and that the event was produced by the delegated
// endpoint of the delegated Agent in the delegated network.
//
// This is a scope check only. It is not a substitute for session
// authentication, inbox policy, or the execution gate.
func AdmittedBy(delegation identity.Delegation, event Event) error {
	if err := ValidateEvent(event); err != nil {
		return err
	}
	if event.SenderAgentID != delegation.AgentID || event.SenderEndpointID != delegation.EndpointID {
		return errors.New("event sender does not match its delegation")
	}
	if event.Network.NetworkId != delegation.Network.NetworkId ||
		event.Network.GenesisRootHash != delegation.Network.GenesisRootHash ||
		event.Network.GenesisFileHash != delegation.Network.GenesisFileHash {
		return errors.New("event network tuple does not match its delegation")
	}
	class, known := ClassOf(event.Kind)
	if !known {
		return errors.New("unrecognised event kind")
	}
	if !identity.AllowsEventClass(delegation, class) {
		return errors.New("event class is outside the delegated scope")
	}
	return nil
}

func validateEventFields(event Event) error {
	if event.Network == nil || event.Network.NetworkId == "" || len(event.Network.NetworkId) > 128 ||
		!canon.HashPattern.MatchString(event.Network.GenesisRootHash) ||
		!canon.HashPattern.MatchString(event.Network.GenesisFileHash) {
		return errors.New("invalid event network domain")
	}
	if !conversationPattern.MatchString(event.ConversationID) {
		return errors.New("invalid conversation identifier")
	}
	if !identity.AgentPattern.MatchString(event.SenderAgentID) ||
		!identity.EndpointPattern.MatchString(event.SenderEndpointID) ||
		!devicePattern.MatchString(event.SenderDeviceID) {
		return errors.New("invalid event sender identity")
	}
	if event.RoomID != "" && !roomPattern.MatchString(event.RoomID) {
		return errors.New("invalid event room identifier")
	}
	if event.ThreadID != "" && !threadPattern.MatchString(event.ThreadID) {
		return errors.New("invalid event thread identifier")
	}
	if event.ReplyToEventID != "" && !eventPattern.MatchString(event.ReplyToEventID) {
		return errors.New("invalid event reply reference")
	}
	if err := validateCausalParents(event); err != nil {
		return err
	}
	if event.CreatedAtUnix == 0 {
		return errors.New("event has no creation time")
	}
	if event.ExpiresAtUnix != 0 && event.ExpiresAtUnix <= event.CreatedAtUnix {
		return errors.New("event expires before it was created")
	}
	if len(event.Kind) == 0 || len(event.Kind) > identity.MaxEventClassBytes ||
		!eventKindPattern.MatchString(event.Kind) {
		return errors.New("invalid event kind")
	}
	// A known kind carries the schema the protocol fixed for it. An unknown
	// kind may declare its own, which is what makes a forward-compatible event
	// storable without making it interpretable.
	if schema, known := payload.SchemaFor(event.Kind); known {
		if event.PayloadSchema != schema {
			return errors.New("event payload schema does not match its kind")
		}
	} else if !payloadSchemaPattern.MatchString(event.PayloadSchema) {
		return errors.New("invalid event payload schema")
	}
	if len(event.Rendering) > MaxRenderingBytes {
		return errors.New("event rendering exceeds its bound")
	}
	if event.IdempotencyKey != "" && !idempotencyPattern.MatchString(event.IdempotencyKey) {
		return errors.New("invalid event idempotency key")
	}
	if len(event.Content) > MaxContentBytes {
		return errors.New("event content exceeds its bound")
	}
	if err := validateAttachments(event.AttachmentReferences); err != nil {
		return err
	}
	if event.Kind == "artifact.encrypted" {
		body, err := payload.Decode(event.Kind, event.Content)
		if err != nil {
			return err
		}
		attachment, ok := body.(payload.EncryptedAttachment)
		if !ok || len(event.AttachmentReferences) != 1 || event.AttachmentReferences[0] != attachment.ManifestDigest {
			return errors.New("encrypted attachment event does not name its exact manifest")
		}
	}
	if event.ServiceBinding != "" && !bindingPattern.MatchString(event.ServiceBinding) {
		return errors.New("invalid event service binding")
	}
	return nil
}

var eventKindPattern = regexp.MustCompile(`^[a-z][a-z0-9]*(\.[a-z][a-z0-9]*)*$`)

var payloadSchemaPattern = regexp.MustCompile(`^tos\.messaging\.payload\.[a-z0-9-]{1,48}\.v[0-9]{1,3}$`)

func validateCausalParents(event Event) error {
	if len(event.CausalParents) > MaxCausalParents {
		return errors.New("too many causal parents")
	}
	for index, parent := range event.CausalParents {
		if !eventPattern.MatchString(parent) {
			return errors.New("invalid causal parent")
		}
		if index > 0 && event.CausalParents[index-1] >= parent {
			return errors.New("causal parents must be sorted and unique")
		}
		if parent == event.EventID {
			return errors.New("event cannot be its own causal parent")
		}
	}
	return nil
}

func validateAttachments(references []string) error {
	if len(references) > MaxAttachmentReferences {
		return errors.New("too many attachment references")
	}
	for index, reference := range references {
		if !canon.ValidDigest(reference) {
			return errors.New("invalid attachment reference")
		}
		if index > 0 && references[index-1] >= reference {
			return errors.New("attachment references must be sorted and unique")
		}
	}
	return nil
}

// ConversationID formats a conversation identifier.
func ConversationID(raw []byte) (string, error) {
	return ids.Format("conv_", raw)
}

// DeviceID formats a device identifier.
func DeviceID(raw []byte) (string, error) {
	return ids.Format("dev_", raw)
}
