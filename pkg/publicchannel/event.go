package publicchannel

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"regexp"
	"sort"
	"time"

	"github.com/tosnetwork/tos-messenger/internal/canon"
	"github.com/tosnetwork/tos-messenger/internal/ids"
	"github.com/tosnetwork/tos-messenger/pkg/identity"
)

const (
	EventSchema           = "tos.messaging.public-channel-event.v1"
	MaxEventParents       = 16
	MaxPublicContentBytes = 64 << 10
)

var publicEventPattern = regexp.MustCompile(`^pce_[0-9a-f]{64}$`)

type EventKind string

const (
	KindPost    EventKind = "post"
	KindHide    EventKind = "moderation.hide"
	KindRestore EventKind = "moderation.restore"
)

// Event is independently signed public content. Sequence and PreviousEventID
// form one strict chain per publisher; Parents adds cross-publisher causality.
// Arrival order is never consensus.
type Event struct {
	ChannelID                string
	ProfileDigest            string
	PublisherAgentID         string
	PublisherEndpointID      string
	Sequence                 uint64
	PreviousPublisherEventID string
	Parents                  []string
	PublishedAtUnix          uint64
	Kind                     EventKind
	TargetEventID            string
	MediaType                string
	Content                  []byte
	PublisherSignature       []byte
}

func EventSigningBytes(event Event) ([]byte, error) {
	if err := validateEvent(event, false); err != nil {
		return nil, err
	}
	b := bytes.NewBufferString(canon.DomainPublicChannelEvent)
	canon.Text(b, EventSchema)
	canon.Text(b, event.ChannelID)
	canon.Text(b, event.ProfileDigest)
	canon.Text(b, event.PublisherAgentID)
	canon.Text(b, event.PublisherEndpointID)
	canon.Uint64(b, event.Sequence)
	canon.Text(b, event.PreviousPublisherEventID)
	canon.Uint32(b, uint32(len(event.Parents)))
	for _, parent := range event.Parents {
		canon.Text(b, parent)
	}
	canon.Uint64(b, event.PublishedAtUnix)
	canon.Text(b, string(event.Kind))
	canon.Text(b, event.TargetEventID)
	canon.Text(b, event.MediaType)
	canon.Bytes(b, event.Content)
	return b.Bytes(), nil
}

func SignEvent(event Event, key ed25519.PrivateKey) (Event, error) {
	if len(key) != ed25519.PrivateKeySize {
		return Event{}, errors.New("invalid public channel publisher key")
	}
	event.PublisherSignature = nil
	preimage, err := EventSigningBytes(event)
	if err != nil {
		return Event{}, err
	}
	event.PublisherSignature = ed25519.Sign(key, preimage)
	return event, nil
}

func (e Event) ID() (string, error) {
	if err := validateEvent(e, true); err != nil {
		return "", err
	}
	preimage, err := EventSigningBytes(e)
	if err != nil {
		return "", err
	}
	b := bytes.NewBuffer(preimage)
	canon.Bytes(b, e.PublisherSignature)
	digest := sha256.Sum256(b.Bytes())
	return "pce_" + hex.EncodeToString(digest[:]), nil
}

// VerifyEvent checks role and signature against an already verified profile
// and a caller-supplied finalized publisher delegation. Verification occurs at
// the signed publication instant; now only prevents future-dated history.
func VerifyEvent(event Event, profile Profile, publisher identity.Delegation, now time.Time) error {
	if now.IsZero() || now.Unix() < 0 || uint64(now.Unix()) < event.PublishedAtUnix {
		return errors.New("invalid public channel Event verification time")
	}
	if err := validateEvent(event, true); err != nil {
		return err
	}
	profileDigest, err := profile.Digest()
	if err != nil || event.ChannelID != profile.ChannelID || event.ProfileDigest != profileDigest ||
		event.PublishedAtUnix < profile.IssuedAtUnix || event.PublishedAtUnix >= profile.ExpiresAtUnix {
		return errors.New("public channel Event is outside its profile")
	}
	role, found := profile.role(event.PublisherAgentID, event.PublisherEndpointID)
	if !found || !role.Publisher || (event.Kind == KindHide || event.Kind == KindRestore) && !role.Moderator {
		return errors.New("public channel Event kind is not authorized")
	}
	if publisher.AgentID != event.PublisherAgentID || publisher.EndpointID != event.PublisherEndpointID ||
		!sameNetwork(profile.Network, publisher.Network) || identity.Validate(publisher) != nil ||
		identity.CheckWindow(publisher, time.Unix(int64(event.PublishedAtUnix), 0)) != nil ||
		!identity.AllowsEventClass(publisher, "public.channel") {
		return errors.New("public channel publisher is not finalized or delegated")
	}
	preimage, err := EventSigningBytes(event)
	if err != nil {
		return err
	}
	if !ed25519.Verify(publisher.IdentityPublicKey, preimage, event.PublisherSignature) {
		return errors.New("invalid public channel Event signature")
	}
	return nil
}

func validateEvent(event Event, signed bool) error {
	if !channelPattern.MatchString(event.ChannelID) || !canon.ValidDigest(event.ProfileDigest) ||
		!ids.Agent.MatchString(event.PublisherAgentID) || !ids.Endpoint.MatchString(event.PublisherEndpointID) ||
		event.Sequence == 0 || event.PublishedAtUnix == 0 || len(event.Parents) > MaxEventParents ||
		len(event.MediaType) > 128 || len(event.Content) > MaxPublicContentBytes {
		return errors.New("invalid public channel Event")
	}
	if event.Sequence == 1 {
		if event.PreviousPublisherEventID != "" {
			return errors.New("first public channel Event has a predecessor")
		}
	} else if !publicEventPattern.MatchString(event.PreviousPublisherEventID) {
		return errors.New("public channel Event has no publisher predecessor")
	}
	for index, parent := range event.Parents {
		if !publicEventPattern.MatchString(parent) || index > 0 && event.Parents[index-1] >= parent {
			return errors.New("public channel Event parents are invalid or unordered")
		}
	}
	if event.PreviousPublisherEventID != "" {
		index := sort.SearchStrings(event.Parents, event.PreviousPublisherEventID)
		if index == len(event.Parents) || event.Parents[index] != event.PreviousPublisherEventID {
			return errors.New("publisher predecessor must be a causal parent")
		}
	}
	switch event.Kind {
	case KindPost:
		if event.TargetEventID != "" || event.MediaType == "" || len(event.Content) == 0 {
			return errors.New("public channel post needs content and no moderation target")
		}
	case KindHide, KindRestore:
		if !publicEventPattern.MatchString(event.TargetEventID) || event.MediaType != "" || len(event.Content) != 0 {
			return errors.New("public channel moderation needs only a target")
		}
		index := sort.SearchStrings(event.Parents, event.TargetEventID)
		if index == len(event.Parents) || event.Parents[index] != event.TargetEventID {
			return errors.New("public channel moderation target must be a causal parent")
		}
	default:
		return errors.New("unknown public channel Event kind")
	}
	if signed && len(event.PublisherSignature) != ed25519.SignatureSize {
		return errors.New("invalid public channel Event signature")
	}
	return nil
}
