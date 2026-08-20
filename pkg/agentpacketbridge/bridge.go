// Package agentpacketbridge carries exact Agent Packet V1 bytes through an
// E2EE Messenger event, reuses the service protocol's finalized verifier, and
// replaces its process-local replay map with the Messenger's durable journal.
package agentpacketbridge

import (
	"context"
	"errors"
	"math"
	"sync"
	"time"

	"github.com/tosnetwork/tos-messenger/internal/ids"
	"github.com/tosnetwork/tos-messenger/pkg/eventlog"
	"github.com/tosnetwork/tos-messenger/pkg/payload"
	"github.com/tosnetwork/tos-service-protocol/pkg/agentpacket"
)

const (
	DefaultMaxAge     = 24 * time.Hour
	DefaultFutureSkew = 5 * time.Minute
)

type Config struct {
	Resolver         agentpacket.AgentResolver
	Journal          *eventlog.Journal
	Receiver         agentpacket.Receiver
	RecipientAgentID string
	MaxAge           time.Duration
	MaxFutureSkew    time.Duration
}

type Bridge struct {
	resolver           agentpacket.AgentResolver
	journal            *eventlog.Journal
	receiver           agentpacket.Receiver
	recipient          string
	maxAge, futureSkew time.Duration
	mutex              sync.Mutex
}

func New(c Config) (*Bridge, error) {
	if c.Resolver == nil || c.Journal == nil || c.Receiver == nil || !ids.Agent.MatchString(c.RecipientAgentID) {
		return nil, errors.New("invalid Agent Packet bridge configuration")
	}
	if c.MaxAge == 0 {
		c.MaxAge = DefaultMaxAge
	}
	if c.MaxFutureSkew == 0 {
		c.MaxFutureSkew = DefaultFutureSkew
	}
	if c.MaxAge < time.Minute || c.MaxAge > 7*24*time.Hour || c.MaxFutureSkew < 0 || c.MaxFutureSkew > time.Hour {
		return nil, errors.New("invalid Agent Packet time policy")
	}
	return &Bridge{resolver: c.Resolver, journal: c.Journal, receiver: c.Receiver, recipient: c.RecipientAgentID, maxAge: c.MaxAge, futureSkew: c.MaxFutureSkew}, nil
}

// Handle consumes a decoded Messenger body. Verification is deliberately
// repeated on every retry before the durable claim is consulted, so revocation
// in finalized state takes effect even for a packet seen earlier.
func (b *Bridge) Handle(ctx context.Context, eventSenderAgentID string, body payload.AgentPacketMessage, now time.Time) error {
	if b == nil || ctx == nil || now.IsZero() || now.Unix() < 0 {
		return errors.New("invalid Agent Packet bridge call")
	}
	if !ids.Agent.MatchString(eventSenderAgentID) {
		return errors.New("invalid authenticated Event sender")
	}
	if err := body.Validate(); err != nil {
		return err
	}
	packet, err := agentpacket.DecodeJSON(body.Body)
	if err != nil {
		return err
	}
	if packet.RecipientAgentID != b.recipient {
		return errors.New("Agent Packet names another recipient")
	}
	if packet.SenderAgentID != eventSenderAgentID {
		return errors.New("Agent Packet sender does not match its E2EE Event sender")
	}
	nowUnix := uint64(now.Unix())
	age := uint64(b.maxAge / time.Second)
	skew := uint64(b.futureSkew / time.Second)
	if packet.CreatedAtUnix > nowUnix && packet.CreatedAtUnix-nowUnix > skew {
		return errors.New("Agent Packet is from the future")
	}
	if nowUnix > packet.CreatedAtUnix && nowUnix-packet.CreatedAtUnix > age {
		return errors.New("Agent Packet is stale")
	}
	if packet.CreatedAtUnix > math.MaxUint64-age-skew {
		return errors.New("Agent Packet expiry overflows")
	}
	// A fresh process-local guard makes the service protocol run all signature
	// and finalized-state checks without making its in-memory claim authoritative.
	if err := agentpacket.Verify(b.resolver, &agentpacket.ReplayGuard{}, packet, now); err != nil {
		return err
	}
	recipient, found, err := b.resolver.ResolveAgent(packet.RecipientAgentID)
	if err != nil {
		return err
	}
	if !found || recipient == nil || recipient.Tombstoned {
		return errors.New("recipient Agent is not finalized and live")
	}
	canonical, err := agentpacket.EncodeJSON(packet)
	if err != nil {
		return err
	}
	expires := packet.CreatedAtUnix + age + skew

	// One process owns the journal; serializing bridge delivery prevents two
	// concurrent retries from both reaching Receiver while still leaving a
	// pending durable record recoverable after a crash or receiver error.
	b.mutex.Lock()
	defer b.mutex.Unlock()
	record, _, err := b.journal.ClaimAgentPacket(packet.SenderAgentID, packet.Nonce, canonical, packet.CreatedAtUnix, expires, now)
	if err != nil {
		return err
	}
	if record.CompletedAtUnix != 0 {
		return nil
	}
	if err := b.receiver.Receive(ctx, packet); err != nil {
		return err
	}
	return b.journal.CompleteAgentPacket(record.ClaimID, record.PacketDigest, now)
}
