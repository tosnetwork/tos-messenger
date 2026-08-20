package mailbox

import (
	"context"
	"errors"
	"fmt"

	"github.com/tosnetwork/tos-messenger/internal/canon"
	"github.com/tosnetwork/tos-messenger/pkg/envelope"
)

const MaxRelayTargets = 8

// RelayClient is a transport-neutral Mailbox operation. Implementations may
// use the route selected after M0-R; the fan-out policy does not assume one.
type RelayClient interface {
	PublicKeyHex() string
	Store(context.Context, envelope.RelayEnvelope) (StoredAck, error)
}

type Attempt struct {
	RelayPublicKeyHex string
	Ack               *StoredAck
	Err               error
}

type FanoutResult struct{ Attempts []Attempt }

func (r FanoutResult) StoredCopies() int {
	count := 0
	for _, attempt := range r.Attempts {
		if attempt.Ack != nil {
			count++
		}
	}
	return count
}

// StoreRedundant asks every predeclared Relay to store the same ciphertext and
// succeeds only at the requested redundancy. A bad Relay acknowledgement is a
// failed attempt, never evidence that another Relay stored the message.
func StoreRedundant(ctx context.Context, clients []RelayClient, value envelope.RelayEnvelope, minimum int) (FanoutResult, error) {
	if ctx == nil {
		return FanoutResult{}, errors.New("Mailbox fan-out needs a context")
	}
	if len(clients) == 0 || len(clients) > MaxRelayTargets || minimum < 1 || minimum > len(clients) {
		return FanoutResult{}, errors.New("invalid Mailbox redundancy policy")
	}
	if err := envelope.ValidateRelay(value); err != nil {
		return FanoutResult{}, err
	}
	seen := make(map[string]struct{}, len(clients))
	result := FanoutResult{Attempts: make([]Attempt, 0, len(clients))}
	for _, client := range clients {
		if client == nil {
			result.Attempts = append(result.Attempts, Attempt{Err: errors.New("nil Relay client")})
			continue
		}
		key := client.PublicKeyHex()
		if _, duplicate := seen[key]; duplicate {
			return result, errors.New("Mailbox redundancy cannot count one Relay twice")
		}
		seen[key] = struct{}{}
		attempt := Attempt{RelayPublicKeyHex: key}
		ack, err := client.Store(ctx, value)
		if err == nil {
			err = verifyStoredValue(ack, key, value)
		}
		if err != nil {
			attempt.Err = err
		} else {
			attempt.Ack = &ack
		}
		result.Attempts = append(result.Attempts, attempt)
	}
	if result.StoredCopies() < minimum {
		return result, fmt.Errorf("Mailbox redundancy unmet: stored %d of required %d", result.StoredCopies(), minimum)
	}
	return result, nil
}

func verifyStoredValue(ack StoredAck, pinnedKey string, value envelope.RelayEnvelope) error {
	if err := VerifyAck(ack); err != nil {
		return err
	}
	if ack.RelayPublicKeyHex != pinnedKey || ack.MailboxID != value.OpaqueMailboxID || ack.MessageID != value.MessageID ||
		ack.CiphertextDigest != canon.Digest(value.Ciphertext) || ack.ExpiresAtUnix != value.ExpiresAtUnix {
		return errors.New("StoredAck does not bind the requested ciphertext")
	}
	return nil
}
