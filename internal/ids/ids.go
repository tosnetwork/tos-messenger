// Package ids holds every Messenger identifier pattern in one place.
//
// Identifiers are checked in several packages, and a second pattern that is
// almost the same as the first is how identifier confusion gets in. Every
// package matches against these and nothing else.
package ids

import (
	"encoding/hex"
	"errors"
	"regexp"

	"github.com/tosnetwork/tos-messenger/internal/canon"
)

// Identifier patterns. Every value is a prefix and 32 bytes of lowercase hex,
// so no identifier can be mistaken for one of another kind.
var (
	// Agent matches a finalized Agent identifier.
	Agent = regexp.MustCompile(`^agent_[0-9a-f]{64}$`)
	// Capability matches a finalized Capability identifier.
	Capability = regexp.MustCompile(`^cap_[0-9a-f]{64}$`)
	// Endpoint matches a Messaging Endpoint identifier.
	Endpoint = regexp.MustCompile(`^mep_[0-9a-f]{64}$`)
	// Device matches a device identifier.
	Device = regexp.MustCompile(`^dev_[0-9a-f]{64}$`)
	// Conversation matches a conversation identifier.
	Conversation = regexp.MustCompile(`^conv_[0-9a-f]{64}$`)
	// Event matches a Messaging Event identifier.
	Event = regexp.MustCompile(`^evt_[0-9a-f]{64}$`)
	// Room matches a room identifier.
	Room = regexp.MustCompile(`^room_[0-9a-f]{64}$`)
	// Thread matches a thread identifier.
	Thread = regexp.MustCompile(`^thr_[0-9a-f]{64}$`)
	// Mailbox matches an opaque Relay mailbox identifier.
	Mailbox = regexp.MustCompile(`^mbx_[0-9a-f]{64}$`)
	// RelayMessage matches a Relay-level message identifier.
	RelayMessage = regexp.MustCompile(`^msg_[0-9a-f]{64}$`)
	// ADNL matches an ADNL identity commitment.
	ADNL = regexp.MustCompile(`^adnl:[0-9a-f]{64}$`)
)

// Format renders 32 bytes under a prefix. A short or all-zero value is never a
// legitimate identifier, so it is refused rather than formatted.
func Format(prefix string, raw []byte) (string, error) {
	if prefix == "" || len(raw) != 32 || canon.IsZero(raw) {
		return "", errors.New("invalid identifier material")
	}
	return prefix + hex.EncodeToString(raw), nil
}
