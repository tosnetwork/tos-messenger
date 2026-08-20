package probe

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"net"
	"net/netip"
	"time"

	"github.com/tosnetwork/tos-messenger/pkg/reachability"
)

// FilterResult is what one filter exchange with one coordinator produced.
//
// The byte counters are returned rather than accumulated in place so a caller
// that accounts traffic per trial can fold them into its own totals.
type FilterResult struct {
	// Observations are the coordinator's signed receipts, one per cold source
	// the endpoint demonstrably received from, already verified under the key
	// each one names. An empty set is not evidence of strict filtering: a
	// dropped probe and a lost probe are the same silence.
	Observations []reachability.FilteringObservation
	TxBytes      uint64
	RxBytes      uint64
}

// MeasureFiltering runs the filter exchange with one coordinator over the
// endpoint's established bind socket, during the bind phase.
//
// It has to be the same socket the endpoint bound with: the coordinator sends
// its cold probes to the observed source address of this flow, and the whole
// question is whether the NAT admits them back to this mapping. A fresh socket
// would measure a mapping nobody is using.
//
// Messages that belong to the wider session rather than to this exchange --
// early peer punches, mostly -- are handed to stray, so running the exchange
// does not eat datagrams the caller's own loop would have acted on. A nil
// stray drops them.
//
// Failure is an empty result, not an error: the coordinator not answering, the
// probes being filtered, and the probes being lost are indistinguishable from
// here, and the evidence model already treats absence as proof of nothing.
func MeasureFiltering(ctx context.Context, connection net.PacketConn, coordinator string,
	config Config, stray func(Message, netip.AddrPort)) FilterResult {
	var result FilterResult
	if connection == nil || ctx == nil {
		return result
	}
	if !sessionPattern.MatchString(config.SessionID) ||
		(config.Role != RoleA && config.Role != RoleB) ||
		!endpointKeyPattern.MatchString(config.EndpointKeyHex) ||
		(config.Probe != reachability.ProbeUDP && config.Probe != reachability.ProbeADNL) {
		return result
	}
	target, err := net.ResolveUDPAddr("udp", coordinator)
	if err != nil {
		return result
	}
	window := config.BindTimeout
	if window <= 0 {
		window = DefaultBindTimeout
	}
	interval := config.PollInterval
	if interval <= 0 {
		interval = DefaultPollInterval
	}

	nonce, err := randomHex16()
	if err != nil {
		return result
	}
	request, err := EncodeRequest(Message{
		Kind: KindFilter, SessionID: config.SessionID, Role: config.Role, Nonce: nonce,
		EndpointKey: config.EndpointKeyHex, Probe: string(config.Probe),
	})
	if err != nil {
		return result
	}

	collected := make(map[reachability.FilterSourceKind]struct{}, 2)
	echoed := make(map[string]struct{}, 4)
	deadline := time.Now().Add(window)
	// A coordinator without cold sources answers a filter request with
	// deliberate silence -- the same silence a filtering NAT produces -- so
	// from here the two are indistinguishable, and that is the measurement
	// stance. What the client controls is how long it keeps asking a
	// coordinator that has never said anything filter-shaped at all: this
	// evidence is opportunistic, and burning the whole bind window against
	// every unsupporting coordinator would multiply the coordinator traffic
	// other phases have already budgeted. A few paced rounds are enough for
	// a supporting coordinator's first probe to arrive; after that, silence
	// ends the exchange rather than the window.
	const silentRoundLimit = 3
	rounds, heard := 0, false
	for time.Now().Before(deadline) {
		if ctx.Err() != nil {
			return result
		}
		if !heard {
			rounds++
			if rounds > silentRoundLimit {
				return result
			}
		}
		if written, err := connection.WriteTo(request, target); err == nil {
			result.TxBytes += uint64(written)
		}
		pollUntil := time.Now().Add(interval)
		if pollUntil.After(deadline) {
			pollUntil = deadline
		}
		for time.Now().Before(pollUntil) {
			message, from, err := receiveFilter(connection, &result, pollUntil)
			if err != nil {
				break
			}
			if message.SessionID != config.SessionID {
				continue
			}
			switch {
			case message.Kind == KindFilterProbe && message.Role == config.Role:
				heard = true
				// The token arrived, which is the fact under test. Prove the
				// receipt over the established flow; the echo is a padded
				// request of its own, so the signed answer it earns cannot
				// amplify it.
				if _, already := echoed[message.Token]; already {
					continue
				}
				echo, err := EncodeRequest(Message{
					Kind: KindFilterEcho, SessionID: config.SessionID, Role: config.Role,
					Nonce: message.Token, Token: message.Token,
					EndpointKey: config.EndpointKeyHex, Probe: string(config.Probe),
				})
				if err != nil {
					continue
				}
				if written, err := connection.WriteTo(echo, target); err == nil {
					result.TxBytes += uint64(written)
					echoed[message.Token] = struct{}{}
				}
			case message.Kind == KindFilterOK && message.Role == config.Role:
				heard = true
				observation, err := filterObservation(message, config)
				if err != nil {
					continue
				}
				if _, already := collected[observation.Source]; already {
					continue
				}
				collected[observation.Source] = struct{}{}
				result.Observations = append(result.Observations, observation)
				// Both cold source kinds answered; there is nothing more this
				// exchange can learn.
				if len(collected) == 2 {
					return result
				}
			default:
				if stray != nil {
					stray(message, from)
				}
			}
		}
	}
	return result
}

// filterObservation reconstructs the coordinator's signed filtering
// observation from a filter answer. The session, role, endpoint key, and probe
// are this endpoint's own inputs, not something the reply echoes: the
// signature verifies only if the coordinator signed exactly what was
// presented, so filling them in locally is reconstruction, not trust. The
// observed address and source kind come from the reply, and the verification
// below is what makes them the coordinator's statement rather than the wire's.
func filterObservation(reply Message, config Config) (reachability.FilteringObservation, error) {
	if reply.Signature == "" || reply.SignerKey == "" {
		return reachability.FilteringObservation{}, errors.New("unsigned filter answer")
	}
	key, err := hex.DecodeString(reply.SignerKey)
	if err != nil {
		return reachability.FilteringObservation{}, err
	}
	identifier, err := reachability.CoordinatorID(key)
	if err != nil {
		return reachability.FilteringObservation{}, err
	}
	observation := reachability.FilteringObservation{
		CoordinatorID:        identifier,
		SessionID:            config.SessionID,
		Role:                 string(config.Role),
		EndpointPublicKeyHex: config.EndpointKeyHex,
		Probe:                string(config.Probe),
		Observed:             reply.Observed,
		Source:               reachability.FilterSourceKind(reply.FilterSource),
		AtUnix:               reply.ObservedAt,
		PublicKeyHex:         reply.SignerKey,
		SignatureHex:         reply.Signature,
	}
	if err := reachability.VerifyFilteringObservation(observation); err != nil {
		return reachability.FilteringObservation{}, err
	}
	return observation, nil
}

// receiveFilter reads one datagram within the deadline, counting the bytes.
func receiveFilter(connection net.PacketConn, result *FilterResult, deadline time.Time) (Message, netip.AddrPort, error) {
	if err := connection.SetReadDeadline(deadline); err != nil {
		return Message{}, netip.AddrPort{}, err
	}
	buffer := make([]byte, MaxMessageBytes)
	count, from, err := connection.ReadFrom(buffer)
	if err != nil {
		return Message{}, netip.AddrPort{}, err
	}
	result.RxBytes += uint64(count)
	source, ok := addrPort(from)
	if !ok {
		return Message{}, netip.AddrPort{}, errors.New("unexpected source address")
	}
	message, err := Decode(buffer[:count])
	if err != nil {
		return Message{}, netip.AddrPort{}, err
	}
	return message, source, nil
}

// randomHex16 returns 16 random bytes as lowercase hex, the shape both nonces
// and filter tokens carry.
func randomHex16() (string, error) {
	raw := make([]byte, 16)
	if _, err := rand.Read(raw); err != nil {
		return "", errors.New("generate probe token")
	}
	return hex.EncodeToString(raw), nil
}
