package probe

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/tosnetwork/tos-messenger/pkg/reachability"
	"github.com/tosnetwork/tosutils-go/adnl"
	"github.com/tosnetwork/tosutils-go/tl"
)

// The probe's cross-implementation round trip is an ADNL query whose payload
// is this ASCII prefix followed by random bytes; the answer is exactly the
// 32-byte sha256 of the random bytes. The convention is what the native
// sidecar speaks for session confirmation, keepalives, and echo alike, so a
// collector that can send and answer such queries interoperates with every
// phase of a native peer.
const (
	// EchoPrefix is the 16-byte query payload prefix.
	EchoPrefix = "tosprobe-echo/1\n"
	// MaxEchoBytes is the largest random-byte count an echo may carry. The
	// native stack caps ADNL query payloads at 8192 bytes and the prefix
	// spends 16 of them; a larger request would be refused or dropped rather
	// than measured, so it is refused here where the operator can see it.
	MaxEchoBytes = int(reachability.MaxSizedEchoPayloadBytes)
	// echoConfirmBytes is the random-byte count of the round trips that stand
	// in for a ping: session confirmation and keepalives. It matches the
	// native sidecar's own confirmation payload, so the two implementations
	// measure the same act.
	echoConfirmBytes = 32
	// echoAttempts bounds the number of fresh queries used for one configured
	// size. All attempts share the caller's overall time window; a fresh query
	// gets a fresh ID and multipart assembly state.
	echoAttempts = 3
)

// echoQueryPayload is how the raw echo query becomes visible to this
// collector's TL parser. The wire payload is raw bytes, not a TL object, but
// tosutils-go parses every inbound query payload as a boxed TL structure and
// drops the whole packet when the leading four bytes are no registered
// constructor. Registering a manual-codec type under exactly the constructor
// id the prefix begins with ("tosp", read little-endian) turns the raw
// payload into a parseable object without changing a byte on the wire.
type echoQueryPayload struct {
	// rest is everything after the four prefix bytes the TL layer consumed as
	// the constructor id.
	rest []byte
}

// Parse keeps the whole remainder. The payload is opaque bytes, so nothing is
// left for another constructor to claim.
func (p *echoQueryPayload) Parse(data []byte) ([]byte, error) {
	p.rest = append([]byte(nil), data...)
	return nil, nil
}

// Serialize writes the remainder back; the TL layer prepends the constructor
// id, which is the first four payload bytes.
func (p *echoQueryPayload) Serialize(buf *bytes.Buffer) error {
	buf.Write(p.rest)
	return nil
}

func init() {
	// 0x70736f74 little-endian is the bytes "tosp", the start of EchoPrefix.
	tl.Register(echoQueryPayload{}, "tosprobe.echoQuery#70736f74 = tosprobe.EchoQuery")
}

// fullPayload reassembles the wire payload from the parsed form.
func (p *echoQueryPayload) fullPayload() []byte {
	payload := make([]byte, 0, 4+len(p.rest))
	payload = append(payload, EchoPrefix[:4]...)
	return append(payload, p.rest...)
}

// answerWatch is how this collector receives the raw 32-byte echo answer. The
// answer is a hash, not a TL object, so tosutils-go's packet parser rejects it
// as an unregistered constructor and drops the packet -- after decrypting and
// authenticating it -- with a log line that carries the undecodable bytes in
// hex. The querier knows the exact hash it expects, so finding that hex in the
// log line is finding the answer: the bytes arrived over the session under
// test, or the line could not exist. It is a side channel, but everything it
// proves travelled the measured wire.
var answerWatch = struct {
	sync.Mutex
	pending map[string]chan struct{}
}{pending: map[string]chan struct{}{}}

// watchForAnswer registers interest in a hash before the query is sent, so the
// answer cannot slip through between send and watch. The returned cancel is
// idempotent and must always be called.
func watchForAnswer(hashHex string) (<-chan struct{}, func()) {
	arrived := make(chan struct{}, 1)
	answerWatch.Lock()
	answerWatch.pending[hashHex] = arrived
	answerWatch.Unlock()
	return arrived, func() {
		answerWatch.Lock()
		delete(answerWatch.pending, hashHex)
		answerWatch.Unlock()
	}
}

// noteUndecodable scans one dropped-packet log line for every answer some
// echo round trip is waiting on.
func noteUndecodable(line string) {
	answerWatch.Lock()
	for hashHex, arrived := range answerWatch.pending {
		if strings.Contains(line, hashHex) {
			select {
			case arrived <- struct{}{}:
			default:
			}
			delete(answerWatch.pending, hashHex)
		}
	}
	answerWatch.Unlock()
}

// installADNLLogger points the gateway's package-level logger at this
// collector's needs, once: silence (the responder's punch datagrams are not
// ADNL and the peer's gateway drops them noisily), except that dropped-packet
// lines are scanned for awaited echo answers first.
var adnlLoggerOnce sync.Once

func installADNLLogger() {
	adnlLoggerOnce.Do(func() {
		adnl.Logger = func(parts ...any) {
			answerWatch.Lock()
			waiting := len(answerWatch.pending) > 0
			answerWatch.Unlock()
			if waiting {
				noteUndecodable(fmt.Sprintln(parts...))
			}
		}
	})
}

// answerEchoQueries makes a peer answer the probe's echo queries: the prefix
// is acknowledged with the sha256 of the remainder, exactly as the native
// sidecar answers, so a native peer can confirm, keep alive, and echo against
// this collector. Anything that is not an echo query is left unanswered,
// which is what the peer saw before any handler existed.
func answerEchoQueries(peer adnl.Peer) {
	peer.SetQueryHandler(func(msg *adnl.MessageQuery) error {
		parsed, ok := msg.Data.(echoQueryPayload)
		if !ok {
			return nil
		}
		payload := parsed.fullPayload()
		if len(payload) < len(EchoPrefix) || string(payload[:len(EchoPrefix)]) != EchoPrefix {
			return nil
		}
		sum := sha256.Sum256(payload[len(EchoPrefix):])
		answerCtx, cancel := context.WithTimeout(context.Background(), keepalivePingTimeout)
		defer cancel()
		// The answer is the raw hash, no TL wrapper: the native querier
		// requires exactly 32 bytes.
		_ = peer.Answer(answerCtx, msg.ID, tl.Raw(sum[:]))
		return nil
	})
}

// echoRoundTrip sends one echo query and waits for its answer, within the
// given window. It reports whether the exact expected hash came back and how
// long the round trip took; a failure leaves the latency at zero, the
// schema's "not measured".
func echoRoundTrip(ctx context.Context, peer adnl.Peer, size int, window time.Duration) (uint64, bool) {
	if size < 1 || size > MaxEchoBytes {
		return 0, false
	}
	payload := make([]byte, len(EchoPrefix)+size)
	copy(payload, EchoPrefix)
	if _, err := rand.Read(payload[len(EchoPrefix):]); err != nil {
		return 0, false
	}
	sum := sha256.Sum256(payload[len(EchoPrefix):])
	expected := hex.EncodeToString(sum[:])

	installADNLLogger()
	arrived, cancelWatch := watchForAnswer(expected)
	defer cancelWatch()

	queryCtx, cancelQuery := context.WithTimeout(ctx, window)
	defer cancelQuery()

	// The query itself is sent (and resent, on the library's own cadence)
	// until the window closes. Its parsed-answer path can only ever complete
	// against a peer whose answer happens to be a registered TL object, which
	// the raw hash never is, so completion is signalled by the watch; the
	// call's own return is nothing more than the resend loop ending.
	started := time.Now()
	queryDone := make(chan struct{}, 1)
	go func() {
		var discard tl.Serializable
		_ = peer.Query(queryCtx, tl.Raw(payload), &discard)
		queryDone <- struct{}{}
	}()

	if echoAnswerArrived(arrived, queryDone) {
		cancelQuery()
		elapsed := time.Since(started).Milliseconds()
		if elapsed < 1 {
			elapsed = 1
		}
		return uint64(elapsed), true
	}
	return 0, false
}

// echoAnswerArrived resolves the boundary race between the raw-answer watch
// and Query's completion. A raw native answer is deliberately not parseable
// by tosutils-go: its receive path logs the authenticated bytes (which fires
// arrived), while Query can finish at the same deadline. If both channels are
// ready, select may choose queryDone, so that branch must recheck arrived
// before declaring the measurement failed.
func echoAnswerArrived(arrived, queryDone <-chan struct{}) bool {
	select {
	case <-arrived:
		return true
	case <-queryDone:
		select {
		case <-arrived:
			return true
		default:
			return false
		}
	}
}

// echoDialectPeers remembers, per peer object, that the peer answered an echo
// query after ignoring a ping. A native peer never answers the library's ping
// (it is not an adnl.Message constructor there), so once the echo dialect is
// established there is no point burning half of every later round-trip window
// on a ping that cannot complete. Entries live as long as the peer objects
// do, which is the lifetime of one measurement.
var echoDialectPeers sync.Map

// sessionRoundTrip is the probe's "did the session answer" primitive: first
// the library's native ping, then -- only if the ping went unanswered -- a
// small echo query, the round trip the native stack does speak.
//
// The order matters more than it looks. Between two of this collector's own
// endpoints the ping always answers, so no echo is sent and, crucially, no
// raw 32-byte answer is ever produced while the ADNL channel is still being
// confirmed: the raw answer is unparseable to this library and takes its
// whole datagram down with it, including any channel-control message sharing
// the packet, which can livelock the channel handshake. Racing the two
// dialects in parallel was observed doing exactly that on loopback. Against a
// native peer the ping half of the window is a writeoff, paid once: the peer
// is then remembered as echo-dialect and later round trips go straight to the
// query.
func sessionRoundTrip(ctx context.Context, peer adnl.Peer, window time.Duration) error {
	if _, echoOnly := echoDialectPeers.Load(peer); !echoOnly {
		attempt, cancel := context.WithTimeout(ctx, window/2)
		_, err := peer.Ping(attempt)
		cancel()
		if err == nil {
			return nil
		}
		if ctx.Err() != nil {
			return ctx.Err()
		}
	}
	if _, ok := echoRoundTrip(ctx, peer, echoConfirmBytes, window/2); ok {
		echoDialectPeers.Store(peer, struct{}{})
		return nil
	}
	return errors.New("session round trip went unanswered")
}
