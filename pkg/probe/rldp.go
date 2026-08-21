package probe

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"github.com/tosnetwork/tosutils-go/adnl"
	"github.com/tosnetwork/tosutils-go/adnl/rldp"
	"github.com/tosnetwork/tosutils-go/tl"

	"github.com/tosnetwork/tos-messenger/internal/canon"
)

const (
	// RLDPPartSizeBytes is the pinned TOS RLDPv2 part size. The collector checks
	// the dependency value at runtime instead of silently claiming segmentation
	// if the implementation changes underneath the evidence format.
	RLDPPartSizeBytes = 2_000_000
	// MaxRLDPPayloadBytes follows the Messenger service response ceiling. A
	// reachability collector is not allowed to turn into an unbounded allocator.
	MaxRLDPPayloadBytes = 16 << 20
	minRLDPInterruption = 100 * time.Millisecond
	maxRLDPInterruption = 10 * time.Second
)

type rldpProbeRequest struct {
	PayloadBytes uint32 `tl:"int"`
	Seed         []byte `tl:"int256"`
}

type rldpProbeResponse struct {
	Seed    []byte `tl:"int256"`
	Payload []byte `tl:"bytes"`
}

func init() {
	tl.Register(rldpProbeRequest{}, "tosprobe.rldpRequest payload_bytes:int seed:int256 = tosprobe.RLDPRequest")
	tl.Register(rldpProbeResponse{}, "tosprobe.rldpResponse seed:int256 payload:bytes = tosprobe.RLDPResponse")
}

// interruptibleADNL applies a bounded, observable loss window without ending
// the peer object or the RLDP client. Both outbound and inbound custom messages
// are discarded while blocked, so a successful result demonstrates recovery
// by the existing RLDP transfer rather than a fresh application request.
type interruptibleADNL struct {
	peer    adnl.Peer
	until   atomic.Int64
	dropped atomic.Uint64

	interruptionMu sync.Mutex
	armed          *rldpInterruption
}

type rldpInterruption struct {
	window      time.Duration
	triggerPart uint32
	started     chan time.Time
}

// armInterruption makes the first inbound symbol at or after triggerPart
// observable loss and starts the requested window at that drop. RLDP advances
// to that part only after the preceding part was decoded and acknowledged.
// Starting the clock before any traffic is due can create a quiet pause rather
// than packet loss when the retransmission interval exceeds the window.
func (a *interruptibleADNL) armInterruption(window time.Duration, triggerPart uint32) (*rldpInterruption, error) {
	a.interruptionMu.Lock()
	defer a.interruptionMu.Unlock()
	if a.armed != nil || time.Now().UnixNano() < a.until.Load() {
		return nil, errors.New("RLDP interruption already active")
	}
	armed := &rldpInterruption{window: window, triggerPart: triggerPart, started: make(chan time.Time, 1)}
	a.armed = armed
	return armed, nil
}

func (a *interruptibleADNL) disarmInterruption(armed *rldpInterruption) {
	a.interruptionMu.Lock()
	if a.armed == armed {
		a.armed = nil
	}
	a.interruptionMu.Unlock()
}

func (a *interruptibleADNL) dropCustomMessage(message any, inbound bool) bool {
	now := time.Now()
	if now.UnixNano() < a.until.Load() {
		a.dropped.Add(1)
		return true
	}
	a.interruptionMu.Lock()
	defer a.interruptionMu.Unlock()
	// Recheck after taking the lock: another direction may have triggered the
	// armed interruption between the optimistic check and this critical section.
	now = time.Now()
	if now.UnixNano() < a.until.Load() {
		a.dropped.Add(1)
		return true
	}
	if a.armed == nil {
		return false
	}
	part, isPart := rldpMessagePart(message)
	if !inbound || !isPart || part < a.armed.triggerPart {
		return false
	}
	armed := a.armed
	a.armed = nil
	a.until.Store(now.Add(armed.window).UnixNano())
	a.dropped.Add(1)
	armed.started <- now
	close(armed.started)
	return true
}

func rldpMessagePart(message any) (uint32, bool) {
	switch value := message.(type) {
	case rldp.MessagePart:
		return value.Part, true
	case rldp.MessagePartV2:
		return rldp.MessagePart(value).Part, true
	default:
		return 0, false
	}
}
func (a *interruptibleADNL) RemoteAddr() string { return a.peer.RemoteAddr() }
func (a *interruptibleADNL) GetID() []byte      { return a.peer.GetID() }
func (a *interruptibleADNL) SetCustomMessageHandler(handler func(*adnl.MessageCustom) error) {
	a.peer.SetCustomMessageHandler(func(message *adnl.MessageCustom) error {
		if a.dropCustomMessage(message.Data, true) {
			return nil
		}
		return handler(message)
	})
}
func (a *interruptibleADNL) SetDisconnectHandler(handler func(string, ed25519.PublicKey)) {
	a.peer.SetDisconnectHandler(handler)
}
func (a *interruptibleADNL) GetDisconnectHandler() func(string, ed25519.PublicKey) {
	return a.peer.GetDisconnectHandler()
}
func (a *interruptibleADNL) SendCustomMessage(ctx context.Context, message tl.Serializable) error {
	if a.dropCustomMessage(message, false) {
		return nil
	}
	return a.peer.SendCustomMessage(ctx, message)
}
func (a *interruptibleADNL) GetCloserCtx() context.Context { return a.peer.GetCloserCtx() }
func (a *interruptibleADNL) Close()                        { a.peer.Close() }

type rldpProbeSession struct {
	transport *interruptibleADNL
	client    *rldp.RLDP
}

var rldpSessions = struct {
	sync.Mutex
	byPeer map[adnl.Peer]*rldpProbeSession
}{byPeer: make(map[adnl.Peer]*rldpProbeSession)}

// prepareRLDPSession is called as soon as either side obtains a peer, before
// establishment is reported. This removes a readiness race where the faster
// endpoint could send an RLDP query before the slower endpoint installed its
// handler.
func prepareRLDPSession(peer adnl.Peer) *rldpProbeSession {
	rldpSessions.Lock()
	defer rldpSessions.Unlock()
	if existing := rldpSessions.byPeer[peer]; existing != nil {
		return existing
	}
	transport := &interruptibleADNL{peer: peer}
	client := rldp.NewClientV2(transport)
	client.SetOnQuery(func(transferID []byte, query *rldp.Query) error {
		request, ok := query.Data.(rldpProbeRequest)
		if !ok || len(request.Seed) != 32 || request.PayloadBytes <= RLDPPartSizeBytes || request.PayloadBytes > MaxRLDPPayloadBytes {
			return errors.New("invalid RLDP probe request")
		}
		payload := deterministicRLDPPayload(request.Seed, int(request.PayloadBytes))
		answerCtx, cancel := context.WithDeadline(context.Background(), time.Unix(int64(query.Timeout), 0))
		defer cancel()
		return client.SendAnswer(answerCtx, query.MaxAnswerSize, query.Timeout, query.ID, transferID,
			rldpProbeResponse{Seed: append([]byte(nil), request.Seed...), Payload: payload})
	})
	session := &rldpProbeSession{transport: transport, client: client}
	rldpSessions.byPeer[peer] = session
	return session
}

func forgetRLDPSession(peer adnl.Peer) {
	rldpSessions.Lock()
	delete(rldpSessions.byPeer, peer)
	rldpSessions.Unlock()
}

func deterministicRLDPPayload(seed []byte, size int) []byte {
	payload := make([]byte, size)
	var counter uint64
	for offset := 0; offset < len(payload); {
		h := sha256.New()
		h.Write([]byte(canon.DomainReachabilityRLDPPayload))
		h.Write(seed)
		var encoded [8]byte
		binary.BigEndian.PutUint64(encoded[:], counter)
		h.Write(encoded[:])
		block := h.Sum(nil)
		offset += copy(payload[offset:], block)
		counter++
	}
	return payload
}

func validateRLDPPlan(plan RLDPTransferPlan) error {
	if rldp.PartSize != RLDPPartSizeBytes {
		return fmt.Errorf("RLDP dependency part size is %d, evidence profile pins %d", rldp.PartSize, RLDPPartSizeBytes)
	}
	if plan.PayloadBytes <= RLDPPartSizeBytes || plan.PayloadBytes > MaxRLDPPayloadBytes {
		return errors.New("RLDP payload must be segmented and within the Messenger response ceiling")
	}
	if plan.InterruptAfterBytes == 0 && plan.Interruption == 0 {
		return nil
	}
	if plan.InterruptAfterBytes < RLDPPartSizeBytes || plan.InterruptAfterBytes >= uint64(plan.PayloadBytes) {
		return errors.New("RLDP interruption must follow one complete part and precede completion")
	}
	if plan.InterruptAfterBytes%RLDPPartSizeBytes != 0 {
		return errors.New("RLDP interruption point must be an exact complete-part boundary")
	}
	if plan.Interruption < minRLDPInterruption || plan.Interruption > maxRLDPInterruption {
		return errors.New("RLDP interruption must be between 100ms and 10s")
	}
	return nil
}

func runRLDPTransfer(ctx context.Context, session *rldpProbeSession, plan RLDPTransferPlan, timeout time.Duration) RLDPResult {
	result := RLDPResult{PayloadBytes: plan.PayloadBytes, PartSizeBytes: RLDPPartSizeBytes,
		ExpectedParts:             uint32((plan.PayloadBytes + RLDPPartSizeBytes - 1) / RLDPPartSizeBytes),
		InterruptAfterBytes:       plan.InterruptAfterBytes,
		PlannedInterruptionMillis: uint64(plan.Interruption / time.Millisecond)}
	if err := validateRLDPPlan(plan); err != nil || session == nil {
		return result
	}
	seed := make([]byte, 32)
	if _, err := rand.Read(seed); err != nil {
		return result
	}
	expected := deterministicRLDPPayload(seed, plan.PayloadBytes)
	sum := sha256.Sum256(expected)
	result.PayloadSHA256 = "sha256:" + hex.EncodeToString(sum[:])

	queryCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	var armed *rldpInterruption
	before := session.transport.dropped.Load()
	if plan.Interruption > 0 {
		// RLDP sends part N+1 only after it receives the receiver's completion
		// for part N. Arming before DoQuery and triggering on the first inbound
		// symbol of that next part therefore binds the outage to this query's
		// exact decoded-part boundary without polling process-wide statistics.
		triggerPart := uint32(plan.InterruptAfterBytes / RLDPPartSizeBytes)
		var err error
		armed, err = session.transport.armInterruption(plan.Interruption, triggerPart)
		if err != nil {
			result.Failure = err.Error()
			return result
		}
	}
	done := make(chan error, 1)
	var response rldpProbeResponse
	started := time.Now()
	go func() {
		done <- session.client.DoQuery(queryCtx, uint64(plan.PayloadBytes+1024),
			rldpProbeRequest{PayloadBytes: uint32(plan.PayloadBytes), Seed: seed}, &response)
	}()

	if armed != nil {
		select {
		case <-queryCtx.Done():
			session.transport.disarmInterruption(armed)
			return result
		case err := <-done:
			session.transport.disarmInterruption(armed)
			if err != nil {
				result.Failure = err.Error()
			} else {
				result.Failure = "transfer completed before observable interruption"
			}
			return result
		case interrupted := <-armed.started:
			result.InterruptionAttempted = true
			timer := time.NewTimer(time.Until(interrupted.Add(plan.Interruption)))
			select {
			case <-queryCtx.Done():
				timer.Stop()
				return result
			case <-timer.C:
			}
			result.InterruptionMillis = uint64(time.Since(interrupted).Milliseconds())
		}
		result.SuppressedMessages = session.transport.dropped.Load() - before
	}

	err := <-done
	elapsed := time.Since(started).Milliseconds()
	if err != nil {
		result.Failure = err.Error()
		return result
	}
	if len(response.Seed) != 32 || string(response.Seed) != string(seed) || len(response.Payload) != len(expected) {
		result.Failure = "RLDP response shape or seed mismatch"
		return result
	}
	got := sha256.Sum256(response.Payload)
	if got != sum {
		result.Failure = "RLDP response digest mismatch"
		return result
	}
	result.Succeeded = true
	if elapsed < 1 {
		elapsed = 1
	}
	result.RoundTripMillis = uint64(elapsed)
	if result.InterruptionAttempted && result.SuppressedMessages > 0 && result.InterruptionMillis >= uint64(minRLDPInterruption/time.Millisecond) {
		result.SameTransferResumed = true
	}
	return result
}
