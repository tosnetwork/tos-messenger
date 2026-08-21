package probe

import (
	"testing"
	"time"

	"github.com/tosnetwork/tosutils-go/adnl/rldp"
)

func TestInterruptibleADNLStartsWindowAtObservableDrop(t *testing.T) {
	transport := &interruptibleADNL{}
	armed, err := transport.armInterruption(150*time.Millisecond, 1)
	if err != nil {
		t.Fatal(err)
	}
	if transport.dropCustomMessage(rldp.MessagePartV2(rldp.MessagePart{Part: 0}), true) {
		t.Fatal("the part before the configured boundary was dropped")
	}
	if !transport.dropCustomMessage(rldp.MessagePartV2(rldp.MessagePart{Part: 1}), true) {
		t.Fatal("the first message after arming was not dropped")
	}
	var started time.Time
	select {
	case started = <-armed.started:
	case <-time.After(time.Second):
		t.Fatal("the observable interruption did not start")
	}
	if started.IsZero() || transport.until.Load() < started.Add(150*time.Millisecond).UnixNano() {
		t.Fatalf("interruption window did not begin at the first drop: started=%v until=%v",
			started, time.Unix(0, transport.until.Load()))
	}
	if !transport.dropCustomMessage(rldp.ConfirmV2{}, false) || transport.dropped.Load() != 2 {
		t.Fatalf("active window did not suppress the second message: dropped=%d", transport.dropped.Load())
	}

	transport.until.Store(time.Now().Add(-time.Second).UnixNano())
	if transport.dropCustomMessage(rldp.MessagePartV2(rldp.MessagePart{Part: 2}), true) {
		t.Fatal("an expired interruption continued dropping messages")
	}
}

func TestInterruptibleADNLDisarmsQuietWindow(t *testing.T) {
	transport := &interruptibleADNL{}
	armed, err := transport.armInterruption(150*time.Millisecond, 1)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := transport.armInterruption(150*time.Millisecond, 1); err == nil {
		t.Fatal("overlapping interruption was accepted")
	}
	transport.disarmInterruption(armed)
	if transport.dropCustomMessage(rldp.MessagePartV2(rldp.MessagePart{Part: 1}), true) {
		t.Fatal("a disarmed interruption dropped a message")
	}
	select {
	case <-armed.started:
		t.Fatal("a disarmed interruption reported a start")
	default:
	}
}

func TestValidateRLDPPlanRequiresExactPartBoundary(t *testing.T) {
	plan := RLDPTransferPlan{
		PayloadBytes:        4_000_001,
		InterruptAfterBytes: RLDPPartSizeBytes + 1,
		Interruption:        150 * time.Millisecond,
	}
	if err := validateRLDPPlan(plan); err == nil {
		t.Fatal("a non-part interruption boundary was accepted")
	}
}
