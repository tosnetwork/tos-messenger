package e2ee

import (
	"strings"
	"testing"
	"time"
)

func device(seed byte) string {
	return "dev_" + strings.Repeat(string("0123456789abcdef"[seed%16]), 64)
}

// setOf builds a signed set for one endpoint, with per-device issue times.
func setOf(t *testing.T, issued map[string]uint64) []Bundle {
	t.Helper()
	key := endpointKey(t, 0x11)
	delegation := testDelegation(t, key)
	bundles := make([]Bundle, 0, len(issued))
	for deviceID, at := range issued {
		bundle := testBundle(t, delegation, deviceID)
		bundle.IssuedAtUnix = at
		bundle.ExpiresAtUnix = at + 3600
		signed, err := SignBundle(bundle, key)
		if err != nil {
			t.Fatalf("sign: %v", err)
		}
		bundles = append(bundles, signed)
	}
	return bundles
}

func mustSummary(t *testing.T, bundles []Bundle) SetSummary {
	t.Helper()
	summary, err := Summarize(bundles)
	if err != nil {
		t.Fatalf("summarize: %v", err)
	}
	return summary
}

// Adding a device issues fresh material, so the set is strictly fresher and
// succeeds. Removing one re-issues nothing and still succeeds, and the removed
// device is reported so its sessions can be closed.
func TestSuccessionAddsAndRetires(t *testing.T) {
	first := setOf(t, map[string]uint64{device(1): baseUnix, device(2): baseUnix})
	current := mustSummary(t, first)

	grown := append(append([]Bundle{}, first...),
		setOf(t, map[string]uint64{device(3): baseUnix + 100})...)
	succession, err := Succeed(current, nil, grown)
	if err != nil {
		t.Fatalf("a grown set was refused: %v", err)
	}
	if len(succession.Removed) != 0 {
		t.Fatalf("growth removed devices: %v", succession.Removed)
	}

	// Pure retirement: same bundles, one device gone, same freshness.
	var retained []Bundle
	for _, bundle := range first {
		if bundle.DeviceID != device(2) {
			retained = append(retained, bundle)
		}
	}
	retirement, err := Succeed(current, nil, retained)
	if err != nil {
		t.Fatalf("a pure retirement was refused: %v", err)
	}
	if len(retirement.Removed) != 1 || retirement.Removed[0] != device(2) {
		t.Fatalf("the retired device was not reported: %v", retirement.Removed)
	}
}

// A replayed old set must not displace a newer one. The receiver's record is
// the defence: a directory entry is replayable by whoever can reach the DHT.
func TestSuccessionRefusesRollback(t *testing.T) {
	old := setOf(t, map[string]uint64{device(1): baseUnix})
	newer := setOf(t, map[string]uint64{device(1): baseUnix, device(2): baseUnix + 500})
	current := mustSummary(t, newer)

	if _, err := Succeed(current, nil, old); err == nil {
		t.Fatal("an older set displaced a newer one")
	}
	// Same freshness, different content, not a subset: two sets claiming the
	// same moment, and accepting either would make "whoever spoke last" the
	// authority.
	rival := setOf(t, map[string]uint64{device(1): baseUnix, device(3): baseUnix + 500})
	if _, err := Succeed(current, nil, rival); err == nil {
		t.Fatal("a rival set at equal freshness was accepted")
	}
}

// Removal is revocation, and revocation with an undo is a suggestion.
func TestSuccessionKeepsTombstones(t *testing.T) {
	tombstones := map[string]struct{}{device(2): {}}
	returning := setOf(t, map[string]uint64{device(1): baseUnix, device(2): baseUnix + 1000})
	if _, err := Succeed(SetSummary{}, tombstones, returning); err == nil {
		t.Fatal("a revoked device returned to the set")
	}
}

// Both ends derive the same session for a device pair without negotiating.
func TestDeviceSessionsAreSymmetricAndDistinct(t *testing.T) {
	forward, err := DeviceSessionID(device(1), device(2))
	if err != nil {
		t.Fatalf("derive: %v", err)
	}
	backward, err := DeviceSessionID(device(2), device(1))
	if err != nil {
		t.Fatalf("derive: %v", err)
	}
	if forward != backward {
		t.Fatal("the two ends derived different sessions")
	}
	other, err := DeviceSessionID(device(1), device(3))
	if err != nil {
		t.Fatalf("derive: %v", err)
	}
	if other == forward {
		t.Fatal("two pairs shared a session")
	}
	if !strings.HasPrefix(forward, "ses_") || len(forward) != 4+64 {
		t.Fatalf("unexpected session identifier: %s", forward)
	}
	if _, err := DeviceSessionID(device(1), device(1)); err == nil {
		t.Fatal("a device held a session with itself")
	}
}

// One event, many sealed copies: every live recipient device, and every other
// device of the sender.
func TestFanOutCoversBothSets(t *testing.T) {
	sender := setOf(t, map[string]uint64{device(1): baseUnix, device(2): baseUnix})
	recipient := setOf(t, map[string]uint64{device(8): baseUnix, device(9): baseUnix})

	established := map[string]bool{}
	sessionA8, _ := DeviceSessionID(device(1), device(8))
	established[sessionA8] = true

	result, err := FanOut(PlanInput{
		SenderDeviceID: device(1),
		SenderSet:      sender,
		RecipientSet:   recipient,
		Now:            time.Unix(int64(baseUnix)+10, 0),
		SessionExists:  func(id string) bool { return established[id] },
	})
	if err != nil {
		t.Fatalf("fan out: %v", err)
	}
	if len(result.Recipients) != 2 {
		t.Fatalf("expected two recipient copies, got %+v", result.Recipients)
	}
	// The established session is reused; the other bootstraps from its bundle.
	for _, target := range result.Recipients {
		if target.DeviceID == device(8) && target.Bootstrap {
			t.Fatal("an established session was re-bootstrapped")
		}
		if target.DeviceID == device(9) && (!target.Bootstrap || target.BundleDigest == "") {
			t.Fatalf("a fresh device did not bootstrap: %+v", target)
		}
	}
	if len(result.SelfCopies) != 1 || result.SelfCopies[0].DeviceID != device(2) {
		t.Fatalf("the sender's other device was not covered: %+v", result.SelfCopies)
	}
	if len(result.Unreachable) != 0 {
		t.Fatalf("unexpectedly unreachable: %v", result.Unreachable)
	}
}

// A bundle only bootstraps. Its expiry does not close an established session,
// and a device with no session and no live bundle is reported unreachable
// rather than guessed at.
func TestExpiredBundlesBootstrapNothing(t *testing.T) {
	sender := setOf(t, map[string]uint64{device(1): baseUnix})
	recipient := setOf(t, map[string]uint64{device(8): baseUnix, device(9): baseUnix})
	late := time.Unix(int64(baseUnix)+7200, 0) // both recipient bundles expired

	sessionWith8, _ := DeviceSessionID(device(1), device(8))
	result, err := FanOut(PlanInput{
		SenderDeviceID: device(1),
		SenderSet:      sender,
		RecipientSet:   recipient,
		Now:            late,
		SessionExists:  func(id string) bool { return id == sessionWith8 },
	})
	if err != nil {
		t.Fatalf("fan out: %v", err)
	}
	if len(result.Recipients) != 1 || result.Recipients[0].DeviceID != device(8) {
		t.Fatalf("the established session did not survive bundle expiry: %+v", result.Recipients)
	}
	if len(result.Unreachable) != 1 || result.Unreachable[0] != device(9) {
		t.Fatalf("the dead-bundle device was not reported: %v", result.Unreachable)
	}
}

// A sender not in its own published set is a rotation gone wrong, not
// something to plan around.
func TestFanOutRefusesAnUnpublishedSender(t *testing.T) {
	sender := setOf(t, map[string]uint64{device(2): baseUnix})
	recipient := setOf(t, map[string]uint64{device(8): baseUnix})
	if _, err := FanOut(PlanInput{
		SenderDeviceID: device(1),
		SenderSet:      sender,
		RecipientSet:   recipient,
		Now:            time.Unix(int64(baseUnix)+10, 0),
		SessionExists:  func(string) bool { return false },
	}); err == nil {
		t.Fatal("an unpublished sender planned a fan-out")
	}
}
