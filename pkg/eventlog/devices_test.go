package eventlog

import (
	"bytes"
	"crypto/ed25519"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/tosnetwork/tos-messenger/internal/canon"
	"github.com/tosnetwork/tos-messenger/pkg/e2ee"
	nativev1 "github.com/tosnetwork/tos-service-protocol/gen/tos/service/v1"
)

func deviceNetwork() *nativev1.NetworkDomain {
	return &nativev1.NetworkDomain{
		NetworkId: "tos-local", GenesisRootHash: strings.Repeat("a", 64),
		GenesisFileHash: strings.Repeat("b", 64),
	}
}

var deviceEndpoint = "mep_" + strings.Repeat("c", 64)
var deviceAgent = "agent_" + strings.Repeat("d", 64)

func deviceID(seed byte) string {
	return "dev_" + strings.Repeat(string("0123456789abcdef"[seed%16]), 64)
}

// bundleSet signs a device set for the fixed endpoint. The material varies by
// device so the per-bundle digests differ.
func bundleSet(t *testing.T, issued map[string]uint64) []e2ee.Bundle {
	t.Helper()
	// A stable, valid ed25519 key that the bundles are signed under. The
	// ledger does not re-verify signatures -- the descriptor path does -- so
	// any self-consistent signed set exercises succession.
	bundles := make([]e2ee.Bundle, 0, len(issued))
	for id, at := range issued {
		bundle := e2ee.Bundle{
			Network: deviceNetwork(), AgentID: deviceAgent, EndpointID: deviceEndpoint,
			DeviceID: id, AlgorithmID: "tos.messaging.e2ee.example-suite.v1",
			Material:      []byte(canon.Digest([]byte(id))),
			IssuedAtUnix:  at,
			ExpiresAtUnix: at + 3600,
		}
		signed, err := e2ee.SignBundle(bundle, testBundleKey())
		if err != nil {
			t.Fatalf("sign: %v", err)
		}
		bundles = append(bundles, signed)
	}
	return bundles
}

func deviceLedger(t *testing.T) *DeviceLedger {
	t.Helper()
	journal := approvalJournal(t)
	ledger, err := journal.OpenDevices()
	if err != nil {
		t.Fatalf("open devices: %v", err)
	}
	return ledger
}

// A revoked device stays revoked across a restart, and a rollback is refused
// against the record rather than only against memory.
func TestDeviceLedgerSurvivesAndRefusesRollback(t *testing.T) {
	root := t.TempDir() + "/state"
	journal, err := Open(root)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	ledger, err := journal.OpenDevices()
	if err != nil {
		t.Fatalf("devices: %v", err)
	}
	now := time.Unix(1_800_000_000, 0)

	full := bundleSet(t, map[string]uint64{deviceID(1): 1_800_000_000, deviceID(2): 1_800_000_000})
	if _, err := ledger.AcceptSet(deviceEndpoint, full, now); err != nil {
		t.Fatalf("accept: %v", err)
	}
	// Retire device 2.
	retired := bundleSet(t, map[string]uint64{deviceID(1): 1_800_000_000})
	succession, err := ledger.AcceptSet(deviceEndpoint, retired, now)
	if err != nil {
		t.Fatalf("retire: %v", err)
	}
	if len(succession.Removed) != 1 || succession.Removed[0] != deviceID(2) {
		t.Fatalf("the retirement was not recorded: %v", succession.Removed)
	}

	// The process ends here.
	if err := journal.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	reopened, err := Open(root)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	defer reopened.Close()
	restored, err := reopened.OpenDevices()
	if err != nil {
		t.Fatalf("devices: %v", err)
	}

	// The revocation survived: device 2 cannot come back.
	if standing, err := restored.Judge(deviceEndpoint, deviceID(2)); err != nil {
		t.Fatalf("judge: %v", err)
	} else if standing != DeviceRevoked {
		t.Fatalf("a revoked device was not remembered: %q", standing)
	}
	returning := bundleSet(t, map[string]uint64{deviceID(1): 1_800_000_000, deviceID(2): 1_800_000_500})
	if _, err := restored.AcceptSet(deviceEndpoint, returning, now); err == nil {
		t.Fatal("a revoked device returned after a restart")
	}
	// And the full old set is a rollback against the record.
	if _, err := restored.AcceptSet(deviceEndpoint, full, now); err == nil {
		t.Fatal("an older set displaced the recorded one after a restart")
	}
}

// Judge distinguishes the three standings a receiver must act on differently.
func TestDeviceJudgeClassifies(t *testing.T) {
	ledger := deviceLedger(t)
	now := time.Unix(1_800_000_000, 0)
	if standing, err := ledger.Judge(deviceEndpoint, deviceID(1)); err != nil {
		t.Fatalf("judge: %v", err)
	} else if standing != DeviceUnknown {
		t.Fatalf("an unseen endpoint was not unknown: %q", standing)
	}
	set := bundleSet(t, map[string]uint64{deviceID(1): 1_800_000_000, deviceID(2): 1_800_000_000})
	if _, err := ledger.AcceptSet(deviceEndpoint, set, now); err != nil {
		t.Fatalf("accept: %v", err)
	}
	for _, want := range []struct {
		device   string
		standing DeviceStanding
	}{
		{deviceID(1), DeviceCurrent},
		{deviceID(3), DeviceUnknown}, // maybe added since we fetched
	} {
		if standing, err := ledger.Judge(deviceEndpoint, want.device); err != nil {
			t.Fatalf("judge: %v", err)
		} else if standing != want.standing {
			t.Fatalf("device %s: expected %q, got %q", want.device, want.standing, standing)
		}
	}
}

// Re-accepting the same set is idempotent: nothing is removed a second time.
func TestReacceptingTheSameSetIsIdempotent(t *testing.T) {
	ledger := deviceLedger(t)
	now := time.Unix(1_800_000_000, 0)
	set := bundleSet(t, map[string]uint64{deviceID(1): 1_800_000_000})
	if _, err := ledger.AcceptSet(deviceEndpoint, set, now); err != nil {
		t.Fatalf("accept: %v", err)
	}
	succession, err := ledger.AcceptSet(deviceEndpoint, set, now)
	if err != nil {
		t.Fatalf("re-accept: %v", err)
	}
	if len(succession.Removed) != 0 {
		t.Fatalf("an unchanged set removed devices: %v", succession.Removed)
	}
}

func TestDeviceLedgerReturnsEquivocationEvidence(t *testing.T) {
	ledger := deviceLedger(t)
	now := time.Unix(1_800_000_000, 0)
	current := bundleSet(t, map[string]uint64{deviceID(1): 1_800_000_000})
	if _, err := ledger.AcceptSet(deviceEndpoint, current, now); err != nil {
		t.Fatalf("accept: %v", err)
	}
	candidate := bundleSet(t, map[string]uint64{deviceID(2): 1_800_000_000})
	_, err := ledger.AcceptSet(deviceEndpoint, candidate, now)
	if !errors.Is(err, ErrDeviceEquivocation) {
		t.Fatalf("equal-time fork was not classified: %v", err)
	}
	var evidence *e2ee.SetEquivocationError
	if !errors.As(err, &evidence) || evidence.CurrentDigest == evidence.CandidateDigest ||
		evidence.IssuedAtUnix != uint64(now.Unix()) {
		t.Fatalf("equivocation evidence is incomplete: %+v", evidence)
	}
}

// testBundleKey is a stable signing key for the fixtures. The device ledger
// judges succession, not signatures, so a self-consistent set suffices.
func testBundleKey() ed25519.PrivateKey {
	return ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x44}, ed25519.SeedSize))
}
