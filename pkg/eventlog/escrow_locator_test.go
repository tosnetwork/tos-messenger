package eventlog

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const (
	testQuoteCommitment = "tvm-cell-sha256:abababababababababababababababababababababababababababababababab"
	testEscrowAddress   = "0:cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd"
)

func TestEscrowLocationSurvivesRestartAndRefusesRedirect(t *testing.T) {
	root := filepath.Join(t.TempDir(), "journal")
	journal, err := Open(root)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	fresh, err := journal.RecordEscrowLocation(testQuoteCommitment, testEscrowAddress, "software.audit")
	if err != nil || !fresh {
		t.Fatalf("record: fresh=%v err=%v", fresh, err)
	}
	if fresh, err := journal.RecordEscrowLocation(testQuoteCommitment, testEscrowAddress, "software.audit"); err != nil || fresh {
		t.Fatalf("idempotent retry: fresh=%v err=%v", fresh, err)
	}
	if _, err := journal.RecordEscrowLocation(testQuoteCommitment, "0:"+strings.Repeat("1", 64), "software.audit"); !errors.Is(err, ErrConflict) {
		t.Fatalf("redirect was not a conflict: %v", err)
	}
	if err := journal.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}

	journal, err = Open(root)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	defer journal.Close()
	address, class, found, err := journal.LocateEscrow(testQuoteCommitment)
	if err != nil || !found || address != testEscrowAddress || class != "software.audit" {
		t.Fatalf("locate after restart: %q %q found=%v err=%v", address, class, found, err)
	}
	unknown := "tvm-cell-sha256:" + strings.Repeat("2", 64)
	if _, _, found, err := journal.LocateEscrow(unknown); err != nil || found {
		t.Fatalf("unknown commitment: found=%v err=%v", found, err)
	}
}

func TestEscrowLocationRefusesMalformedAndDamagedState(t *testing.T) {
	journal := approvalJournal(t)
	for name, values := range map[string][3]string{
		"commitment": {"sha256:" + strings.Repeat("a", 64), testEscrowAddress, "software.audit"},
		"address":    {testQuoteCommitment, "not-an-address", "software.audit"},
		"class":      {testQuoteCommitment, testEscrowAddress, "Software Audit"},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := journal.RecordEscrowLocation(values[0], values[1], values[2]); err == nil {
				t.Fatalf("malformed escrow location was accepted: %v", values)
			}
		})
	}

	if _, err := journal.RecordEscrowLocation(testQuoteCommitment, testEscrowAddress, "software.audit"); err != nil {
		t.Fatalf("record: %v", err)
	}
	path := journal.escrowLocationPath(testQuoteCommitment)
	if err := os.WriteFile(path, []byte(`{"schema":"tos.messaging.escrow-location.v1"}`), 0o600); err != nil {
		t.Fatalf("damage: %v", err)
	}
	if _, _, _, err := journal.LocateEscrow(testQuoteCommitment); err == nil {
		t.Fatal("damaged escrow location was accepted")
	}
}
