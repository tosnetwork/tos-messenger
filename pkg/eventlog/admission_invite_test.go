package eventlog

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestAdmissionInviteIsOpaqueOneShotAndRestartSafe(t *testing.T) {
	root := filepath.Join(t.TempDir(), "state")
	now := time.Unix(1_800_000_000, 0)
	recipient := "mep_" + strings.Repeat("a", 64)
	sender := "agent_" + strings.Repeat("b", 64)
	eventID := "evt_" + strings.Repeat("c", 64)
	journal, err := Open(root)
	if err != nil {
		t.Fatal(err)
	}
	var entropy [32]byte
	copy(entropy[:], bytes.Repeat([]byte{7}, 32))
	token, record, err := journal.CreateAdmissionInvite(entropy, recipient, sender, now.Add(time.Hour), now)
	if err != nil {
		t.Fatal(err)
	}
	if token == "" || strings.Contains(record.InviteDigest, token) {
		t.Fatal("invite was not represented by an opaque digest")
	}
	onDisk, err := os.ReadFile(journal.admissionInvitePath(record.InviteDigest))
	if err != nil || bytes.Contains(onDisk, []byte(token)) {
		t.Fatal("bearer token was persisted")
	}
	if fresh, err := journal.ClaimAdmissionInvite(token, recipient, sender, eventID, now.Add(time.Minute)); err != nil || !fresh {
		t.Fatalf("first claim: fresh=%v err=%v", fresh, err)
	}
	if fresh, err := journal.ClaimAdmissionInvite(token, recipient, sender, eventID, now.Add(2*time.Hour)); err != nil || fresh {
		t.Fatalf("exact retry after expiry: fresh=%v err=%v", fresh, err)
	}
	if err := journal.Close(); err != nil {
		t.Fatal(err)
	}
	journal, err = Open(root)
	if err != nil {
		t.Fatal(err)
	}
	defer journal.Close()
	if _, err := journal.ClaimAdmissionInvite(token, recipient, sender, "evt_"+strings.Repeat("d", 64), now.Add(3*time.Minute)); err == nil {
		t.Fatal("spent invite authorized another event after restart")
	}
}

func TestAdmissionInviteRefusesScopeEncodingExpiryAndSubstitution(t *testing.T) {
	journal, err := Open(filepath.Join(t.TempDir(), "state"))
	if err != nil {
		t.Fatal(err)
	}
	defer journal.Close()
	now := time.Unix(1_800_000_000, 0)
	recipient := "mep_" + strings.Repeat("a", 64)
	sender := "agent_" + strings.Repeat("b", 64)
	var entropy [32]byte
	copy(entropy[:], bytes.Repeat([]byte{8}, 32))
	token, _, err := journal.CreateAdmissionInvite(entropy, recipient, sender, now.Add(time.Minute), now)
	if err != nil {
		t.Fatal(err)
	}
	for name, claim := range map[string]func() error{
		"bad encoding": func() error {
			_, err := journal.ClaimAdmissionInvite(token+"=", recipient, sender, "evt_"+strings.Repeat("c", 64), now)
			return err
		},
		"other recipient": func() error {
			_, err := journal.ClaimAdmissionInvite(token, "mep_"+strings.Repeat("d", 64), sender, "evt_"+strings.Repeat("c", 64), now)
			return err
		},
		"other sender": func() error {
			_, err := journal.ClaimAdmissionInvite(token, recipient, "agent_"+strings.Repeat("e", 64), "evt_"+strings.Repeat("c", 64), now)
			return err
		},
		"expired": func() error {
			_, err := journal.ClaimAdmissionInvite(token, recipient, sender, "evt_"+strings.Repeat("c", 64), now.Add(time.Minute))
			return err
		},
	} {
		t.Run(name, func(t *testing.T) {
			if err := claim(); err == nil {
				t.Fatal("invalid invite claim accepted")
			}
		})
	}
}
