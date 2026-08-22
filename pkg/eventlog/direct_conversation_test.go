package eventlog

import (
	"errors"
	"os"
	"strings"
	"testing"
	"time"
)

func TestDirectConversationPinsAgentIdentityAcrossRetryRotationAndRestart(t *testing.T) {
	root := t.TempDir() + "/state"
	journal, err := Open(root)
	if err != nil {
		t.Fatal(err)
	}
	local := "agent_" + strings.Repeat("1", 64)
	remoteA := "agent_" + strings.Repeat("2", 64)
	remoteB := "agent_" + strings.Repeat("3", 64)
	endpointA1 := "mep_" + strings.Repeat("4", 64)
	endpointA2 := "mep_" + strings.Repeat("5", 64)
	endpointB := "mep_" + strings.Repeat("6", 64)
	now := time.Unix(1_800_000_000, 0)

	first, created, err := journal.EnsureDirectConversation(local, remoteA, endpointA1, 100, now, [32]byte{1})
	if err != nil || !created || first.RemoteAgentID != remoteA || first.VerifiedRemoteEndpointID != endpointA1 ||
		first.State != DirectConversationDiscovered {
		t.Fatalf("first ensure: record=%+v created=%v err=%v", first, created, err)
	}
	retry, created, err := journal.EnsureDirectConversation(local, remoteA, endpointA1, 100, now, [32]byte{2})
	if err != nil || created || retry.ConversationID != first.ConversationID {
		t.Fatalf("retry replaced conversation: record=%+v created=%v err=%v", retry, created, err)
	}
	rotated, created, err := journal.EnsureDirectConversation(
		local, remoteA, endpointA2, 101, now.Add(time.Second), [32]byte{3},
	)
	if err != nil || created || rotated.ConversationID != first.ConversationID ||
		rotated.VerifiedRemoteEndpointID != endpointA2 {
		t.Fatalf("rotation changed identity: record=%+v created=%v err=%v", rotated, created, err)
	}
	transferred, created, err := journal.EnsureDirectConversation(
		local, remoteB, endpointB, 102, now.Add(2*time.Second), [32]byte{4},
	)
	if err != nil || !created || transferred.ConversationID == first.ConversationID {
		t.Fatalf("new Agent reused old conversation: record=%+v created=%v err=%v", transferred, created, err)
	}
	if err := journal.Close(); err != nil {
		t.Fatal(err)
	}

	reopened, err := Open(root)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	restored, found, err := reopened.DirectConversation(local, remoteA)
	if err != nil || !found || restored.ConversationID != first.ConversationID ||
		restored.RemoteAgentID != remoteA || restored.VerifiedRemoteEndpointID != endpointA2 {
		t.Fatalf("restart lost pinned conversation: record=%+v found=%v err=%v", restored, found, err)
	}
}

func TestDirectConversationRejectsRollbackSubstitutionAndCorruption(t *testing.T) {
	journal, err := Open(t.TempDir() + "/state")
	if err != nil {
		t.Fatal(err)
	}
	defer journal.Close()
	local := "agent_" + strings.Repeat("1", 64)
	remote := "agent_" + strings.Repeat("2", 64)
	endpoint := "mep_" + strings.Repeat("3", 64)
	now := time.Unix(1_800_000_000, 0)
	if _, _, err := journal.EnsureDirectConversation(local, remote, endpoint, 100, now, [32]byte{1}); err != nil {
		t.Fatal(err)
	}
	if _, _, err := journal.EnsureDirectConversation(
		local, remote, endpoint, 99, now.Add(time.Second), [32]byte{2},
	); !errors.Is(err, ErrDirectConversationRollback) {
		t.Fatalf("checkpoint rollback error=%v", err)
	}
	if _, _, err := journal.EnsureDirectConversation(
		local, remote, "mep_"+strings.Repeat("4", 64), 100, now.Add(time.Second), [32]byte{2},
	); !errors.Is(err, ErrConflict) {
		t.Fatalf("same-checkpoint endpoint substitution error=%v", err)
	}
	if _, _, err := journal.EnsureDirectConversation(local, local, endpoint, 101, now, [32]byte{2}); err == nil {
		t.Fatal("self conversation was accepted")
	}
	if _, _, err := journal.EnsureDirectConversation(local, "agent_"+strings.Repeat("5", 64), endpoint, 101, now, [32]byte{}); err == nil {
		t.Fatal("zero conversation entropy was accepted")
	}
	if _, _, err := journal.DirectConversation("agent_"+strings.Repeat("6", 64), remote); err == nil {
		t.Fatal("conversation was readable under another local Agent")
	}
	path := journal.directConversationPath(remote)
	if err := os.WriteFile(path, []byte("{\"schema\":\"unknown\"}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := journal.DirectConversation(local, remote); err == nil {
		t.Fatal("corrupt direct conversation was accepted")
	}
}
