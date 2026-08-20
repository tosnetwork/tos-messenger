package eventlog

import (
	"bytes"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/tosnetwork/tos-messenger/internal/canon"
	"github.com/tosnetwork/tos-messenger/pkg/group"
	"github.com/tosnetwork/tos-messenger/pkg/room"
)

func TestOpenMLSControllerIntegrationPersistsBeforeRestartChat(t *testing.T) {
	binary := os.Getenv("TOS_OPENMLS_DRIVER")
	if binary == "" {
		t.Skip("TOS_OPENMLS_DRIVER is set by make test-openmls")
	}
	driver := &group.OpenMLSSidecar{Command: []string{binary}, Timeout: 10 * time.Second}
	alice, err := driver.NewIdentity([]byte("alice-controller"))
	if err != nil {
		t.Fatal(err)
	}
	bob, err := driver.NewIdentity([]byte("bob-controller"))
	if err != nil {
		t.Fatal(err)
	}
	charlie, err := driver.NewIdentity([]byte("charlie-controller"))
	if err != nil {
		t.Fatal(err)
	}

	membership, err := room.Found("room_"+strings.Repeat("9", 64), []string{"agent_" + strings.Repeat("a", 64), "agent_" + strings.Repeat("b", 64), "agent_" + strings.Repeat("c", 64)})
	if err != nil {
		t.Fatal(err)
	}
	founder := group.State{RoomID: membership.RoomID, Clock: group.Clock{RoomEpoch: 1, MLSEpoch: 0}, MembershipDigest: membership.Digest}
	groupID := bytes.Repeat([]byte{0x73}, group.MLSGroupIDBytes)
	roots := []string{t.TempDir() + "/alice", t.TempDir() + "/bob", t.TempDir() + "/charlie"}
	journals := make([]*Journal, 3)
	controllers := make([]*MLSController, 3)
	for i := range journals {
		journals[i], err = Open(roots[i])
		if err != nil {
			t.Fatal(err)
		}
		ledger, openErr := journals[i].OpenMLS()
		if openErr != nil {
			t.Fatal(openErr)
		}
		controllers[i], err = NewMLSController(ledger, driver, func() time.Time { return time.Unix(1000, 0) })
		if err != nil {
			t.Fatal(err)
		}
	}
	if err := controllers[0].CreateFounder(founder, alice.State, alice.KeyPackage, groupID, canon.Digest(alice.KeyPackage)); err != nil {
		t.Fatal(err)
	}

	bobRef := canon.Digest(bob.KeyPackage)
	template1 := group.Transition{Prior: founder, Next: group.State{RoomID: founder.RoomID, Clock: group.Clock{RoomEpoch: 1, MLSEpoch: 1}, MembershipDigest: founder.MembershipDigest}}
	transition1, _, welcomes1, err := controllers[0].Commit(template1, []group.LeafOperation{{Kind: group.LeafAdd, Next: &group.Leaf{CredentialIdentity: []byte("bob-controller"), LeafSignaturePublicKey: bob.LeafSignaturePublicKey, KeyPackageRef: bobRef, KeyPackage: bob.KeyPackage}}})
	if err != nil {
		t.Fatal(err)
	}
	if err := controllers[1].Join(transition1.Next, groupID, bob.State, welcomes1[bobRef], bobRef); err != nil {
		t.Fatal(err)
	}

	charlieRef := canon.Digest(charlie.KeyPackage)
	template2 := group.Transition{Prior: transition1.Next, Next: group.State{RoomID: founder.RoomID, Clock: group.Clock{RoomEpoch: 1, MLSEpoch: 2}, MembershipDigest: founder.MembershipDigest}}
	transition2, commit2, welcomes2, err := controllers[0].Commit(template2, []group.LeafOperation{{Kind: group.LeafAdd, Next: &group.Leaf{CredentialIdentity: []byte("charlie-controller"), LeafSignaturePublicKey: charlie.LeafSignaturePublicKey, KeyPackageRef: charlieRef, KeyPackage: charlie.KeyPackage}}})
	if err != nil {
		t.Fatal(err)
	}
	if err := controllers[1].Apply(transition2, commit2); err != nil {
		t.Fatal(err)
	}
	if err := controllers[2].Join(transition2.Next, groupID, charlie.State, welcomes2[charlieRef], charlieRef); err != nil {
		t.Fatal(err)
	}
	template3 := group.Transition{Prior: transition2.Next, Next: group.State{RoomID: founder.RoomID, Clock: group.Clock{RoomEpoch: 1, MLSEpoch: 3}, MembershipDigest: founder.MembershipDigest}}
	transition3, refreshCommit, refreshWelcomes, err := controllers[0].Commit(template3, nil)
	if err != nil || len(refreshWelcomes) != 0 {
		t.Fatalf("persist PCS refresh: welcomes=%d err=%v", len(refreshWelcomes), err)
	}
	if err := controllers[1].Apply(transition3, refreshCommit); err != nil {
		t.Fatal(err)
	}
	if err := controllers[2].Apply(transition3, refreshCommit); err != nil {
		t.Fatal(err)
	}

	aad := []byte("durable room/event/content binding")
	message, err := controllers[1].Seal(founder.RoomID, aad, []byte("persist before publishing this ciphertext"))
	if err != nil {
		t.Fatal(err)
	}
	for _, journal := range journals {
		if err := journal.Close(); err != nil {
			t.Fatal(err)
		}
	}

	for i := range journals {
		journals[i], err = Open(roots[i])
		if err != nil {
			t.Fatal(err)
		}
		defer journals[i].Close()
		ledger, _ := journals[i].OpenMLS()
		controllers[i], err = NewMLSController(ledger, driver, func() time.Time { return time.Unix(1001, 0) })
		if err != nil {
			t.Fatal(err)
		}
	}
	plaintext, err := controllers[2].Open(founder.RoomID, aad, message)
	if err != nil || string(plaintext) != "persist before publishing this ciphertext" {
		t.Fatalf("post-restart receive: %q %v", plaintext, err)
	}
	reply, err := controllers[2].Seal(founder.RoomID, aad, []byte("restart-safe reply"))
	if err != nil {
		t.Fatal(err)
	}
	plaintext, err = controllers[0].Open(founder.RoomID, aad, reply)
	if err != nil || string(plaintext) != "restart-safe reply" {
		t.Fatalf("post-restart reply: %q %v", plaintext, err)
	}
}
