package group

import (
	"bytes"
	"os"
	"testing"
	"time"

	"github.com/tosnetwork/tos-messenger/internal/canon"
)

func TestOpenMLSSidecarIntegrationThreeMemberRestartChat(t *testing.T) {
	binary := os.Getenv("TOS_OPENMLS_DRIVER")
	if binary == "" {
		t.Skip("TOS_OPENMLS_DRIVER is set by make test-openmls")
	}
	driver := &OpenMLSSidecar{Command: []string{binary}, Timeout: 10 * time.Second}
	alice, err := driver.NewIdentity([]byte("alice-authority"))
	if err != nil {
		t.Fatal(err)
	}
	bob, err := driver.NewIdentity([]byte("bob-authority"))
	if err != nil {
		t.Fatal(err)
	}
	charlie, err := driver.NewIdentity([]byte("charlie-authority"))
	if err != nil {
		t.Fatal(err)
	}
	if err := driver.ValidateKeyPackage(bob.KeyPackage, []byte("bob-authority"), bob.LeafSignaturePublicKey); err != nil {
		t.Fatalf("validate Bob: %v", err)
	}
	if err := driver.ValidateKeyPackage(bob.KeyPackage, []byte("charlie-authority"), bob.LeafSignaturePublicKey); err == nil {
		t.Fatal("authority-substituted KeyPackage accepted")
	}

	groupID := bytes.Repeat([]byte{0x42}, MLSGroupIDBytes)
	aliceState, err := driver.CreateGroup(alice.State, alice.KeyPackage, groupID)
	if err != nil {
		t.Fatal(err)
	}
	bobRef := canon.Digest(bob.KeyPackage)
	if _, _, _, err := driver.Commit(aliceState, []LeafOperation{{Kind: LeafAdd, Next: &Leaf{KeyPackageRef: bobRef, KeyPackage: bob.KeyPackage, CredentialIdentity: []byte("charlie-authority"), LeafSignaturePublicKey: bob.LeafSignaturePublicKey}}}); err == nil {
		t.Fatal("authority-substituted add operation accepted")
	}
	aliceState, commit1, welcomes1, err := driver.Commit(aliceState, []LeafOperation{{Kind: LeafAdd, Next: &Leaf{KeyPackageRef: bobRef, KeyPackage: bob.KeyPackage, CredentialIdentity: []byte("bob-authority"), LeafSignaturePublicKey: bob.LeafSignaturePublicKey}}})
	if err != nil {
		t.Fatal(err)
	}
	bobState, err := driver.Join(bob.State, welcomes1[bobRef])
	if err != nil {
		t.Fatal(err)
	}
	// A joiner must not apply the commit represented by its Welcome again.
	if _, err := driver.Apply(bobState, commit1); err == nil {
		t.Fatal("Welcome commit replay accepted")
	}

	charlieRef := canon.Digest(charlie.KeyPackage)
	aliceState, commit2, welcomes2, err := driver.Commit(aliceState, []LeafOperation{{Kind: LeafAdd, Next: &Leaf{KeyPackageRef: charlieRef, KeyPackage: charlie.KeyPackage, CredentialIdentity: []byte("charlie-authority"), LeafSignaturePublicKey: charlie.LeafSignaturePublicKey}}})
	if err != nil {
		t.Fatal(err)
	}
	bobState, err = driver.Apply(bobState, commit2)
	if err != nil {
		t.Fatalf("Bob apply Charlie commit: %v", err)
	}
	charlieState, err := driver.Join(charlie.State, welcomes2[charlieRef])
	if err != nil {
		t.Fatal(err)
	}

	aad := []byte("room + event + content binding")
	bobState, encrypted, err := driver.Seal(bobState, aad, []byte("hello from Bob after every sidecar process restarted"))
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := driver.Open(charlieState, []byte("wrong event"), encrypted); err == nil {
		t.Fatal("wrong authenticated data accepted")
	}
	charlieState, plaintext, err := driver.Open(charlieState, aad, encrypted)
	if err != nil {
		t.Fatal(err)
	}
	if string(plaintext) != "hello from Bob after every sidecar process restarted" {
		t.Fatalf("wrong plaintext: %q", plaintext)
	}
	if _, _, err := driver.Open(charlieState, aad, encrypted); err == nil {
		t.Fatal("application message replay accepted")
	}

	charlieState, reply, err := driver.Seal(charlieState, aad, []byte("Charlie replies to the founder"))
	if err != nil {
		t.Fatal(err)
	}
	_ = charlieState
	aliceState, plaintext, err = driver.Open(aliceState, aad, reply)
	if err != nil || string(plaintext) != "Charlie replies to the founder" {
		t.Fatalf("founder did not receive reply: %q %v", plaintext, err)
	}

	charlieV2, err := driver.NewIdentity([]byte("charlie-authority-v2"))
	if err != nil {
		t.Fatal(err)
	}
	charlieV2Ref := canon.Digest(charlieV2.KeyPackage)
	aliceState, replaceCommit, replacementWelcomes, err := driver.Commit(aliceState, []LeafOperation{{
		Kind:  LeafUpdate,
		Prior: &Leaf{CredentialIdentity: []byte("charlie-authority")},
		Next:  &Leaf{CredentialIdentity: []byte("charlie-authority-v2"), LeafSignaturePublicKey: charlieV2.LeafSignaturePublicKey, KeyPackageRef: charlieV2Ref, KeyPackage: charlieV2.KeyPackage},
	}})
	if err != nil {
		t.Fatalf("replace Charlie device: %v", err)
	}
	bobState, err = driver.Apply(bobState, replaceCommit)
	if err != nil {
		t.Fatalf("Bob apply replacement: %v", err)
	}
	if _, err := driver.Apply(charlieState, replaceCommit); err != nil {
		t.Fatalf("old Charlie apply own replacement: %v", err)
	}
	charlieV2State, err := driver.Join(charlieV2.State, replacementWelcomes[charlieV2Ref])
	if err != nil {
		t.Fatalf("new Charlie join: %v", err)
	}
	charlieV2State, reply, err = driver.Seal(charlieV2State, aad, []byte("replacement device is live"))
	if err != nil {
		t.Fatal(err)
	}
	aliceState, plaintext, err = driver.Open(aliceState, aad, reply)
	if err != nil || string(plaintext) != "replacement device is live" {
		t.Fatalf("replacement device failed: %q %v", plaintext, err)
	}

	aliceState, removeCommit, removeWelcomes, err := driver.Commit(aliceState, []LeafOperation{{Kind: LeafRemove, Prior: &Leaf{CredentialIdentity: []byte("bob-authority")}}})
	if err != nil || len(removeWelcomes) != 0 {
		t.Fatalf("remove Bob: welcomes=%d err=%v", len(removeWelcomes), err)
	}
	charlieV2State, err = driver.Apply(charlieV2State, removeCommit)
	if err != nil {
		t.Fatalf("Charlie apply removal: %v", err)
	}
	bobState, err = driver.Apply(bobState, removeCommit)
	if err != nil {
		t.Fatalf("Bob apply own removal: %v", err)
	}
	if _, _, err := driver.Seal(bobState, aad, []byte("removed member")); err == nil {
		t.Fatal("removed member could still send")
	}
	_, finalMessage, err := driver.Seal(aliceState, aad, []byte("room survives removal"))
	if err != nil {
		t.Fatal(err)
	}
	_, plaintext, err = driver.Open(charlieV2State, aad, finalMessage)
	if err != nil || string(plaintext) != "room survives removal" {
		t.Fatalf("remaining members failed after removal: %q %v", plaintext, err)
	}
}
