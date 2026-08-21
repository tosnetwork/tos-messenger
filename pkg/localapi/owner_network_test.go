package localapi

import (
	"bytes"
	"strings"
	"testing"
)

func TestMandateDecisionCommitsTheCompleteNetworkIdentity(t *testing.T) {
	request := Request{
		Op:        OpPlaceMandate,
		Challenge: strings.Repeat("a", 64),
		Mandate: &MandateTerms{
			Objective: "buy inference", Authority: "agent", CapabilityClass: "inference",
			Asset: AssetIdentity{
				NetworkID: "tos-mainnet", GenesisRootHash: strings.Repeat("b", 64),
				GenesisFileHash: strings.Repeat("c", 64), Workchain: -1,
				AccountID: strings.Repeat("d", 64), MasterCodeHash: strings.Repeat("e", 64),
				WalletCodeHash: strings.Repeat("f", 64), Decimals: 9,
			},
			MaxTotalAtomic: "100", ApprovalAboveAtomic: "10", MaxCounteroffers: 2, ExpiresAtUnix: 1_900_000_000,
		},
	}
	original, err := DecisionBytes(request, request.Challenge)
	if err != nil {
		t.Fatal(err)
	}
	mutations := map[string]func(*AssetIdentity){
		"network":      func(asset *AssetIdentity) { asset.NetworkID = "tos-testnet" },
		"genesis root": func(asset *AssetIdentity) { asset.GenesisRootHash = strings.Repeat("0", 64) },
		"genesis file": func(asset *AssetIdentity) { asset.GenesisFileHash = strings.Repeat("1", 64) },
	}
	for name, mutate := range mutations {
		t.Run(name, func(t *testing.T) {
			changed := request
			terms := *request.Mandate
			changed.Mandate = &terms
			mutate(&changed.Mandate.Asset)
			encoded, err := DecisionBytes(changed, changed.Challenge)
			if err != nil {
				t.Fatal(err)
			}
			if bytes.Equal(original, encoded) {
				t.Fatal("network identity substitution retained the owner signature preimage")
			}
		})
	}
	bad := request
	badTerms := *request.Mandate
	bad.Mandate = &badTerms
	bad.Mandate.Asset.GenesisRootHash = "sha256:" + strings.Repeat("b", 64)
	if _, err := DecisionBytes(bad, bad.Challenge); err == nil {
		t.Fatal("SDK-prefixed genesis hash accepted in an owner preimage")
	}
}

func TestAdmissionInviteDecisionCommitsScopeAndExpiry(t *testing.T) {
	request := Request{
		Op: OpCreateAdmissionInvite, Challenge: strings.Repeat("a", 64),
		InvitedAgentID: "agent_" + strings.Repeat("b", 64), InviteExpiresAtUnix: 1_900_000_000,
	}
	original, err := DecisionBytes(request, request.Challenge)
	if err != nil {
		t.Fatal(err)
	}
	changedAgent := request
	changedAgent.InvitedAgentID = "agent_" + strings.Repeat("c", 64)
	changedExpiry := request
	changedExpiry.InviteExpiresAtUnix++
	for name, changed := range map[string]Request{"agent": changedAgent, "expiry": changedExpiry} {
		encoded, err := DecisionBytes(changed, changed.Challenge)
		if err != nil {
			t.Fatal(err)
		}
		if bytes.Equal(original, encoded) {
			t.Fatalf("%s substitution retained owner signature preimage", name)
		}
	}
}

func TestEscrowLocationDecisionCommitsEveryFundingBinding(t *testing.T) {
	request := Request{Op: OpRecordEscrowLocation, Challenge: strings.Repeat("a", 64),
		QuoteCommitment: "tvm-cell-sha256:" + strings.Repeat("b", 64),
		EscrowAddress:   "0:" + strings.Repeat("c", 64), CapabilityClass: "software.audit"}
	original, err := DecisionBytes(request, request.Challenge)
	if err != nil {
		t.Fatal(err)
	}
	mutations := map[string]Request{}
	changed := request
	changed.QuoteCommitment = "tvm-cell-sha256:" + strings.Repeat("d", 64)
	mutations["commitment"] = changed
	changed = request
	changed.EscrowAddress = "0:" + strings.Repeat("e", 64)
	mutations["escrow"] = changed
	changed = request
	changed.CapabilityClass = "software.build"
	mutations["class"] = changed
	for name, mutation := range mutations {
		encoded, err := DecisionBytes(mutation, mutation.Challenge)
		if err != nil {
			t.Fatal(err)
		}
		if bytes.Equal(original, encoded) {
			t.Fatalf("%s substitution retained owner signature preimage", name)
		}
	}
}
