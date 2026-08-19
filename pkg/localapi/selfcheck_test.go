package localapi

import (
	"strings"
	"testing"

	"github.com/tosnetwork/tos-messenger/pkg/eventlog"
	"github.com/tosnetwork/tos-messenger/pkg/firewall"
	"github.com/tosnetwork/tos-messenger/pkg/negotiation"
)

func selfCheckTerms() *negotiation.Terms {
	return &negotiation.Terms{
		CapabilityID:           "cap_" + strings.Repeat("9", 64),
		CapabilityVersion:      "1.0.0",
		CapabilityClass:        "software.audit",
		ProviderAgentID:        "agent_" + strings.Repeat("5", 64),
		ManifestDigest:         "sha256:" + strings.Repeat("d", 64),
		TransportBindingDigest: "sha256:" + strings.Repeat("e", 64),
		Price: negotiation.Money{Asset: negotiation.Asset{
			Workchain: 0, AccountID: strings.Repeat("a", 64),
			MasterCodeHash: "tvm-cell-sha256:" + strings.Repeat("b", 64),
			WalletCodeHash: "tvm-cell-sha256:" + strings.Repeat("c", 64), Decimals: 6,
		}, Atomic: "100"},
		EscrowTermsDigest:   "sha256:" + strings.Repeat("f", 64),
		DisputePolicyDigest: "sha256:" + strings.Repeat("1", 64),
		NotAfterUnix:        1_800_000_000 + 3600,
	}
}

// The daemon's own check: a stored approval whose structured fields reproduce
// its identifier is presentable, and one whose summary was swapped for a gentler
// one -- while the identifier still commits the real action -- is not. This is
// what stops a runtime showing the owner a mild description of a harsher action.
func TestApprovalReproducesID(t *testing.T) {
	origins := []firewall.Origin{{
		AgentID: "agent_" + strings.Repeat("2", 64), EndpointID: "mep_" + strings.Repeat("3", 64),
		DeviceID: "dev_" + strings.Repeat("6", 64), EventID: "evt_" + strings.Repeat("4", 64),
		ConversationID: "conv_" + strings.Repeat("5", 64), Kind: "text", ReceivedAtUnix: 1_800_000_000,
	}}
	terms := selfCheckTerms()
	action := firewall.Action{
		Effect: firewall.EffectSpend, Summary: "pay 100 for an audit",
		DerivedFrom: origins, Terms: terms,
	}
	id, err := firewall.ActionID(action)
	if err != nil {
		t.Fatalf("action id: %v", err)
	}
	approval := eventlog.Approval{
		ActionID: id, Effect: string(firewall.EffectSpend), Summary: action.Summary,
		Origins: toApprovalOrigins(origins), Terms: terms,
	}
	if !approvalReproducesID(approval) {
		t.Fatal("a faithful record did not reproduce its own identifier")
	}

	// The runtime shows a gentle summary while the identifier still commits the
	// real one: the record no longer reproduces its identifier.
	tampered := approval
	tampered.Summary = "say hello"
	if approvalReproducesID(tampered) {
		t.Fatal("a swapped summary still reproduced the identifier")
	}

	// A swapped price is likewise caught: the terms are part of the identifier.
	cheaper := *terms
	cheaper.Price.Atomic = "1"
	priceTampered := approval
	priceTampered.Terms = &cheaper
	if approvalReproducesID(priceTampered) {
		t.Fatal("a swapped price still reproduced the identifier")
	}
}
