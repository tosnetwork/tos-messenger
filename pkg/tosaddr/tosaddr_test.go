package tosaddr

import (
	"strings"
	"testing"

	nativev1 "github.com/tosnetwork/tos-service-protocol/gen/tos/service/v1"
	"github.com/tosnetwork/tos-service-protocol/pkg/nativecore"
)

// A real, if trivial, contract code cell and the digest it hashes to.
const (
	codeBOC  = "te6cckEBAQEABwAACk1FU0cB2RT7gA=="
	codeHash = "tvm-cell-sha256:c42a36d160f60ec70926f63cb06d7429306e332b2e3752b275971ad628c0c9f1"
)

func testNetwork() *nativev1.NetworkDomain {
	return &nativev1.NetworkDomain{
		NetworkId:       "tos-local",
		GenesisRootHash: strings.Repeat("a", 64),
		GenesisFileHash: strings.Repeat("b", 64),
	}
}

func testAgent() string { return "agent_" + strings.Repeat("2", 64) }

// The address this package returns must be the one the protocol SDK computes.
// A second implementation of an addressing rule is a second implementation
// that can drift, and this test is what says there is only one.
func TestAddressMatchesTheProtocolSDK(t *testing.T) {
	locator, err := New(testNetwork(), []Registry{{CodeHash: codeHash, CodeBOC: codeBOC}})
	if err != nil {
		t.Fatalf("new: %v", err)
	}
	got, err := locator.Locate(codeHash, testAgent())
	if err != nil {
		t.Fatalf("locate: %v", err)
	}

	domain, err := normalize(testNetwork())
	if err != nil {
		t.Fatalf("normalize: %v", err)
	}
	reference, err := nativecore.NewLocator(domain, 0, codeBOC, codeHash)
	if err != nil {
		t.Fatalf("reference locator: %v", err)
	}
	identity, err := reference.Locate(testAgent())
	if err != nil {
		t.Fatalf("reference locate: %v", err)
	}
	if got != identity.Address {
		t.Fatalf("address %q does not match the SDK's %q", got, identity.Address)
	}
}

// The workchain is part of the address, so two registries that differ only in
// workchain must not resolve to the same account.
func TestWorkchainIsPartOfTheAddress(t *testing.T) {
	base, err := New(testNetwork(), []Registry{{CodeHash: codeHash, CodeBOC: codeBOC, Workchain: 0}})
	if err != nil {
		t.Fatalf("new: %v", err)
	}
	master, err := New(testNetwork(), []Registry{{CodeHash: codeHash, CodeBOC: codeBOC, Workchain: -1}})
	if err != nil {
		t.Fatalf("new: %v", err)
	}
	first, err := base.Locate(codeHash, testAgent())
	if err != nil {
		t.Fatalf("locate: %v", err)
	}
	second, err := master.Locate(codeHash, testAgent())
	if err != nil {
		t.Fatalf("locate: %v", err)
	}
	if first == second {
		t.Fatal("two workchains produced one address")
	}
}

func TestConfigurationErrorsAreRefused(t *testing.T) {
	cases := map[string][]Registry{
		"no registries": nil,
		"no code":       {{CodeHash: codeHash}},
		"no hash":       {{CodeBOC: codeBOC}},
		"code that does not hash to its pin": {{
			CodeHash: "tvm-cell-sha256:" + strings.Repeat("a", 64), CodeBOC: codeBOC,
		}},
		"duplicate registry": {
			{CodeHash: codeHash, CodeBOC: codeBOC},
			{CodeHash: codeHash, CodeBOC: codeBOC},
		},
	}
	for name, registries := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := New(testNetwork(), registries); err == nil {
				t.Fatalf("expected %q to be refused", name)
			}
		})
	}
	if _, err := New(nil, []Registry{{CodeHash: codeHash, CodeBOC: codeBOC}}); err == nil {
		t.Fatal("a locator without a network was accepted")
	}
}

// An unrecognised registry code must be an error, not an address computed
// under some other contract.
func TestUnknownRegistryIsRefused(t *testing.T) {
	locator, err := New(testNetwork(), []Registry{{CodeHash: codeHash, CodeBOC: codeBOC}})
	if err != nil {
		t.Fatalf("new: %v", err)
	}
	if _, err := locator.Locate("tvm-cell-sha256:"+strings.Repeat("f", 64), testAgent()); err == nil {
		t.Fatal("an unknown registry produced an address")
	}
	var absent *Locator
	if _, err := absent.Locate(codeHash, testAgent()); err == nil {
		t.Fatal("a nil locator produced an address")
	}
}
