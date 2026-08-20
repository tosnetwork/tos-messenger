package directory

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/tosnetwork/tos-messenger/pkg/identity"
)

func TestFileDelegationsReloadsPinnedAgentDocument(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "peer.json")
	policyPath := filepath.Join(root, "policy.json")
	first := testDelegation(t, endpointKey(t, 0x11))
	writeDelegationFile(t, path, first)
	writePolicyFile(t, policyPath, testPolicy())
	source, err := NewFileDelegations([]DelegationFile{{AgentID: first.AgentID, Path: path, DescriptorPolicyPath: policyPath}})
	if err != nil {
		t.Fatal(err)
	}
	raw, err := source.Delegation(context.Background(), first.AgentID)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := identity.DecodeJSON(raw)
	if err != nil || decoded.EndpointID != first.EndpointID {
		t.Fatalf("decoded=%+v err=%v", decoded, err)
	}

	rotated := testDelegation(t, endpointKey(t, 0x22))
	writeDelegationFile(t, path, rotated)
	raw, err = source.Delegation(context.Background(), first.AgentID)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err = identity.DecodeJSON(raw)
	if err != nil || decoded.EndpointID != rotated.EndpointID {
		t.Fatalf("rotation was not reloaded: %+v err=%v", decoded, err)
	}
}

func TestFileDelegationsFailsClosed(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "peer.json")
	policyPath := filepath.Join(root, "policy.json")
	delegation := testDelegation(t, endpointKey(t, 0x11))
	writeDelegationFile(t, path, delegation)
	writePolicyFile(t, policyPath, testPolicy())
	source, err := NewFileDelegations([]DelegationFile{{AgentID: delegation.AgentID, Path: path, DescriptorPolicyPath: policyPath}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := source.Delegation(context.Background(), "agent_"+strings.Repeat("9", 64)); err == nil {
		t.Fatal("accepted unprovisioned Agent")
	}
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := source.Delegation(canceled, delegation.AgentID); err == nil {
		t.Fatal("ignored canceled context")
	}
	foreign := delegation
	foreign.AgentID = "agent_" + strings.Repeat("8", 64)
	foreign.EndpointID, err = identity.DeriveEndpointID(foreign.Network, foreign.AgentID, foreign.IdentityPublicKey)
	if err != nil {
		t.Fatal(err)
	}
	writeDelegationFile(t, path, foreign)
	if _, err := source.Delegation(context.Background(), delegation.AgentID); err == nil {
		t.Fatal("accepted another Agent's document")
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(root, "target"), path); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "target"), []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := source.Delegation(context.Background(), delegation.AgentID); err == nil {
		t.Fatal("followed peer delegation symlink")
	}
	writeDelegationFile(t, path, delegation)
	wrongPolicy := testPolicy()
	wrongPolicy.MaxLifetimeSeconds--
	writePolicyFile(t, policyPath, wrongPolicy)
	if _, err := source.DescriptorPolicy(context.Background(), delegation); err == nil {
		t.Fatal("accepted a policy outside the delegation commitment")
	}
}

func TestFileDelegationConfigurationIsBounded(t *testing.T) {
	agent := "agent_" + strings.Repeat("2", 64)
	path := "/etc/tos-messengerd/peers/peer.json"
	policyPath := "/etc/tos-messengerd/peers/peer-policy.json"
	for name, files := range map[string][]DelegationFile{
		"empty":           nil,
		"bad agent":       {{AgentID: "agent_bad", Path: path, DescriptorPolicyPath: policyPath}},
		"relative":        {{AgentID: agent, Path: "peer.json", DescriptorPolicyPath: policyPath}},
		"relative policy": {{AgentID: agent, Path: path, DescriptorPolicyPath: "policy.json"}},
		"duplicate":       {{AgentID: agent, Path: path, DescriptorPolicyPath: policyPath}, {AgentID: agent, Path: path + ".2", DescriptorPolicyPath: policyPath + ".2"}},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := NewFileDelegations(files); err == nil {
				t.Fatal("accepted invalid configuration")
			}
		})
	}
}

func writePolicyFile(t *testing.T, path string, policy DescriptorPolicy) {
	t.Helper()
	raw, err := EncodeDescriptorPolicyJSON(policy)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
}

func writeDelegationFile(t *testing.T, path string, delegation identity.Delegation) {
	t.Helper()
	raw, err := identity.EncodeJSON(delegation)
	if err != nil {
		t.Fatal(err)
	}
	temporary := path + ".new"
	if err := os.WriteFile(temporary, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(temporary, path); err != nil {
		t.Fatal(err)
	}
}
