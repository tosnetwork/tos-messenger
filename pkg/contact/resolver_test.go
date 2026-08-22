package contact

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/tosnetwork/tos-messenger/pkg/directory"
	"github.com/tosnetwork/tos-messenger/pkg/identity"
	nativev1 "github.com/tosnetwork/tos-service-protocol/gen/tos/service/v1"
	"google.golang.org/protobuf/proto"
)

const testCodeHash = "tvm-cell-sha256:abababababababababababababababababababababababababababababababab"

type aliasClient struct {
	responses []*nativev1.ResolveDNSAliasResponse
	requests  []*nativev1.ResolveDNSAliasRequest
	err       error
}

func (c *aliasClient) ResolveDNSAlias(_ context.Context, request *nativev1.ResolveDNSAliasRequest) (*nativev1.ResolveDNSAliasResponse, error) {
	c.requests = append(c.requests, proto.Clone(request).(*nativev1.ResolveDNSAliasRequest))
	if c.err != nil {
		return nil, c.err
	}
	if len(c.responses) == 0 {
		return nil, errors.New("no response")
	}
	response := c.responses[0]
	c.responses = c.responses[1:]
	return proto.Clone(response).(*nativev1.ResolveDNSAliasResponse), nil
}

type contactDirectory struct {
	calls    []string
	mismatch bool
	err      error
}

func (d *contactDirectory) Ensure(_ context.Context, agentID string) (directory.RefreshResult, error) {
	d.calls = append(d.calls, agentID)
	if d.err != nil {
		return directory.RefreshResult{}, d.err
	}
	if d.mismatch {
		agentID = "agent_" + strings.Repeat("f", 64)
	}
	return directory.RefreshResult{Delegation: identity.Delegation{AgentID: agentID}}, nil
}

type accountLocator map[string]string

func (l accountLocator) Locate(_ string, objectID string) (string, error) {
	account, found := l[objectID]
	if !found {
		return "", errors.New("unknown object")
	}
	return account, nil
}

func TestResolveDNSContactRunsExistingDirectoryChain(t *testing.T) {
	now := testNow()
	agentID := testAgent("a")
	response, account := testDNSResponse(agentID, now)
	client := &aliasClient{responses: []*nativev1.ResolveDNSAliasResponse{response}}
	directory := &contactDirectory{}
	resolver := testResolver(client, directory, map[string]string{agentID: account}, now)

	result, err := resolver.Resolve(context.Background(), "Alice.TOS")
	if err != nil {
		t.Fatalf("resolve DNS contact: %v", err)
	}
	if result.AgentID != agentID || result.CanonicalName != "alice.tos" || result.Directory.Delegation.AgentID != agentID {
		t.Fatalf("unexpected result: %+v", result)
	}
	if len(directory.calls) != 1 || directory.calls[0] != agentID {
		t.Fatalf("directory did not receive only the resolved Agent ID: %v", directory.calls)
	}
	if len(client.requests) != 1 {
		t.Fatalf("DNS request count = %d", len(client.requests))
	}
	request := client.requests[0]
	if request.Name != "alice.tos" || request.Kind != nativev1.DNSAliasKindV1_DNS_ALIAS_KIND_V1_MESSENGER ||
		request.Context == nil || request.Context.CallerId != "messenger-test" ||
		request.Context.DeadlineUnixMillis != now.Add(dnsRequestTimeout).UnixMilli() ||
		!strings.HasPrefix(request.Context.RequestId, "dns_") {
		t.Fatalf("unexpected DNS request: %+v", request)
	}
}

func TestResolveAgentIDNeverUsesDNS(t *testing.T) {
	agentID := testAgent("b")
	client := &aliasClient{err: errors.New("DNS must not be called")}
	directory := &contactDirectory{}
	resolver := &Resolver{DNS: client, Directory: directory}

	result, err := resolver.Resolve(context.Background(), agentID)
	if err != nil {
		t.Fatalf("resolve Agent contact: %v", err)
	}
	if result.AgentID != agentID || result.CanonicalName != "" || len(client.requests) != 0 {
		t.Fatalf("Agent input crossed DNS boundary: result=%+v requests=%d", result, len(client.requests))
	}
}

func TestResolveDNSContactRejectsUnsafeEvidence(t *testing.T) {
	now := testNow()
	agentID := testAgent("c")
	base, account := testDNSResponse(agentID, now)
	tests := []struct {
		name   string
		mutate func(*nativev1.ResolveDNSAliasResponse)
	}{
		{"non-quorum provenance", func(r *nativev1.ResolveDNSAliasResponse) { r.Provenance = 0 }},
		{"wrong category", func(r *nativev1.ResolveDNSAliasResponse) { r.CategoryHash = strings.Repeat("0", 64) }},
		{"wrong kind", func(r *nativev1.ResolveDNSAliasResponse) { r.Kind = nativev1.DNSAliasKindV1_DNS_ALIAS_KIND_V1_AGENT }},
		{"active or unsettled auction", func(r *nativev1.ResolveDNSAliasResponse) { r.Lifecycle.AuctionEndUnixSeconds = 1 }},
		{"overdue", func(r *nativev1.ResolveDNSAliasResponse) {
			r.Lifecycle.RenewalDeadlineUnixSeconds = uint64(now.Unix() - 1)
		}},
		{"resolver cycle", func(r *nativev1.ResolveDNSAliasResponse) {
			r.ResolverPath[2] = proto.Clone(r.ResolverPath[1]).(*nativev1.TOSAccountAddressV1)
		}},
		{"ninth resolver hop", func(r *nativev1.ResolveDNSAliasResponse) {
			for len(r.ResolverPath) < 9 {
				r.ResolverPath = append(r.ResolverPath, &nativev1.TOSAccountAddressV1{Workchain: 0, AccountId: bytes32(byte(len(r.ResolverPath) + 20))})
			}
		}},
		{"checkpoint mismatch", func(r *nativev1.ResolveDNSAliasResponse) { r.NativeState.Reference.FinalizedCheckpoint++ }},
		{"wrong network", func(r *nativev1.ResolveDNSAliasResponse) { r.NativeState.Network.NetworkId = "other" }},
		{"tombstoned Agent", func(r *nativev1.ResolveDNSAliasResponse) { r.NativeState.GetAgent().Tombstoned = true }},
		{"wrong Agent", func(r *nativev1.ResolveDNSAliasResponse) { r.NativeState.GetAgent().AgentId = testAgent("d") }},
		{"account provenance mismatch", func(r *nativev1.ResolveDNSAliasResponse) {
			r.NativeState.Reference.Account = "0:" + strings.Repeat("e", 64)
		}},
		{"wrong deterministic account", func(r *nativev1.ResolveDNSAliasResponse) {
			r.ResolvedAccount.AccountId = bytes32('e')
			r.NativeState.Reference.Account = "0:" + hex.EncodeToString(r.ResolvedAccount.AccountId)
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			response := proto.Clone(base).(*nativev1.ResolveDNSAliasResponse)
			test.mutate(response)
			client := &aliasClient{responses: []*nativev1.ResolveDNSAliasResponse{response}}
			directory := &contactDirectory{}
			resolver := testResolver(client, directory, map[string]string{agentID: account}, now)
			if _, err := resolver.Resolve(context.Background(), "alice.tos"); err == nil {
				t.Fatal("unsafe DNS evidence was accepted")
			}
			if len(directory.calls) != 0 {
				t.Fatalf("unsafe evidence reached directory: %v", directory.calls)
			}
		})
	}
}

func TestResolveDNSContactExpiryBoundaryAndTransfer(t *testing.T) {
	now := testNow()
	firstID, secondID := testAgent("1"), testAgent("2")
	first, firstAccount := testDNSResponse(firstID, now)
	first.Lifecycle.LastFillUpUnixSeconds = uint64(now.Unix()) - dnsLeaseSeconds
	first.Lifecycle.RenewalDeadlineUnixSeconds = uint64(now.Unix())
	second, secondAccount := testDNSResponse(secondID, now)
	client := &aliasClient{responses: []*nativev1.ResolveDNSAliasResponse{first, second}}
	directory := &contactDirectory{}
	resolver := testResolver(client, directory, map[string]string{firstID: firstAccount, secondID: secondAccount}, now)

	firstResult, err := resolver.Resolve(context.Background(), "alice.tos")
	if err != nil {
		t.Fatalf("exact renewal deadline must remain live: %v", err)
	}
	secondResult, err := resolver.Resolve(context.Background(), "alice.tos")
	if err != nil {
		t.Fatalf("resolve transferred name: %v", err)
	}
	if firstResult.AgentID != firstID || secondResult.AgentID != secondID ||
		len(directory.calls) != 2 || directory.calls[0] != firstID || directory.calls[1] != secondID {
		t.Fatalf("name transfer did not create separate ID-bound resolutions: first=%s second=%s calls=%v",
			firstResult.AgentID, secondResult.AgentID, directory.calls)
	}
}

func TestResolveDNSContactFailsClosedOnDirectorySubstitution(t *testing.T) {
	now := testNow()
	agentID := testAgent("3")
	response, account := testDNSResponse(agentID, now)
	resolver := testResolver(&aliasClient{responses: []*nativev1.ResolveDNSAliasResponse{response}},
		&contactDirectory{mismatch: true}, map[string]string{agentID: account}, now)
	if _, err := resolver.Resolve(context.Background(), "alice.tos"); err == nil {
		t.Fatal("another Agent's directory result was accepted")
	}
}

func testResolver(client DNSAliasClient, directory Directory, accounts map[string]string, now time.Time) *Resolver {
	return &Resolver{
		DNS: client, Directory: directory, Network: testContactNetwork(), CallerID: "messenger-test",
		Chain: identity.ChainPolicy{RegistryCodeHashes: []string{testCodeHash}, Locator: accountLocator(accounts)},
		Now:   func() time.Time { return now }, random: strings.NewReader(strings.Repeat("r", 64)),
	}
}

func testDNSResponse(agentID string, now time.Time) (*nativev1.ResolveDNSAliasResponse, string) {
	accountBytes := bytes32(agentID[len(agentID)-1])
	account := "0:" + hex.EncodeToString(accountBytes)
	category := sha256.Sum256([]byte("messenger"))
	deadline := uint64(now.Unix()) + dnsLeaseSeconds
	return &nativev1.ResolveDNSAliasResponse{
		CanonicalName: "alice.tos", Kind: nativev1.DNSAliasKindV1_DNS_ALIAS_KIND_V1_MESSENGER,
		CategoryHash:    hex.EncodeToString(category[:]),
		ResolvedAccount: &nativev1.TOSAccountAddressV1{Workchain: 0, AccountId: accountBytes},
		NativeObjectId:  agentID,
		NativeState: &nativev1.NativeStateV1{
			Network:      &nativev1.NetworkDomain{NetworkId: "tos-test", GenesisRootHash: "sha256:" + strings.Repeat("a", 64), GenesisFileHash: "sha256:" + strings.Repeat("b", 64)},
			TvmStateHash: "tvm-cell-sha256:" + strings.Repeat("c", 64),
			Reference:    &nativev1.ChainReference{Workchain: 0, Account: account, TransactionHash: "sha256:" + strings.Repeat("d", 64), ContractCodeHash: testCodeHash, FinalizedCheckpoint: 42},
			State:        &nativev1.NativeStateV1_Agent{Agent: &nativev1.AgentStateV1{AgentId: agentID, Policy: &nativev1.ControllerPolicyV1{}}},
		},
		Checkpoint: &nativev1.DNSCheckpointV1{Workchain: -1, Shard: -1, Sequence: 42, RootHash: bytes32(7), FileHash: bytes32(8), GenerationUnixSeconds: uint64(now.Unix())},
		Lifecycle:  &nativev1.DNSLifecycleV1{LastFillUpUnixSeconds: uint64(now.Unix()), RenewalDeadlineUnixSeconds: deadline},
		Provenance: nativev1.DNSProvenanceV1_DNS_PROVENANCE_V1_QUORUM_AGREED,
		ResolverPath: []*nativev1.TOSAccountAddressV1{
			{Workchain: -1, AccountId: bytes32(1)},
			{Workchain: 0, AccountId: bytes32(2)},
			{Workchain: 0, AccountId: bytes32(3)},
		},
	}, account
}

func testContactNetwork() *nativev1.NetworkDomain {
	return &nativev1.NetworkDomain{NetworkId: "tos-test", GenesisRootHash: strings.Repeat("a", 64), GenesisFileHash: strings.Repeat("b", 64)}
}

func testNow() time.Time { return time.Unix(int64(dnsLeaseSeconds)+2_000, 0) }

func testAgent(value string) string { return "agent_" + strings.Repeat(value, 64) }

func bytes32(value byte) []byte { return bytesRepeat(value, 32) }

func bytesRepeat(value byte, count int) []byte {
	result := make([]byte, count)
	for index := range result {
		result[index] = value
	}
	return result
}
