// Package contact owns the human-input boundary for Messenger contacts.
// A DNS name is discovery metadata only: it is reduced to a finalized Agent
// identifier before the existing delegation, DHT, Descriptor, and prekey
// verification pipeline is entered.
package contact

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/tosnetwork/tos-messenger/pkg/directory"
	"github.com/tosnetwork/tos-messenger/pkg/identity"
	nativev1 "github.com/tosnetwork/tos-service-protocol/gen/tos/service/v1"
	"google.golang.org/protobuf/proto"
)

const (
	dnsRequestTimeout = 30 * time.Second
	dnsLeaseSeconds   = uint64(31_622_400)
)

// DNSAliasClient is the narrow, read-only DNS Connect method Messenger uses.
type DNSAliasClient interface {
	ResolveDNSAlias(context.Context, *nativev1.ResolveDNSAliasRequest) (*nativev1.ResolveDNSAliasResponse, error)
}

// Directory resolves the Agent identifier through Messenger's existing
// finalized delegation -> DHT locator -> Contact Descriptor -> prekey chain.
type Directory interface {
	Ensure(context.Context, string) (directory.RefreshResult, error)
}

// Result contains the identity-bound contact snapshot. CanonicalName is only
// display metadata and is empty when the input was already an Agent identifier.
// Callers must persist and authorize AgentID, never CanonicalName.
type Result struct {
	AgentID       string
	CanonicalName string
	Directory     directory.RefreshResult
}

// Resolver accepts either an Agent identifier or a .tos contact name. DNS is
// never consulted for an Agent identifier and DNS answers are deliberately not
// cached here, so a later name transfer cannot rewrite an existing ID-bound
// contact or session.
type Resolver struct {
	DNS       DNSAliasClient
	Directory Directory
	Network   *nativev1.NetworkDomain
	Chain     identity.ChainPolicy
	CallerID  string
	Now       func() time.Time

	random io.Reader
}

// Resolve reduces input to an Agent identifier and then executes the ordinary
// Messenger directory verification chain. Uppercase ASCII in a human-entered
// DNS name is normalized; leading or trailing whitespace remains an error.
func (r *Resolver) Resolve(ctx context.Context, input string) (Result, error) {
	if r == nil || ctx == nil || r.Directory == nil {
		return Result{}, errors.New("contact: resolver is incomplete")
	}
	if identity.AgentPattern.MatchString(input) {
		return r.ensure(ctx, input, "")
	}
	if r.DNS == nil || r.Network == nil || r.CallerID == "" {
		return Result{}, errors.New("contact: DNS resolver is incomplete")
	}
	if err := r.Chain.Validate(); err != nil {
		return Result{}, errors.New("contact: invalid chain policy: " + err.Error())
	}
	if input == "" || strings.TrimSpace(input) != input {
		return Result{}, errors.New("contact: DNS input has surrounding whitespace")
	}
	name := strings.ToLower(input)
	if err := validateDNSName(name); err != nil {
		return Result{}, err
	}
	now := time.Now()
	if r.Now != nil {
		now = r.Now()
	}
	if now.IsZero() || now.Unix() < 0 {
		return Result{}, errors.New("contact: invalid resolution time")
	}
	requestID, err := r.requestID()
	if err != nil {
		return Result{}, err
	}
	callContext, cancel := context.WithTimeout(ctx, dnsRequestTimeout)
	defer cancel()
	response, err := r.DNS.ResolveDNSAlias(callContext, &nativev1.ResolveDNSAliasRequest{
		Context: &nativev1.RequestContext{
			RequestId: requestID, CallerId: r.CallerID,
			DeadlineUnixMillis: now.Add(dnsRequestTimeout).UnixMilli(),
		},
		Name: name, Kind: nativev1.DNSAliasKindV1_DNS_ALIAS_KIND_V1_MESSENGER,
	})
	if err != nil {
		return Result{}, fmt.Errorf("contact: resolve DNS alias: %w", err)
	}
	agentID, err := validateDNSEvidence(response, r.Network, r.Chain, name, uint64(now.Unix()))
	if err != nil {
		return Result{}, err
	}
	return r.ensure(ctx, agentID, name)
}

func (r *Resolver) ensure(ctx context.Context, agentID, name string) (Result, error) {
	resolved, err := r.Directory.Ensure(ctx, agentID)
	if err != nil {
		return Result{}, fmt.Errorf("contact: verify Agent directory: %w", err)
	}
	if resolved.Delegation.AgentID != agentID {
		return Result{}, errors.New("contact: directory returned another Agent")
	}
	return Result{AgentID: agentID, CanonicalName: name, Directory: resolved}, nil
}

func (r *Resolver) requestID() (string, error) {
	reader := r.random
	if reader == nil {
		reader = rand.Reader
	}
	var value [16]byte
	if _, err := io.ReadFull(reader, value[:]); err != nil {
		return "", errors.New("contact: create DNS request ID")
	}
	return "dns_" + hex.EncodeToString(value[:]), nil
}

func validateDNSName(name string) error {
	if len(name) == 0 || len(name) > 126 || strings.HasPrefix(name, ".") || strings.HasSuffix(name, ".") {
		return errors.New("contact: invalid .tos name boundary")
	}
	parts := strings.Split(name, ".")
	if len(parts) < 2 || parts[len(parts)-1] != "tos" {
		return errors.New("contact: input is neither an Agent ID nor a .tos name")
	}
	for _, part := range parts {
		if part == "" {
			return errors.New("contact: .tos name has an empty component")
		}
		for index := 0; index < len(part); index++ {
			value := part[index]
			if value < 0x21 || value > 0x7e || value >= 'A' && value <= 'Z' || value == '/' || value == ':' {
				return errors.New("contact: .tos name has a non-canonical byte")
			}
		}
	}
	return nil
}

func validateDNSEvidence(response *nativev1.ResolveDNSAliasResponse, network *nativev1.NetworkDomain,
	chain identity.ChainPolicy, name string, now uint64) (string, error) {
	if response == nil || response.CanonicalName != name ||
		response.Kind != nativev1.DNSAliasKindV1_DNS_ALIAS_KIND_V1_MESSENGER ||
		response.Provenance != nativev1.DNSProvenanceV1_DNS_PROVENANCE_V1_QUORUM_AGREED ||
		response.NativeState == nil || response.ResolvedAccount == nil {
		return "", errors.New("contact: DNS response is not quorum-bound Messenger evidence")
	}
	category := sha256.Sum256([]byte("messenger"))
	if response.CategoryHash != hex.EncodeToString(category[:]) {
		return "", errors.New("contact: DNS Messenger category mismatch")
	}
	if !validAgentID(response.NativeObjectId) {
		return "", errors.New("contact: DNS target is not a canonical Agent identifier")
	}
	account := response.ResolvedAccount
	if account.Workchain != 0 || len(account.AccountId) != 32 {
		return "", errors.New("contact: DNS target account is invalid")
	}
	state := response.NativeState
	if !sameNativeNetwork(state.Network, network) || state.Reference == nil || state.Reference.Workchain != 0 ||
		state.Reference.Account != "0:"+hex.EncodeToString(account.AccountId) {
		return "", errors.New("contact: DNS Native account or network provenance mismatch")
	}
	checkpoint := response.Checkpoint
	if checkpoint == nil || checkpoint.Workchain != -1 || checkpoint.Sequence == 0 ||
		len(checkpoint.RootHash) != 32 || len(checkpoint.FileHash) != 32 || checkpoint.GenerationUnixSeconds == 0 ||
		state.Reference.FinalizedCheckpoint != checkpoint.Sequence {
		return "", errors.New("contact: DNS finalized checkpoint is incomplete")
	}
	evaluationTime := now
	if checkpoint.GenerationUnixSeconds > evaluationTime {
		evaluationTime = checkpoint.GenerationUnixSeconds
	}
	if err := validateLifecycle(response.Lifecycle, evaluationTime); err != nil {
		return "", err
	}
	if err := validateResolverPath(response.ResolverPath); err != nil {
		return "", err
	}

	// Native DNS state uses digest-prefixed genesis fields while Messenger's
	// identity package uses its configured raw genesis digests. They encode the
	// same exact tuple; normalize only after checking that equivalence.
	normalized := proto.Clone(state).(*nativev1.NativeStateV1)
	normalized.Network = proto.Clone(network).(*nativev1.NetworkDomain)
	agent, err := identity.CheckState(chain, network, response.NativeObjectId, normalized)
	if err != nil {
		return "", errors.New("contact: DNS target fails finalized Agent verification: " + err.Error())
	}
	if agent.AgentId != response.NativeObjectId {
		return "", errors.New("contact: DNS state identifies another Agent")
	}
	return response.NativeObjectId, nil
}

func sameNativeNetwork(actual, configured *nativev1.NetworkDomain) bool {
	if actual == nil || configured == nil || actual.NetworkId != configured.NetworkId {
		return false
	}
	return equivalentDigest(actual.GenesisRootHash, configured.GenesisRootHash) &&
		equivalentDigest(actual.GenesisFileHash, configured.GenesisFileHash)
}

func equivalentDigest(actual, configured string) bool {
	return actual == configured || actual == "sha256:"+configured || "sha256:"+actual == configured
}

func validateLifecycle(value *nativev1.DNSLifecycleV1, now uint64) error {
	if value == nil || value.AuctionEndUnixSeconds != 0 || value.LastFillUpUnixSeconds == 0 ||
		value.LastFillUpUnixSeconds > ^uint64(0)-dnsLeaseSeconds ||
		value.RenewalDeadlineUnixSeconds != value.LastFillUpUnixSeconds+dnsLeaseSeconds ||
		now > value.RenewalDeadlineUnixSeconds {
		return errors.New("contact: DNS name is auctioning, unsettled, overdue, or lacks a valid renewal clock")
	}
	return nil
}

func validateResolverPath(path []*nativev1.TOSAccountAddressV1) error {
	if len(path) < 3 || len(path) > 8 {
		return errors.New("contact: DNS resolver path is outside 3..8 hops")
	}
	seen := make(map[string]struct{}, len(path))
	for index, address := range path {
		if address == nil || len(address.AccountId) != 32 || index == 0 && address.Workchain != -1 ||
			index > 0 && address.Workchain != 0 {
			return errors.New("contact: DNS resolver path address is invalid")
		}
		key := fmt.Sprintf("%d:%s", address.Workchain, hex.EncodeToString(address.AccountId))
		if _, duplicate := seen[key]; duplicate {
			return errors.New("contact: DNS resolver path contains a cycle")
		}
		seen[key] = struct{}{}
	}
	return nil
}

func validAgentID(value string) bool {
	if !identity.AgentPattern.MatchString(value) || value != strings.ToLower(value) {
		return false
	}
	_, err := hex.DecodeString(strings.TrimPrefix(value, "agent_"))
	return err == nil
}
