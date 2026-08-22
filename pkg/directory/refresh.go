package directory

import (
	"context"
	"errors"
	"time"

	"github.com/tosnetwork/tos-messenger/pkg/e2ee"
	"github.com/tosnetwork/tos-messenger/pkg/identity"
	nativev1 "github.com/tosnetwork/tos-service-protocol/gen/tos/service/v1"
)

// RefreshSource separates the four retrieval operations so tests and
// operators can observe which authority boundary failed. None of the returned
// bytes are trusted: Refresh verifies each object before asking for the next.
type RefreshSource interface {
	Delegation(context.Context, string) ([]byte, error)
	DescriptorPolicy(context.Context, identity.Delegation) (DescriptorPolicy, error)
	Locator(context.Context, DHTKey) ([]byte, error)
	Descriptor(context.Context, string) ([]byte, error)
	Prekeys(context.Context, Descriptor, Locator) ([]e2ee.Bundle, error)
}

// PublishedSetAdmitter is the durable rollback and revocation boundary. The
// event log implements it without making discovery depend on a concrete store.
type PublishedSetAdmitter interface {
	AdmitPublishedSet(identity.Delegation, string, []e2ee.Bundle, time.Time) (e2ee.Succession, error)
}

// RefreshStage identifies the last boundary a refresh crossed. It is intended
// for metrics and diagnostics; it is never authority for retry or admission.
type RefreshStage string

const (
	StageDelegation RefreshStage = "delegation"
	StagePolicy     RefreshStage = "policy"
	StageLocator    RefreshStage = "locator"
	StageDescriptor RefreshStage = "descriptor"
	StagePrekeys    RefreshStage = "prekeys"
	StageCommitted  RefreshStage = "committed"
)

// RefreshResult is the verified snapshot installed by one refresh.
type RefreshResult struct {
	Delegation identity.Delegation
	Descriptor Descriptor
	Locator    Locator
	// Bundles are the exact public device prekeys that passed delegation,
	// descriptor-commitment and durable succession verification. Session
	// bootstrap must consume these bytes instead of fetching an unbound copy.
	Bundles             []e2ee.Bundle
	Succession          e2ee.Succession
	FinalizedCheckpoint uint64
	RefreshedAt         time.Time
}

// RefreshError preserves the failed boundary without treating retrieval
// failure as a revoked identity. Callers may retry it, but must not use a
// previous descriptor past its verified expiry.
type RefreshError struct {
	Stage RefreshStage
	Err   error
}

func (e *RefreshError) Error() string { return string(e.Stage) + " refresh: " + e.Err.Error() }
func (e *RefreshError) Unwrap() error { return e.Err }

// Refresher performs the route-independent half of peer discovery.
type Refresher struct {
	Source   RefreshSource
	Resolver identity.AgentResolver
	Network  *nativev1.NetworkDomain
	Chain    identity.ChainPolicy
	Admitter PublishedSetAdmitter
	Now      func() time.Time
}

// Refresh resolves finalized authority again on every call. In particular it
// never reuses a delegation merely because a cached descriptor is still live:
// revocation in finalized state must take effect at the next refresh.
func (r Refresher) Refresh(ctx context.Context, agentID string) (RefreshResult, error) {
	if ctx == nil {
		return RefreshResult{}, errors.New("refresh needs a context")
	}
	if !identity.AgentPattern.MatchString(agentID) {
		return RefreshResult{}, errors.New("invalid refresh Agent identifier")
	}
	if r.Source == nil || r.Resolver == nil || r.Admitter == nil {
		return RefreshResult{}, errors.New("refresh dependencies are incomplete")
	}
	now := time.Now()
	if r.Now != nil {
		now = r.Now()
	}
	if now.IsZero() || now.Unix() < 0 {
		return RefreshResult{}, errors.New("invalid refresh time")
	}
	delegationRaw, err := r.Source.Delegation(ctx, agentID)
	if err != nil {
		return RefreshResult{}, &RefreshError{Stage: StageDelegation, Err: err}
	}
	delegation, finalizedCheckpoint, err := identity.VerifyWithCheckpoint(
		r.Resolver, r.Network, r.Chain, delegationRaw, now,
	)
	if err != nil {
		return RefreshResult{}, &RefreshError{Stage: StageDelegation, Err: err}
	}
	if delegation.AgentID != agentID {
		return RefreshResult{}, &RefreshError{Stage: StageDelegation, Err: errors.New("source returned another Agent's delegation")}
	}
	policy, err := r.Source.DescriptorPolicy(ctx, delegation)
	if err != nil {
		return RefreshResult{}, &RefreshError{Stage: StagePolicy, Err: err}
	}
	key, err := LocatorKey(delegation)
	if err != nil {
		return RefreshResult{}, &RefreshError{Stage: StageLocator, Err: err}
	}
	locatorRaw, err := r.Source.Locator(ctx, key)
	if err != nil {
		return RefreshResult{}, &RefreshError{Stage: StageLocator, Err: err}
	}
	locator, err := DecodeLocator(locatorRaw)
	if err == nil {
		err = VerifyLocator(delegation, locator, now)
	}
	if err != nil {
		return RefreshResult{}, &RefreshError{Stage: StageLocator, Err: err}
	}
	descriptorRaw, err := r.Source.Descriptor(ctx, locator.DescriptorLocator)
	if err != nil {
		return RefreshResult{}, &RefreshError{Stage: StageDescriptor, Err: err}
	}
	descriptor, err := DecodeDescriptorJSON(descriptorRaw)
	if err == nil {
		err = MatchesDescriptor(locator, descriptor)
	}
	if err == nil {
		err = Bind(delegation, descriptor, policy, now)
	}
	if err != nil {
		return RefreshResult{}, &RefreshError{Stage: StageDescriptor, Err: err}
	}
	bundles, err := r.Source.Prekeys(ctx, descriptor, locator)
	if err != nil {
		return RefreshResult{}, &RefreshError{Stage: StagePrekeys, Err: err}
	}
	succession, err := r.Admitter.AdmitPublishedSet(delegation, descriptor.PrekeyBundleDigest, bundles, now)
	if err != nil {
		return RefreshResult{}, &RefreshError{Stage: StagePrekeys, Err: err}
	}
	return RefreshResult{Delegation: delegation, Descriptor: descriptor, Locator: locator, Bundles: cloneBundles(bundles),
		Succession: succession, FinalizedCheckpoint: finalizedCheckpoint, RefreshedAt: now}, nil
}

func cloneBundles(values []e2ee.Bundle) []e2ee.Bundle {
	cloned := make([]e2ee.Bundle, len(values))
	for index, value := range values {
		cloned[index] = value
		if value.Network != nil {
			cloned[index].Network = &nativev1.NetworkDomain{
				NetworkId: value.Network.NetworkId, GenesisRootHash: value.Network.GenesisRootHash,
				GenesisFileHash: value.Network.GenesisFileHash,
			}
		}
		cloned[index].Material = append([]byte(nil), value.Material...)
		cloned[index].EndpointSignature = append([]byte(nil), value.EndpointSignature...)
	}
	return cloned
}

func cloneRefreshResult(value RefreshResult) RefreshResult {
	value.Bundles = cloneBundles(value.Bundles)
	value.Succession.Accepted.DeviceIDs = append([]string(nil), value.Succession.Accepted.DeviceIDs...)
	value.Succession.Accepted.BundleDigests = append([]string(nil), value.Succession.Accepted.BundleDigests...)
	value.Succession.Removed = append([]string(nil), value.Succession.Removed...)
	return value
}

// RefreshAt returns a conservative refresh deadline. The caller refreshes
// before either signed cache object expires, leaving a bounded window for a
// transient source failure without treating stale data as live.
func RefreshAt(result RefreshResult, lead time.Duration) (time.Time, error) {
	if lead < 0 {
		return time.Time{}, errors.New("refresh lead cannot be negative")
	}
	expires := result.Descriptor.ExpiresAtUnix
	if result.Locator.ExpiresAtUnix < expires {
		expires = result.Locator.ExpiresAtUnix
	}
	if expires == 0 {
		return time.Time{}, errors.New("refresh result has no expiry")
	}
	deadline := time.Unix(int64(expires), 0).Add(-lead)
	if deadline.Before(result.RefreshedAt) {
		return result.RefreshedAt, nil
	}
	return deadline, nil
}
