package directory

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/tosnetwork/tos-messenger/pkg/e2ee"
	"github.com/tosnetwork/tos-messenger/pkg/identity"
)

type refreshSource struct {
	delegation []byte
	locator    []byte
	descriptor []byte
	bundles    []e2ee.Bundle
	fail       RefreshStage
	calls      []RefreshStage
}

func (s *refreshSource) Delegation(context.Context, string) ([]byte, error) {
	s.calls = append(s.calls, StageDelegation)
	if s.fail == StageDelegation {
		return nil, errors.New("delegation unavailable")
	}
	return s.delegation, nil
}
func (s *refreshSource) Locator(context.Context, DHTKey) ([]byte, error) {
	s.calls = append(s.calls, StageLocator)
	if s.fail == StageLocator {
		return nil, errors.New("locator unavailable")
	}
	return s.locator, nil
}
func (s *refreshSource) Descriptor(context.Context, string) ([]byte, error) {
	s.calls = append(s.calls, StageDescriptor)
	if s.fail == StageDescriptor {
		return nil, errors.New("descriptor unavailable")
	}
	return s.descriptor, nil
}
func (s *refreshSource) Prekeys(context.Context, Descriptor) ([]e2ee.Bundle, error) {
	s.calls = append(s.calls, StagePrekeys)
	if s.fail == StagePrekeys {
		return nil, errors.New("prekeys unavailable")
	}
	return s.bundles, nil
}

type refreshAdmitter struct{ calls int }

func (a *refreshAdmitter) AdmitPublishedSet(delegation identity.Delegation, digest string,
	bundles []e2ee.Bundle, now time.Time) (e2ee.Succession, error) {
	a.calls++
	if err := e2ee.BindBundleSet(delegation, bundles, digest, now); err != nil {
		return e2ee.Succession{}, err
	}
	summary, err := e2ee.Summarize(bundles)
	return e2ee.Succession{Accepted: summary}, err
}

func refreshFixture(t *testing.T) (*refreshSource, Refresher, *refreshAdmitter) {
	t.Helper()
	key := endpointKey(t, 0x11)
	delegation := testDelegation(t, key)
	bundle, err := e2ee.SignBundle(e2ee.Bundle{
		Network: delegation.Network, AgentID: delegation.AgentID, EndpointID: delegation.EndpointID,
		DeviceID: "dev_" + strings.Repeat("4", 64), AlgorithmID: "tos.messaging.e2ee.x3dh-aes256gcm-dr.v1",
		Material: []byte("published prekey"), IssuedAtUnix: baseUnix, ExpiresAtUnix: baseUnix + 3600,
	}, key)
	if err != nil {
		t.Fatal(err)
	}
	bundles := []e2ee.Bundle{bundle}
	digest, err := e2ee.SetDigest(bundles)
	if err != nil {
		t.Fatal(err)
	}
	descriptor := testDescriptor(t, delegation)
	descriptor.PrekeyBundleDigest = digest
	descriptor, err = SignDescriptor(descriptor, key)
	if err != nil {
		t.Fatal(err)
	}
	locator := signedLocator(t, descriptor, key, "https://endpoint.example/descriptor")
	delegationRaw, err := identity.EncodeJSON(delegation)
	if err != nil {
		t.Fatal(err)
	}
	descriptorRaw, err := EncodeDescriptorJSON(descriptor)
	if err != nil {
		t.Fatal(err)
	}
	locatorRaw, err := EncodeLocator(locator)
	if err != nil {
		t.Fatal(err)
	}
	source := &refreshSource{delegation: delegationRaw, locator: locatorRaw, descriptor: descriptorRaw, bundles: bundles}
	admitter := &refreshAdmitter{}
	refresher := Refresher{Source: source, Resolver: liveResolver(t, delegation), Network: testNetwork(),
		Chain: testChain(), Policy: testPolicy(), Admitter: admitter,
		Now: func() time.Time { return time.Unix(int64(baseUnix)+60, 0) }}
	return source, refresher, admitter
}

func TestRefreshVerifiesAndCommitsTheWholeChain(t *testing.T) {
	source, refresher, admitter := refreshFixture(t)
	result, err := refresher.Refresh(context.Background(), agentID)
	if err != nil {
		t.Fatalf("refresh: %v", err)
	}
	if admitter.calls != 1 || result.Succession.Accepted.Digest == "" {
		t.Fatal("published set was not committed")
	}
	want := []RefreshStage{StageDelegation, StageLocator, StageDescriptor, StagePrekeys}
	if len(source.calls) != len(want) {
		t.Fatalf("calls=%v", source.calls)
	}
	for i := range want {
		if source.calls[i] != want[i] {
			t.Fatalf("calls=%v", source.calls)
		}
	}
	deadline, err := RefreshAt(result, 5*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if want := time.Unix(int64(baseUnix+3300), 0); !deadline.Equal(want) {
		t.Fatalf("deadline=%v want=%v", deadline, want)
	}
}

func TestRefreshStopsAtTheFailedBoundary(t *testing.T) {
	for _, stage := range []RefreshStage{StageDelegation, StageLocator, StageDescriptor, StagePrekeys} {
		t.Run(string(stage), func(t *testing.T) {
			source, refresher, admitter := refreshFixture(t)
			source.fail = stage
			_, err := refresher.Refresh(context.Background(), agentID)
			var refreshErr *RefreshError
			if !errors.As(err, &refreshErr) || refreshErr.Stage != stage {
				t.Fatalf("error=%v", err)
			}
			if admitter.calls != 0 {
				t.Fatal("failed refresh mutated the device ledger")
			}
		})
	}
}

func TestRefreshRejectsAStaleLocatorBeforeFetchingDescriptor(t *testing.T) {
	source, refresher, admitter := refreshFixture(t)
	refresher.Now = func() time.Time { return time.Unix(int64(baseUnix+3600), 0) }
	_, err := refresher.Refresh(context.Background(), agentID)
	var refreshErr *RefreshError
	if !errors.As(err, &refreshErr) || refreshErr.Stage != StageLocator {
		t.Fatalf("error=%v", err)
	}
	if len(source.calls) != 2 || admitter.calls != 0 {
		t.Fatalf("calls=%v admits=%d", source.calls, admitter.calls)
	}
}

func TestRefreshRechecksFinalizedRevocation(t *testing.T) {
	_, refresher, admitter := refreshFixture(t)
	resolver := refresher.Resolver.(stubResolver)
	state := resolver.states[agentID]
	state.GetAgent().Tombstoned = true
	_, err := refresher.Refresh(context.Background(), agentID)
	var refreshErr *RefreshError
	if !errors.As(err, &refreshErr) || refreshErr.Stage != StageDelegation {
		t.Fatalf("error=%v", err)
	}
	if admitter.calls != 0 {
		t.Fatal("revoked Agent reached the device ledger")
	}
}
