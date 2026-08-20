package directory

import (
	"context"
	"errors"
	"path/filepath"

	"github.com/tosnetwork/tos-messenger/internal/ids"
	"github.com/tosnetwork/tos-messenger/internal/securefile"
	"github.com/tosnetwork/tos-messenger/pkg/identity"
)

const MaxDelegationWireBytes = 64 << 10

// DelegationFile pins one Agent identifier to an operator-provisioned
// delegation document. The mapping is rendezvous only: Refresher still checks
// the document against finalized Agent state on every refresh.
type DelegationFile struct {
	AgentID              string
	Path                 string
	DescriptorPolicyPath string
}

// FileDelegations is the explicit first-contact bootstrap required before an
// Endpoint-key-derived DHT locator can be queried.
type FileDelegations struct {
	files map[string]DelegationFile
}

func NewFileDelegations(files []DelegationFile) (*FileDelegations, error) {
	if len(files) == 0 || len(files) > 4096 {
		return nil, errors.New("invalid peer delegation set size")
	}
	configured := make(map[string]DelegationFile, len(files))
	for _, file := range files {
		if !ids.Agent.MatchString(file.AgentID) {
			return nil, errors.New("invalid peer delegation Agent identifier")
		}
		if !filepath.IsAbs(file.Path) || filepath.Clean(file.Path) != file.Path {
			return nil, errors.New("peer delegation path must be absolute and clean")
		}
		if !filepath.IsAbs(file.DescriptorPolicyPath) || filepath.Clean(file.DescriptorPolicyPath) != file.DescriptorPolicyPath {
			return nil, errors.New("peer descriptor policy path must be absolute and clean")
		}
		if _, duplicate := configured[file.AgentID]; duplicate {
			return nil, errors.New("duplicate peer delegation Agent identifier")
		}
		configured[file.AgentID] = file
	}
	return &FileDelegations{files: configured}, nil
}

// Delegation rereads the pinned path so an atomic operator update can rotate a
// delegation without restarting the daemon. The decoded Agent identifier must
// match before chain verification, preventing a path-map mistake from turning
// into a query about an unintended Agent.
func (f *FileDelegations) Delegation(ctx context.Context, agentID string) ([]byte, error) {
	if f == nil {
		return nil, errors.New("no peer delegation bootstrap")
	}
	if ctx == nil {
		return nil, errors.New("peer delegation lookup needs a context")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	file, found := f.files[agentID]
	if !found {
		return nil, errors.New("peer delegation is not provisioned")
	}
	raw, err := securefile.ReadBoundedRegular(file.Path, MaxDelegationWireBytes)
	if err != nil {
		return nil, err
	}
	delegation, err := identity.DecodeJSON(raw)
	if err != nil {
		return nil, err
	}
	if delegation.AgentID != agentID {
		return nil, errors.New("peer delegation file belongs to another Agent")
	}
	return raw, nil
}

// DescriptorPolicy retrieves the exact policy document the already-verified
// delegation commits. The path is bootstrap; matching its digest makes the
// Agent controller's prior commitment the authority.
func (f *FileDelegations) DescriptorPolicy(ctx context.Context, delegation identity.Delegation) (DescriptorPolicy, error) {
	if f == nil || ctx == nil {
		return DescriptorPolicy{}, errors.New("invalid peer descriptor policy lookup")
	}
	if err := ctx.Err(); err != nil {
		return DescriptorPolicy{}, err
	}
	file, found := f.files[delegation.AgentID]
	if !found {
		return DescriptorPolicy{}, errors.New("peer descriptor policy is not provisioned")
	}
	raw, err := securefile.ReadBoundedRegular(file.DescriptorPolicyPath, MaxDescriptorPolicyWireBytes)
	if err != nil {
		return DescriptorPolicy{}, err
	}
	policy, err := DecodeDescriptorPolicyJSON(raw)
	if err != nil {
		return DescriptorPolicy{}, err
	}
	digest, err := policy.Digest()
	if err != nil || digest != delegation.ContactDescriptorPolicyDigest {
		return DescriptorPolicy{}, errors.New("peer descriptor policy does not match its delegation commitment")
	}
	return policy, nil
}

var _ DelegationSource = (*FileDelegations)(nil)
var _ PolicySource = (*FileDelegations)(nil)
