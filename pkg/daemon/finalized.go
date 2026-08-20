package daemon

import (
	"errors"
	"os"
	"time"

	"github.com/tosnetwork/tos-messenger/pkg/chainagent"
	"github.com/tosnetwork/tos-messenger/pkg/identity"
	"github.com/tosnetwork/tos-service-protocol/pkg/nativecore"
)

const maxDelegationFileBytes = 64 << 10

type delegationVerifier interface {
	Verify(Config, time.Time) (identity.Delegation, error)
}

type finalizedVerifier struct{}

func (finalizedVerifier) Verify(config Config, now time.Time) (identity.Delegation, error) {
	adapter, err := config.ChainAdapter()
	if err != nil {
		return identity.Delegation{}, err
	}
	registry, err := config.NativeRegistry()
	if err != nil {
		return identity.Delegation{}, err
	}
	locator, err := nativecore.NewLocator(config.Network(), registry.Workchain, registry.CodeBOC, registry.CodeHash)
	if err != nil {
		return identity.Delegation{}, err
	}
	resolver, err := chainagent.NewFromChain(adapter, locator, config.ChainCheckpointPath)
	if err != nil {
		return identity.Delegation{}, err
	}
	raw, err := readBoundedRegularFile(config.DelegationPath, maxDelegationFileBytes)
	if err != nil {
		return identity.Delegation{}, err
	}
	policy, err := config.Chain()
	if err != nil {
		return identity.Delegation{}, err
	}
	return identity.Verify(resolver, config.Network(), policy, raw, now)
}

func readBoundedRegularFile(path string, limit int64) ([]byte, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, errors.New("read delegation file")
	}
	if !info.Mode().IsRegular() || info.Size() <= 0 || info.Size() > limit {
		return nil, errors.New("delegation file must be a non-empty bounded regular file")
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, errors.New("read delegation file")
	}
	if int64(len(raw)) > limit {
		return nil, errors.New("delegation file exceeds size limit")
	}
	return raw, nil
}
