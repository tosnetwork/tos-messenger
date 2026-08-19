// Package tosaddr recomputes TOS account addresses using the registry's own
// addressing rules.
//
// The Messenger needs to know that a finalized Agent record came from the
// account that Agent must live at, and an account address is deterministic
// from the network, the object identifier, the registry code, and the
// workchain. This package does not reimplement that derivation: it calls the
// protocol SDK that the chain side uses, because a second implementation of an
// addressing rule is a second implementation that can drift, and a drifted
// address check would refuse correct state while looking like a safety
// measure.
package tosaddr

import (
	"encoding/hex"
	"errors"
	"strings"

	nativev1 "github.com/tosnetwork/tos-service-protocol/gen/tos/service/v1"
	"github.com/tosnetwork/tos-service-protocol/pkg/nativecore"
)

// Registry is one registry contract an operator accepts: its code, and the
// workchain its objects live in.
type Registry struct {
	// CodeHash is the tvm-cell-sha256 digest of the contract code.
	CodeHash string
	// CodeBOC is the contract code itself, base64 BOC. The hash is checked
	// against it, so a mismatched pair is a configuration error rather than a
	// silent acceptance of whatever code was supplied.
	CodeBOC string
	// Workchain is the workchain the registry's objects are addressed in.
	Workchain int32
}

// Locator recomputes account addresses for a fixed set of registries.
type Locator struct {
	byCode map[string]*nativecore.Locator
}

// New builds a locator for every registry an operator predeclared.
//
// A registry whose code does not hash to the digest it was filed under is
// refused here rather than accepted and used: the digest is what the chain
// policy pins, so a pair that disagrees would let the pinned value name one
// contract while the addresses came from another.
func New(network *nativev1.NetworkDomain, registries []Registry) (*Locator, error) {
	if network == nil {
		return nil, errors.New("an account locator needs a network domain")
	}
	if len(registries) == 0 {
		return nil, errors.New("an account locator needs at least one registry")
	}
	domain, err := normalize(network)
	if err != nil {
		return nil, err
	}
	byCode := make(map[string]*nativecore.Locator, len(registries))
	for _, registry := range registries {
		if registry.CodeHash == "" || registry.CodeBOC == "" {
			return nil, errors.New("a registry must name both its code hash and its code")
		}
		if _, duplicate := byCode[registry.CodeHash]; duplicate {
			return nil, errors.New("a registry code hash was configured twice")
		}
		located, err := nativecore.NewLocator(domain, registry.Workchain, registry.CodeBOC, registry.CodeHash)
		if err != nil {
			return nil, err
		}
		byCode[registry.CodeHash] = located
	}
	return &Locator{byCode: byCode}, nil
}

// normalize converts a network domain into the form the protocol SDK expects.
//
// The Messenger carries genesis hashes as bare hex; the SDK carries them
// prefixed with their algorithm. Both describe the same 32 bytes, and the
// conversion happens here rather than by reinterpreting the Messenger's own
// field, so that neither side has to guess which convention it is holding.
// Which of the two forms the protocol freezes on is still open.
func normalize(network *nativev1.NetworkDomain) (*nativev1.NetworkDomain, error) {
	root, err := prefixed(network.GetGenesisRootHash())
	if err != nil {
		return nil, err
	}
	file, err := prefixed(network.GetGenesisFileHash())
	if err != nil {
		return nil, err
	}
	return &nativev1.NetworkDomain{
		NetworkId:       network.GetNetworkId(),
		GenesisRootHash: root,
		GenesisFileHash: file,
	}, nil
}

func prefixed(hash string) (string, error) {
	if strings.HasPrefix(hash, "sha256:") {
		hash = strings.TrimPrefix(hash, "sha256:")
	}
	raw, err := hex.DecodeString(hash)
	if err != nil || len(raw) != 32 {
		return "", errors.New("invalid genesis hash")
	}
	return "sha256:" + hex.EncodeToString(raw), nil
}

// Locate implements identity.AccountLocator.
//
// An unknown registry code is an error. Returning the object's address under
// some other registry would answer a question nobody asked, and returning no
// error at all would turn an unrecognised contract into an accepted one.
func (l *Locator) Locate(registryCodeHash, objectID string) (string, error) {
	if l == nil {
		return "", errors.New("no account locator")
	}
	located, known := l.byCode[registryCodeHash]
	if !known {
		return "", errors.New("no registry code was configured for " + registryCodeHash)
	}
	identity, err := located.Locate(objectID)
	if err != nil {
		return "", err
	}
	return identity.Address, nil
}
