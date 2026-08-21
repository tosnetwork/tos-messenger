package negotiation

import (
	"bytes"
	"errors"

	"github.com/tosnetwork/tos-messenger/internal/canon"
	nativev1 "github.com/tosnetwork/tos-service-protocol/gen/tos/service/v1"
)

// Network is the identity of one TOS network: the id and both genesis hashes,
// exactly the triple the finalisation-time binding compares.
//
// It exists as a value type so an asset -- and through the asset every terms
// and mandate digest -- can commit the network it lives on. A network id alone
// is not identity, because the same id can front different genesis state; and
// the same workchain, account and code hashes can exist on another network, so
// an asset identity without the network is two different assets sharing one
// digest. The genesis hashes are committed as bare lowercase hex, the form
// this repository validates and persists; the protocol SDK's prefixed form is
// converted at the boundary, never committed.
type Network struct {
	ID              string `json:"network_id"`
	GenesisRootHash string `json:"genesis_root_hash"`
	GenesisFileHash string `json:"genesis_file_hash"`
}

// Validate enforces a fully identified network.
func (n Network) Validate() error {
	if n.ID == "" || len(n.ID) > 128 ||
		!canon.HashPattern.MatchString(n.GenesisRootHash) ||
		!canon.HashPattern.MatchString(n.GenesisFileHash) {
		return errors.New("invalid network identity")
	}
	return nil
}

// Same reports whether two identities name the same TOS network. All three
// fields must agree: a shared id over different genesis state is a different
// network.
func (n Network) Same(other Network) bool {
	return n.ID == other.ID &&
		n.GenesisRootHash == other.GenesisRootHash &&
		n.GenesisFileHash == other.GenesisFileHash
}

func (n Network) canonical(buffer *bytes.Buffer) error {
	canon.Text(buffer, n.ID)
	if err := canon.Hash32(buffer, n.GenesisRootHash); err != nil {
		return err
	}
	if err := canon.Hash32(buffer, n.GenesisFileHash); err != nil {
		return err
	}
	return nil
}

// NetworkFromDomain converts the protocol form of a network domain into the
// committed value form, refusing anything short of the full triple.
func NetworkFromDomain(domain *nativev1.NetworkDomain) (Network, error) {
	if domain == nil {
		return Network{}, errors.New("no network domain")
	}
	network := Network{
		ID:              domain.NetworkId,
		GenesisRootHash: domain.GenesisRootHash,
		GenesisFileHash: domain.GenesisFileHash,
	}
	if err := network.Validate(); err != nil {
		return Network{}, err
	}
	return network, nil
}
