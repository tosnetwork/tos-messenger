package identity

import (
	"errors"
	"regexp"

	nativev1 "github.com/tosnetwork/tos-service-protocol/gen/tos/service/v1"
)

// MaxRegistryCodeHashes bounds a predeclared registry code set.
const MaxRegistryCodeHashes = 8

var (
	cellDigestPattern  = regexp.MustCompile(`^tvm-cell-sha256:[0-9a-f]{64}$`)
	chainDigestPattern = regexp.MustCompile(`^(?:sha256|tvm-cell-sha256):[0-9a-f]{64}$`)
	accountPattern     = regexp.MustCompile(`^[0-9A-Za-z_:+/=-]{1,128}$`)
)

// AgentResolver reads finalized Agent state.
//
// It returns the outer state rather than the Agent alone. The Agent record
// carries no network, no chain reference, no contract code hash and no
// finalized checkpoint, so a resolver returning only that record asks its
// caller to trust an implicit promise: that the answer came from the right
// network, from the registry the caller expects, and from a block that is
// actually final. Returning the outer state lets the Messenger boundary check
// those things instead of assuming them.
type AgentResolver interface {
	ResolveAgent(string) (*nativev1.NativeStateV1, bool, error)
}

// AccountLocator recomputes the deterministic account address an object must
// live at under a given registry contract.
//
// It is an interface here rather than a derivation because the addressing
// rules belong to the registry, not to the Messenger. Reimplementing them
// would create a second implementation that can silently drift from the one
// the chain actually uses, and a drifted address check is worse than none: it
// would refuse correct state.
type AccountLocator interface {
	// Locate returns the account address for an object under one registry code
	// hash. An unknown code hash is an error, never a pass.
	Locate(registryCodeHash, objectID string) (string, error)
}

// ChainPolicy is what a caller predeclares about the finalized state it will
// accept.
//
// The registry code hash is the load-bearing entry. Typed TVM state is only
// meaningful under the contract that produced it, so state from an
// unrecognised contract is not Agent state that happens to be unfamiliar; it
// is a different object with a familiar shape.
type ChainPolicy struct {
	// RegistryCodeHashes are the registry contract code hashes whose state is
	// accepted, as tvm-cell-sha256 digests.
	RegistryCodeHashes []string
	// MinFinalizedCheckpoint refuses state finalized before a point the
	// operator already knows about. Zero accepts any finalized state.
	MinFinalizedCheckpoint uint64
	// Locator recomputes the account address an object must live at. It is
	// required: without it a resolver could return the right Agent record read
	// from the wrong account, and every check downstream would pass. An
	// optional binding is a binding an operator can forget to make.
	Locator AccountLocator
}

// Validate enforces that a chain policy can decide anything.
func (c ChainPolicy) Validate() error {
	if len(c.RegistryCodeHashes) == 0 || len(c.RegistryCodeHashes) > MaxRegistryCodeHashes {
		return errors.New("a chain policy must name the registry code it accepts")
	}
	seen := make(map[string]struct{}, len(c.RegistryCodeHashes))
	for _, hash := range c.RegistryCodeHashes {
		if !cellDigestPattern.MatchString(hash) {
			return errors.New("invalid registry code hash")
		}
		if _, duplicate := seen[hash]; duplicate {
			return errors.New("a chain policy cannot name the same registry code twice")
		}
		seen[hash] = struct{}{}
	}
	if c.Locator == nil {
		return errors.New("a chain policy must be able to recompute account addresses")
	}
	return nil
}

// AcceptsRegistry reports whether a code hash is one the policy named.
func (c ChainPolicy) AcceptsRegistry(hash string) bool {
	for _, candidate := range c.RegistryCodeHashes {
		if candidate == hash {
			return true
		}
	}
	return false
}

// CheckState re-verifies the binding between what was asked and what came
// back.
//
// Every check here is one a correct resolver already performs. They are
// repeated because the cost is a few comparisons and the alternative is that a
// mistaken adapter, a test double left in a build, or a later refactor decides
// what the Messenger treats as authority.
func CheckState(policy ChainPolicy, network *nativev1.NetworkDomain, agentID string, state *nativev1.NativeStateV1) (*nativev1.AgentStateV1, error) {
	if err := policy.Validate(); err != nil {
		return nil, err
	}
	if err := validateNetwork(network); err != nil {
		return nil, err
	}
	if !AgentPattern.MatchString(agentID) {
		return nil, errors.New("invalid Agent identifier")
	}
	if state == nil {
		return nil, errors.New("resolver returned no state")
	}
	if state.Network == nil || state.Network.NetworkId != network.NetworkId ||
		state.Network.GenesisRootHash != network.GenesisRootHash ||
		state.Network.GenesisFileHash != network.GenesisFileHash {
		return nil, errors.New("resolver returned state from another network")
	}
	if !chainDigestPattern.MatchString(state.TvmStateHash) {
		return nil, errors.New("resolver returned state with no typed state hash")
	}
	reference := state.Reference
	if reference == nil {
		return nil, errors.New("resolver returned state with no chain reference")
	}
	// A checkpoint of zero is not a low checkpoint; it is state nobody claimed
	// was final.
	if reference.FinalizedCheckpoint == 0 {
		return nil, errors.New("resolver returned state that is not finalized")
	}
	if reference.FinalizedCheckpoint < policy.MinFinalizedCheckpoint {
		return nil, errors.New("resolver returned state older than the operator's known checkpoint")
	}
	if !policy.AcceptsRegistry(reference.ContractCodeHash) {
		return nil, errors.New("resolver returned state from an unrecognised registry contract")
	}
	if !accountPattern.MatchString(reference.Account) {
		return nil, errors.New("resolver returned state with no account")
	}
	if !chainDigestPattern.MatchString(reference.TransactionHash) {
		return nil, errors.New("resolver returned state with no transaction hash")
	}
	// The account is deterministic from the object and the registry that
	// produced it. Recomputing it is what stops a resolver from handing back a
	// genuine Agent record it read from an account of its own choosing.
	expected, err := policy.Locator.Locate(reference.ContractCodeHash, agentID)
	if err != nil {
		return nil, errors.New("could not recompute the Agent account address: " + err.Error())
	}
	if expected != reference.Account {
		return nil, errors.New("resolver returned Agent state from the wrong account")
	}
	agent := state.GetAgent()
	if agent == nil {
		return nil, errors.New("resolver returned state that is not an Agent")
	}
	if agent.AgentId != agentID {
		return nil, errors.New("resolver returned state for another Agent")
	}
	if agent.Tombstoned || agent.Policy == nil {
		return nil, errors.New("Agent is not finalized and live")
	}
	return agent, nil
}
