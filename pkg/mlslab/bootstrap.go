package mlslab

import (
	"bytes"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/tosnetwork/tos-messenger/internal/canon"
	"github.com/tosnetwork/tos-messenger/pkg/group"
	"github.com/tosnetwork/tos-messenger/pkg/labgroup"
)

// Bootstrap creates one independently persisted OpenMLS snapshot per Agent.
// Members are added in the supplied order, so a three-Agent bootstrap executes
// two genuine Welcome/Commit epoch transitions rather than sharing one secret.
func Bootstrap(stateDir, label string, members []string, driver *group.OpenMLSSidecar) (labgroup.Room, error) {
	if stateDir == "" || strings.TrimSpace(label) == "" || len(label) > 128 || driver == nil {
		return labgroup.Room{}, errors.New("invalid MLS lab bootstrap configuration")
	}
	normalized, err := labgroup.NormalizeMembers(members)
	if err != nil {
		return labgroup.Room{}, err
	}
	if len(normalized) != len(members) {
		return labgroup.Room{}, errors.New("invalid MLS lab member order")
	}
	seen := map[string]bool{}
	for _, member := range members {
		if seen[member] {
			return labgroup.Room{}, errors.New("duplicate MLS lab member")
		}
		seen[member] = true
	}
	roomID := labgroup.DeriveRoomID(strings.TrimSpace(label), normalized)
	groupID, err := hex.DecodeString(strings.TrimPrefix(roomID, "room_"))
	if err != nil || len(groupID) != group.MLSGroupIDBytes {
		return labgroup.Room{}, errors.New("invalid derived MLS group id")
	}
	if _, err := os.Lstat(stateDir); err == nil {
		return labgroup.Room{}, errors.New("MLS lab bootstrap refuses to replace an existing state directory")
	} else if !errors.Is(err, os.ErrNotExist) {
		return labgroup.Room{}, err
	}
	parent := filepath.Dir(stateDir)
	if err := os.MkdirAll(parent, 0o700); err != nil {
		return labgroup.Room{}, err
	}
	staging, err := os.MkdirTemp(parent, ".openfox-mls-bootstrap-*")
	if err != nil {
		return labgroup.Room{}, err
	}
	defer os.RemoveAll(staging)
	if err := os.Chmod(staging, 0o700); err != nil {
		return labgroup.Room{}, err
	}

	identities := make([]group.OpenMLSIdentity, len(members))
	states := make([][]byte, len(members))
	for i, member := range members {
		identity, err := driver.NewIdentity([]byte(member))
		if err != nil {
			return labgroup.Room{}, fmt.Errorf("create identity for %s: %w", member, err)
		}
		if err := driver.ValidateKeyPackage(identity.KeyPackage, []byte(member), identity.LeafSignaturePublicKey); err != nil {
			return labgroup.Room{}, fmt.Errorf("validate KeyPackage for %s: %w", member, err)
		}
		identities[i] = identity
	}
	states[0], err = driver.CreateGroup(identities[0].State, identities[0].KeyPackage, groupID)
	if err != nil {
		return labgroup.Room{}, err
	}
	for joining := 1; joining < len(members); joining++ {
		ref := canon.Digest(identities[joining].KeyPackage)
		operation := group.LeafOperation{Kind: group.LeafAdd, Next: &group.Leaf{
			CredentialIdentity:     []byte(members[joining]),
			LeafSignaturePublicKey: identities[joining].LeafSignaturePublicKey,
			KeyPackageRef:          ref,
			KeyPackage:             identities[joining].KeyPackage,
		}}
		nextFounder, commit, welcomes, err := driver.Commit(states[0], []group.LeafOperation{operation})
		if err != nil {
			return labgroup.Room{}, err
		}
		states[0] = nextFounder
		for existing := 1; existing < joining; existing++ {
			states[existing], err = driver.Apply(states[existing], commit)
			if err != nil {
				return labgroup.Room{}, err
			}
		}
		welcome, found := welcomes[ref]
		if !found {
			return labgroup.Room{}, errors.New("OpenMLS omitted a joining Welcome")
		}
		states[joining], err = driver.Join(identities[joining].State, welcome)
		if err != nil {
			return labgroup.Room{}, err
		}
	}

	for i, member := range members {
		info, err := driver.Inspect(states[i])
		if err != nil || !bytes.Equal(info.GroupID, groupID) || info.Epoch != uint64(len(members)-1) {
			return labgroup.Room{}, errors.New("bootstrapped MLS members did not converge")
		}
		state := AgentState{
			Schema:  StateSchema,
			AgentID: member,
			Room:    RoomState{RoomID: roomID, Label: strings.TrimSpace(label), Members: append([]string(nil), normalized...), MLSEpoch: info.Epoch},
			Pending: map[string]Pending{},
			Sent:    map[string]Pending{},
		}
		setOpaque(&state.Room, states[i])
		path := StatePath(staging, member)
		if err := writeState(path, state); err != nil {
			return labgroup.Room{}, fmt.Errorf("persist MLS state for %s: %w", member, err)
		}
	}
	directory, err := os.Open(staging)
	if err != nil {
		return labgroup.Room{}, err
	}
	if err := directory.Sync(); err != nil {
		directory.Close()
		return labgroup.Room{}, err
	}
	if err := directory.Close(); err != nil {
		return labgroup.Room{}, err
	}
	if err := os.Rename(staging, stateDir); err != nil {
		return labgroup.Room{}, err
	}
	parentDirectory, err := os.Open(parent)
	if err != nil {
		return labgroup.Room{}, err
	}
	defer parentDirectory.Close()
	if err := parentDirectory.Sync(); err != nil {
		return labgroup.Room{}, err
	}
	return labgroup.Room{RoomID: roomID, Label: strings.TrimSpace(label), Members: normalized, CreatedBy: members[0]}, nil
}

func StatePath(stateDir, agentID string) string {
	return filepath.Join(stateDir, agentID+".json")
}

// OrderedMembers returns a deterministic creator-first order when callers do
// not have an application-selected invitation order.
func OrderedMembers(creator string, members []string) ([]string, error) {
	normalized, err := labgroup.NormalizeMembers(members)
	if err != nil {
		return nil, err
	}
	index := sort.SearchStrings(normalized, creator)
	if index == len(normalized) || normalized[index] != creator {
		return nil, errors.New("creator is not a room member")
	}
	result := []string{creator}
	for _, member := range normalized {
		if member != creator {
			result = append(result, member)
		}
	}
	return result, nil
}
