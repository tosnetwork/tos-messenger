package eventlog

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"regexp"

	"github.com/tosnetwork/tos-service-protocol/pkg/toschain"
)

const (
	escrowLocatorDir    = "escrow-locations"
	escrowLocatorSchema = "tos.messaging.escrow-location.v1"
)

var (
	quoteCommitmentPattern = regexp.MustCompile(`^tvm-cell-sha256:[0-9a-f]{64}$`)
	capabilityClassPattern = regexp.MustCompile(`^[a-z][a-z0-9]*(\.[a-z][a-z0-9]*)*$`)
)

type escrowLocation struct {
	Schema          string `json:"schema"`
	Commitment      string `json:"quote_commitment"`
	EscrowAddress   string `json:"escrow_address"`
	CapabilityClass string `json:"capability_class"`
}

// RecordEscrowLocation durably binds a funded quote commitment to its escrow
// account and capability class. The funding flow calls this only after it has
// prepared the exact escrow; a retry is idempotent and a redirect conflicts.
func (j *Journal) RecordEscrowLocation(commitment, escrowAddress, capabilityClass string) (bool, error) {
	if err := j.usable(); err != nil {
		return false, err
	}
	location, err := validateEscrowLocation(escrowLocation{
		Schema: escrowLocatorSchema, Commitment: commitment,
		EscrowAddress: escrowAddress, CapabilityClass: capabilityClass,
	})
	if err != nil {
		return false, err
	}
	j.mutex.Lock()
	defer j.mutex.Unlock()
	existing, found, err := j.readEscrowLocation(commitment)
	if err != nil {
		return false, err
	}
	if found {
		if existing != location {
			return false, ErrConflict
		}
		return false, nil
	}
	encoded, err := json.Marshal(location)
	if err != nil {
		return false, errors.New("encode escrow location")
	}
	if err := j.replace(j.escrowLocationPath(commitment), encoded); err != nil {
		return false, err
	}
	return true, nil
}

// LocateEscrow implements chainquote.EscrowLocator over daemon-owned state.
func (j *Journal) LocateEscrow(commitment string) (string, string, bool, error) {
	if err := j.usable(); err != nil {
		return "", "", false, err
	}
	if !quoteCommitmentPattern.MatchString(commitment) {
		return "", "", false, errors.New("invalid quote commitment")
	}
	j.mutex.Lock()
	defer j.mutex.Unlock()
	location, found, err := j.readEscrowLocation(commitment)
	if err != nil || !found {
		return "", "", found, err
	}
	return location.EscrowAddress, location.CapabilityClass, true, nil
}

func validateEscrowLocation(location escrowLocation) (escrowLocation, error) {
	if location.Schema != escrowLocatorSchema || !quoteCommitmentPattern.MatchString(location.Commitment) {
		return escrowLocation{}, errors.New("invalid escrow location commitment")
	}
	address, err := toschain.CanonicalAddress(location.EscrowAddress)
	if err != nil {
		return escrowLocation{}, errors.New("invalid escrow location address")
	}
	if !capabilityClassPattern.MatchString(location.CapabilityClass) || len(location.CapabilityClass) > 64 {
		return escrowLocation{}, errors.New("invalid escrow location capability class")
	}
	location.EscrowAddress = address
	return location, nil
}

func (j *Journal) readEscrowLocation(commitment string) (escrowLocation, bool, error) {
	raw, err := readRecordBytes(j.escrowLocationPath(commitment))
	if errors.Is(err, os.ErrNotExist) {
		return escrowLocation{}, false, nil
	}
	if err != nil {
		return escrowLocation{}, false, errors.New("read escrow location")
	}
	var location escrowLocation
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&location); err != nil {
		return escrowLocation{}, false, errors.New("invalid escrow location record")
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return escrowLocation{}, false, errors.New("escrow location record has trailing content")
	}
	location, err = validateEscrowLocation(location)
	if err != nil || location.Commitment != commitment {
		return escrowLocation{}, false, errors.New("escrow location record does not describe this commitment")
	}
	return location, true, nil
}

func (j *Journal) escrowLocationPath(commitment string) string {
	return filepath.Join(j.root, escrowLocatorDir, commitment[len("tvm-cell-sha256:"):]+".json")
}
