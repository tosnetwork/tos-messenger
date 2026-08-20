package reachability

import (
	"bytes"
	"crypto/ed25519"
	"encoding/hex"
	"errors"
	"net/netip"
	"regexp"

	"github.com/tosnetwork/tos-messenger/internal/canon"
)

const (
	// ObservationSchema is the strict schema of a coordinator observation.
	ObservationSchema = "tos.messaging.reachability-observation.v1"

	// BindObservationSchema is the strict schema of a per-coordinator bind
	// observation. It shares the observation domain separator with
	// ObservationSchema, and the two are told apart by this schema string:
	// canon.Text length-prefixes it, so a preimage under one schema can never
	// be reinterpreted as the other, and a signature over a bind observation
	// cannot be worn as a pair observation or the reverse.
	BindObservationSchema = "tos.messaging.reachability-bind-observation.v1"

	// MaxCoordinatorsPerPolicy bounds a predeclared coordinator set.
	MaxCoordinatorsPerPolicy = 16

	// MaxBindObservations bounds the per-coordinator bind observations one
	// trial may carry. A runner binds to a handful of coordinators; a set
	// larger than that is padding, and an unbounded one is a preimage a
	// reporter chooses the size of.
	MaxBindObservations = 8
)

var (
	keyPattern    = regexp.MustCompile(`^[0-9a-f]{64}$`)
	serverPattern = regexp.MustCompile(`^srv_[0-9a-f]{16}$`)
)

// Observation is what a coordinator saw and is willing to attest to.
//
// The address a coordinator observed and whether the peer was publicly
// addressable are the two facts that place a trial in its stratum, and an
// endpoint cannot check either about itself. Left unsigned they are the
// endpoint's own claim about the cell its result should count towards, which
// is the one claim an operator has a reason to get wrong.
type Observation struct {
	CoordinatorID string `json:"coordinator_id"`
	SessionID     string `json:"session_id"`
	Role          string `json:"role"`
	// EndpointPublicKeyHex is the key of the endpoint this attestation is
	// about. Without it an attestation is a statement about a session rather
	// than about a party, and a bystander could copy a published one and sign
	// a third trial for the same pair under a key of their own. Three halves
	// is not a measurement, so the honest pair would be discarded: the
	// attestation would have become a way to delete somebody else's evidence.
	EndpointPublicKeyHex string `json:"endpoint_public_key_hex"`
	// Probe is what was being measured. An attestation from a datagram probe
	// must not stand in for one from a session probe.
	Probe        string `json:"probe"`
	Observed     string `json:"observed"`
	PeerPublic   string `json:"peer_public"`
	AtUnix       uint64 `json:"at_unix"`
	PublicKeyHex string `json:"coordinator_public_key_hex"`
	SignatureHex string `json:"coordinator_signature_hex"`
}

// BindObservation is what one coordinator saw at bind time: this endpoint's
// external address as reflected off that coordinator, and nothing about a peer.
//
// The mapping class a route decision reads -- endpoint-independent versus a
// destination-dependent mapping -- is a fact about how the endpoint's NAT maps
// the same socket toward different destinations. No single coordinator can see
// it, and the endpoint cannot check it about itself, so it is derived from the
// set of these signed observations rather than taken from the endpoint's own
// declaration. Each coordinator attests only to the address it reflected, for a
// named endpoint, probe, session, and role; agreement or disagreement across
// several coordinators is what places the mapping.
type BindObservation struct {
	CoordinatorID string `json:"coordinator_id"`
	SessionID     string `json:"session_id"`
	Role          string `json:"role"`
	// EndpointPublicKeyHex is the key of the endpoint this reflection is about.
	// Without it a bind observation is a statement about a session rather than a
	// party, and one published by a bystander could be folded into a third
	// endpoint's trial.
	EndpointPublicKeyHex string `json:"endpoint_public_key_hex"`
	// Probe is what was being measured. A bind observation from one probe must
	// not stand in for another.
	Probe string `json:"probe"`
	// Observed is the external ip:port the coordinator reflected. Equal values
	// across coordinators mean the mapping does not depend on the destination;
	// differing values mean it does.
	Observed     string `json:"observed"`
	AtUnix       uint64 `json:"at_unix"`
	PublicKeyHex string `json:"coordinator_public_key_hex"`
	SignatureHex string `json:"coordinator_signature_hex"`
}

// CoordinatorID derives a coordinator's identifier from its key, so a
// coordinator cannot present itself under an identifier it does not hold the
// key for.
func CoordinatorID(key ed25519.PublicKey) (string, error) {
	if len(key) != ed25519.PublicKeySize || canon.IsZero(key) {
		return "", errors.New("invalid coordinator public key")
	}
	buffer := bytes.NewBufferString(canon.DomainReachabilityCoordinator)
	canon.Bytes(buffer, key)
	digest := canon.Digest(buffer.Bytes())
	return "srv_" + digest[len("sha256:"):len("sha256:")+16], nil
}

// ObservationSigningBytes returns the preimage a coordinator signs.
func ObservationSigningBytes(observation Observation) ([]byte, error) {
	if err := validateObservationShape(observation, false); err != nil {
		return nil, err
	}
	buffer := bytes.NewBufferString(canon.DomainReachabilityObservation)
	canon.Text(buffer, ObservationSchema)
	canon.Text(buffer, observation.CoordinatorID)
	canon.Text(buffer, observation.SessionID)
	canon.Text(buffer, observation.Role)
	canon.Text(buffer, observation.EndpointPublicKeyHex)
	canon.Text(buffer, observation.Probe)
	canon.Text(buffer, observation.Observed)
	canon.Text(buffer, observation.PeerPublic)
	canon.Uint64(buffer, observation.AtUnix)
	return buffer.Bytes(), nil
}

// SignObservation attests to what a coordinator saw.
func SignObservation(observation Observation, key ed25519.PrivateKey) (Observation, error) {
	if len(key) != ed25519.PrivateKeySize {
		return Observation{}, errors.New("invalid coordinator signing key")
	}
	public, ok := key.Public().(ed25519.PublicKey)
	if !ok {
		return Observation{}, errors.New("invalid coordinator signing key")
	}
	identifier, err := CoordinatorID(public)
	if err != nil {
		return Observation{}, err
	}
	observation.CoordinatorID = identifier
	observation.PublicKeyHex = hex.EncodeToString(public)
	observation.SignatureHex = ""
	preimage, err := ObservationSigningBytes(observation)
	if err != nil {
		return Observation{}, err
	}
	observation.SignatureHex = hex.EncodeToString(ed25519.Sign(key, preimage))
	return observation, nil
}

// VerifyObservation checks an attestation against the key it names.
func VerifyObservation(observation Observation) error {
	if err := validateObservationShape(observation, true); err != nil {
		return err
	}
	key, err := hex.DecodeString(observation.PublicKeyHex)
	if err != nil || len(key) != ed25519.PublicKeySize {
		return errors.New("invalid coordinator public key")
	}
	identifier, err := CoordinatorID(key)
	if err != nil {
		return err
	}
	if identifier != observation.CoordinatorID {
		return errors.New("coordinator identifier does not match its key")
	}
	signature, err := hex.DecodeString(observation.SignatureHex)
	if err != nil || len(signature) != ed25519.SignatureSize {
		return errors.New("invalid coordinator signature")
	}
	preimage, err := ObservationSigningBytes(observation)
	if err != nil {
		return err
	}
	if !ed25519.Verify(key, preimage, signature) {
		return errors.New("coordinator signature does not verify")
	}
	return nil
}

func validateObservationShape(observation Observation, signed bool) error {
	if !serverPattern.MatchString(observation.CoordinatorID) {
		return errors.New("invalid coordinator identifier")
	}
	if observation.SessionID == "" || len(observation.SessionID) > 128 {
		return errors.New("invalid observation session")
	}
	if observation.Role != "a" && observation.Role != "b" {
		return errors.New("invalid observation role")
	}
	if !keyPattern.MatchString(observation.EndpointPublicKeyHex) {
		return errors.New("invalid attested endpoint public key")
	}
	if !member(probes, ProbeKind(observation.Probe)) {
		return errors.New("invalid attested probe")
	}
	if _, err := netip.ParseAddrPort(observation.Observed); err != nil {
		return errors.New("invalid observed address")
	}
	if observation.PeerPublic != "yes" && observation.PeerPublic != "no" {
		return errors.New("invalid observed peer reachability")
	}
	if observation.AtUnix == 0 {
		return errors.New("invalid observation time")
	}
	if !keyPattern.MatchString(observation.PublicKeyHex) {
		return errors.New("invalid coordinator public key")
	}
	if signed && observation.SignatureHex == "" {
		return errors.New("observation is unsigned")
	}
	return nil
}

// BindObservationSigningBytes returns the preimage a coordinator signs for a
// bind observation.
func BindObservationSigningBytes(observation BindObservation) ([]byte, error) {
	if err := validateBindObservationShape(observation, false); err != nil {
		return nil, err
	}
	buffer := bytes.NewBufferString(canon.DomainReachabilityObservation)
	canon.Text(buffer, BindObservationSchema)
	canon.Text(buffer, observation.CoordinatorID)
	canon.Text(buffer, observation.SessionID)
	canon.Text(buffer, observation.Role)
	canon.Text(buffer, observation.EndpointPublicKeyHex)
	canon.Text(buffer, observation.Probe)
	canon.Text(buffer, observation.Observed)
	canon.Uint64(buffer, observation.AtUnix)
	return buffer.Bytes(), nil
}

// SignBindObservation attests to the external address a coordinator reflected.
func SignBindObservation(observation BindObservation, key ed25519.PrivateKey) (BindObservation, error) {
	if len(key) != ed25519.PrivateKeySize {
		return BindObservation{}, errors.New("invalid coordinator signing key")
	}
	public, ok := key.Public().(ed25519.PublicKey)
	if !ok {
		return BindObservation{}, errors.New("invalid coordinator signing key")
	}
	identifier, err := CoordinatorID(public)
	if err != nil {
		return BindObservation{}, err
	}
	observation.CoordinatorID = identifier
	observation.PublicKeyHex = hex.EncodeToString(public)
	observation.SignatureHex = ""
	preimage, err := BindObservationSigningBytes(observation)
	if err != nil {
		return BindObservation{}, err
	}
	observation.SignatureHex = hex.EncodeToString(ed25519.Sign(key, preimage))
	return observation, nil
}

// VerifyBindObservation checks a bind observation against the key it names.
func VerifyBindObservation(observation BindObservation) error {
	if err := validateBindObservationShape(observation, true); err != nil {
		return err
	}
	key, err := hex.DecodeString(observation.PublicKeyHex)
	if err != nil || len(key) != ed25519.PublicKeySize {
		return errors.New("invalid coordinator public key")
	}
	identifier, err := CoordinatorID(key)
	if err != nil {
		return err
	}
	if identifier != observation.CoordinatorID {
		return errors.New("coordinator identifier does not match its key")
	}
	signature, err := hex.DecodeString(observation.SignatureHex)
	if err != nil || len(signature) != ed25519.SignatureSize {
		return errors.New("invalid coordinator signature")
	}
	preimage, err := BindObservationSigningBytes(observation)
	if err != nil {
		return err
	}
	if !ed25519.Verify(key, preimage, signature) {
		return errors.New("coordinator signature does not verify")
	}
	return nil
}

func validateBindObservationShape(observation BindObservation, signed bool) error {
	if !serverPattern.MatchString(observation.CoordinatorID) {
		return errors.New("invalid bind coordinator identifier")
	}
	if observation.SessionID == "" || len(observation.SessionID) > 128 {
		return errors.New("invalid bind observation session")
	}
	if observation.Role != "a" && observation.Role != "b" {
		return errors.New("invalid bind observation role")
	}
	if !keyPattern.MatchString(observation.EndpointPublicKeyHex) {
		return errors.New("invalid bind attested endpoint public key")
	}
	if !member(probes, ProbeKind(observation.Probe)) {
		return errors.New("invalid bind attested probe")
	}
	if _, err := netip.ParseAddrPort(observation.Observed); err != nil {
		return errors.New("invalid bind observed address")
	}
	if observation.AtUnix == 0 {
		return errors.New("invalid bind observation time")
	}
	if !keyPattern.MatchString(observation.PublicKeyHex) {
		return errors.New("invalid bind coordinator public key")
	}
	if signed && observation.SignatureHex == "" {
		return errors.New("bind observation is unsigned")
	}
	return nil
}

// deriveMapping classifies the NAT mapping from coordinator-signed bind
// observations, exactly as the collector does at bind time.
//
// Two or more distinct coordinators that all reflected the same external
// address place an endpoint-independent mapping: the address does not depend on
// where the endpoint sends. Distinct coordinators that reflected differing
// addresses place a destination-dependent mapping; the bind test cannot tell
// its flavours (address-dependent, address-and-port-dependent, symmetric)
// apart, so the general address-and-port-dependent class stands for all of
// them. Fewer than two distinct coordinators cannot separate the two, so the
// mapping is undetermined -- and, deliberately, the no-NAT (none) case is not
// decided here at all: confirming it needs the host's own interface addresses,
// which a remote verifier does not hold.
func deriveMapping(observations []BindObservation) NATBehavior {
	coordinators := make(map[string]struct{}, len(observations))
	addresses := make(map[string]struct{}, len(observations))
	for _, observation := range observations {
		coordinators[observation.CoordinatorID] = struct{}{}
		addresses[observation.Observed] = struct{}{}
	}
	if len(coordinators) < 2 {
		return NATUndetermined
	}
	if len(addresses) == 1 {
		return NATEndpointIndependent
	}
	return NATAddressPortDependent
}

// mappingConsistent reports whether a declared NAT mapping class can stand
// against the class derived from the signed bind observations.
//
// The check refutes; it does not dictate. Undetermined evidence refutes
// nothing. All-equal reflections refute a destination-dependent declaration but
// leave a no-NAT claim alone, because an all-equal reflection is what a public
// host would also produce and the none case is not remotely verifiable.
// Differing reflections refute both endpoint-independent and no-NAT, because a
// host whose external address changes with the destination is behind a mapping
// that does. Undetermined is always allowed as a declaration: it under-claims
// rather than asserting a stratum the evidence denies.
//
// FILTERING behaviour -- whether the mapping also drops unsolicited inbound
// datagrams -- is a separate dimension a different probe measures, and is
// deliberately NOT derived or enforced here: the bind reflections speak only to
// how the address is mapped, not to what the filter admits. Deriving it is the
// remaining NAT-taxonomy work.
func mappingConsistent(declared, derived NATBehavior) bool {
	switch derived {
	case NATUndetermined:
		return true
	case NATEndpointIndependent:
		switch declared {
		case NATEndpointIndependent, NATNone, NATUndetermined:
			return true
		default:
			return false
		}
	case NATAddressPortDependent:
		switch declared {
		case NATAddressDependent, NATAddressPortDependent, NATSymmetric, NATUndetermined:
			return true
		default:
			return false
		}
	default:
		return false
	}
}

// SignTrial binds a trial to the endpoint that produced it.
//
// It does not make the endpoint trustworthy. What it does is make a trial
// unrewritable after the fact, and make one host reporting under several
// operator names detectable, because the same key would appear under each of
// them.
func SignTrial(trial Trial, key ed25519.PrivateKey) (Trial, error) {
	if len(key) != ed25519.PrivateKeySize {
		return Trial{}, errors.New("invalid endpoint signing key")
	}
	public, ok := key.Public().(ed25519.PublicKey)
	if !ok {
		return Trial{}, errors.New("invalid endpoint signing key")
	}
	trial.EndpointPublicKeyHex = hex.EncodeToString(public)
	trial.EndpointSignatureHex = ""
	digest, err := trial.Digest()
	if err != nil {
		return Trial{}, err
	}
	trial.EndpointSignatureHex = hex.EncodeToString(ed25519.Sign(key, []byte(digest)))
	return trial, nil
}

// VerifyTrial checks that a trial is signed by the endpoint it names and
// carries an attestation from a coordinator the policy predeclared.
//
// An unverifiable trial is not evidence. Accepting one because it looks
// plausible would make every threshold in the policy advisory.
func VerifyTrial(policy Policy, trial Trial) error {
	if err := trial.Validate(); err != nil {
		return err
	}
	key, err := hex.DecodeString(trial.EndpointPublicKeyHex)
	if err != nil || len(key) != ed25519.PublicKeySize {
		return errors.New("invalid endpoint public key")
	}
	signature, err := hex.DecodeString(trial.EndpointSignatureHex)
	if err != nil || len(signature) != ed25519.SignatureSize {
		return errors.New("invalid endpoint signature")
	}
	digest, err := trial.Digest()
	if err != nil {
		return err
	}
	if !ed25519.Verify(key, []byte(digest), signature) {
		return errors.New("endpoint signature does not verify")
	}
	if err := VerifyObservation(trial.Observation); err != nil {
		return err
	}
	if !policy.AcceptsCoordinator(trial.Observation.CoordinatorID) {
		return errors.New("observation comes from a coordinator the policy did not predeclare")
	}
	if trial.Observation.Role != string(trial.Role) {
		return errors.New("observation describes another role")
	}
	if trial.Observation.SessionID != trial.SessionID {
		return errors.New("observation describes another session")
	}
	// The attestation is about this endpoint, in this probe. A copied one
	// names somebody else's key and cannot be worn.
	if trial.Observation.EndpointPublicKeyHex != trial.EndpointPublicKeyHex {
		return errors.New("observation attests to another endpoint")
	}
	if trial.Observation.Probe != string(trial.Probe) {
		return errors.New("observation attests to another probe")
	}
	// The address family decides which cell a trial counts toward, and the
	// endpoint signs that declaration itself. The coordinator-signed observed
	// address is the family it was actually reached over, so a declaration that
	// contradicts it is the endpoint attesting to a stratum the evidence did not
	// see: a v4-only host claiming a v6 cell, or the reverse.
	observed, err := observedFamily(trial.Observation.Observed)
	if err != nil {
		return err
	}
	if !familyConsistent(trial.Local.Family, observed) {
		return errors.New("declared address family contradicts the coordinator-signed observed address")
	}
	// The NAT mapping class is derived from the per-coordinator bind
	// observations rather than taken from the endpoint's own declaration. Each
	// one has to verify under the key it names, come from a coordinator the
	// policy predeclared, and attest to this same endpoint, probe, session, and
	// role, or it is an unchecked assertion wearing a coordinator's name.
	for _, observation := range trial.BindObservations {
		if err := VerifyBindObservation(observation); err != nil {
			return err
		}
		if !policy.AcceptsCoordinator(observation.CoordinatorID) {
			return errors.New("a bind observation comes from a coordinator the policy did not predeclare")
		}
		if observation.EndpointPublicKeyHex != trial.EndpointPublicKeyHex {
			return errors.New("a bind observation attests to another endpoint")
		}
		if observation.Probe != string(trial.Probe) {
			return errors.New("a bind observation attests to another probe")
		}
		if observation.SessionID != trial.SessionID {
			return errors.New("a bind observation describes another session")
		}
		if observation.Role != string(trial.Role) {
			return errors.New("a bind observation describes another role")
		}
	}
	// The declared mapping must be consistent with what the signed reflections
	// show. Declaring endpoint-independent while distinct coordinators reflected
	// differing addresses, or the reverse, is the endpoint attesting to a
	// mapping class the evidence refutes, and the trial is rejected. With fewer
	// than two distinct coordinators the reflections are insufficient, so the
	// derived class is undetermined and no declaration is refuted -- the
	// residual case documented on mappingConsistent and EndpointStratum.
	if !mappingConsistent(trial.Local.NATBehavior, deriveMapping(trial.BindObservations)) {
		return errors.New("declared NAT mapping contradicts the coordinator-signed bind observations")
	}
	return nil
}

// observedFamily reports the address family a coordinator's signed observation
// was reached over. An endpoint cannot forge this without forging the
// coordinator's signature, which is why the family a trial counts toward is
// derived from here rather than taken from the endpoint's own declaration.
func observedFamily(observed string) (AddressFamily, error) {
	addrPort, err := netip.ParseAddrPort(observed)
	if err != nil {
		return "", errors.New("invalid observed address")
	}
	if addrPort.Addr().Unmap().Is4() {
		return FamilyIPv4, nil
	}
	return FamilyIPv6, nil
}

// familyConsistent reports whether a declared family can hold an observation of
// the given family. A dual-stack endpoint legitimately answers over either
// family, so only a single-family declaration that contradicts what the
// coordinator observed is a claim the signed evidence refutes.
func familyConsistent(declared, observed AddressFamily) bool {
	switch declared {
	case FamilyIPv4:
		return observed == FamilyIPv4
	case FamilyIPv6:
		return observed == FamilyIPv6
	case FamilyDual:
		return true
	default:
		return false
	}
}

// AcceptsCoordinator reports whether a policy predeclared a coordinator.
func (p Policy) AcceptsCoordinator(identifier string) bool {
	for _, candidate := range p.Coordinators {
		if candidate == identifier {
			return true
		}
	}
	return false
}
