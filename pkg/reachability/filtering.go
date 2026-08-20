package reachability

import (
	"bytes"
	"crypto/ed25519"
	"encoding/hex"
	"errors"
	"net/netip"

	"github.com/tosnetwork/tos-messenger/internal/canon"
)

const (
	// FilteringObservationSchema is the strict schema of a per-coordinator
	// filtering observation. It shares the observation domain separator with
	// ObservationSchema and BindObservationSchema, and the three are told apart
	// by this schema string: canon.Text length-prefixes it, so a preimage under
	// one schema can never be reinterpreted as another, and a signature over a
	// filtering observation cannot be worn as a bind or pair observation.
	FilteringObservationSchema = "tos.messaging.reachability-filtering-observation.v1"

	// MaxFilteringObservations bounds the per-coordinator filtering
	// observations one trial may carry: at most one per coordinator and cold
	// source kind. Anything larger is padding, and an unbounded set is a
	// preimage a reporter chooses the size of.
	MaxFilteringObservations = 2 * MaxBindObservations
)

// FilteringBehavior is what a NAT's filter demonstrably admits.
//
// Filtering and mapping are independent axes of NAT behavior. The mapping says
// which external address a socket appears at; the filter says which remote
// sources may reach that address inbound. The bind reflections that classify
// the mapping say nothing about the filter, so the filter has its own evidence
// (FilteringObservation) and its own vocabulary here. A route decision that
// read the mapping class as if it covered filtering would be reading evidence
// that was never collected.
type FilteringBehavior string

const (
	// FilteringEndpointIndependent means a datagram from a source the endpoint
	// never contacted was demonstrably admitted, including one from an address
	// the endpoint never sent to.
	FilteringEndpointIndependent FilteringBehavior = "endpoint-independent"
	// FilteringAddressDependent means a datagram from an uncontacted port on a
	// contacted address was demonstrably admitted; nothing showed an
	// uncontacted address through.
	FilteringAddressDependent FilteringBehavior = "address-dependent"
	// FilteringAddressPortDependent means only the exact contacted ip:port may
	// answer. It is in the vocabulary so a consumer can express the class, but
	// it is never derived remotely: the only signal for it is a probe that did
	// not arrive, and an absent probe is indistinguishable from a lost one.
	FilteringAddressPortDependent FilteringBehavior = "address-and-port-dependent"
	// FilteringUndetermined means no cold-source receipt was demonstrated.
	FilteringUndetermined FilteringBehavior = "undetermined"
)

// FilterSourceKind names the relation of a cold probe's source to the flow the
// endpoint had established: a second port on the address the endpoint was
// already talking to, or an address it never contacted at all.
type FilterSourceKind string

const (
	// FilterSourceOtherPort is a source port the endpoint never contacted, on
	// the coordinator address it was already talking to. A receipt from it
	// shows the filter is not port-restricted.
	FilterSourceOtherPort FilterSourceKind = "same-address-other-port"
	// FilterSourceOtherAddress is an address the endpoint never contacted. A
	// receipt from it shows the filter admits arbitrary external sources.
	FilterSourceOtherAddress FilterSourceKind = "other-address"
)

var filterSourceKinds = set(FilterSourceOtherPort, FilterSourceOtherAddress)

// FilteringObservation is what one coordinator attests about an endpoint's
// inbound filtering: that a datagram it sent from a cold source -- one the
// endpoint had never contacted -- was demonstrably received.
//
// The proof is a random token. The coordinator sends it from the cold source
// to the external address it observed on the endpoint's established flow, and
// the endpoint can only echo the token back if the datagram was admitted.
// Nothing is taken from the endpoint's own claim: the endpoint cannot forge a
// receipt it never had, because the token travels only through the path being
// tested, and it cannot wear somebody else's, because the attestation names
// the endpoint key that will sign the trial.
type FilteringObservation struct {
	CoordinatorID string `json:"coordinator_id"`
	SessionID     string `json:"session_id"`
	Role          string `json:"role"`
	// EndpointPublicKeyHex is the key of the endpoint this receipt is about.
	// Without it a filtering observation is a statement about a session rather
	// than a party, and one published by a bystander could be folded into a
	// third endpoint's trial.
	EndpointPublicKeyHex string `json:"endpoint_public_key_hex"`
	// Probe is what was being measured. A filtering observation from one probe
	// must not stand in for another.
	Probe string `json:"probe"`
	// Observed is the external ip:port the cold probe was sent to: the source
	// address of the endpoint's established flow as the coordinator saw it.
	Observed string `json:"observed"`
	// Source is which cold source the endpoint demonstrably received from.
	Source       FilterSourceKind `json:"filter_source"`
	AtUnix       uint64           `json:"at_unix"`
	PublicKeyHex string           `json:"coordinator_public_key_hex"`
	SignatureHex string           `json:"coordinator_signature_hex"`
}

// FilteringObservationSigningBytes returns the preimage a coordinator signs
// for a filtering observation.
func FilteringObservationSigningBytes(observation FilteringObservation) ([]byte, error) {
	if err := validateFilteringObservationShape(observation, false); err != nil {
		return nil, err
	}
	buffer := bytes.NewBufferString(canon.DomainReachabilityObservation)
	canon.Text(buffer, FilteringObservationSchema)
	canon.Text(buffer, observation.CoordinatorID)
	canon.Text(buffer, observation.SessionID)
	canon.Text(buffer, observation.Role)
	canon.Text(buffer, observation.EndpointPublicKeyHex)
	canon.Text(buffer, observation.Probe)
	canon.Text(buffer, observation.Observed)
	canon.Text(buffer, string(observation.Source))
	canon.Uint64(buffer, observation.AtUnix)
	return buffer.Bytes(), nil
}

// SignFilteringObservation attests that an endpoint demonstrably received a
// coordinator's cold-source probe.
func SignFilteringObservation(observation FilteringObservation, key ed25519.PrivateKey) (FilteringObservation, error) {
	if len(key) != ed25519.PrivateKeySize {
		return FilteringObservation{}, errors.New("invalid coordinator signing key")
	}
	public, ok := key.Public().(ed25519.PublicKey)
	if !ok {
		return FilteringObservation{}, errors.New("invalid coordinator signing key")
	}
	identifier, err := CoordinatorID(public)
	if err != nil {
		return FilteringObservation{}, err
	}
	observation.CoordinatorID = identifier
	observation.PublicKeyHex = hex.EncodeToString(public)
	observation.SignatureHex = ""
	preimage, err := FilteringObservationSigningBytes(observation)
	if err != nil {
		return FilteringObservation{}, err
	}
	observation.SignatureHex = hex.EncodeToString(ed25519.Sign(key, preimage))
	return observation, nil
}

// VerifyFilteringObservation checks a filtering observation against the key it
// names.
func VerifyFilteringObservation(observation FilteringObservation) error {
	if err := validateFilteringObservationShape(observation, true); err != nil {
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
	preimage, err := FilteringObservationSigningBytes(observation)
	if err != nil {
		return err
	}
	if !ed25519.Verify(key, preimage, signature) {
		return errors.New("coordinator signature does not verify")
	}
	return nil
}

func validateFilteringObservationShape(observation FilteringObservation, signed bool) error {
	if !serverPattern.MatchString(observation.CoordinatorID) {
		return errors.New("invalid filtering coordinator identifier")
	}
	if observation.SessionID == "" || len(observation.SessionID) > 128 {
		return errors.New("invalid filtering observation session")
	}
	if observation.Role != "a" && observation.Role != "b" {
		return errors.New("invalid filtering observation role")
	}
	if !keyPattern.MatchString(observation.EndpointPublicKeyHex) {
		return errors.New("invalid filtering attested endpoint public key")
	}
	if !member(probes, ProbeKind(observation.Probe)) {
		return errors.New("invalid filtering attested probe")
	}
	if _, err := netip.ParseAddrPort(observation.Observed); err != nil {
		return errors.New("invalid filtering observed address")
	}
	if !member(filterSourceKinds, observation.Source) {
		return errors.New("invalid filtering source kind")
	}
	if observation.AtUnix == 0 {
		return errors.New("invalid filtering observation time")
	}
	if !keyPattern.MatchString(observation.PublicKeyHex) {
		return errors.New("invalid filtering coordinator public key")
	}
	if signed && observation.SignatureHex == "" {
		return errors.New("filtering observation is unsigned")
	}
	return nil
}

// DeriveFiltering classifies the NAT's inbound filtering from coordinator
// signed cold-source receipts, and from nothing else.
//
// The stance mirrors deriveMapping's, with one difference the evidence forces:
// there is no declared filtering class to refute, because an endpoint is never
// asked for one. Filtering is derived from evidence or it is undetermined --
// evidence over declaration, taken to the point where the declaration does not
// exist.
//
// The derivation is asymmetric because the evidence is. A receipt proves the
// filter admitted a source, so it can only ever loosen the class: a receipt
// from an uncontacted address demonstrates endpoint-independent filtering, and
// a receipt from an uncontacted port on a contacted address demonstrates the
// filter is at most address-dependent. The absence of a receipt proves
// nothing, because a probe the filter dropped and a probe the network lost are
// the same silence; that is why address-and-port-dependent is never derived
// here and why an empty set is undetermined rather than strict.
func DeriveFiltering(observations []FilteringObservation) FilteringBehavior {
	otherPort := false
	for _, observation := range observations {
		switch observation.Source {
		case FilterSourceOtherAddress:
			return FilteringEndpointIndependent
		case FilterSourceOtherPort:
			otherPort = true
		}
	}
	if otherPort {
		return FilteringAddressDependent
	}
	return FilteringUndetermined
}
