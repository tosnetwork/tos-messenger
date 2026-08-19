// Package probe implements the M0-R measurement transport.
//
// The study needs two things the Messenger protocol itself does not: a
// rendezvous point that both endpoints can reach, and a datagram exchange that
// tries to establish a direct path between them. Neither is part of the
// Messenger. Nothing here signs, encrypts, or carries application content, and
// no code in this package may be reused as a transport: it exists to produce
// evidence, and it says so.
//
// The wire format has one property that is not about measurement. A UDP
// service that answers with more bytes than it received is a traffic amplifier
// for anyone willing to spoof a source address. Requests therefore carry
// padding to a floor, and a response larger than the request it answers is
// never sent.
package probe

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"net/netip"
	"regexp"
	"strings"

	"github.com/tosnetwork/tos-messenger/pkg/reachability"
)

const (
	// Schema is the strict message schema identifier.
	Schema = "tos.messaging.reachability-probe.v1"

	// MinRequestBytes is the padded floor every client request must reach. It
	// is what makes a response strictly smaller than its request, and it rose
	// when responses began carrying a signed attestation.
	MinRequestBytes = 768
	// MaxMessageBytes bounds one datagram this package will parse.
	MaxMessageBytes = 1400
	// MaxCandidates bounds one advertised candidate set.
	MaxCandidates = 8
)

// Kind is the message type.
type Kind string

const (
	// KindBind asks the coordinator what source address it observed.
	KindBind Kind = "bind"
	// KindBindOK reports the observed address.
	KindBindOK Kind = "bind-ok"
	// KindPair publishes this endpoint's candidates and asks for the peer's.
	KindPair Kind = "pair"
	// KindPairOK returns the peer's candidates, empty until the peer arrives.
	KindPairOK Kind = "pair-ok"
	// KindPunch is a direct peer-to-peer probe.
	KindPunch Kind = "punch"
	// KindPunchAck answers a direct probe.
	KindPunchAck Kind = "punch-ack"
	// KindError reports a refused request.
	KindError Kind = "error"

	// PeerPublicYes reports that the peer's reflexive address is one of its
	// own local addresses, so nothing mapped it.
	PeerPublicYes = "yes"
	// PeerPublicNo reports that the peer sits behind a mapping.
	PeerPublicNo = "no"
)

// Role distinguishes the two endpoints of one measured pair.
type Role string

const (
	// RoleA is the endpoint that initiates the session.
	RoleA Role = "a"
	// RoleB is the endpoint that joins it.
	RoleB Role = "b"
)

var (
	sessionPattern      = regexp.MustCompile(`^ses_[0-9a-f]{32}$`)
	noncePattern        = regexp.MustCompile(`^[0-9a-f]{32}$`)
	endpointKeyPattern  = regexp.MustCompile(`^[0-9a-f]{64}$`)
	serverPattern       = regexp.MustCompile(`^srv_[0-9a-f]{16}$`)
	paddingPattern      = regexp.MustCompile(`^p*$`)
	commitPattern       = regexp.MustCompile(`^[0-9a-f]{40}$|^[0-9a-f]{64}$`)
	hexKeyPattern       = regexp.MustCompile(`^[0-9a-f]{64}$`)
	hexSignaturePattern = regexp.MustCompile(`^[0-9a-f]{128}$`)
	kinds               = map[Kind]struct{}{
		KindBind: {}, KindBindOK: {}, KindPair: {}, KindPairOK: {},
		KindPunch: {}, KindPunchAck: {}, KindError: {},
	}
)

// Message is one probe datagram.
type Message struct {
	Schema     string   `json:"schema"`
	Kind       Kind     `json:"kind"`
	SessionID  string   `json:"session_id"`
	Role       Role     `json:"role"`
	Nonce      string   `json:"nonce"`
	Sequence   uint32   `json:"sequence,omitempty"`
	Observed   string   `json:"observed,omitempty"`
	Candidates []string `json:"candidates,omitempty"`
	ServerID   string   `json:"server_id,omitempty"`
	Commit     string   `json:"commit,omitempty"`
	PeerCommit string   `json:"peer_commit,omitempty"`
	PeerPublic string   `json:"peer_public,omitempty"`
	// EndpointKey is the key the endpoint will sign its trial with, presented
	// so the coordinator can attest to a party rather than only to a session.
	EndpointKey string `json:"endpoint_key,omitempty"`
	// Probe names what is being measured, so an attestation from one probe
	// cannot stand in for another.
	Probe      string `json:"probe,omitempty"`
	ObservedAt uint64 `json:"observed_at,omitempty"`
	SignerKey  string `json:"coordinator_public_key,omitempty"`
	Signature  string `json:"coordinator_signature,omitempty"`
	Reason     string `json:"reason,omitempty"`
	Padding    string `json:"padding,omitempty"`
}

// Peer returns the other role.
func (r Role) Peer() Role {
	if r == RoleA {
		return RoleB
	}
	return RoleA
}

// Encode returns the datagram for a valid message.
func Encode(message Message) ([]byte, error) {
	if err := Validate(message); err != nil {
		return nil, err
	}
	message.Schema = Schema
	encoded, err := json.Marshal(message)
	if err != nil {
		return nil, err
	}
	if len(encoded) > MaxMessageBytes {
		return nil, errors.New("probe message exceeds its datagram bound")
	}
	return encoded, nil
}

// EncodeRequest pads a client request to the amplification floor.
func EncodeRequest(message Message) ([]byte, error) {
	encoded, err := Encode(message)
	if err != nil {
		return nil, err
	}
	if len(encoded) >= MinRequestBytes {
		return encoded, nil
	}
	// Padding is added to the message and re-encoded so the padded bytes are
	// covered by the same validation as everything else.
	message.Padding = strings.Repeat("p", MinRequestBytes-len(encoded))
	padded, err := Encode(message)
	if err != nil {
		return nil, err
	}
	if len(padded) < MinRequestBytes {
		return nil, errors.New("probe request could not reach its padding floor")
	}
	return padded, nil
}

// Decode parses and validates one datagram.
func Decode(raw []byte) (Message, error) {
	if len(raw) == 0 || len(raw) > MaxMessageBytes {
		return Message{}, errors.New("probe message is outside its datagram bound")
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	var message Message
	if err := decoder.Decode(&message); err != nil {
		return Message{}, err
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return Message{}, errors.New("probe message has trailing JSON")
	}
	if message.Schema != Schema {
		return Message{}, errors.New("unsupported probe schema")
	}
	if err := Validate(message); err != nil {
		return Message{}, err
	}
	return message, nil
}

// Validate enforces every structural rule.
func Validate(message Message) error {
	if _, known := kinds[message.Kind]; !known {
		return errors.New("invalid probe message kind")
	}
	if !sessionPattern.MatchString(message.SessionID) {
		return errors.New("invalid probe session identifier")
	}
	if message.Role != RoleA && message.Role != RoleB {
		return errors.New("invalid probe role")
	}
	if !noncePattern.MatchString(message.Nonce) {
		return errors.New("invalid probe nonce")
	}
	if message.Observed != "" {
		if _, err := netip.ParseAddrPort(message.Observed); err != nil {
			return errors.New("invalid observed address")
		}
	}
	if len(message.Candidates) > MaxCandidates {
		return errors.New("too many probe candidates")
	}
	seen := make(map[string]struct{}, len(message.Candidates))
	for _, candidate := range message.Candidates {
		address, err := netip.ParseAddrPort(candidate)
		if err != nil {
			return errors.New("invalid probe candidate")
		}
		if address.Port() == 0 || !address.Addr().IsValid() {
			return errors.New("invalid probe candidate")
		}
		if _, duplicate := seen[candidate]; duplicate {
			return errors.New("duplicate probe candidate")
		}
		seen[candidate] = struct{}{}
	}
	if message.ServerID != "" && !serverPattern.MatchString(message.ServerID) {
		return errors.New("invalid probe server identifier")
	}
	if message.PeerPublic != "" && message.PeerPublic != PeerPublicYes && message.PeerPublic != PeerPublicNo {
		return errors.New("invalid peer reachability")
	}
	if message.EndpointKey != "" && !endpointKeyPattern.MatchString(message.EndpointKey) {
		return errors.New("invalid endpoint key")
	}
	if message.Probe != "" && message.Probe != string(reachability.ProbeUDP) &&
		message.Probe != string(reachability.ProbeADNL) {
		return errors.New("invalid probe kind")
	}
	// A pairing request is what the coordinator attests to, so it has to say
	// which endpoint and which probe it is asking about.
	if message.Kind == KindPair {
		if message.EndpointKey == "" {
			return errors.New("a pairing request must present the endpoint key it will sign with")
		}
		if message.Probe == "" {
			return errors.New("a pairing request must say what it is measuring")
		}
	}
	if message.Commit != "" && !commitPattern.MatchString(message.Commit) {
		return errors.New("invalid probe commit")
	}
	if message.SignerKey != "" && !hexKeyPattern.MatchString(message.SignerKey) {
		return errors.New("invalid coordinator public key")
	}
	if message.Signature != "" && !hexSignaturePattern.MatchString(message.Signature) {
		return errors.New("invalid coordinator signature")
	}
	if message.PeerCommit != "" && !commitPattern.MatchString(message.PeerCommit) {
		return errors.New("invalid probe peer commit")
	}
	if len(message.Reason) > 64 {
		return errors.New("probe reason exceeds its bound")
	}
	if !paddingPattern.MatchString(message.Padding) {
		return errors.New("invalid probe padding")
	}
	return nil
}

// CheckNoAmplification refuses a response that is larger than the request it
// answers. The caller drops the response rather than sending it, which is what
// keeps a spoofed source address from turning this service into a weapon.
func CheckNoAmplification(request, response []byte) error {
	if len(request) < MinRequestBytes {
		return errors.New("probe request is below the padding floor")
	}
	if len(response) > len(request) {
		return errors.New("probe response would amplify its request")
	}
	return nil
}
