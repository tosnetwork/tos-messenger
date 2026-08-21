package localapi

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"sync"
	"time"

	"github.com/tosnetwork/tos-messenger/internal/canon"
	"github.com/tosnetwork/tos-messenger/pkg/fault"
)

const (
	// ChallengeBytes is the size of a single-use decision nonce.
	ChallengeBytes = 32
	// DefaultChallengeLifetime bounds how long an unanswered challenge stands.
	DefaultChallengeLifetime = 2 * time.Minute
	// MaxOutstandingChallenges bounds how many may stand at once, so a caller
	// cannot fill memory by asking for challenges it never uses.
	MaxOutstandingChallenges = 64
)

// deciding is the set of operations that change something on the owner's
// authority. Reading what is waiting is not one of them: seeing the queue
// grants nothing, and requiring a signature to look at it would push owners
// towards leaving a signing key where their tools can reach it.
var deciding = map[Operation]struct{}{
	OpAdmit: {}, OpRefuse: {}, OpApprove: {}, OpDeny: {},
	OpGrantAction: {}, OpDenyAction: {},
	OpPlaceMandate: {}, OpRevokeMandate: {},
	OpCreateAdmissionInvite: {},
	OpRecordEscrowLocation:  {},
	OpExportDeviceHistory:   {},
}

// Deciding reports whether an operation needs the owner's signature.
func Deciding(operation Operation) bool {
	_, found := deciding[operation]
	return found
}

// challenges issues and retires single-use decision nonces.
//
// A signature with no nonce would be replayable: whoever saw one approve a
// payment could present it again for the next identical request. The nonce is
// issued here, spent once, and expires whether or not it is used.
type challenges struct {
	mutex    sync.Mutex
	issued   map[string]time.Time
	lifetime time.Duration
}

func newChallenges(lifetime time.Duration) *challenges {
	if lifetime <= 0 {
		lifetime = DefaultChallengeLifetime
	}
	return &challenges{issued: map[string]time.Time{}, lifetime: lifetime}
}

func (c *challenges) issue(now time.Time) (string, error) {
	raw := make([]byte, ChallengeBytes)
	if _, err := rand.Read(raw); err != nil {
		return "", errors.New("could not generate a decision challenge")
	}
	value := hex.EncodeToString(raw)

	c.mutex.Lock()
	defer c.mutex.Unlock()
	c.expire(now)
	if len(c.issued) >= MaxOutstandingChallenges {
		return "", errors.New("too many decision challenges are outstanding")
	}
	c.issued[value] = now.Add(c.lifetime)
	return value, nil
}

// spend consumes a challenge, once.
func (c *challenges) spend(value string, now time.Time) error {
	c.mutex.Lock()
	defer c.mutex.Unlock()
	c.expire(now)
	deadline, found := c.issued[value]
	if !found {
		return errors.New("this decision challenge was never issued, or has already been used")
	}
	if !now.Before(deadline) {
		delete(c.issued, value)
		return errors.New("this decision challenge has expired")
	}
	delete(c.issued, value)
	return nil
}

func (c *challenges) expire(now time.Time) {
	for value, deadline := range c.issued {
		if !now.Before(deadline) {
			delete(c.issued, value)
		}
	}
}

// DecisionBytes returns what an owner signs to authorise one decision.
//
// It commits the operation and its subject, so a signature for admitting an
// event cannot be presented as one for releasing a payment, and it commits the
// challenge, so a signature cannot be presented twice.
func DecisionBytes(request Request, challenge string) ([]byte, error) {
	if !Deciding(request.Op) {
		return nil, errors.New("this operation is not an owner decision")
	}
	if !challengePattern.MatchString(challenge) {
		return nil, errors.New("invalid decision challenge")
	}
	buffer := bytes.NewBufferString(canon.DomainOwnerDecision)
	canon.Text(buffer, RequestSchema)
	canon.Text(buffer, string(request.Op))
	canon.Text(buffer, challenge)
	canon.Text(buffer, request.EventID)
	canon.Text(buffer, request.ActionID)
	canon.Text(buffer, request.MandateID)
	canon.Text(buffer, string(request.Code))
	canon.Text(buffer, request.Reason)
	canon.Text(buffer, request.InvitedAgentID)
	canon.Uint64(buffer, request.InviteExpiresAtUnix)
	if request.Op == OpRecordEscrowLocation {
		canon.Text(buffer, request.QuoteCommitment)
		canon.Text(buffer, request.EscrowAddress)
		canon.Text(buffer, request.CapabilityClass)
	}
	if request.Op == OpExportDeviceHistory {
		canon.Text(buffer, request.TargetDeviceID)
		canon.Text(buffer, request.ConversationID)
		canon.Uint64(buffer, request.HistorySequence)
		canon.Text(buffer, request.PreviousSegmentDigest)
		canon.Uint64(buffer, request.AfterCreatedAtUnix)
		canon.Text(buffer, request.AfterEventID)
		canon.Uint32(buffer, uint32(request.Limit))
		canon.Text(buffer, request.IdempotencyKey)
		canon.Uint64(buffer, request.ExpiresAtUnix)
	}
	// A mandate is placed by value, so what is signed is the authorisation
	// itself rather than a name for it.
	if request.Mandate != nil {
		genesisRoot, rootErr := hex.DecodeString(request.Mandate.Asset.GenesisRootHash)
		genesisFile, fileErr := hex.DecodeString(request.Mandate.Asset.GenesisFileHash)
		if rootErr != nil || fileErr != nil || len(genesisRoot) != 32 || len(genesisFile) != 32 {
			return nil, errors.New("invalid mandate network hashes")
		}
		canon.Text(buffer, request.Mandate.Objective)
		canon.Text(buffer, request.Mandate.Authority)
		canon.Text(buffer, request.Mandate.CapabilityClass)
		canon.Text(buffer, request.Mandate.Asset.NetworkID)
		canon.Bytes(buffer, genesisRoot)
		canon.Bytes(buffer, genesisFile)
		canon.Uint32(buffer, uint32(request.Mandate.Asset.Workchain))
		canon.Text(buffer, request.Mandate.Asset.AccountID)
		canon.Text(buffer, request.Mandate.Asset.MasterCodeHash)
		canon.Text(buffer, request.Mandate.Asset.WalletCodeHash)
		canon.Uint32(buffer, request.Mandate.Asset.Decimals)
		canon.Text(buffer, request.Mandate.MaxTotalAtomic)
		canon.Text(buffer, request.Mandate.ApprovalAboveAtomic)
		canon.Uint32(buffer, request.Mandate.MaxCounteroffers)
		canon.Uint64(buffer, request.Mandate.ExpiresAtUnix)
	}
	return buffer.Bytes(), nil
}

// SignDecision produces the signature an owner tool presents.
func SignDecision(request Request, challenge string, key ed25519.PrivateKey) (string, error) {
	if len(key) != ed25519.PrivateKeySize {
		return "", errors.New("invalid owner signing key")
	}
	preimage, err := DecisionBytes(request, challenge)
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(ed25519.Sign(key, preimage)), nil
}

// authoriseDecision checks that a decision came from the owner.
//
// Peer credentials cannot do this. They establish which Unix user is calling,
// and the Agent runtime very often runs as that same user: a runtime that
// asked for an approval could then connect to the owner's socket and grant its
// own request. What separates the two is possession of a key the runtime does
// not have, so that is what is checked.
func (s *Server) authoriseDecision(request Request, now time.Time) error {
	if !Deciding(request.Op) {
		return nil
	}
	signature, err := hex.DecodeString(request.OwnerSignature)
	if err != nil || len(signature) != ed25519.SignatureSize {
		return errors.New("invalid owner signature")
	}
	preimage, err := DecisionBytes(request, request.Challenge)
	if err != nil {
		return err
	}
	if !ed25519.Verify(s.config.OwnerKey, preimage, signature) {
		return errors.New("this decision was not signed by the owner")
	}
	// The challenge is spent only after the signature verifies, so a wrong
	// signature cannot burn a challenge the owner is about to use.
	return s.challenges.spend(request.Challenge, now)
}

// challenge issues a fresh nonce for one decision.
func (s *Server) challenge(now time.Time) Response {
	value, err := s.challenges.issue(now)
	if err != nil {
		return refuse(fault.CodeInternal, err)
	}
	return Response{Schema: ResponseSchema, OK: true, Challenge: value}
}
