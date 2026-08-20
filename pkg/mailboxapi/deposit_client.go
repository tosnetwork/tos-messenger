package mailboxapi

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"time"

	"github.com/tosnetwork/tos-messenger/pkg/envelope"
	"github.com/tosnetwork/tos-messenger/pkg/mailbox"
)

// DepositClient adapts the bounded service protocol to mailbox.RelayClient.
// Every attempt signs a fresh operation nonce while preserving the caller's
// exact ciphertext and message identifier for idempotent storage retries.
type DepositClient struct {
	client *Client
	grant  mailbox.CapabilityGrant
	key    ed25519.PrivateKey
	now    func() time.Time
}

func NewDepositClient(client *Client, grant mailbox.CapabilityGrant, key ed25519.PrivateKey, now func() time.Time) (*DepositClient, error) {
	if client == nil || len(key) != ed25519.PrivateKeySize {
		return nil, errors.New("invalid Mailbox deposit client")
	}
	if _, err := mailbox.GrantCanonicalBytes(grant); err != nil {
		return nil, err
	}
	public, err := hex.DecodeString(grant.CapabilityPublicKeyHex)
	if err != nil || !ed25519.PublicKey(key.Public().(ed25519.PublicKey)).Equal(ed25519.PublicKey(public)) {
		return nil, errors.New("Mailbox capability key does not match its grant")
	}
	if now == nil {
		now = time.Now
	}
	return &DepositClient{client: client, grant: grant, key: append(ed25519.PrivateKey(nil), key...), now: now}, nil
}

func (c *DepositClient) PublicKeyHex() string {
	if c == nil {
		return ""
	}
	return c.grant.RelayPublicKeyHex
}

func (c *DepositClient) Store(ctx context.Context, value envelope.RelayEnvelope) (mailbox.StoredAck, error) {
	if c == nil || ctx == nil {
		return mailbox.StoredAck{}, errors.New("invalid Mailbox deposit attempt")
	}
	digest, err := mailbox.DepositBodyDigest(value)
	if err != nil {
		return mailbox.StoredAck{}, err
	}
	grantDigest, err := mailbox.GrantDigest(c.grant)
	if err != nil {
		return mailbox.StoredAck{}, err
	}
	now := c.now()
	if now.IsZero() || now.Unix() < 0 {
		return mailbox.StoredAck{}, errors.New("invalid Mailbox deposit time")
	}
	expires := now.Add(mailbox.MaxRequestLifetime)
	if expires.Unix() > int64(c.grant.ExpiresAtUnix) {
		expires = time.Unix(int64(c.grant.ExpiresAtUnix), 0)
	}
	if !expires.After(now) {
		return mailbox.StoredAck{}, errors.New("Mailbox grant is expired")
	}
	var nonce [32]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return mailbox.StoredAck{}, err
	}
	access, err := mailbox.SignAccessRequest(mailbox.AccessRequest{GrantDigest: grantDigest, Operation: mailbox.OperationDeposit, MailboxID: c.grant.MailboxID, BodyDigest: digest, NonceHex: hex.EncodeToString(nonce[:]), IssuedAtUnix: uint64(now.Unix()), ExpiresAtUnix: uint64(expires.Unix())}, c.key)
	if err != nil {
		return mailbox.StoredAck{}, err
	}
	grantRaw, err := mailbox.EncodeGrantJSON(c.grant)
	if err != nil {
		return mailbox.StoredAck{}, err
	}
	accessRaw, err := mailbox.EncodeAccessRequestJSON(access)
	if err != nil {
		return mailbox.StoredAck{}, err
	}
	envelopeRaw, err := envelope.EncodeRelayJSON(value)
	if err != nil {
		return mailbox.StoredAck{}, err
	}
	response, err := c.client.Call(ctx, Request{Op: OpDeposit, Grant: grantRaw, Access: accessRaw, Envelope: envelopeRaw})
	if err != nil {
		return mailbox.StoredAck{}, err
	}
	return mailbox.DecodeAckJSON(response.Ack)
}

var _ mailbox.RelayClient = (*DepositClient)(nil)
