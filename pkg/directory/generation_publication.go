package directory

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ed25519"
	"errors"
	"time"

	"github.com/tosnetwork/tos-messenger/pkg/identity"
)

// PublicGeneration is the durable public-only output of an exact device
// collection. The publication coordinator needs no answering secret.
type PublicGeneration struct {
	SetDigest string
	JSON      []byte
	IssuedAt  uint64
	ExpiresAt uint64
}

// LocatorPublisher is the final authority-changing publication boundary.
type LocatorPublisher interface {
	PublishLocator(context.Context, identity.Delegation, Locator, crypto.Signer) (int, error)
}

// GenerationPublisher composes immutable HTTPS objects and the native DHT
// locator without owning the Endpoint key. Repeated calls are byte-identical;
// the native DHT adapter refreshes the outer cache envelope around that same
// inner signed locator.
type GenerationPublisher struct {
	Objects         HTTPSPublicationSink
	Locators        LocatorPublisher
	Signer          crypto.Signer
	Delegation      identity.Delegation
	Policy          DescriptorPolicy
	Descriptor      Descriptor
	PublishInterval time.Duration
}

func (p *GenerationPublisher) Validate() error {
	if p == nil || p.Objects == nil || p.Locators == nil || p.Signer == nil {
		return errors.New("generation publication is not configured")
	}
	if p.PublishInterval < time.Minute || p.PublishInterval > time.Hour {
		return errors.New("generation publication interval is outside its bound")
	}
	activationStep := time.Duration(p.Policy.MaxLifetimeSeconds/2) * time.Second
	if activationStep < time.Minute || p.PublishInterval > activationStep {
		return errors.New("generation publication interval cannot cover the descriptor renewal window")
	}
	public, ok := p.Signer.Public().(ed25519.PublicKey)
	if !ok || len(public) != ed25519.PublicKeySize || !bytes.Equal(public, p.Delegation.IdentityPublicKey) {
		return errors.New("generation publisher signer is not the delegated Endpoint key")
	}
	policyDigest, err := p.Policy.Digest()
	if err != nil || policyDigest != p.Delegation.ContactDescriptorPolicyDigest {
		return errors.New("generation publisher policy does not match its delegation")
	}
	delegationDigest, err := identity.Digest(p.Delegation)
	if err != nil || p.Descriptor.Network == nil || p.Descriptor.AgentID != p.Delegation.AgentID ||
		p.Descriptor.EndpointID != p.Delegation.EndpointID || p.Descriptor.DelegationDigest != delegationDigest ||
		p.Descriptor.ADNLID != p.Delegation.ADNLID ||
		p.Descriptor.InboxAdmissionPolicyDigest != p.Delegation.InboxAdmissionPolicyDigest ||
		p.Descriptor.Network.NetworkId != p.Delegation.Network.NetworkId ||
		p.Descriptor.Network.GenesisRootHash != p.Delegation.Network.GenesisRootHash ||
		p.Descriptor.Network.GenesisFileHash != p.Delegation.Network.GenesisFileHash {
		return errors.New("generation publisher descriptor does not match its delegation")
	}
	descriptor := p.Descriptor
	descriptor.PrekeyBundleDigest = "sha256:" + "1111111111111111111111111111111111111111111111111111111111111111"
	descriptor.IssuedAtUnix = p.Delegation.NotBeforeUnix
	descriptor.ExpiresAtUnix = descriptor.IssuedAtUnix + 1
	if err := ValidateDescriptor(descriptor, false); err != nil {
		return err
	}
	return p.Policy.Permits(descriptor)
}

func (p *GenerationPublisher) Publish(ctx context.Context, generation PublicGeneration, now time.Time) (HTTPSActivation, int, error) {
	if ctx == nil {
		return HTTPSActivation{}, 0, errors.New("generation publication needs a context")
	}
	if err := p.Validate(); err != nil {
		return HTTPSActivation{}, 0, err
	}
	if now.IsZero() || now.Unix() < 0 || generation.IssuedAt == 0 || generation.ExpiresAt <= generation.IssuedAt ||
		uint64(now.Unix()) < generation.IssuedAt || uint64(now.Unix()) >= generation.ExpiresAt {
		return HTTPSActivation{}, 0, errors.New("public generation is outside its publication window")
	}
	activationStep := p.Policy.MaxLifetimeSeconds / 2
	descriptorIssued := uint64(now.Unix()) / activationStep * activationStep
	if descriptorIssued < generation.IssuedAt {
		descriptorIssued = generation.IssuedAt
	}
	descriptorExpiry := generation.ExpiresAt
	if maximum := descriptorIssued + p.Policy.MaxLifetimeSeconds; descriptorExpiry > maximum {
		descriptorExpiry = maximum
	}
	if descriptorExpiry > p.Delegation.ExpiresAtUnix {
		descriptorExpiry = p.Delegation.ExpiresAtUnix
	}
	if descriptorExpiry <= uint64(now.Unix()) {
		return HTTPSActivation{}, 0, errors.New("descriptor window cannot cover publication time")
	}
	descriptor := p.Descriptor
	descriptor.IssuedAtUnix = descriptorIssued
	descriptor.ExpiresAtUnix = descriptorExpiry
	locatorIssued := descriptorIssued
	locatorExpiry := locatorIssued + MaxLocatorLifetimeSeconds
	if locatorExpiry > descriptorExpiry {
		locatorExpiry = descriptorExpiry
	}
	activation, err := ActivateHTTPSPublication(ctx, p.Objects, p.Signer, p.Delegation, p.Policy,
		HTTPSActivationPlan{Descriptor: descriptor, LocatorIssuedAt: locatorIssued, LocatorExpiresAt: locatorExpiry},
		generation.SetDigest, append([]byte(nil), generation.JSON...), now)
	if err != nil {
		return HTTPSActivation{}, 0, err
	}
	stored, err := p.Locators.PublishLocator(ctx, p.Delegation, activation.Locator, p.Signer)
	if err != nil {
		return HTTPSActivation{}, 0, err
	}
	return activation, stored, nil
}
