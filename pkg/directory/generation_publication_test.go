package directory

import (
	"bytes"
	"context"
	"crypto"
	"errors"
	"testing"
	"time"

	"github.com/tosnetwork/tos-messenger/pkg/identity"
)

type locatorSink struct {
	locators []Locator
	fail     bool
}

func (s *locatorSink) PublishLocator(_ context.Context, _ identity.Delegation, locator Locator, _ crypto.Signer) (int, error) {
	if s.fail {
		return 0, errors.New("DHT unavailable")
	}
	s.locators = append(s.locators, locator)
	return 3, nil
}

func TestGenerationPublisherIsRetryStableAndOrdersAuthorityLast(t *testing.T) {
	key := endpointKey(t, 0x51)
	delegation := testDelegation(t, key)
	descriptor := testDescriptor(t, delegation)
	digest, raw := publicationPrekeys(t, key, descriptor)
	objects := new(activationSink)
	locators := new(locatorSink)
	publisher := GenerationPublisher{
		Objects: objects, Locators: locators, Signer: key, Delegation: delegation,
		Policy: testPolicy(), Descriptor: descriptor, PublishInterval: time.Minute,
	}
	generation := PublicGeneration{SetDigest: digest, JSON: raw, IssuedAt: baseUnix, ExpiresAt: baseUnix + 1800}
	now := time.Unix(int64(baseUnix+61), 0)
	first, stored, err := publisher.Publish(context.Background(), generation, now)
	if err != nil || stored != 3 {
		t.Fatalf("publish: stored=%d err=%v", stored, err)
	}
	second, _, err := publisher.Publish(context.Background(), generation, now.Add(20*time.Second))
	if err != nil {
		t.Fatalf("retry: %v", err)
	}
	if first.DescriptorDigest != second.DescriptorDigest ||
		!bytes.Equal(first.DescriptorJSON, second.DescriptorJSON) ||
		!bytes.Equal(first.Locator.EndpointSignature, second.Locator.EndpointSignature) {
		t.Fatal("same-interval retry changed signed publication bytes")
	}
	if len(objects.calls) != 4 || len(locators.locators) != 2 {
		t.Fatalf("unexpected publication calls: objects=%v locators=%d", objects.calls, len(locators.locators))
	}
}

func TestGenerationPublisherKeepsInnerLocatorStableAcrossIntervals(t *testing.T) {
	key := endpointKey(t, 0x52)
	delegation := testDelegation(t, key)
	descriptor := testDescriptor(t, delegation)
	digest, raw := publicationPrekeys(t, key, descriptor)
	publisher := GenerationPublisher{
		Objects: new(activationSink), Locators: new(locatorSink), Signer: key, Delegation: delegation,
		Policy: testPolicy(), Descriptor: descriptor, PublishInterval: time.Minute,
	}
	generation := PublicGeneration{SetDigest: digest, JSON: raw, IssuedAt: baseUnix, ExpiresAt: baseUnix + 1800}
	first, _, err := publisher.Publish(context.Background(), generation, time.Unix(int64(baseUnix+61), 0))
	if err != nil {
		t.Fatalf("first: %v", err)
	}
	second, _, err := publisher.Publish(context.Background(), generation, time.Unix(int64(baseUnix+121), 0))
	if err != nil {
		t.Fatalf("second: %v", err)
	}
	if first.DescriptorDigest != second.DescriptorDigest ||
		first.Locator.IssuedAtUnix != second.Locator.IssuedAtUnix ||
		first.Locator.ExpiresAtUnix != second.Locator.ExpiresAtUnix ||
		!bytes.Equal(first.Locator.EndpointSignature, second.Locator.EndpointSignature) {
		t.Fatalf("unexpected interval transition: first=%+v second=%+v", first, second)
	}
}

func TestGenerationPublisherRenewsDescriptorOncePerPolicyHalfLife(t *testing.T) {
	key := endpointKey(t, 0x55)
	delegation := testDelegation(t, key)
	descriptor := testDescriptor(t, delegation)
	digest, raw := publicationPrekeys(t, key, descriptor)
	policy := testPolicy()
	policy.MaxLifetimeSeconds = 600
	policyDigest, err := policy.Digest()
	if err != nil {
		t.Fatalf("policy: %v", err)
	}
	delegation.ContactDescriptorPolicyDigest = policyDigest
	descriptor.DelegationDigest, err = identity.Digest(delegation)
	if err != nil {
		t.Fatalf("delegation: %v", err)
	}
	publisher := GenerationPublisher{Objects: new(activationSink), Locators: new(locatorSink), Signer: key,
		Delegation: delegation, Policy: policy, Descriptor: descriptor, PublishInterval: time.Minute}
	generation := PublicGeneration{SetDigest: digest, JSON: raw, IssuedAt: baseUnix, ExpiresAt: baseUnix + 1800}
	first, _, err := publisher.Publish(context.Background(), generation, time.Unix(int64(baseUnix+1), 0))
	if err != nil {
		t.Fatalf("first: %v", err)
	}
	second, _, err := publisher.Publish(context.Background(), generation, time.Unix(int64(baseUnix+301), 0))
	if err != nil {
		t.Fatalf("renew: %v", err)
	}
	if first.DescriptorDigest == second.DescriptorDigest || first.Descriptor.ExpiresAtUnix >= second.Descriptor.ExpiresAtUnix {
		t.Fatalf("descriptor did not renew by policy bucket: first=%+v second=%+v", first.Descriptor, second.Descriptor)
	}
}

func TestGenerationPublisherNeverHidesObjectOrDHTFailure(t *testing.T) {
	key := endpointKey(t, 0x53)
	delegation := testDelegation(t, key)
	descriptor := testDescriptor(t, delegation)
	digest, raw := publicationPrekeys(t, key, descriptor)
	generation := PublicGeneration{SetDigest: digest, JSON: raw, IssuedAt: baseUnix, ExpiresAt: baseUnix + 1800}
	now := time.Unix(int64(baseUnix+1), 0)

	objects := &activationSink{fail: "descriptor"}
	locators := new(locatorSink)
	publisher := GenerationPublisher{Objects: objects, Locators: locators, Signer: key, Delegation: delegation,
		Policy: testPolicy(), Descriptor: descriptor, PublishInterval: time.Minute}
	if _, _, err := publisher.Publish(context.Background(), generation, now); err == nil || len(locators.locators) != 0 {
		t.Fatalf("object failure reached authority sink: locators=%d err=%v", len(locators.locators), err)
	}

	publisher.Objects = new(activationSink)
	publisher.Locators = &locatorSink{fail: true}
	if _, _, err := publisher.Publish(context.Background(), generation, now); err == nil {
		t.Fatal("DHT failure was hidden")
	}
}

func TestGenerationPublisherRefusesSubstitutedAuthorityBeforeMutation(t *testing.T) {
	key := endpointKey(t, 0x54)
	delegation := testDelegation(t, key)
	descriptor := testDescriptor(t, delegation)
	digest, raw := publicationPrekeys(t, key, descriptor)
	generation := PublicGeneration{SetDigest: digest, JSON: raw, IssuedAt: baseUnix, ExpiresAt: baseUnix + 1800}
	objects := new(activationSink)
	locators := new(locatorSink)
	publisher := GenerationPublisher{Objects: objects, Locators: locators, Signer: key, Delegation: delegation,
		Policy: testPolicy(), Descriptor: descriptor, PublishInterval: time.Minute}
	publisher.Descriptor.AgentID = "agent_" + "1111111111111111111111111111111111111111111111111111111111111111"
	if _, _, err := publisher.Publish(context.Background(), generation, time.Unix(int64(baseUnix+1), 0)); err == nil {
		t.Fatal("substituted descriptor authority was accepted")
	}
	if len(objects.calls) != 0 || len(locators.locators) != 0 {
		t.Fatalf("authority substitution mutated sinks: objects=%v locators=%d", objects.calls, len(locators.locators))
	}
}
