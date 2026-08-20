// Package vectors publishes the canonical forms a second implementation checks
// itself against.
//
// Every signed or digest-committed object in this repository is reconstructed
// here from fixed inputs, and its canonical preimage digest is written down.
// An implementation in another language reads the wire form, recomputes the
// preimage, and compares: agreement on these values is what "the same
// protocol" means, and it is the only way to find out that two implementations
// disagree before a deployment does.
//
// The file is committed. A change to it is a wire-format change, and it should
// be as visible in review as one.
package vectors

import (
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"flag"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/tosnetwork/tos-messenger/internal/canon"
	"github.com/tosnetwork/tos-messenger/pkg/directory"
	"github.com/tosnetwork/tos-messenger/pkg/e2ee"
	"github.com/tosnetwork/tos-messenger/pkg/envelope"
	"github.com/tosnetwork/tos-messenger/pkg/fault"
	"github.com/tosnetwork/tos-messenger/pkg/identity"
	"github.com/tosnetwork/tos-messenger/pkg/payload"
	"github.com/tosnetwork/tos-messenger/pkg/reachability"
	nativev1 "github.com/tosnetwork/tos-service-protocol/gen/tos/service/v1"
)

var update = flag.Bool("update", false, "rewrite the committed vectors")

const (
	baseUnix  = uint64(1_800_000_000)
	agentID   = "agent_" + "2222222222222222222222222222222222222222222222222222222222222222"
	deviceOne = "dev_" + "4444444444444444444444444444444444444444444444444444444444444444"
	deviceTwo = "dev_" + "7777777777777777777777777777777777777777777777777777777777777777"
	convoID   = "conv_" + "1111111111111111111111111111111111111111111111111111111111111111"
	algorithm = "tos.messaging.e2ee.example-suite.v1"
)

// Vector is one object in both forms: what travels, and what is hashed.
type Vector struct {
	Name string `json:"name"`
	// Wire is the transport encoding, hex for binary formats and JSON
	// otherwise.
	Wire string `json:"wire"`
	// CanonicalSHA256 is the digest of the canonical preimage: the bytes that
	// are signed or committed, never the transport encoding.
	CanonicalSHA256 string `json:"canonical_sha256"`
	// Digest is the object's own identifier where it has one.
	Digest string `json:"digest,omitempty"`
}

func testNetwork() *nativev1.NetworkDomain {
	return &nativev1.NetworkDomain{
		NetworkId:       "tos-local",
		GenesisRootHash: strings.Repeat("a", 64),
		GenesisFileHash: strings.Repeat("b", 64),
	}
}

func endpointKey() ed25519.PrivateKey {
	seed := make([]byte, ed25519.SeedSize)
	for index := range seed {
		seed[index] = 0x11
	}
	return ed25519.NewKeyFromSeed(seed)
}

func descriptorPolicy() directory.DescriptorPolicy {
	return directory.DescriptorPolicy{
		MaxEnvelopeBytes:   128 << 10,
		MaxLifetimeSeconds: 24 * 60 * 60,
		AllowHTTPSEndpoint: true,
	}
}

func delegation(t *testing.T) identity.Delegation {
	t.Helper()
	public, ok := endpointKey().Public().(ed25519.PublicKey)
	if !ok {
		t.Fatal("unexpected public key type")
	}
	network := testNetwork()
	endpointID, err := identity.DeriveEndpointID(network, agentID, public)
	if err != nil {
		t.Fatalf("derive endpoint: %v", err)
	}
	policyDigest, err := descriptorPolicy().Digest()
	if err != nil {
		t.Fatalf("policy digest: %v", err)
	}
	return identity.Delegation{
		Network:                       network,
		AgentID:                       agentID,
		EndpointID:                    endpointID,
		IdentityPublicKey:             public,
		ADNLID:                        "adnl:" + strings.Repeat("2e", 32),
		AllowedProtocolVersions:       []uint32{1},
		AllowedOutboundEventClasses:   []string{"agent.task", "text"},
		NotBeforeUnix:                 baseUnix,
		ExpiresAtUnix:                 baseUnix + 86_400,
		MaximumSessionLifetimeSeconds: 3600,
		ContactDescriptorPolicyDigest: policyDigest,
		InboxAdmissionPolicyDigest:    "sha256:" + strings.Repeat("4c", 32),
	}
}

func TestVectors(t *testing.T) {
	produced := build(t)
	path := filepath.Join("testdata", "vectors.json")

	encoded, err := json.MarshalIndent(produced, "", "  ")
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	encoded = append(encoded, '\n')

	if *update {
		if err := os.WriteFile(path, encoded, 0o644); err != nil {
			t.Fatalf("write: %v", err)
		}
		return
	}
	committed, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read committed vectors: %v (run with -update to create them)", err)
	}
	if string(committed) != string(encoded) {
		t.Fatalf("the canonical forms changed.\nThis is a wire-format change: another implementation " +
			"that agreed with the committed vectors no longer agrees with this one.\n" +
			"If the change is intended, re-run with -update and review the diff.")
	}
}

func build(t *testing.T) []Vector {
	t.Helper()
	key := endpointKey()
	del := delegation(t)
	var vectors []Vector

	add := func(name string, wire []byte, canonical []byte, digest string) {
		encoded := string(wire)
		if !json.Valid(wire) {
			encoded = hex.EncodeToString(wire)
		}
		vectors = append(vectors, Vector{
			Name:            name,
			Wire:            encoded,
			CanonicalSHA256: canon.Digest(canonical),
			Digest:          digest,
		})
	}

	// Endpoint delegation.
	delegationWire, err := identity.EncodeJSON(del)
	if err != nil {
		t.Fatalf("delegation: %v", err)
	}
	delegationCanonical, err := identity.CanonicalBytes(del)
	if err != nil {
		t.Fatalf("delegation canonical: %v", err)
	}
	delegationDigest, err := identity.Digest(del)
	if err != nil {
		t.Fatalf("delegation digest: %v", err)
	}
	add("endpoint-delegation", delegationWire, delegationCanonical, delegationDigest)

	// Descriptor policy and Relay set.
	policyDigest, err := descriptorPolicy().Digest()
	if err != nil {
		t.Fatalf("descriptor policy: %v", err)
	}
	vectors = append(vectors, Vector{Name: "descriptor-policy", Digest: policyDigest})
	vectors = append(vectors, Vector{Name: "empty-relay-set", Digest: directory.EmptyRelaySetDigest()})

	// Contact descriptor.
	descriptor := directory.Descriptor{
		Network:                    del.Network,
		AgentID:                    del.AgentID,
		EndpointID:                 del.EndpointID,
		DelegationDigest:           delegationDigest,
		SupportedMessagingVersions: []uint32{1},
		SupportedA2AVersions:       []string{"0.3"},
		SupportedMCPVersions:       []string{"2025-06-18"},
		ADNLID:                     del.ADNLID,
		HTTPSEndpoint:              "https://endpoint.example/messaging",
		PrekeyBundleDigest:         "sha256:" + strings.Repeat("7a", 32),
		MailboxRelaySetDigest:      directory.EmptyRelaySetDigest(),
		InboxAdmissionPolicyDigest: del.InboxAdmissionPolicyDigest,
		MaximumEnvelopeBytes:       64 << 10,
		IssuedAtUnix:               baseUnix,
		ExpiresAtUnix:              baseUnix + 3600,
	}
	descriptor, err = directory.SignDescriptor(descriptor, key)
	if err != nil {
		t.Fatalf("sign descriptor: %v", err)
	}
	descriptorWire, err := directory.EncodeDescriptorJSON(descriptor)
	if err != nil {
		t.Fatalf("descriptor: %v", err)
	}
	descriptorCanonical, err := directory.SigningBytes(descriptor)
	if err != nil {
		t.Fatalf("descriptor canonical: %v", err)
	}
	descriptorDigest, err := directory.DescriptorDigest(descriptor)
	if err != nil {
		t.Fatalf("descriptor digest: %v", err)
	}
	add("contact-descriptor", descriptorWire, descriptorCanonical, descriptorDigest)

	// DHT locator.
	locator, err := directory.NewLocator(descriptor, "https://directory.example/descriptor",
		baseUnix, descriptor.ExpiresAtUnix)
	if err != nil {
		t.Fatalf("locator: %v", err)
	}
	locator, err = directory.SignLocator(locator, key)
	if err != nil {
		t.Fatalf("sign locator: %v", err)
	}
	locatorWire, err := directory.EncodeLocator(locator)
	if err != nil {
		t.Fatalf("locator wire: %v", err)
	}
	locatorCanonical, err := directory.LocatorSigningBytes(locator)
	if err != nil {
		t.Fatalf("locator canonical: %v", err)
	}
	add("dht-locator", locatorWire, locatorCanonical, "")

	// Prekey bundle and set.
	bundle := e2ee.Bundle{
		Network: del.Network, AgentID: del.AgentID, EndpointID: del.EndpointID,
		DeviceID: deviceOne, AlgorithmID: algorithm,
		Material:     []byte("published prekey material"),
		IssuedAtUnix: baseUnix, ExpiresAtUnix: baseUnix + 3600,
	}
	bundle, err = e2ee.SignBundle(bundle, key)
	if err != nil {
		t.Fatalf("sign bundle: %v", err)
	}
	bundleWire, err := e2ee.EncodeBundleJSON(bundle)
	if err != nil {
		t.Fatalf("bundle: %v", err)
	}
	bundleCanonical, err := e2ee.BundleSigningBytes(bundle)
	if err != nil {
		t.Fatalf("bundle canonical: %v", err)
	}
	bundleDigest, err := e2ee.BundleDigest(bundle)
	if err != nil {
		t.Fatalf("bundle digest: %v", err)
	}
	add("prekey-bundle", bundleWire, bundleCanonical, bundleDigest)

	second := bundle
	second.DeviceID = deviceTwo
	second, err = e2ee.SignBundle(second, key)
	if err != nil {
		t.Fatalf("sign second bundle: %v", err)
	}
	setDigest, err := e2ee.SetDigest([]e2ee.Bundle{bundle, second})
	if err != nil {
		t.Fatalf("set digest: %v", err)
	}
	vectors = append(vectors, Vector{Name: "prekey-bundle-set", Digest: setDigest})

	// Ciphertext binding.
	binding := e2ee.Binding{
		Network: del.Network, AlgorithmID: algorithm, ConversationID: convoID,
		SenderAgentID: del.AgentID, SenderEndpointID: del.EndpointID, SenderDeviceID: deviceOne,
		RecipientAgentID:    "agent_" + strings.Repeat("5", 64),
		RecipientEndpointID: "mep_" + strings.Repeat("6", 64),
		RecipientDeviceID:   deviceTwo,
	}
	bindingBytes, err := binding.Bytes()
	if err != nil {
		t.Fatalf("binding: %v", err)
	}
	add("e2ee-binding", bindingBytes, bindingBytes, "")

	// Messaging event. The body is a real typed payload, because an event
	// whose content does not parse under its own kind is one the dispatcher
	// refuses to send and the gate refuses to admit. Freezing such an event
	// would publish a vector for a message the protocol's main path rejects.
	textBody, err := payload.Encode(payload.Text{
		MediaType: "text/plain; charset=utf-8", Body: "hello",
	})
	if err != nil {
		t.Fatalf("payload: %v", err)
	}
	event, err := envelope.NewEvent(envelope.Event{
		Network: del.Network, ConversationID: convoID,
		SenderAgentID: del.AgentID, SenderEndpointID: del.EndpointID, SenderDeviceID: deviceOne,
		CreatedAtUnix: baseUnix + 10, Kind: "text", Content: textBody,
		Rendering: "hello",
	})
	if err != nil {
		t.Fatalf("event: %v", err)
	}
	// The frozen event has to survive the checks the protocol actually runs,
	// not only the ones the encoder runs.
	if err := payload.Validate(event.Kind, event.Content); err != nil {
		t.Fatalf("the frozen event carries a body its own kind rejects: %v", err)
	}
	eventWire, err := envelope.EncodeEventJSON(event)
	if err != nil {
		t.Fatalf("event wire: %v", err)
	}
	eventCanonical, err := envelope.EventCanonicalBytes(event)
	if err != nil {
		t.Fatalf("event canonical: %v", err)
	}
	add("messaging-event", eventWire, eventCanonical, event.EventID)

	// Relay envelope.
	relayEnvelope := envelope.RelayEnvelope{
		OpaqueMailboxID: "mbx_" + strings.Repeat("5a", 32),
		MessageID:       "msg_" + strings.Repeat("6b", 32),
		Ciphertext:      []byte("0123456789abcdef0123456789abcdef0123456789"),
		ExpiresAtUnix:   baseUnix + 3600,
		StorageToken:    "quota-token.1",
	}
	relayWire, err := envelope.EncodeRelayJSON(relayEnvelope)
	if err != nil {
		t.Fatalf("relay envelope: %v", err)
	}
	add("relay-envelope", relayWire, relayWire, "")

	// Typed fault response.
	responseWire, err := fault.EncodeResponseJSON(fault.PeerCode(fault.CodeRateLimited, 30))
	if err != nil {
		t.Fatalf("fault response: %v", err)
	}
	add("fault-response", responseWire, responseWire, "")

	// Reachability policy and trial.
	coordinatorKey := ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize))
	coordinatorPublic, ok := coordinatorKey.Public().(ed25519.PublicKey)
	if !ok {
		t.Fatal("unexpected public key type")
	}
	coordinatorID, err := reachability.CoordinatorID(coordinatorPublic)
	if err != nil {
		t.Fatalf("coordinator id: %v", err)
	}
	policy := reachability.Policy{
		MinSamplesPerCell: 30, MinOperatorsPerCell: 3, MinSitesPerCell: 3,
		MaxTrialsPerOperatorPerCell: 20, DirectViableRate: 0.8, TunnelViableRate: 0.95,
		MinDirectSurvivalRate: 0.9, MinTunnelSurvivalRate: 0.9, MinReconnectSuccessRate: 0.9,
		MinSurvivalSamplesPerCell: 10, MinReconnectSamplesPerMobilityCell: 10,
		Coordinators: []string{coordinatorID},
		RequiredScenarios: []reachability.Scenario{
			{
				Initiator: reachability.EndpointStratum{
					Family: reachability.FamilyIPv4, Reachability: reachability.BehindNAT,
					NATBehavior: reachability.NATEndpointIndependent, Carrier: reachability.CarrierConsumerISP,
					UDPPolicy: reachability.UDPAllowed, Mobility: reachability.MobilityStationary,
					EndpointClass: reachability.ClassDesktop, Assistance: reachability.AssistanceNone,
				},
				Responder: reachability.EndpointStratum{
					Family: reachability.FamilyIPv4, Reachability: reachability.PublicAddress,
					NATBehavior: reachability.NATNone, Carrier: reachability.CarrierDatacenter,
					UDPPolicy: reachability.UDPAllowed, Mobility: reachability.MobilityStationary,
					EndpointClass: reachability.ClassServer, Assistance: reachability.AssistanceNone,
				},
			},
			{
				Initiator: reachability.EndpointStratum{
					Family: reachability.FamilyIPv6, Reachability: reachability.BehindNAT,
					NATBehavior: reachability.NATSymmetric, Carrier: reachability.CarrierCarrierGrade,
					UDPPolicy: reachability.UDPRateLimited, Mobility: reachability.MobilityStationary,
					EndpointClass: reachability.ClassEdgeARM, Assistance: reachability.AssistanceNone,
				},
				Responder: reachability.EndpointStratum{
					Family: reachability.FamilyIPv6, Reachability: reachability.BehindNAT,
					NATBehavior: reachability.NATAddressPortDependent, Carrier: reachability.CarrierConsumerISP,
					UDPPolicy: reachability.UDPAllowed, Mobility: reachability.MobilityStationary,
					EndpointClass: reachability.ClassDesktop, Assistance: reachability.AssistanceNone,
				},
			},
			{
				Initiator: reachability.EndpointStratum{
					Family: reachability.FamilyIPv4, Reachability: reachability.BehindNAT,
					NATBehavior: reachability.NATAddressDependent, Carrier: reachability.CarrierMobile,
					UDPPolicy: reachability.UDPRateLimited, Mobility: reachability.MobilityWiFiToMobile,
					EndpointClass: reachability.ClassMobile, Assistance: reachability.AssistanceNone,
				},
				Responder: reachability.EndpointStratum{
					Family: reachability.FamilyIPv4, Reachability: reachability.PublicAddress,
					NATBehavior: reachability.NATNone, Carrier: reachability.CarrierDatacenter,
					UDPPolicy: reachability.UDPAllowed, Mobility: reachability.MobilityStationary,
					EndpointClass: reachability.ClassServer, Assistance: reachability.AssistanceNone,
				},
			},
		},
	}
	policyCanonical, err := policy.CanonicalBytes()
	if err != nil {
		t.Fatalf("reachability policy: %v", err)
	}
	policyDigestValue, err := policy.Digest()
	if err != nil {
		t.Fatalf("reachability policy digest: %v", err)
	}
	add("reachability-policy", policyCanonical, policyCanonical, policyDigestValue)

	return vectors
}
