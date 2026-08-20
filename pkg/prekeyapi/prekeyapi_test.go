package prekeyapi

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/tosnetwork/tos-messenger/pkg/e2ee"
	"github.com/tosnetwork/tos-messenger/pkg/eventlog"
	"github.com/tosnetwork/tos-messenger/pkg/identity"
	nativev1 "github.com/tosnetwork/tos-service-protocol/gen/tos/service/v1"
)

type apiHarness struct {
	journal      *eventlog.Journal
	server       *Server
	collector    *eventlog.PrekeyContributionLedger
	publications *eventlog.PrekeyPublicationLedger
	delegation   identity.Delegation
	private      ed25519.PrivateKey
	now          time.Time
	devices      []string
}

func newAPIHarness(t *testing.T, planned bool) *apiHarness {
	t.Helper()
	private := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x51}, ed25519.SeedSize))
	network := &nativev1.NetworkDomain{
		NetworkId: "tos-local", GenesisRootHash: strings.Repeat("a", 64), GenesisFileHash: strings.Repeat("b", 64),
	}
	agentID := "agent_" + strings.Repeat("c", 64)
	endpointID, err := identity.DeriveEndpointID(network, agentID, private.Public().(ed25519.PublicKey))
	if err != nil {
		t.Fatal(err)
	}
	delegation := identity.Delegation{
		Network: network, AgentID: agentID, EndpointID: endpointID,
		IdentityPublicKey: private.Public().(ed25519.PublicKey), AllowedProtocolVersions: []uint32{1},
		AllowedOutboundEventClasses: []string{"message.text"}, NotBeforeUnix: 1_799_999_000,
		ExpiresAtUnix: 1_800_100_000, MaximumSessionLifetimeSeconds: 3600,
		ContactDescriptorPolicyDigest: "sha256:" + strings.Repeat("d", 64),
		InboxAdmissionPolicyDigest:    "sha256:" + strings.Repeat("e", 64),
	}
	journal, err := eventlog.Open(t.TempDir() + "/state")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = journal.Close() })
	collector, err := journal.OpenPrekeyContributions()
	if err != nil {
		t.Fatal(err)
	}
	publications, err := journal.OpenPrekeyPublications()
	if err != nil {
		t.Fatal(err)
	}
	now := time.Unix(1_800_000_000, 0)
	devices := []string{"dev_" + strings.Repeat("1", 64), "dev_" + strings.Repeat("2", 64)}
	if planned {
		if _, _, err := collector.BeginPrekeyCollection(delegation, eventlog.PrekeyCollectionPlan{
			DeviceIDs: devices, AlgorithmID: e2ee.NewDefaultSuite().AlgorithmID(),
			IssuedAtUnix: uint64(now.Unix()), ExpiresAtUnix: uint64(now.Add(time.Hour).Unix()),
		}, now); err != nil {
			t.Fatal(err)
		}
	}
	server, err := NewServer(Config{
		Delegation: delegation, Journal: journal, Now: func() time.Time { return now },
	})
	if err != nil {
		t.Fatal(err)
	}
	return &apiHarness{
		journal: journal, server: server, collector: collector, publications: publications,
		delegation: delegation, private: private, now: now, devices: devices,
	}
}

func (h *apiHarness) bundle(t *testing.T, deviceID string, material byte) e2ee.Bundle {
	t.Helper()
	bundle, err := e2ee.SignBundle(e2ee.Bundle{
		Network: h.delegation.Network, AgentID: h.delegation.AgentID, EndpointID: h.delegation.EndpointID,
		DeviceID: deviceID, AlgorithmID: e2ee.NewDefaultSuite().AlgorithmID(), Material: bytes.Repeat([]byte{material}, 32),
		IssuedAtUnix: uint64(h.now.Unix()), ExpiresAtUnix: uint64(h.now.Add(time.Hour).Unix()),
	}, h.private)
	if err != nil {
		t.Fatal(err)
	}
	return bundle
}

func requestBody(t *testing.T, request Request) []byte {
	t.Helper()
	framed, err := EncodeRequest(request)
	if err != nil {
		t.Fatal(err)
	}
	body, err := ReadFrame(bytes.NewReader(framed))
	if err != nil {
		t.Fatal(err)
	}
	return body
}

func TestDeviceAPICollectsOnlyPublicBundlesAndFinalizes(t *testing.T) {
	h := newAPIHarness(t, true)
	current := h.server.Handle(context.Background(), requestBody(t, Request{Op: OpCurrentGeneration}))
	if !current.OK || current.Generation == nil || current.Generation.ContributionCount != 0 ||
		len(current.Generation.DeviceIDs) != 2 {
		t.Fatalf("current=%+v", current)
	}

	firstRaw, _ := e2ee.EncodeBundleJSON(h.bundle(t, h.devices[0], 0x11))
	first := h.server.Handle(context.Background(), requestBody(t, Request{Op: OpSubmitContribution, Bundle: firstRaw}))
	if !first.OK || !first.ContributionFresh || first.PublicationFresh || first.Generation.Complete ||
		first.Generation.ContributionCount != 1 {
		t.Fatalf("first=%+v", first)
	}
	retry := h.server.Handle(context.Background(), requestBody(t, Request{Op: OpSubmitContribution, Bundle: firstRaw}))
	if !retry.OK || retry.ContributionFresh || retry.PublicationFresh {
		t.Fatalf("retry=%+v", retry)
	}

	secondRaw, _ := e2ee.EncodeBundleJSON(h.bundle(t, h.devices[1], 0x22))
	second := h.server.Handle(context.Background(), requestBody(t, Request{Op: OpSubmitContribution, Bundle: secondRaw}))
	if !second.OK || !second.ContributionFresh || !second.PublicationFresh || !second.Generation.Complete ||
		second.Generation.FinalizedSetDigest == "" {
		t.Fatalf("second=%+v", second)
	}
	publication, found, err := h.publications.CurrentPrekeyPublication(h.delegation.EndpointID)
	if err != nil || !found || publication.SetDigest != second.Generation.FinalizedSetDigest || len(publication.Bundles) != 2 {
		t.Fatalf("publication=%+v found=%v err=%v", publication, found, err)
	}
	current = h.server.Handle(context.Background(), requestBody(t, Request{Op: OpCurrentGeneration}))
	if !current.OK || current.Generation.FinalizedSetDigest != publication.SetDigest {
		t.Fatalf("final current=%+v", current)
	}
}

func TestDeviceAPIRejectsInvalidUnplannedAndConflictingBundles(t *testing.T) {
	h := newAPIHarness(t, true)
	valid := h.bundle(t, h.devices[0], 0x11)
	tampered := valid
	tampered.EndpointSignature = append([]byte(nil), valid.EndpointSignature...)
	tampered.EndpointSignature[0] ^= 0xff
	tamperedRaw, _ := e2ee.EncodeBundleJSON(tampered)
	response := h.server.Handle(context.Background(), requestBody(t, Request{Op: OpSubmitContribution, Bundle: tamperedRaw}))
	if response.OK || response.Code != CodeNotAccepted {
		t.Fatalf("tampered=%+v", response)
	}

	unplannedRaw, _ := e2ee.EncodeBundleJSON(h.bundle(t, "dev_"+strings.Repeat("3", 64), 0x33))
	response = h.server.Handle(context.Background(), requestBody(t, Request{Op: OpSubmitContribution, Bundle: unplannedRaw}))
	if response.OK || response.Code != CodeNotAccepted {
		t.Fatalf("unplanned=%+v", response)
	}
	validRaw, _ := e2ee.EncodeBundleJSON(valid)
	if accepted := h.server.Handle(context.Background(), requestBody(t, Request{Op: OpSubmitContribution, Bundle: validRaw})); !accepted.OK {
		t.Fatalf("valid=%+v", accepted)
	}
	conflictRaw, _ := e2ee.EncodeBundleJSON(h.bundle(t, h.devices[0], 0x44))
	response = h.server.Handle(context.Background(), requestBody(t, Request{Op: OpSubmitContribution, Bundle: conflictRaw}))
	if response.OK || response.Code != CodeConflict {
		t.Fatalf("conflict=%+v", response)
	}
	current := h.server.Handle(context.Background(), requestBody(t, Request{Op: OpCurrentGeneration}))
	if !current.OK || current.Generation.ContributionCount != 1 {
		t.Fatalf("invalid submissions mutated collection: %+v", current)
	}
}

func TestDeviceAPIStrictShapeAndNoPlanAuthority(t *testing.T) {
	h := newAPIHarness(t, false)
	noPlan := h.server.Handle(context.Background(), requestBody(t, Request{Op: OpCurrentGeneration}))
	if noPlan.OK || noPlan.Code != CodeNoGeneration {
		t.Fatalf("no plan=%+v", noPlan)
	}
	for name, raw := range map[string][]byte{
		"unknown operation": []byte(`{"schema":"tos.messaging.prekey-device-request.v1","op":"generation.begin"}`),
		"unknown field":     []byte(`{"schema":"tos.messaging.prekey-device-request.v1","op":"generation.current","device_id":"x"}`),
		"trailing":          []byte(`{"schema":"tos.messaging.prekey-device-request.v1","op":"generation.current"}{}`),
		"bundle on lookup":  []byte(`{"schema":"tos.messaging.prekey-device-request.v1","op":"generation.current","bundle":{}}`),
	} {
		t.Run(name, func(t *testing.T) {
			response := h.server.Handle(context.Background(), raw)
			if response.OK || response.Code != CodeInvalidRequest {
				t.Fatalf("response=%+v", response)
			}
		})
	}
}

func TestDeviceAPIRejectsMalformedResponsesAndMissingJournal(t *testing.T) {
	h := newAPIHarness(t, true)
	if _, err := NewServer(Config{Delegation: h.delegation}); err == nil {
		t.Fatal("server opened without a journal")
	}
	for name, raw := range map[string][]byte{
		"success without plan": []byte(`{"schema":"tos.messaging.prekey-device-response.v1","ok":true}`),
		"failure with plan":    []byte(`{"schema":"tos.messaging.prekey-device-response.v1","ok":false,"code":"internal","detail":"failed","generation":{}}`),
		"unknown code":         []byte(`{"schema":"tos.messaging.prekey-device-response.v1","ok":false,"code":"surprise","detail":"failed"}`),
		"trailing":             []byte(`{"schema":"tos.messaging.prekey-device-response.v1","ok":false,"code":"internal","detail":"failed"}{}`),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := DecodeResponse(raw); err == nil {
				t.Fatal("malformed response was accepted")
			}
		})
	}
}

func TestDeviceAPIRejectsNonCanonicalBundleAndCopiesDelegation(t *testing.T) {
	h := newAPIHarness(t, true)
	bundleRaw, _ := e2ee.EncodeBundleJSON(h.bundle(t, h.devices[0], 0x11))
	var indented bytes.Buffer
	if err := json.Indent(&indented, bundleRaw, "", "  "); err != nil {
		t.Fatal(err)
	}
	noncanonicalRequest := append([]byte(`{"schema":"tos.messaging.prekey-device-request.v1","op":"contribution.submit","bundle":`), indented.Bytes()...)
	noncanonicalRequest = append(noncanonicalRequest, '}')
	response := h.server.Handle(context.Background(), noncanonicalRequest)
	if response.OK || response.Code != CodeInvalidRequest {
		t.Fatalf("noncanonical=%+v", response)
	}
	clear(h.delegation.IdentityPublicKey)
	response = h.server.Handle(context.Background(), requestBody(t, Request{Op: OpSubmitContribution, Bundle: bundleRaw}))
	if !response.OK {
		t.Fatalf("caller mutated server delegation: %+v", response)
	}
}

func TestDeviceAPIServesPrivateUnixSocket(t *testing.T) {
	h := newAPIHarness(t, true)
	path := filepath.Join(t.TempDir(), "run", "prekeys.sock")
	listener, err := Listen(path)
	if err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("socket mode=%v", info.Mode().Perm())
	}
	defer listener.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = h.server.Serve(ctx, listener) }()
	connection, err := net.Dial("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Close()
	request, err := EncodeRequest(Request{Op: OpCurrentGeneration})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := connection.Write(request); err != nil {
		t.Fatal(err)
	}
	body, err := ReadFrame(bufio.NewReader(connection))
	if err != nil {
		t.Fatal(err)
	}
	response, err := DecodeResponse(body)
	if err != nil || !response.OK || response.Generation == nil {
		t.Fatalf("response=%+v err=%v", response, err)
	}
}
