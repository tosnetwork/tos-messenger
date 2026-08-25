package daemon

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"errors"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/tosnetwork/tos-messenger/pkg/admission"
	"github.com/tosnetwork/tos-messenger/pkg/directhttps"
	"github.com/tosnetwork/tos-messenger/pkg/directory"
	"github.com/tosnetwork/tos-messenger/pkg/dispatch"
	"github.com/tosnetwork/tos-messenger/pkg/e2ee"
	"github.com/tosnetwork/tos-messenger/pkg/envelope"
	"github.com/tosnetwork/tos-messenger/pkg/eventlog"
	"github.com/tosnetwork/tos-messenger/pkg/identity"
	"github.com/tosnetwork/tos-messenger/pkg/payload"
	nativev1 "github.com/tosnetwork/tos-service-protocol/gen/tos/service/v1"
	commerce "github.com/tosnetwork/tos-service-protocol/pkg/agentcommerce"
)

type phaseAResolver struct {
	states map[string]*nativev1.NativeStateV1
}

func (r phaseAResolver) ResolveAgent(agentID string) (*nativev1.NativeStateV1, bool, error) {
	state, found := r.states[agentID]
	return state, found, nil
}

type phaseALocator struct{}

func (phaseALocator) Locate(codeHash, _ string) (string, error) {
	if codeHash != registryCode {
		return "", errors.New("unknown registry")
	}
	return "0:" + strings.Repeat("d", 64), nil
}

type phaseALoopSender struct{ recipient *Daemon }

func (s phaseALoopSender) Send(ctx context.Context, message dispatch.Message) error {
	result, err := s.recipient.ReceiveSealed(ctx, message, admission.RouteDirect)
	if err != nil {
		return err
	}
	if result.Outcome == admission.Rejected {
		return errors.New("recipient rejected loopback message")
	}
	return nil
}

type phaseAHTTPSTarget struct{ target directhttps.Target }

func (r phaseAHTTPSTarget) ResolveHTTPS(context.Context, string) (directhttps.Target, error) {
	return r.target, nil
}

func TestTwoIndependentDaemonsExchangeEncryptedDirectMessages(t *testing.T) {
	now := time.Unix(1_900_000_000, 0)
	a := newPhaseADaemon(t, now, "2", "4")
	b := newPhaseADaemon(t, now, "7", "9")
	connectPhaseADirectories(a, b, now)
	connectPhaseADirectories(b, a, now)
	installPhaseAAdmission(t, now, a, b)
	installPhaseAAdmission(t, now, b, a)
	installPhaseATransport(t, now, a, b)
	installPhaseATransport(t, now, b, a)

	first, err := a.SendDirectMessage(context.Background(), b.config.AgentID,
		"text/plain; charset=utf-8", "hello B", "idem_"+strings.Repeat("a", 64),
		uint64(now.Add(time.Hour).Unix()))
	if err != nil {
		t.Fatalf("queue first message: %v", err)
	}
	if summary, err := a.dispatch.Sweep(context.Background(), 0); err != nil || summary.Sent != 1 {
		t.Fatalf("deliver first message: summary=%+v err=%v", summary, err)
	}
	assertPhaseAPendingText(t, b, first.EventID, "hello B", now)

	reply, err := b.ReplyDirectMessage(context.Background(), first.EventID,
		"text/plain; charset=utf-8", "hello A", "idem_"+strings.Repeat("b", 64),
		uint64(now.Add(time.Hour).Unix()))
	if err != nil {
		t.Fatalf("queue reply: %v", err)
	}
	if summary, err := b.dispatch.Sweep(context.Background(), 0); err != nil || summary.Sent != 1 {
		t.Fatalf("deliver reply: summary=%+v err=%v", summary, err)
	}
	assertPhaseAPendingText(t, a, reply.EventID, "hello A", now)

	// The same proactive intent cannot create or deliver a sibling Event.
	retry, err := a.SendDirectMessage(context.Background(), b.config.AgentID,
		"text/plain; charset=utf-8", "hello B", "idem_"+strings.Repeat("a", 64),
		uint64(now.Add(time.Hour).Unix()))
	if err != nil || retry.EventID != first.EventID {
		t.Fatalf("idempotent retry: first=%+v retry=%+v err=%v", first, retry, err)
	}
	if due, err := a.journal.Due(now); err != nil || len(due) != 0 {
		t.Fatalf("delivered retry returned to queue: due=%+v err=%v", due, err)
	}
}

func TestEstablishedDaemonsCarryExactGiftApplicationBytes(t *testing.T) {
	now := time.Unix(1_900_000_000, 0)
	a := newPhaseADaemon(t, now, "2", "4")
	b := newPhaseADaemon(t, now, "7", "9")
	connectPhaseADirectories(a, b, now)
	connectPhaseADirectories(b, a, now)
	installPhaseAAdmission(t, now, a, b)
	installPhaseAAdmission(t, now, b, a)
	installPhaseATransport(t, now, a, b)
	installPhaseATransport(t, now, b, a)

	first, err := a.SendDirectMessage(context.Background(), b.config.AgentID,
		"text/plain; charset=utf-8", "establish", "idem_"+strings.Repeat("1", 64), uint64(now.Add(time.Hour).Unix()))
	if err != nil {
		t.Fatal(err)
	}
	if summary, err := a.dispatch.Sweep(context.Background(), 0); err != nil || summary.Sent != 1 {
		t.Fatalf("establish direct: %+v %v", summary, err)
	}
	assertPhaseAPendingText(t, b, first.EventID, "establish", now)

	assertGift := func(d *Daemon, eventID, kind string, canonical []byte) {
		t.Helper()
		records, err := d.journal.ListPending(now, 10)
		if err != nil {
			t.Fatal(err)
		}
		for _, record := range records {
			if record.EventID != eventID {
				continue
			}
			raw, _ := record.Payload()
			event, decodeErr := envelope.DecodeEventJSON(raw)
			decoded, payloadErr := payload.Decode(event.Kind, event.Content)
			var got []byte
			switch value := decoded.(type) {
			case payload.GiftAddressRequest:
				got = value.CanonicalRequest
			case payload.GiftAddressResponse:
				got = value.CanonicalResponse
			case payload.GiftSignedBOCOffer:
				got = value.CanonicalOffer
			}
			if decodeErr != nil || payloadErr != nil || event.Kind != kind || !bytes.Equal(got, canonical) || event.RoomID != "" || event.Rendering != "" {
				t.Fatalf("wrong E2EE Gift event: %+v %+v %v %v", event, decoded, decodeErr, payloadErr)
			}
			return
		}
		t.Fatalf("Gift event %s was not durably received", eventID)
	}

	requestCanonical := []byte{0xa2, 0x01, 0x02, 0x03, 0x04}
	gift, err := a.SendDirectApplication(context.Background(), b.config.AgentID,
		"agent.gift.address-request", requestCanonical, "idem_"+strings.Repeat("2", 64), uint64(now.Add(time.Hour).Unix()))
	if err != nil {
		t.Fatal(err)
	}
	if summary, err := a.dispatch.Sweep(context.Background(), 0); err != nil || summary.Sent != 1 {
		t.Fatalf("deliver Gift: %+v %v", summary, err)
	}
	assertGift(b, gift.EventID, "agent.gift.address-request", requestCanonical)

	responseCanonical := []byte{0xa3, 0x01, 0x03, 0x02, 0x05, 0x03, 0x07}
	response, err := b.SendDirectApplication(context.Background(), a.config.AgentID,
		"agent.gift.address-response", responseCanonical, "idem_"+strings.Repeat("3", 64), uint64(now.Add(time.Hour).Unix()))
	if err != nil {
		t.Fatal(err)
	}
	if summary, err := b.dispatch.Sweep(context.Background(), 0); err != nil || summary.Sent != 1 {
		t.Fatalf("deliver Gift response: %+v %v", summary, err)
	}
	assertGift(a, response.EventID, "agent.gift.address-response", responseCanonical)

	offerCanonical := []byte{0xa3, 0x01, 0x04, 0x02, 0x58, 0x04, 0xb5, 0xee, 0x9c, 0x72, 0x03, 0x08}
	offer, err := a.SendDirectApplication(context.Background(), b.config.AgentID,
		"agent.gift.signed-boc-offer", offerCanonical, "idem_"+strings.Repeat("4", 64), uint64(now.Add(time.Hour).Unix()))
	if err != nil {
		t.Fatal(err)
	}
	if summary, err := a.dispatch.Sweep(context.Background(), 0); err != nil || summary.Sent != 1 {
		t.Fatalf("deliver signed BOC offer: %+v %v", summary, err)
	}
	assertGift(b, offer.EventID, "agent.gift.signed-boc-offer", offerCanonical)
}

func TestFirstContactGiftIsRejectedBeforeRuntimeAdmission(t *testing.T) {
	now := time.Unix(1_900_000_000, 0)
	a := newPhaseADaemon(t, now, "2", "4")
	b := newPhaseADaemon(t, now, "7", "9")
	connectPhaseADirectories(a, b, now)
	connectPhaseADirectories(b, a, now)
	installPhaseAAdmission(t, now, a, b)
	installPhaseAAdmission(t, now, b, a)
	installPhaseATransport(t, now, a, b)
	if _, err := a.SendDirectApplication(context.Background(), b.config.AgentID,
		"agent.gift.address-request", []byte{0xa1, 0x01, 0x02}, "idem_"+strings.Repeat("3", 64), uint64(now.Add(time.Hour).Unix())); err != nil {
		t.Fatal(err)
	}
	summary, _ := a.dispatch.Sweep(context.Background(), 0)
	if summary.Sent != 0 {
		t.Fatalf("first-contact Gift was delivered: %+v", summary)
	}
	if pending, err := b.journal.ListPending(now, 10); err != nil || len(pending) != 0 {
		t.Fatalf("first-contact Gift reached runtime admission: %+v %v", pending, err)
	}
}

func TestFirstContactIntentApplicationRemainsTypedAndNonAuthorizing(t *testing.T) {
	now := time.Unix(1_900_000_000, 0)
	a := newPhaseADaemon(t, now, "2", "4")
	b := newPhaseADaemon(t, now, "7", "9")
	connectPhaseADirectories(a, b, now)
	connectPhaseADirectories(b, a, now)
	installPhaseAAdmission(t, now, a, b)
	installPhaseAAdmission(t, now, b, a)
	installPhaseATransport(t, now, a, b)
	canonical, err := commerce.CanonicalIntentApplication(commerce.IntentApplication{SchemaVersion: 1,
		IntentDigest: "sha256:" + strings.Repeat("8", 64), IntentIssuerAgentID: b.config.AgentID, ApplicantAgentID: a.config.AgentID,
		Message: "I can perform this signed request.", ExpiresAtUnix: uint64(now.Add(time.Hour).Unix())})
	if err != nil {
		t.Fatal(err)
	}
	sent, err := a.SendDirectApplication(context.Background(), b.config.AgentID, "intent.application", canonical,
		"idem_"+strings.Repeat("6", 64), uint64(now.Add(time.Hour).Unix()))
	if err != nil {
		t.Fatal(err)
	}
	if summary, err := a.dispatch.Sweep(context.Background(), 0); err != nil || summary.Sent != 1 {
		t.Fatalf("deliver application: %+v %v", summary, err)
	}
	records, err := b.journal.ListPending(now, 10)
	if err != nil {
		t.Fatal(err)
	}
	for _, record := range records {
		if record.EventID != sent.EventID {
			continue
		}
		raw, _ := record.Payload()
		event, decodeErr := envelope.DecodeEventJSON(raw)
		decoded, payloadErr := payload.Decode(event.Kind, event.Content)
		applicationPayload, ok := decoded.(payload.IntentApplication)
		application, applicationErr := commerce.DecodeIntentApplication(applicationPayload.CanonicalApplication)
		if decodeErr != nil || payloadErr != nil || applicationErr != nil || !ok || event.Kind != "intent.application" ||
			application.IntentDigest != "sha256:"+strings.Repeat("8", 64) {
			t.Fatalf("typed application=%+v event=%+v errors=%v/%v/%v", application, event, decodeErr, payloadErr, applicationErr)
		}
		return
	}
	t.Fatal("typed Intent application was not durably received")
}

func TestTwoIndependentDaemonsExchangeDirectMessagesOverTLS(t *testing.T) {
	now := time.Unix(1_900_000_000, 0)
	a := newPhaseADaemon(t, now, "2", "4")
	b := newPhaseADaemon(t, now, "7", "9")
	connectPhaseADirectories(a, b, now)
	connectPhaseADirectories(b, a, now)
	installPhaseAAdmission(t, now, a, b)
	installPhaseAAdmission(t, now, b, a)
	installPhaseAHTTPSTransport(t, now, a, b)
	installPhaseAHTTPSTransport(t, now, b, a)

	first, err := a.SendDirectMessage(context.Background(), b.config.AgentID,
		"text/plain; charset=utf-8", "hello over real TLS", "idem_"+strings.Repeat("c", 64),
		uint64(now.Add(time.Hour).Unix()))
	if err != nil {
		t.Fatalf("queue TLS message: %v", err)
	}
	if summary, err := a.dispatch.Sweep(context.Background(), 0); err != nil || summary.Sent != 1 {
		t.Fatalf("deliver TLS message: summary=%+v err=%v", summary, err)
	}
	assertPhaseAPendingText(t, b, first.EventID, "hello over real TLS", now)

	reply, err := b.ReplyDirectMessage(context.Background(), first.EventID,
		"text/plain; charset=utf-8", "TLS reply", "idem_"+strings.Repeat("d", 64),
		uint64(now.Add(time.Hour).Unix()))
	if err != nil {
		t.Fatalf("queue TLS reply: %v", err)
	}
	if summary, err := b.dispatch.Sweep(context.Background(), 0); err != nil || summary.Sent != 1 {
		t.Fatalf("deliver TLS reply: summary=%+v err=%v", summary, err)
	}
	assertPhaseAPendingText(t, a, reply.EventID, "TLS reply", now)
}

func newPhaseADaemon(t *testing.T, now time.Time, agentDigit, deviceDigit string) *Daemon {
	t.Helper()
	config := testConfig(t)
	config.AgentID = "agent_" + strings.Repeat(agentDigit, 64)
	config.DeviceID = "dev_" + strings.Repeat(deviceDigit, 64)
	delegation, key := publicationFixture(t, &config, now)
	if agentDigit == "7" {
		key = ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x67}, ed25519.SeedSize))
		endpoint, err := identity.DeriveEndpointID(config.Network(), config.AgentID, key.Public().(ed25519.PublicKey))
		if err != nil {
			t.Fatalf("derive independent endpoint: %v", err)
		}
		config.EndpointID = endpoint
		delegation.EndpointID = endpoint
		delegation.IdentityPublicKey = key.Public().(ed25519.PublicKey)
	}
	journal, err := eventlog.Open(config.StateDir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = journal.Close() })
	prekeys, err := newPrekeyRuntime(config, delegation, journal, func() time.Time { return now })
	if err != nil {
		t.Fatalf("prekeys: %v", err)
	}
	if err := prekeys.configureLocalDevice(config.DeviceID, key); err != nil {
		t.Fatalf("configure prekeys: %v", err)
	}
	return &Daemon{config: config, journal: journal, prekeys: prekeys, now: func() time.Time { return now }}
}

func connectPhaseADirectories(local, peer *Daemon, now time.Time) {
	bundles := peer.prekeysCurrentBundles(now)
	result := &directory.RefreshResult{Delegation: peer.prekeys.planner.delegation,
		Descriptor: directory.Descriptor{AgentID: peer.config.AgentID, EndpointID: peer.config.EndpointID},
		Bundles:    bundles, FinalizedCheckpoint: 100, RefreshedAt: now}
	local.discovery = &discoveryRuntime{contacts: &daemonContactDirectory{result: result}}
}

func installPhaseAAdmission(t *testing.T, now time.Time, local, peer *Daemon) {
	t.Helper()
	localDelegation := local.prekeys.planner.delegation
	peerDelegation := peer.prekeys.planner.delegation
	localDigest, _ := identity.Digest(localDelegation)
	peerDigest, _ := identity.Digest(peerDelegation)
	network := local.config.Network()
	state := func(agentID, digest string) *nativev1.NativeStateV1 {
		return &nativev1.NativeStateV1{Network: network,
			TvmStateHash: "tvm-cell-sha256:" + strings.Repeat("c", 64),
			Reference: &nativev1.ChainReference{Workchain: 0, Account: "0:" + strings.Repeat("d", 64),
				LogicalTime: 42, TransactionHash: "sha256:" + strings.Repeat("e", 64),
				ContractCodeHash: registryCode, FinalizedCheckpoint: 100},
			State: &nativev1.NativeStateV1_Agent{Agent: &nativev1.AgentStateV1{AgentId: agentID,
				Policy: &nativev1.ControllerPolicyV1{Threshold: 1}, DelegationDigests: []string{digest}}}}
	}
	resolver := phaseAResolver{states: map[string]*nativev1.NativeStateV1{
		local.config.AgentID: state(local.config.AgentID, localDigest),
		peer.config.AgentID:  state(peer.config.AgentID, peerDigest),
	}}
	devices, err := local.journal.OpenDevices()
	if err != nil {
		t.Fatal(err)
	}
	localRaw, _ := identity.EncodeJSON(localDelegation)
	policy, _ := local.config.AdmissionPolicy()
	gate, err := admission.New(admission.Config{Network: network,
		Chain:    identity.ChainPolicy{RegistryCodeHashes: []string{registryCode}, Locator: phaseALocator{}},
		Resolver: resolver, Journal: local.journal, Devices: devices, Policy: policy,
		LocalDelegationJSON: localRaw, LocalAgentID: local.config.AgentID, LocalEndpointID: local.config.EndpointID,
		Now: func() time.Time { return now }, InstallSalt: bytes.Repeat([]byte{0x5a}, admission.MinInstallSaltBytes)})
	if err != nil {
		t.Fatalf("admission: %v", err)
	}
	local.admission = gate
}

func installPhaseATransport(t *testing.T, now time.Time, sender, recipient *Daemon) {
	t.Helper()
	dispatcher, err := dispatch.New(dispatch.Config{Journal: sender.journal, Suite: e2ee.NewDefaultSuite(),
		Sender: phaseALoopSender{recipient: recipient}, Bindings: dispatch.SessionBindings{Journal: sender.journal,
			Identity: sender.config.Identity(), Network: sender.config.Network()},
		Now: func() time.Time { return now }, Identity: sender.config.Identity(), Network: sender.config.Network(),
		AllowedEventClasses: []string{"agent.gift", "negotiation", "text"}})
	if err != nil {
		t.Fatalf("transport: %v", err)
	}
	sender.dispatch = dispatcher
}

func installPhaseAHTTPSTransport(t *testing.T, now time.Time, sender, recipient *Daemon) {
	t.Helper()
	handler, err := directhttps.NewHandler(directhttps.HandlerConfig{
		Receiver: daemonHTTPSReceiver{daemon: recipient}, Signer: recipient.prekeys.signer,
		EndpointID: recipient.config.EndpointID, DeviceID: recipient.config.DeviceID,
		Now: func() time.Time { return now },
	})
	if err != nil {
		t.Fatalf("HTTPS handler: %v", err)
	}
	server := httptest.NewTLSServer(handler)
	t.Cleanup(server.Close)
	target := directhttps.Target{URL: server.URL + directhttps.IngressPath,
		EndpointPublicKey: append(ed25519.PublicKey(nil), recipient.prekeys.planner.delegation.IdentityPublicKey...)}
	dispatcher, err := dispatch.New(dispatch.Config{Journal: sender.journal, Suite: e2ee.NewDefaultSuite(),
		Sender: directhttps.Sender{Client: server.Client(), Targets: phaseAHTTPSTarget{target: target},
			Now: func() time.Time { return now }},
		Bindings: dispatch.SessionBindings{Journal: sender.journal, Identity: sender.config.Identity(),
			Network: sender.config.Network()},
		Now: func() time.Time { return now }, Identity: sender.config.Identity(), Network: sender.config.Network(),
		AllowedEventClasses: []string{"agent.gift", "negotiation", "text"}})
	if err != nil {
		t.Fatalf("HTTPS transport: %v", err)
	}
	sender.dispatch = dispatcher
}

func assertPhaseAPendingText(t *testing.T, daemon *Daemon, eventID, body string, now time.Time) {
	t.Helper()
	records, err := daemon.journal.ListPending(now, 10)
	if err != nil {
		t.Fatal(err)
	}
	for _, record := range records {
		if record.EventID != eventID {
			continue
		}
		raw, _ := record.Payload()
		event, err := envelope.DecodeEventJSON(raw)
		if err != nil {
			t.Fatal(err)
		}
		decoded, err := payload.Decode(event.Kind, event.Content)
		text, ok := decoded.(payload.Text)
		if err != nil || !ok || text.Body != body {
			t.Fatalf("pending text: decoded=%+v err=%v", decoded, err)
		}
		return
	}
	t.Fatalf("event %s was not pending", eventID)
}
