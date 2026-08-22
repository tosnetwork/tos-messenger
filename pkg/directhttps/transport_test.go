package directhttps

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/tosnetwork/tos-messenger/internal/canon"
	"github.com/tosnetwork/tos-messenger/pkg/dispatch"
	"github.com/tosnetwork/tos-messenger/pkg/fault"
)

type testReceiver struct {
	message dispatch.Message
	result  ReceiveResult
	calls   int
}

func (r *testReceiver) ReceiveHTTPS(_ context.Context, message dispatch.Message) (ReceiveResult, error) {
	r.calls++
	r.message = message
	return r.result, nil
}

type fixedTarget struct{ target Target }

func (r fixedTarget) ResolveHTTPS(context.Context, string) (Target, error) { return r.target, nil }

func testMessage() dispatch.Message {
	return dispatch.Message{EventID: "evt_" + strings.Repeat("a", 64),
		SessionID:           "ses_" + strings.Repeat("b", 64),
		RecipientEndpointID: "mep_" + strings.Repeat("c", 64),
		RecipientDeviceID:   "dev_" + strings.Repeat("d", 64),
		ConversationID:      "conv_" + strings.Repeat("e", 64), Bootstrap: []byte("public bootstrap"),
		Ciphertext: bytes.Repeat([]byte("authenticated ciphertext"), 2), ExpiresAtUnix: 1_900_003_600}
}

func TestHTTPSCarrierRequiresEndpointSignedDurableAck(t *testing.T) {
	key := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x41}, ed25519.SeedSize))
	receiver := &testReceiver{result: ReceiveResult{Outcome: "accepted"}}
	handler, err := NewHandler(HandlerConfig{Receiver: receiver, Signer: key,
		EndpointID: testMessage().RecipientEndpointID, DeviceID: testMessage().RecipientDeviceID,
		Now: func() time.Time { return time.Unix(1_900_000_000, 0) }})
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewTLSServer(handler)
	defer server.Close()
	sender := Sender{Client: server.Client(), Targets: fixedTarget{Target{
		URL: server.URL + IngressPath, EndpointPublicKey: key.Public().(ed25519.PublicKey)}},
		Now: func() time.Time { return time.Unix(1_900_000_000, 0) }}
	message := testMessage()
	if err := sender.Send(context.Background(), message); err != nil {
		t.Fatalf("send: %v", err)
	}
	if receiver.message.EventID != message.EventID ||
		!bytes.Equal(receiver.message.Ciphertext, message.Ciphertext) ||
		!bytes.Equal(receiver.message.Bootstrap, message.Bootstrap) {
		t.Fatalf("wire changed message: %+v", receiver.message)
	}
}

func TestHTTPSCarrierRejectsForgedAckAndSignedPeerRejection(t *testing.T) {
	serverKey := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x42}, ed25519.SeedSize))
	claimedKey := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x43}, ed25519.SeedSize))
	receiver := &testReceiver{result: ReceiveResult{Outcome: "accepted"}}
	handler, _ := NewHandler(HandlerConfig{Receiver: receiver, Signer: serverKey,
		EndpointID: testMessage().RecipientEndpointID, DeviceID: testMessage().RecipientDeviceID,
		Now: func() time.Time { return time.Unix(1_900_000_000, 0) }})
	server := httptest.NewTLSServer(handler)
	defer server.Close()
	sender := Sender{Client: server.Client(), Targets: fixedTarget{Target{URL: server.URL + IngressPath,
		EndpointPublicKey: claimedKey.Public().(ed25519.PublicKey)}},
		Now: func() time.Time { return time.Unix(1_900_000_000, 0) }}
	if err := sender.Send(context.Background(), testMessage()); fault.CodeOf(err) != fault.CodeNotAuthentic {
		t.Fatalf("forged ack was not refused: %v", err)
	}

	receiver.result = ReceiveResult{Outcome: "rejected", Code: fault.CodeAdmissionRequired}
	sender.Targets = fixedTarget{Target{URL: server.URL + IngressPath,
		EndpointPublicKey: serverKey.Public().(ed25519.PublicKey)}}
	if err := sender.Send(context.Background(), testMessage()); fault.CodeOf(err) != fault.CodeAdmissionRequired {
		t.Fatalf("signed rejection lost its disposition: %v", err)
	}
}

func TestHTTPSWireRejectsUnknownAuthorityFields(t *testing.T) {
	raw, err := encodeRequest(testMessage())
	if err != nil {
		t.Fatal(err)
	}
	raw = append(append([]byte(nil), raw[:len(raw)-1]...), []byte(`,"route":"invented"}`)...)
	if _, err := decodeRequest(raw); err == nil {
		t.Fatal("unknown route authority was accepted")
	}
}

func TestHTTPSIngressRejectsWrongContentTypeBeforeReceiver(t *testing.T) {
	key := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x44}, ed25519.SeedSize))
	receiver := &testReceiver{result: ReceiveResult{Outcome: "accepted"}}
	handler, err := NewHandler(HandlerConfig{Receiver: receiver, Signer: key,
		EndpointID: testMessage().RecipientEndpointID, DeviceID: testMessage().RecipientDeviceID,
		Now: func() time.Time { return time.Unix(1_900_000_000, 0) }})
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := encodeRequest(testMessage())
	request := httptest.NewRequest(http.MethodPost, IngressPath, bytes.NewReader(raw))
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusBadRequest || receiver.calls != 0 {
		t.Fatalf("wrong content type reached receiver: status=%d calls=%d", response.Code, receiver.calls)
	}
}

func TestHTTPSCarrierRejectsSignedAckOutsideMessageWindow(t *testing.T) {
	key := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x45}, ed25519.SeedSize))
	server := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		raw, _ := io.ReadAll(request.Body)
		message, err := decodeRequest(raw)
		if err != nil {
			t.Errorf("decode request: %v", err)
			return
		}
		ack := Ack{Schema: AckSchema, EventID: message.EventID, SessionID: message.SessionID,
			RecipientEndpointID: message.RecipientEndpointID, RecipientDeviceID: message.RecipientDeviceID,
			CiphertextDigest: canon.Digest(message.Ciphertext), Outcome: "accepted",
			AcceptedAtUnix: message.ExpiresAtUnix + 1}
		preimage, _ := ackSigningBytes(ack)
		ack.SignatureHex = hex.EncodeToString(ed25519.Sign(key, preimage))
		writer.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(writer).Encode(ack)
	}))
	defer server.Close()
	sender := Sender{Client: server.Client(), Targets: fixedTarget{Target{URL: server.URL + IngressPath,
		EndpointPublicKey: key.Public().(ed25519.PublicKey)}},
		Now: func() time.Time { return time.Unix(1_900_000_000, 0) }}
	if err := sender.Send(context.Background(), testMessage()); fault.CodeOf(err) != fault.CodeNotAuthentic {
		t.Fatalf("signed out-of-window acknowledgement was accepted: %v", err)
	}
}
