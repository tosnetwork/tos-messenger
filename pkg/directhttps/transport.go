// Package directhttps provides the bounded HTTPS first-contact fallback. It is
// a carrier only: E2EE session authority and admission remain in the daemon.
package directhttps

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"time"

	"github.com/tosnetwork/tos-messenger/internal/canon"
	"github.com/tosnetwork/tos-messenger/internal/ids"
	"github.com/tosnetwork/tos-messenger/pkg/dispatch"
	"github.com/tosnetwork/tos-messenger/pkg/e2ee"
	"github.com/tosnetwork/tos-messenger/pkg/envelope"
	"github.com/tosnetwork/tos-messenger/pkg/eventlog"
	"github.com/tosnetwork/tos-messenger/pkg/fault"
)

const (
	RequestSchema = "tos.messaging.https-delivery.v1"
	AckSchema     = "tos.messaging.https-delivery-ack.v1"
	IngressPath   = "/v1/tos-messenger/messages"
	MaxBodyBytes  = 2 << 20
	MaxAckBytes   = 64 << 10
	MaxClockSkew  = 5 * time.Minute
)

var tokenPattern = regexp.MustCompile(`^[0-9a-zA-Z._~-]+$`)

type wireRequest struct {
	Schema              string `json:"schema"`
	EventID             string `json:"event_id"`
	SessionID           string `json:"session_id"`
	RecipientEndpointID string `json:"recipient_messaging_endpoint_id"`
	RecipientDeviceID   string `json:"recipient_device_id"`
	ConversationID      string `json:"conversation_id"`
	BootstrapBase64     string `json:"bootstrap_base64,omitempty"`
	AdmissionToken      string `json:"admission_token,omitempty"`
	CiphertextBase64    string `json:"ciphertext_base64"`
	CiphertextDigest    string `json:"ciphertext_digest"`
	ExpiresAtUnix       uint64 `json:"expires_at_unix"`
}

type Ack struct {
	Schema              string     `json:"schema"`
	EventID             string     `json:"event_id"`
	SessionID           string     `json:"session_id"`
	RecipientEndpointID string     `json:"recipient_messaging_endpoint_id"`
	RecipientDeviceID   string     `json:"recipient_device_id"`
	CiphertextDigest    string     `json:"ciphertext_digest"`
	Outcome             string     `json:"outcome"`
	Code                fault.Code `json:"code,omitempty"`
	AcceptedAtUnix      uint64     `json:"accepted_at_unix"`
	SignatureHex        string     `json:"endpoint_signature_hex"`
}

type ReceiveResult struct {
	Outcome string
	Code    fault.Code
}

type Receiver interface {
	ReceiveHTTPS(context.Context, dispatch.Message) (ReceiveResult, error)
}

type HandlerConfig struct {
	Receiver             Receiver
	Signer               crypto.Signer
	EndpointID, DeviceID string
	Now                  func() time.Time
}

func NewHandler(config HandlerConfig) (http.Handler, error) {
	if config.Receiver == nil || config.Signer == nil || config.EndpointID == "" || config.DeviceID == "" {
		return nil, errors.New("HTTPS Messenger ingress is incomplete")
	}
	public, ok := config.Signer.Public().(ed25519.PublicKey)
	if !ok || len(public) != ed25519.PublicKeySize {
		return nil, errors.New("HTTPS Messenger ingress needs an Ed25519 Endpoint signer")
	}
	if config.Now == nil {
		config.Now = time.Now
	}
	mux := http.NewServeMux()
	mux.HandleFunc(IngressPath, func(writer http.ResponseWriter, request *http.Request) {
		serve(config, writer, request)
	})
	return mux, nil
}

func serve(config HandlerConfig, writer http.ResponseWriter, request *http.Request) {
	if request.Method != http.MethodPost || request.URL.Path != IngressPath || request.URL.RawQuery != "" {
		http.Error(writer, "not found", http.StatusNotFound)
		return
	}
	if request.Header.Get("Content-Type") != "application/json" {
		http.Error(writer, "invalid request", http.StatusBadRequest)
		return
	}
	request.Body = http.MaxBytesReader(writer, request.Body, MaxBodyBytes)
	raw, err := io.ReadAll(request.Body)
	if err != nil {
		http.Error(writer, "invalid request", http.StatusBadRequest)
		return
	}
	message, err := decodeRequest(raw)
	if err != nil || message.RecipientEndpointID != config.EndpointID || message.RecipientDeviceID != config.DeviceID {
		http.Error(writer, "invalid request", http.StatusBadRequest)
		return
	}
	now := config.Now()
	if now.IsZero() || message.ExpiresAtUnix <= uint64(now.Unix()) ||
		message.ExpiresAtUnix > uint64(now.Add(envelope.MaxEnvelopeLifetimeSeconds*time.Second).Unix()) {
		http.Error(writer, "invalid request", http.StatusBadRequest)
		return
	}
	result, err := config.Receiver.ReceiveHTTPS(request.Context(), message)
	if err != nil {
		http.Error(writer, "temporarily unavailable", http.StatusServiceUnavailable)
		return
	}
	ack := Ack{Schema: AckSchema, EventID: message.EventID, SessionID: message.SessionID,
		RecipientEndpointID: config.EndpointID, RecipientDeviceID: config.DeviceID,
		CiphertextDigest: canon.Digest(message.Ciphertext), Outcome: result.Outcome,
		Code: result.Code, AcceptedAtUnix: uint64(now.Unix())}
	preimage, err := ackSigningBytes(ack)
	if err != nil {
		http.Error(writer, "temporarily unavailable", http.StatusServiceUnavailable)
		return
	}
	signature, err := config.Signer.Sign(rand.Reader, preimage, crypto.Hash(0))
	if err != nil || len(signature) != ed25519.SignatureSize {
		http.Error(writer, "temporarily unavailable", http.StatusServiceUnavailable)
		return
	}
	ack.SignatureHex = hex.EncodeToString(signature)
	encoded, _ := json.Marshal(ack)
	writer.Header().Set("Content-Type", "application/json")
	writer.WriteHeader(http.StatusOK)
	_, _ = writer.Write(encoded)
}

type Target struct {
	URL               string
	EndpointPublicKey ed25519.PublicKey
}

type TargetResolver interface {
	ResolveHTTPS(context.Context, string) (Target, error)
}

type Sender struct {
	Client  *http.Client
	Targets TargetResolver
	Now     func() time.Time
}

func (s Sender) Send(ctx context.Context, message dispatch.Message) error {
	if s.Client == nil || s.Targets == nil || ctx == nil {
		return fault.New(fault.CodeInternal, "HTTPS Messenger sender is incomplete")
	}
	if s.Now == nil {
		s.Now = time.Now
	}
	now := s.Now()
	if now.IsZero() || message.ExpiresAtUnix <= uint64(now.Unix()) ||
		message.ExpiresAtUnix > uint64(now.Add(envelope.MaxEnvelopeLifetimeSeconds*time.Second).Unix()) {
		return fault.New(fault.CodeEventOutsideWindow, "HTTPS Messenger message expiry is invalid")
	}
	target, err := s.Targets.ResolveHTTPS(ctx, message.SessionID)
	if err != nil {
		return fault.Wrap(fault.CodeUnreachable, err)
	}
	parsed, err := url.Parse(target.URL)
	if err != nil || parsed.Scheme != "https" || parsed.User != nil || parsed.RawQuery != "" ||
		parsed.Fragment != "" || parsed.Path != IngressPath || len(target.EndpointPublicKey) != ed25519.PublicKeySize {
		return fault.New(fault.CodeNotAuthentic, "invalid verified HTTPS Messenger target")
	}
	raw, err := encodeRequest(message)
	if err != nil {
		return fault.Wrap(fault.CodeInternal, err)
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, target.URL, bytes.NewReader(raw))
	if err != nil {
		return fault.Wrap(fault.CodeInternal, err)
	}
	request.Header.Set("Content-Type", "application/json")
	response, err := s.Client.Do(request)
	if err != nil {
		return fault.Wrap(fault.CodeUnreachable, err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return fault.New(fault.CodeUnreachable, "HTTPS Messenger peer did not acknowledge")
	}
	if response.Header.Get("Content-Type") != "application/json" {
		return fault.New(fault.CodeNotAuthentic, "HTTPS Messenger peer returned the wrong content type")
	}
	body, err := io.ReadAll(io.LimitReader(response.Body, MaxAckBytes+1))
	if err != nil || len(body) > MaxAckBytes {
		return fault.Wrap(fault.CodeUnreachable, err)
	}
	ack, err := decodeAck(body)
	if err != nil || ack.EventID != message.EventID || ack.SessionID != message.SessionID ||
		ack.RecipientEndpointID != message.RecipientEndpointID || ack.RecipientDeviceID != message.RecipientDeviceID ||
		ack.CiphertextDigest != canon.Digest(message.Ciphertext) {
		return fault.New(fault.CodeNotAuthentic, "HTTPS Messenger acknowledgement mismatch")
	}
	preimage, _ := ackSigningBytes(ack)
	signature, _ := hex.DecodeString(ack.SignatureHex)
	if !ed25519.Verify(target.EndpointPublicKey, preimage, signature) {
		return fault.New(fault.CodeNotAuthentic, "HTTPS Messenger acknowledgement signature failed")
	}
	if now.IsZero() || ack.AcceptedAtUnix > uint64(now.Add(MaxClockSkew).Unix()) ||
		ack.AcceptedAtUnix > message.ExpiresAtUnix {
		return fault.New(fault.CodeNotAuthentic, "HTTPS Messenger acknowledgement time is invalid")
	}
	switch ack.Outcome {
	case "accepted", "duplicate", "held":
		return nil
	case "rejected":
		if ack.Code == "" || !fault.Known(ack.Code) {
			return fault.New(fault.CodeNotAuthentic, "peer returned an invalid rejection")
		}
		return fault.New(ack.Code, "peer rejected encrypted message")
	default:
		return fault.New(fault.CodeNotAuthentic, "peer returned an invalid acknowledgement outcome")
	}
}

func encodeRequest(message dispatch.Message) ([]byte, error) {
	if len(message.Ciphertext) < envelope.MinCiphertextBytes || len(message.Ciphertext) > eventlog.MaxCiphertextBytes ||
		!ids.Event.MatchString(message.EventID) || !ids.Session.MatchString(message.SessionID) ||
		!ids.Endpoint.MatchString(message.RecipientEndpointID) || !ids.Device.MatchString(message.RecipientDeviceID) ||
		!ids.Conversation.MatchString(message.ConversationID) || message.ExpiresAtUnix == 0 ||
		len(message.Bootstrap) > e2ee.MaxBundleSetWireBytes+e2ee.MaxInitialMessageBytes+16<<10 ||
		(message.AdmissionToken != "" && (len(message.AdmissionToken) > envelope.MaxAdmissionTokenBytes ||
			!tokenPattern.MatchString(message.AdmissionToken))) {
		return nil, errors.New("invalid HTTPS Messenger message")
	}
	return json.Marshal(wireRequest{Schema: RequestSchema, EventID: message.EventID,
		SessionID: message.SessionID, RecipientEndpointID: message.RecipientEndpointID,
		RecipientDeviceID: message.RecipientDeviceID, ConversationID: message.ConversationID,
		BootstrapBase64: base64.StdEncoding.EncodeToString(message.Bootstrap), AdmissionToken: message.AdmissionToken,
		CiphertextBase64: base64.StdEncoding.EncodeToString(message.Ciphertext),
		CiphertextDigest: canon.Digest(message.Ciphertext), ExpiresAtUnix: message.ExpiresAtUnix})
}

func decodeRequest(raw []byte) (dispatch.Message, error) {
	var wire wireRequest
	if err := decodeStrict(raw, &wire); err != nil || wire.Schema != RequestSchema {
		return dispatch.Message{}, errors.New("invalid HTTPS Messenger request")
	}
	bootstrap, err := base64.StdEncoding.Strict().DecodeString(wire.BootstrapBase64)
	if err != nil {
		return dispatch.Message{}, errors.New("invalid HTTPS Messenger bootstrap")
	}
	ciphertext, err := base64.StdEncoding.Strict().DecodeString(wire.CiphertextBase64)
	if err != nil || canon.Digest(ciphertext) != wire.CiphertextDigest {
		return dispatch.Message{}, errors.New("invalid HTTPS Messenger ciphertext")
	}
	message := dispatch.Message{EventID: wire.EventID, SessionID: wire.SessionID,
		RecipientEndpointID: wire.RecipientEndpointID, RecipientDeviceID: wire.RecipientDeviceID,
		ConversationID: wire.ConversationID, Bootstrap: bootstrap, AdmissionToken: wire.AdmissionToken,
		Ciphertext: ciphertext, ExpiresAtUnix: wire.ExpiresAtUnix}
	if _, err := encodeRequest(message); err != nil {
		return dispatch.Message{}, err
	}
	return message, nil
}

func decodeAck(raw []byte) (Ack, error) {
	var ack Ack
	if err := decodeStrict(raw, &ack); err != nil || ack.Schema != AckSchema || ack.SignatureHex == "" {
		return Ack{}, errors.New("invalid HTTPS Messenger acknowledgement")
	}
	if _, err := ackSigningBytes(ack); err != nil {
		return Ack{}, err
	}
	return ack, nil
}

func ackSigningBytes(ack Ack) ([]byte, error) {
	if ack.Schema != AckSchema || !ids.Event.MatchString(ack.EventID) || !ids.Session.MatchString(ack.SessionID) ||
		!ids.Endpoint.MatchString(ack.RecipientEndpointID) || !ids.Device.MatchString(ack.RecipientDeviceID) ||
		!canon.ValidDigest(ack.CiphertextDigest) ||
		ack.AcceptedAtUnix == 0 || !validOutcome(ack.Outcome, ack.Code) {
		return nil, errors.New("invalid HTTPS Messenger acknowledgement")
	}
	buffer := bytes.NewBufferString(canon.DomainHTTPSDeliveryAck)
	for _, value := range []string{ack.Schema, ack.EventID, ack.SessionID, ack.RecipientEndpointID,
		ack.RecipientDeviceID, ack.CiphertextDigest, ack.Outcome, string(ack.Code)} {
		canon.Text(buffer, value)
	}
	canon.Uint64(buffer, ack.AcceptedAtUnix)
	return buffer.Bytes(), nil
}

func validOutcome(outcome string, code fault.Code) bool {
	switch outcome {
	case "accepted", "duplicate", "held":
		return code == ""
	case "rejected":
		return code != "" && fault.Known(code)
	default:
		return false
	}
}

func decodeStrict(raw []byte, value any) error {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(value); err != nil {
		return err
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return errors.New("trailing JSON content")
	}
	return nil
}
