// Package prekeyapi exposes the public-only device contribution boundary.
// It is deliberately separate from owner approvals and the Agent runtime: a
// device may read a generation plan and submit one signed public bundle, and
// it receives no authority to create plans or inspect private material.
package prekeyapi

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"

	"github.com/tosnetwork/tos-messenger/internal/canon"
	"github.com/tosnetwork/tos-messenger/internal/ids"
	"github.com/tosnetwork/tos-messenger/internal/localwire"
	"github.com/tosnetwork/tos-messenger/pkg/e2ee"
)

const (
	RequestSchema  = "tos.messaging.prekey-device-request.v1"
	ResponseSchema = "tos.messaging.prekey-device-response.v1"

	// MaxFrameBytes comfortably holds one maximum prekey bundle while keeping
	// this narrower API far below the Agent event API's frame allowance.
	MaxFrameBytes uint32 = 16 << 10
)

type Operation string

const (
	OpCurrentGeneration  Operation = "generation.current"
	OpSubmitContribution Operation = "contribution.submit"
)

type Code string

const (
	CodeInvalidRequest Code = "invalid-request"
	CodeNoGeneration   Code = "no-generation"
	CodeNotAccepted    Code = "not-accepted"
	CodeConflict       Code = "conflict"
	CodeInternal       Code = "internal"
)

// Request is one device-side public contribution operation.
type Request struct {
	Schema string          `json:"schema"`
	Op     Operation       `json:"op"`
	Bundle json.RawMessage `json:"bundle,omitempty"`
}

// Generation reports the exact plan and only aggregate collection state. It
// never returns another device's bundle or any private answering material.
type Generation struct {
	EndpointID         string   `json:"messaging_endpoint_id"`
	DeviceIDs          []string `json:"device_ids"`
	AlgorithmID        string   `json:"algorithm_id"`
	IssuedAtUnix       uint64   `json:"issued_at_unix"`
	ExpiresAtUnix      uint64   `json:"expires_at_unix"`
	ContributionCount  int      `json:"contribution_count"`
	Complete           bool     `json:"complete"`
	FinalizedSetDigest string   `json:"finalized_set_digest,omitempty"`
}

// Response reports whether this exact contribution and complete publication
// transition were fresh, so crash retries need not guess what became durable.
type Response struct {
	Schema            string      `json:"schema"`
	OK                bool        `json:"ok"`
	Code              Code        `json:"code,omitempty"`
	Detail            string      `json:"detail,omitempty"`
	Generation        *Generation `json:"generation,omitempty"`
	ContributionFresh bool        `json:"contribution_fresh,omitempty"`
	PublicationFresh  bool        `json:"publication_fresh,omitempty"`
}

func DecodeRequest(raw []byte) (Request, error) {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	var request Request
	if err := decoder.Decode(&request); err != nil {
		return Request{}, err
	}
	if err := decoder.Decode(new(any)); !errors.Is(err, io.EOF) {
		return Request{}, errors.New("prekey device request has trailing JSON")
	}
	if request.Schema != RequestSchema {
		return Request{}, errors.New("unsupported prekey device request schema")
	}
	switch request.Op {
	case OpCurrentGeneration:
		if len(request.Bundle) != 0 {
			return Request{}, errors.New("generation lookup cannot carry a bundle")
		}
	case OpSubmitContribution:
		if len(request.Bundle) == 0 || len(request.Bundle) > int(MaxFrameBytes/2) {
			return Request{}, errors.New("contribution submission needs one bounded bundle")
		}
	default:
		return Request{}, errors.New("unknown prekey device operation")
	}
	return request, nil
}

func EncodeRequest(request Request) ([]byte, error) {
	request.Schema = RequestSchema
	encoded, err := json.Marshal(request)
	if err != nil {
		return nil, err
	}
	if _, err := DecodeRequest(encoded); err != nil {
		return nil, err
	}
	return localwire.Frame(encoded, MaxFrameBytes)
}

func DecodeResponse(raw []byte) (Response, error) {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	var response Response
	if err := decoder.Decode(&response); err != nil {
		return Response{}, err
	}
	if err := decoder.Decode(new(any)); !errors.Is(err, io.EOF) {
		return Response{}, errors.New("prekey device response has trailing JSON")
	}
	if err := validateResponse(response); err != nil {
		return Response{}, err
	}
	return response, nil
}

func encodeResponse(response Response) ([]byte, error) {
	response.Schema = ResponseSchema
	if err := validateResponse(response); err != nil {
		return nil, err
	}
	encoded, err := json.Marshal(response)
	if err != nil {
		return nil, err
	}
	return localwire.Frame(encoded, MaxFrameBytes)
}

// ReadFrame reads one bounded API body.
func ReadFrame(reader io.Reader) ([]byte, error) {
	return localwire.ReadFrame(reader, MaxFrameBytes)
}

// WriteFrame writes one bounded API body.
func WriteFrame(writer io.Writer, body []byte) error {
	return localwire.WriteFrame(writer, body, MaxFrameBytes)
}

func validateResponse(response Response) error {
	if response.Schema != ResponseSchema {
		return errors.New("unsupported prekey device response schema")
	}
	if response.OK {
		if response.Code != "" || response.Detail != "" || response.Generation == nil {
			return errors.New("invalid successful prekey device response")
		}
		return validateGeneration(*response.Generation)
	}
	if response.Generation != nil || response.ContributionFresh || response.PublicationFresh || response.Detail == "" {
		return errors.New("invalid refused prekey device response")
	}
	switch response.Code {
	case CodeInvalidRequest, CodeNoGeneration, CodeNotAccepted, CodeConflict, CodeInternal:
		return nil
	default:
		return errors.New("unknown prekey device response code")
	}
}

func validateGeneration(generation Generation) error {
	if !ids.Endpoint.MatchString(generation.EndpointID) || len(generation.DeviceIDs) == 0 ||
		len(generation.DeviceIDs) > e2ee.MaxDevicesPerSet || e2ee.ValidateAlgorithmID(generation.AlgorithmID) != nil ||
		generation.IssuedAtUnix == 0 || generation.ExpiresAtUnix <= generation.IssuedAtUnix ||
		generation.ExpiresAtUnix-generation.IssuedAtUnix > e2ee.MaxBundleLifetimeSeconds ||
		generation.ContributionCount < 0 || generation.ContributionCount > len(generation.DeviceIDs) ||
		generation.Complete != (generation.ContributionCount == len(generation.DeviceIDs)) ||
		generation.FinalizedSetDigest != "" && (!generation.Complete || !canon.ValidDigest(generation.FinalizedSetDigest)) {
		return errors.New("invalid prekey device generation response")
	}
	for index, deviceID := range generation.DeviceIDs {
		if !ids.Device.MatchString(deviceID) || index > 0 && generation.DeviceIDs[index-1] >= deviceID {
			return errors.New("invalid prekey device generation roster")
		}
	}
	return nil
}
