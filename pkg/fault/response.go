package fault

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
)

// ResponseSchema is the strict wire schema identifier.
const ResponseSchema = "tos.messaging.fault-response.v1"

// MaxRetryAfterSeconds bounds a hint a peer is asked to honour.
const MaxRetryAfterSeconds = 24 * 60 * 60

// Response is what a peer is told.
//
// It carries a code and, for the few codes where waiting is the remedy, how
// long to wait. It never carries local detail: detail is written for the
// operator reading a log, and the same sentence handed to a stranger is how
// internal state leaks one error message at a time.
type Response struct {
	Code              Code   `json:"code"`
	RetryAfterSeconds uint32 `json:"retry_after_seconds,omitempty"`
}

type wireResponse struct {
	Schema string `json:"schema"`
	Response
}

// Peer converts a failure into what may be returned to the sender.
//
// A code that is not peer-visible becomes CodeRejected, so refusals that would
// otherwise be distinguishable all look alike from the outside.
func Peer(err error, retryAfterSeconds uint32) Response {
	return PeerCode(CodeOf(err), retryAfterSeconds)
}

// PeerCode converts a code into what may be returned to the sender.
func PeerCode(code Code, retryAfterSeconds uint32) Response {
	if !PeerVisible(code) {
		return Response{Code: CodeRejected}
	}
	classification := registry[code]
	if !classification.retryHint || retryAfterSeconds == 0 {
		return Response{Code: code}
	}
	if retryAfterSeconds > MaxRetryAfterSeconds {
		retryAfterSeconds = MaxRetryAfterSeconds
	}
	return Response{Code: code, RetryAfterSeconds: retryAfterSeconds}
}

// EncodeResponseJSON returns the transport representation.
func EncodeResponseJSON(response Response) ([]byte, error) {
	if err := ValidateResponse(response); err != nil {
		return nil, err
	}
	return json.Marshal(wireResponse{Schema: ResponseSchema, Response: response})
}

// DecodeResponseJSON rejects unknown fields, trailing data, and any code this
// build does not classify.
func DecodeResponseJSON(raw []byte) (Response, error) {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	var value wireResponse
	if err := decoder.Decode(&value); err != nil {
		return Response{}, err
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return Response{}, errors.New("fault response has trailing JSON")
	}
	if value.Schema != ResponseSchema {
		return Response{}, errors.New("unsupported fault response schema")
	}
	if err := ValidateResponse(value.Response); err != nil {
		return Response{}, err
	}
	return value.Response, nil
}

// ValidateResponse enforces that a response is one this build classifies, is
// permitted to be seen by a peer, and carries a hint only where a hint means
// something.
func ValidateResponse(response Response) error {
	classification, found := registry[response.Code]
	if !found {
		return errors.New("unknown fault code")
	}
	if !classification.peerVisible {
		return errors.New("fault code may not be disclosed to a peer")
	}
	if response.RetryAfterSeconds != 0 {
		if !classification.retryHint {
			return errors.New("fault code carries no retry hint")
		}
		if response.RetryAfterSeconds > MaxRetryAfterSeconds {
			return errors.New("retry hint exceeds its bound")
		}
	}
	return nil
}
