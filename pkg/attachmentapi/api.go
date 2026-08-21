// Package attachmentapi is the bounded service protocol for authenticated
// opaque attachment storage. The same signed frames can use a private Unix
// carrier for deployment tests or strict public HTTPS without making either
// locator or TLS an authority source.
package attachmentapi

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"

	"github.com/tosnetwork/tos-messenger/internal/localwire"
	"github.com/tosnetwork/tos-messenger/pkg/attachments"
)

const (
	RequestSchema           = "tos.messaging.attachment-service-request.v1"
	ResponseSchema          = "tos.messaging.attachment-service-response.v1"
	MaxBatchChunks          = 16
	MaxRequestBytes  uint32 = 24 << 20
	MaxResponseBytes uint32 = 24 << 20
)

type Operation string

const (
	OpUpload Operation = "upload"
	OpFetch  Operation = "fetch"
	OpDelete Operation = "delete"
)

type Code string

const (
	CodeInvalid  Code = "invalid-request"
	CodeDenied   Code = "denied"
	CodeConflict Code = "conflict"
	CodeQuota    Code = "quota"
	CodeMissing  Code = "missing"
	CodeInternal Code = "internal"
)

type WireChunk struct {
	Index            uint32 `json:"index"`
	Digest           string `json:"digest"`
	CiphertextBase64 string `json:"ciphertext_base64"`
}

type Request struct {
	Schema  string          `json:"schema"`
	Op      Operation       `json:"op"`
	Grant   json.RawMessage `json:"grant"`
	Access  json.RawMessage `json:"access"`
	Chunks  []WireChunk     `json:"chunks,omitempty"`
	Digests []string        `json:"digests,omitempty"`
}

type Response struct {
	Schema   string          `json:"schema"`
	OK       bool            `json:"ok"`
	Code     Code            `json:"code,omitempty"`
	Detail   string          `json:"detail,omitempty"`
	Complete *bool           `json:"complete,omitempty"`
	Ack      json.RawMessage `json:"ack,omitempty"`
	Chunks   *[]WireChunk    `json:"chunks,omitempty"`
}

func EncodeRequest(request Request) ([]byte, error) {
	request.Schema = RequestSchema
	raw, err := json.Marshal(request)
	if err != nil {
		return nil, err
	}
	if _, err := DecodeRequest(raw); err != nil {
		return nil, err
	}
	return raw, nil
}

func DecodeRequest(raw []byte) (Request, error) {
	if len(raw) == 0 || len(raw) > int(MaxRequestBytes) {
		return Request{}, errors.New("attachment service request is outside its bound")
	}
	var request Request
	if err := strict(raw, &request); err != nil {
		return Request{}, err
	}
	if request.Schema != RequestSchema {
		return Request{}, errors.New("unsupported attachment service request schema")
	}
	grant, err := attachments.DecodeGrantJSON(request.Grant)
	if err != nil {
		return Request{}, err
	}
	access, err := attachments.DecodeAccessRequestJSON(request.Access)
	if err != nil {
		return Request{}, err
	}
	switch request.Op {
	case OpUpload:
		if len(request.Chunks) == 0 || len(request.Chunks) > MaxBatchChunks || len(request.Digests) != 0 || access.Operation != attachments.OperationUpload {
			return Request{}, errors.New("invalid attachment upload shape")
		}
		chunks, err := DecodeChunks(request.Chunks)
		if err != nil {
			return Request{}, err
		}
		if _, err := attachments.UploadBodyDigest(grant, chunks); err != nil {
			return Request{}, err
		}
	case OpFetch:
		if len(request.Chunks) != 0 || len(request.Digests) == 0 || len(request.Digests) > MaxBatchChunks || access.Operation != attachments.OperationFetch {
			return Request{}, errors.New("invalid attachment fetch shape")
		}
		if _, err := attachments.FetchBodyDigest(grant, request.Digests); err != nil {
			return Request{}, err
		}
	case OpDelete:
		if len(request.Chunks) != 0 || len(request.Digests) != 0 || access.Operation != attachments.OperationDelete {
			return Request{}, errors.New("invalid attachment delete shape")
		}
		if _, err := attachments.DeleteBodyDigest(grant); err != nil {
			return Request{}, err
		}
	default:
		return Request{}, errors.New("unknown attachment service operation")
	}
	return request, nil
}

func EncodeResponse(response Response) ([]byte, error) {
	response.Schema = ResponseSchema
	if err := validateResponse(response); err != nil {
		return nil, err
	}
	raw, err := json.Marshal(response)
	if err != nil {
		return nil, err
	}
	if len(raw) > int(MaxResponseBytes) {
		return nil, errors.New("attachment service response exceeds its bound")
	}
	return raw, nil
}

func DecodeResponse(raw []byte) (Response, error) {
	if len(raw) == 0 || len(raw) > int(MaxResponseBytes) {
		return Response{}, errors.New("attachment service response is outside its bound")
	}
	var response Response
	if err := strict(raw, &response); err != nil {
		return Response{}, err
	}
	if err := validateResponse(response); err != nil {
		return Response{}, err
	}
	return response, nil
}

func validateResponse(response Response) error {
	if response.Schema != ResponseSchema {
		return errors.New("unsupported attachment service response schema")
	}
	if !response.OK {
		if response.Detail == "" || response.Complete != nil || len(response.Ack) != 0 || response.Chunks != nil {
			return errors.New("invalid refused attachment response")
		}
		switch response.Code {
		case CodeInvalid, CodeDenied, CodeConflict, CodeQuota, CodeMissing, CodeInternal:
			return nil
		}
		return errors.New("unknown attachment response code")
	}
	if response.Code != "" || response.Detail != "" {
		return errors.New("invalid successful attachment response")
	}
	present := 0
	if response.Complete != nil {
		present++
		if *response.Complete {
			if _, err := attachments.DecodeStoredAckJSON(response.Ack); err != nil {
				return err
			}
		} else if len(response.Ack) != 0 {
			return errors.New("partial attachment upload carries an acknowledgement")
		}
	} else if len(response.Ack) != 0 {
		if _, err := attachments.DecodeDeleteAckJSON(response.Ack); err != nil {
			return err
		}
		present++
	}
	if response.Chunks != nil {
		if len(*response.Chunks) == 0 || len(*response.Chunks) > MaxBatchChunks {
			return errors.New("invalid attachment response chunk count")
		}
		if _, err := DecodeChunks(*response.Chunks); err != nil {
			return err
		}
		present++
	}
	if present != 1 {
		return errors.New("ambiguous successful attachment response")
	}
	return nil
}

func EncodeChunks(chunks []attachments.Chunk) ([]WireChunk, error) {
	if len(chunks) == 0 || len(chunks) > MaxBatchChunks {
		return nil, errors.New("invalid attachment wire chunk count")
	}
	values := make([]WireChunk, len(chunks))
	for index, chunk := range chunks {
		values[index] = WireChunk{Index: chunk.Index, Digest: chunk.Digest,
			CiphertextBase64: base64.StdEncoding.EncodeToString(chunk.Ciphertext)}
	}
	if _, err := DecodeChunks(values); err != nil {
		return nil, err
	}
	return values, nil
}

func DecodeChunks(values []WireChunk) ([]attachments.Chunk, error) {
	if len(values) == 0 || len(values) > MaxBatchChunks {
		return nil, errors.New("invalid attachment wire chunk count")
	}
	chunks := make([]attachments.Chunk, len(values))
	var total int
	for index, value := range values {
		ciphertext, err := base64.StdEncoding.Strict().DecodeString(value.CiphertextBase64)
		if err != nil || base64.StdEncoding.EncodeToString(ciphertext) != value.CiphertextBase64 || len(ciphertext) <= 16 || len(ciphertext) > attachments.MaxChunkBytes+16 {
			return nil, errors.New("invalid attachment wire ciphertext")
		}
		total += len(ciphertext)
		if total > MaxBatchChunks*(attachments.MaxChunkBytes+16) {
			return nil, errors.New("attachment wire chunk batch exceeds its bound")
		}
		chunks[index] = attachments.Chunk{Index: value.Index, Digest: value.Digest, Ciphertext: ciphertext}
	}
	return chunks, nil
}

func FrameRequest(raw []byte) ([]byte, error)       { return localwire.Frame(raw, MaxRequestBytes) }
func FrameResponse(raw []byte) ([]byte, error)      { return localwire.Frame(raw, MaxResponseBytes) }
func ReadRequestFrame(r io.Reader) ([]byte, error)  { return localwire.ReadFrame(r, MaxRequestBytes) }
func ReadResponseFrame(r io.Reader) ([]byte, error) { return localwire.ReadFrame(r, MaxResponseBytes) }

func strict(raw []byte, target any) error {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return err
	}
	if err := decoder.Decode(new(any)); !errors.Is(err, io.EOF) {
		return errors.New("attachment service wire has trailing JSON")
	}
	return nil
}
