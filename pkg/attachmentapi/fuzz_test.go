package attachmentapi

import (
	"testing"

	"github.com/tosnetwork/tos-messenger/pkg/attachments"
)

func FuzzDecodeAttachmentServiceRequest(f *testing.F) {
	fixture := newFixture(f, 1)
	request := signedRequest(f, fixture, OpUpload, attachments.OperationUpload,
		mustUploadDigest(f, fixture.grant, fixture.chunks), fixture.chunks, nil, 0x51)
	valid, err := EncodeRequest(request)
	if err != nil {
		f.Fatal(err)
	}
	f.Add(valid)
	f.Add([]byte(`{}`))
	f.Fuzz(func(t *testing.T, raw []byte) {
		request, err := DecodeRequest(raw)
		if err != nil {
			return
		}
		reencoded, err := EncodeRequest(request)
		if err != nil {
			t.Fatalf("accepted request did not re-encode: %v", err)
		}
		decoded, err := DecodeRequest(reencoded)
		if err != nil || decoded.Op != request.Op {
			t.Fatalf("request round trip: %+v %v", decoded, err)
		}
	})
}

func FuzzDecodeAttachmentServiceResponse(f *testing.F) {
	complete := false
	valid, err := EncodeResponse(Response{OK: true, Complete: &complete})
	if err != nil {
		f.Fatal(err)
	}
	f.Add(valid)
	f.Add([]byte(`{}`))
	f.Fuzz(func(t *testing.T, raw []byte) {
		response, err := DecodeResponse(raw)
		if err != nil {
			return
		}
		reencoded, err := EncodeResponse(response)
		if err != nil {
			t.Fatalf("accepted response did not re-encode: %v", err)
		}
		if _, err := DecodeResponse(reencoded); err != nil {
			t.Fatalf("response round trip: %v", err)
		}
	})
}
