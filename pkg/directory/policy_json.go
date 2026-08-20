package directory

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
)

const MaxDescriptorPolicyWireBytes = 4 << 10

type wireDescriptorPolicy struct {
	Schema             string `json:"schema"`
	MaxEnvelopeBytes   uint32 `json:"max_envelope_bytes"`
	MaxLifetimeSeconds uint64 `json:"max_lifetime_seconds"`
	AllowHTTPSEndpoint bool   `json:"allow_https_endpoint"`
	RequireADNL        bool   `json:"require_adnl"`
}

func EncodeDescriptorPolicyJSON(policy DescriptorPolicy) ([]byte, error) {
	if err := policy.Validate(); err != nil {
		return nil, err
	}
	return json.Marshal(wireDescriptorPolicy{
		Schema: DescriptorPolicySchema, MaxEnvelopeBytes: policy.MaxEnvelopeBytes,
		MaxLifetimeSeconds: policy.MaxLifetimeSeconds, AllowHTTPSEndpoint: policy.AllowHTTPSEndpoint,
		RequireADNL: policy.RequireADNL,
	})
}

func DecodeDescriptorPolicyJSON(raw []byte) (DescriptorPolicy, error) {
	if len(raw) == 0 || len(raw) > MaxDescriptorPolicyWireBytes {
		return DescriptorPolicy{}, errors.New("invalid descriptor policy wire size")
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	var value wireDescriptorPolicy
	if err := decoder.Decode(&value); err != nil {
		return DescriptorPolicy{}, err
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return DescriptorPolicy{}, errors.New("descriptor policy has trailing JSON")
	}
	if value.Schema != DescriptorPolicySchema {
		return DescriptorPolicy{}, errors.New("unsupported descriptor policy schema")
	}
	policy := DescriptorPolicy{MaxEnvelopeBytes: value.MaxEnvelopeBytes, MaxLifetimeSeconds: value.MaxLifetimeSeconds,
		AllowHTTPSEndpoint: value.AllowHTTPSEndpoint, RequireADNL: value.RequireADNL}
	if err := policy.Validate(); err != nil {
		return DescriptorPolicy{}, err
	}
	return policy, nil
}
