package directory

import (
	"bytes"
	"errors"

	"github.com/tosnetwork/tos-messenger/internal/canon"
)

const (
	// DescriptorPolicySchema is the strict schema of a descriptor policy.
	DescriptorPolicySchema = "tos.messaging.descriptor-policy.v1"

	// RelaySetSchema namespaces the digest of a published Relay set.
	RelaySetSchema = "tos.messaging.relay-set.v1"
)

// DescriptorPolicy is what an Agent commits its endpoint may advertise.
//
// The delegation carries only this document's digest, and until now nothing
// read it: a commitment that is checked for shape and never for content
// implies an enforcement that does not exist, which is worse than no
// commitment at all.
//
// What it buys is a bound on a delegated key. An endpoint key lives online and
// may be taken; the Agent controller key does not. Whoever holds the endpoint
// key can sign descriptors, but only within the limits the Agent committed to
// before the key was anywhere, and a descriptor outside them is refused even
// though its signature is perfectly good.
type DescriptorPolicy struct {
	// MaxEnvelopeBytes caps what the endpoint may advertise accepting.
	MaxEnvelopeBytes uint32 `json:"max_envelope_bytes"`
	// MaxLifetimeSeconds caps how long one descriptor may stay valid.
	MaxLifetimeSeconds uint64 `json:"max_lifetime_seconds"`
	// AllowHTTPSEndpoint permits the bounded bootstrap route.
	AllowHTTPSEndpoint bool `json:"allow_https_endpoint"`
	// RequireADNL refuses a descriptor that advertises no ADNL identity.
	RequireADNL bool `json:"require_adnl"`
}

// Validate enforces that a policy is expressible and not vacuous.
func (p DescriptorPolicy) Validate() error {
	if p.MaxEnvelopeBytes < MinEnvelopeBytes || p.MaxEnvelopeBytes > MaxEnvelopeBytes {
		return errors.New("invalid descriptor policy envelope bound")
	}
	if p.MaxLifetimeSeconds == 0 || p.MaxLifetimeSeconds > MaxDescriptorLifetimeSeconds {
		return errors.New("invalid descriptor policy lifetime bound")
	}
	if !p.AllowHTTPSEndpoint && !p.RequireADNL {
		// A policy that forbids the bootstrap route without requiring the
		// direct one permits descriptors with no reachable route at all.
		return errors.New("a descriptor policy must leave at least one route open")
	}
	return nil
}

// Digest is the value a delegation commits.
func (p DescriptorPolicy) Digest() (string, error) {
	if err := p.Validate(); err != nil {
		return "", err
	}
	buffer := bytes.NewBufferString(canon.DomainDescriptorPolicy)
	canon.Text(buffer, DescriptorPolicySchema)
	canon.Uint32(buffer, p.MaxEnvelopeBytes)
	canon.Uint64(buffer, p.MaxLifetimeSeconds)
	canon.Uint32(buffer, boolean(p.AllowHTTPSEndpoint))
	canon.Uint32(buffer, boolean(p.RequireADNL))
	return canon.Digest(buffer.Bytes()), nil
}

// Permits reports whether a descriptor stays inside the policy.
func (p DescriptorPolicy) Permits(descriptor Descriptor) error {
	if err := p.Validate(); err != nil {
		return err
	}
	if descriptor.MaximumEnvelopeBytes > p.MaxEnvelopeBytes {
		return errors.New("descriptor advertises a larger envelope than its Agent committed")
	}
	if descriptor.ExpiresAtUnix-descriptor.IssuedAtUnix > p.MaxLifetimeSeconds {
		return errors.New("descriptor lives longer than its Agent committed")
	}
	if !p.AllowHTTPSEndpoint && descriptor.HTTPSEndpoint != "" {
		return errors.New("descriptor advertises an HTTPS endpoint its Agent did not permit")
	}
	if p.RequireADNL && descriptor.ADNLID == "" {
		return errors.New("descriptor advertises no ADNL identity where its Agent required one")
	}
	return nil
}

// RelaySetDigest is the value a descriptor publishes for its Mailbox Relays.
//
// The empty set has a defined digest so that an endpoint with no Relays, which
// is every endpoint until offline delivery exists, publishes a value everyone
// computes the same way instead of inventing a placeholder each.
func RelaySetDigest(relays []string) (string, error) {
	if len(relays) > MaxCandidateRelays {
		return "", errors.New("too many published Relays")
	}
	seen := make(map[string]struct{}, len(relays))
	buffer := bytes.NewBufferString(canon.DomainRelaySet)
	canon.Text(buffer, RelaySetSchema)
	canon.Uint32(buffer, uint32(len(relays)))
	for index, relay := range relays {
		if relay == "" || len(relay) > MaxDescriptorLocatorBytes {
			return "", errors.New("invalid published Relay")
		}
		if index > 0 && relays[index-1] >= relay {
			return "", errors.New("published Relays must be sorted and unique")
		}
		if _, duplicate := seen[relay]; duplicate {
			return "", errors.New("published Relays must be sorted and unique")
		}
		seen[relay] = struct{}{}
		canon.Text(buffer, relay)
	}
	return canon.Digest(buffer.Bytes()), nil
}

// EmptyRelaySetDigest is what an endpoint with no Mailbox Relays publishes.
func EmptyRelaySetDigest() string {
	digest, err := RelaySetDigest(nil)
	if err != nil {
		panic("the empty Relay set must always have a digest: " + err.Error())
	}
	return digest
}

func boolean(value bool) uint32 {
	if value {
		return 1
	}
	return 0
}
