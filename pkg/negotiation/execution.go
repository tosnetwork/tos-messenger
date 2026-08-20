package negotiation

import (
	"bytes"
	"errors"

	"github.com/tosnetwork/tos-messenger/internal/canon"
)

// ExecutionID is the identity of one economic purchase, derived from the
// authorising mandate and the exact terms, and nothing else.
//
// It exists because the action identifier an owner or a policy approves also
// commits how the action was described and where it came from, so the same
// purchase re-described, or driven by different received content, produces a
// different action identifier. Keying a one-shot authorisation on that
// identifier would let a purchase be authorised again by changing its summary.
// The execution identity is stable across those changes: same mandate, same
// terms, same purchase -- and it is what a durable one-shot is keyed on so a
// spend happens once, not once per way of describing it.
//
// The mandate scopes it: a purchase authorised under one mandate is not the same
// economic execution as an identical purchase authorised under another. The
// terms carry the provider, capability, manifest, escrow, and price, so a change
// to any of them is a different purchase with a different identity.
func ExecutionID(mandateID string, terms Terms) (string, error) {
	if mandateID == "" || len(mandateID) > 128 {
		return "", errors.New("an economic execution needs the mandate that authorises it")
	}
	digest, err := terms.Digest()
	if err != nil {
		return "", err
	}
	buffer := bytes.NewBufferString(canon.DomainEconomicExecution)
	canon.Text(buffer, mandateID)
	canon.Text(buffer, digest)
	return "eex_" + canon.Digest(buffer.Bytes())[len("sha256:"):], nil
}
