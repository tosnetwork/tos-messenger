# Route-neutral Mailbox authentication

This profile authenticates technical Mailbox operations without choosing a
public network transport. `pkg/mailboxapi` now supplies its strict bounded
service protocol, a private Unix carrier and client, while `tos-mailboxd`
assembles the finalized authority and durable store. It is not a Relay Lease,
quota-token, Inbox Bond, or payment profile.

## Authority chain

```text
finalized Agent
  -> live Messaging Endpoint delegation
  -> endpoint-signed mailbox capability grant
  -> capability-signed deposit/read/delete request
  -> durable Relay nonce claim
  -> opaque Mailbox store operation
```

The network adapter must resolve the Endpoint against finalized state before
returning its signing key to the Mailbox authorizer. The opaque mailbox ID is
only a lookup key. Possessing it, a message ID, a ciphertext digest, a StoredAck,
or a storage token grants no read or delete authority.

## Grant

`tos.messaging.mailbox-capability-grant.v1` binds raw-byte canonical genesis
hashes, Agent and Endpoint IDs, the exact Relay public key, opaque mailbox ID,
an independent capability public key, a sorted non-empty subset of `deposit`,
`read`, and `delete`, and a bounded validity interval. The live Endpoint signs
the canonical grant.

Capability keys are scoped to one Relay/mailbox grant. They are not Endpoint,
device, MLS leaf, Agent controller, wallet, or execution keys. A grant cannot
extend beyond the Endpoint authority returned by the finalized-state adapter.

## Request

`tos.messaging.mailbox-access-request.v1` signs:

- the exact grant digest;
- one operation;
- the mailbox ID;
- a digest of the complete operation body;
- a fresh 32-byte nonce;
- issued and expiry times inside a two-minute window.

Deposit body commitment covers the mailbox/message identifiers, ciphertext
digest, storage-token digest, and retention deadline. Read covers the mailbox
and limit. Delete covers mailbox, message, and exact ciphertext digest.

The Relay verifies the live Endpoint, grant signature, Relay/mailbox binding,
permission, request signature, body digest, and clock bounds before claiming
the nonce durably. Concurrent or post-restart reuse is refused. A failure after
the claim does not reopen it; the caller signs a fresh nonce and relies on the
underlying idempotent store operation.

## Runnable service boundary

`tos.messaging.mailbox-service-request.v1` carries exactly one canonical
grant, access request, and deposit/read/delete body. Requests are limited to 2
MiB. Reads return at most eight envelopes and the complete response is limited
to 16 MiB, preventing a small authenticated request from producing an
unbounded response. Unknown fields, trailing JSON, malformed nested objects,
damaged StoredAcks, operation/body mismatches and oversized frames fail
closed.

`mailbox.FinalizedAuthority` rereads the provisioned delegation and verifies
its digest against finalized Agent state for every operation. It also checks
the exact network and Endpoint and refuses a capability grant that outlives
the delegation. `mailboxapi.DepositClient` signs a fresh request nonce for
each transport attempt while preserving the exact Relay envelope, allowing
`mailbox.StoreRedundant` to use independent service processes without
spending a new message identity.

Tests cover deposit/read/delete, signed acknowledgement validation, durable
restart, nonce replay refusal after restart, 2-of-2 service fan-out, one-Relay
failure with an explicit 1-of-2 threshold, and refusal when 2-of-2 is no
longer met.

## Deliberate remainder

The post-M0-R network adapter must bind these strict objects to the selected
public transport. The private Unix carrier, local two-listener tests and
finalized authority adapter do not constitute independently operated Relay
evidence. Sender-private deposit tokens, live independent Relay failover, push
wake-ups, and commercial accounting remain separate work.
