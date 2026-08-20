# Route-neutral Mailbox authentication

This profile authenticates technical Mailbox operations without choosing a
network listener or transport. It is not a Relay Lease, quota-token, Inbox
Bond, or payment profile.

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

## Deliberate remainder

The post-M0-R network adapter must bind these strict objects to the selected
transport, impose request/response amplification bounds, and supply the
finalized Endpoint verifier. Sender-private deposit tokens, live independent
Relay failover, push wake-ups, and commercial accounting remain separate work.
