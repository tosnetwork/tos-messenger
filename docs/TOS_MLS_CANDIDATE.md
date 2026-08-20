# TOS-MLS v1 application adapter (candidate)

This repository implements the route-neutral application invariants around RFC
9420 and a process-isolated Driver backed by pinned OpenMLS `0.8.1`. Messenger
does **not** reimplement TreeKEM, HPKE, the MLS key schedule, or MLS parsing;
those operations remain inside OpenMLS through `group.Driver`. Passing these
tests is implementation evidence, not an independent cryptographic review.

The implemented boundary consists of:

- suite `0x0001` only, and a Driver hook that must parse the KeyPackage and
match its BasicCredential identity and LeafNode signing key;
- an endpoint-signed per-device credential binding the exact network tuple,
  Agent, Endpoint, Device, current device-set digest, distinct Ed25519 leaf
  signing public key, exact KeyPackage bytes, and validity window;
- strict JSON publication plus a domain-separated canonical signature preimage
  and committed positive/adversarial vectors;
- exact BasicCredential identity bytes and a 32-byte network-bound MLS
  `group_id`, both with candidate change-detection vectors;
- explicit `room_epoch` and `mls_epoch` clocks. Agent membership advances both;
  device churn and PCS refresh may advance only `mls_epoch`;
- v1 capacity bounds of 32 logical Agents, 64 total active device leaves, the
  existing 16-device-per-Endpoint limit, and 32 leaf operations per Commit;
- deterministic conversion of an accepted device-set succession to MLS leaf
  Add/Remove/Update work. Removing one device leaves the Agent's other devices
  present;
- a crash-safe ledger for opaque library state, current clocks, membership
  commitment, accepted commit parent, globally consumed one-time KeyPackages,
  and processed Welcomes. Exact replay is idempotent; rollback, gaps, state
  substitution, duplicate Welcomes, KeyPackage reuse, and competing children
  fail closed.
- `rust/openmls-driver`, a one-request-per-process OpenMLS adapter fixed to suite
  `0x0001`. It uses strict TLS decoding, a bounded deterministic full-storage
  snapshot, exact BasicCredential/leaf-key validation, canonical group IDs,
  founder/join, mixed Add/Remove replacement commits, encrypted application
  messages, and public group-id/epoch inspection;
- `group.OpenMLSSidecar` and `eventlog.MLSController`, which bound process I/O,
  reject wrong AAD and state bindings, derive the Commit reference from exact
  wire bytes, and persist the next private state before returning a Commit,
  Welcome, ciphertext, or plaintext. Same-epoch send/receive ratchets and
  epoch-changing commits both use old-state-digest compare-and-swap;
- a durable single-authority room ledger. Every founding/successor membership
  carries the recorded Endpoint's bounded signature over the exact digest;
  transfer is one adjacent room epoch signed by the old delegated Endpoint and
  names a finalized live successor Endpoint.

## Canonical MLS identity bytes

All integer lengths and values below use the repository canonical framing:
unsigned big-endian `uint32`/`uint64`; every text or byte string is prefixed by
its `uint32` byte length. Genesis hashes are lowercase bare hex at the JSON
boundary and are decoded to exactly 32 raw bytes before entering a preimage.

The RFC 9420 BasicCredential `identity` is the complete canonical byte string:

```text
"tos.messaging.mls-basic-credential.v1\0"
text("tos.messaging.mls-basic-credential.v1")
text(network_id) || bytes(genesis_root) || bytes(genesis_file)
text(agent_id) || text(endpoint_id) || text(device_id)
text(device_set_digest) || bytes(leaf_signature_public_key)
uint32(0x0001)
```

It is identity data, not standalone authority. The application still verifies
the surrounding endpoint-signed `mls-device-credential.v2`, finalized
delegation, current device set, distinct leaf key, and exact KeyPackage before
passing it to an MLS Driver.

The MLS `group_id` is the raw 32-byte SHA-256 output over:

```text
"tos.messaging.mls-group-id.v1\0"
text("tos.messaging.mls-group-id.v1")
text(network_id) || bytes(genesis_root) || bytes(genesis_file)
text(room_id)
```

`pkg/group` commits positive values and rejects another network, a prefixed
genesis representation, a foreign room, and identity-field substitutions.
These are candidate vectors; independent consumption is still required before
wire freeze.

The device-credential signature preimage is now v2 for the same raw-genesis
reason. Reusing the v1 domain while changing representation would have made a
silent wire fork, so both its schema and domain were advanced.

## Room authority transfer

The room ledger v2 records one authority Agent and Messaging Endpoint. Founding
binds it to a member. Each founding or ordinary successor membership carries a
separate `room-membership-authorization.v1` signature over the network, exact
room epoch/digest, authority identity and bounded window. Merely repeating the
authority's identifier is never enough. The Endpoint key must independently
derive the recorded Endpoint ID. The authority cannot remove itself without
transferring first.
An authority transfer commits the network, room, prior and next epoch and
membership digests, both Agent/Endpoint identities, and a bounded validity
window under `tos.messaging.room-authority-transfer.v1`. The old Endpoint signs
the canonical bytes; both old and new delegations must be live, finalized by
the caller, network-matched, and name members of their respective epochs. The
ledger applies transfer plus successor epoch atomically and persists the new
authority before returning.

## Required call order

For a published KeyPackage, resolve and verify the finalized Endpoint
delegation and current device set first. Decode and bind the credential with
`group.BindDeviceCredential`, then require the selected Driver to validate the
RFC 9420 KeyPackage against suite `0x0001` and the credential's leaf key. A
syntactically valid MLS credential or KeyPackage is never TOS authority by
itself.

Production callers use `eventlog.MLSController`: `CreateFounder`/`Join` verify
the actual OpenMLS group ID and epoch before installation; `Commit` derives and
validates the randomized wire Commit reference; `Apply` checks it; and
`Seal`/`Open` durably CAS the same-epoch ratchet before exposing ciphertext or
plaintext. Direct `MLSLedger` methods remain lower-level persistence primitives.
Relays may deliver these bytes, but Relay order never chooses a commit.

`group.ValidatePrivateRoomCapacity` enforces the stable-state resource shape.
The 32-operation Commit bound keeps a worst-case batch of 64-KiB KeyPackages,
after base64 and JSON expansion, below the sidecar's 4-MiB request ceiling.
The total-leaf bound limits TreeKEM/snapshot work independently of how those
devices are distributed among Agents. Larger rooms require a future version
with measured resource and abuse budgets; v1 does not silently accept them.

`pkg/mlslab` exercises that boundary end to end without choosing the M0-R
route: bootstrap performs sequential KeyPackage/Welcome/Commit invitations,
then three per-Agent proxy processes exchange PrivateMessages through a shared
Hub whose durable state contains neither plaintext nor private MLS snapshots.
Exact send retries reuse one persisted ciphertext, modified ciphertext leaves
receiver state unchanged, and chat continues after every process restarts.
This is executable local acceptance, not independently operated Relay evidence.

## Still open — why this remains 🟡

- independent review of the concrete OpenMLS Driver and its snapshot/process
  boundary;
- the committed integration proves real founding, sequential joins, mixed
  replacement/removal, joiner-no-past and removed-member-no-future secrecy,
  forged-commit/AAD/replay refusal, bidirectional application encryption,
  exporter agreement and label separation, explicit self-update PCS, and full
  restart recovery. Stale and substituted Endpoint authority is also refused;
- offline multi-Relay catch-up using the eventual post-M0-R transport;
- independent cryptographic review and a second MLS implementation cross-check.

The committed device-credential vector is a candidate-profile change detector,
not freeze evidence. A future decision that changes its preimage must use a new
schema/domain version and replace the candidate vector loudly.
