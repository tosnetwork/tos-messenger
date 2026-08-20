# First-principles decisions for the Messenger critical path

**Decision date:** 2026-08-20

**Scope:** route-independent protocol and implementation choices

**Non-effect:** this record does not create gate evidence or select an M1 route

These decisions minimize the amount of authority, consensus, and network
behavior the first Messenger release must trust. A design choice can be closed
while its implementation or independent acceptance remains partial.

## 1. Canonical network identity

The two genesis hashes are values of exactly 32 bytes. Canonical preimages use
those raw bytes. Strict JSON uses 64 lowercase hexadecimal characters. The
`sha256:` form is accepted only at an SDK boundary and is normalized before a
value enters a signature or digest. It is never a second canonical identity.

An already-versioned preimage that encoded another representation is not
silently reinterpreted. It takes a schema/domain version change and regenerated
positive and adversarial vectors.

## 2. One-to-one E2EE

The construction of `tos.messaging.e2ee.x3dh-aes256gcm-dr.v1` is approved:
endpoint-authenticated X25519 three-DH establishment, HKDF/HMAC-SHA-256,
AES-256-GCM, and the Double Ratchet. Algorithm selection is closed; the wire
identifier is not called frozen until an independent cryptographic review and
a second-language vector consumer both succeed.

One-time prekeys and a hybrid post-quantum successor are separate protocol
versions. They are not silently added to v1.

## 3. Independent implementation evidence

The first additional consumer should be a minimal Rust implementation of the
canonical codecs, digests, signatures, and E2EE vectors. A second codebase
proves cross-language agreement; it becomes independent evidence only when an
external operator builds it from the evidence bundle and signs the strict
conformance report. Code produced and run solely by this team is never labelled
independent.

## 4. Reachability and transport

No direct-first, tunnel-first, hybrid, or Relay-required order is selected
before the real M0-R study. Production DHT/descriptor adapters, Mailbox
authentication, interfaces, fakes, runbooks, and evidence automation remain
allowed because none chooses a route. A working transport is built only after
the predeclared study produces a qualifying route finding.

## 5. Mailbox authentication

An opaque mailbox identifier routes; it grants nothing. Each Relay/mailbox
relationship uses an independent Ed25519 capability key authorized by the live
Messaging Endpoint. Grants bind the network, Agent, Endpoint, Relay key,
mailbox, allowed operations, capability key, and a bounded lifetime.

Every operation signs the grant digest, operation, exact body digest, fresh
nonce, and bounded validity window. Deposit, read, and delete are separate
permissions. Delete binds the exact ciphertext digest. Relays claim nonces
durably before an operation; a retry uses a new nonce. Network adapters must
recheck finalized Endpoint authority and cannot treat the capability signature
as Agent, wallet, room, or commercial authority.

## 6. First contact

The v1 default is an allow-list for known contacts, a one-time invite token for
introductions, and owner hold for every other unknown sender. The same policy
runs before durable acceptance on direct and Relay paths. Proof of work is not
added without abuse measurements; Inbox Bonds remain Expansion-Gate locked and
the software-work escrow is not reused.

## 7. Private-room authority

One Agent is the membership writer for a v1 room. The creator is the initial
authority. A transfer is an explicit, current-authority-signed, single-step
room-epoch transition. Relay arrival order is never authority, concurrent
membership children are refused, and membership changes are not merged.

If the authority is irrecoverably lost, members create a new room. V1 does not
hide a consensus, election, or partition-recovery protocol inside MLS. MLS
controls cryptographic membership; the room authority controls which Agents
and devices may become MLS members.

## 8. MLS implementation boundary

The first cryptographic Driver uses OpenMLS with MLS 1.0 cipher suite `0x0001`
behind the existing narrow `group.Driver` boundary. The reviewed library owns
RFC 9420 state transitions; Go owns TOS authority, the room/MLS clocks,
persistence order, Relay semantics, and fail-closed recovery. No TreeKEM or
HPKE implementation is invented in this repository, and no emerging pure-Go
implementation enters the production trust root without equivalent review and
interoperability evidence.

## 9. Delivery order

The critical path is:

1. apply the canonical network representation to every candidate preimage;
2. implement scoped Mailbox authentication;
3. implement production DHT/descriptor adapters;
4. run the multi-operator M0-R study;
5. implement only the route selected by that finding and close S1;
6. integrate the MLS Driver and single-writer room authority and close S2;
7. then add remote attachments, native clients, and public channels.

Lines of code do not reorder this path. S1 and S2 remain incomplete until their
real-network, independently operated scenarios close end to end.

## 10. Prekey publication

The v1 signed prekey is replenished by rotating one complete device set before
its expiry; it is not a consumable one-time prekey. All retained devices share
one issuance watermark per publication. Different non-retirement content at
the same watermark is an equivocation and is refused without a digest or
arrival-order tie-break.

Exact signed bundle-set bytes and their private answering material become
durable before an object sink can see them. The content-addressed object is
published before a signed descriptor names its digest. A retained device's
superseded private material remains selectable by exact bundle digest until
its signed expiry; a revoked device's answering material is dropped with its
tombstone. Endpoint signing stays behind `crypto.Signer`; the publisher never
requires exportable Endpoint private-key bytes. See
[`PREKEY_PUBLICATION.md`](PREKEY_PUBLICATION.md).
