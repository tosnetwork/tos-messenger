# One-to-one E2EE suite decision package

This document recommends the first concrete suite for owner review. It is a
candidate, not a protocol freeze: the identifier and construction become a
wire commitment only after the owner ratifies this package. Until then the
roadmap stays partial and negotiation must not treat the candidate as frozen.

## Recommendation

Adopt `tos.messaging.e2ee.x3dh-aes256gcm-dr.v1`, implemented by
`e2ee.NewDefaultSuite`, for the M0 one-to-one profile.

The profile combines:

- an asynchronous, X3DH-shaped authenticated prekey handshake using X25519;
- HKDF-SHA-256 and HMAC-SHA-256 for root, chain, message-key, and nonce
  derivation;
- the Double Ratchet state transition for forward secrecy and recovery after
  compromise once an uncompromised party contributes a fresh DH key; and
- AES-256-GCM for message confidentiality and integrity, with the canonical
  `e2ee.Binding` and the complete message header as associated data.

This is intentionally a composition of reviewed primitives and a published
ratchet construction. It introduces no cipher, MAC, curve, or ratchet of this
repository's invention, and it adds no dependency outside the Go standard
library.

## Why this candidate

The contract requires offline first contact, bidirectional traffic, persisted
replay protection, out-of-order delivery, bounded state and ciphertext growth,
forward secrecy, and post-compromise recovery. A prekey handshake followed by
the Double Ratchet is the narrowest established construction that supplies all
of those properties.

The alternatives do not clear that floor as directly:

| Candidate | Fit | Reason not recommended for v1 |
|---|---|---|
| X3DH-shaped prekeys + Double Ratchet | Strong | Recommended; asynchronous and designed for independently advancing message state |
| HPKE per message | Partial | Good sealed-message primitive, but replay state, ongoing forward secrecy, and post-compromise recovery would still need a ratchet design |
| Noise handshake + symmetric ratchet | Partial | Strong online session establishment, but an offline recipient and recovery after compromise require additional protocol choices |
| MLS used for a two-member group | Partial | Supplies group membership machinery the one-to-one profile does not need; it also couples this decision to the still-open room-authority decision |
| Hybrid post-quantum prekeys | Deferred | Desirable migration direction, but freezes larger materials and a second KEM before the deployment and interoperability evidence exists |

AES-256-GCM is chosen over adding a ChaCha20-Poly1305 dependency because the
message key is fresh per message, its 96-bit nonce is derived with that key,
and the standard library supplies a widely checked implementation. This choice
must be revisited if target evidence shows unacceptable timing or performance
on a supported architecture; changing it means a new suite identifier, never a
silent substitution.

## Authentication boundary

Both devices publish two X25519 public keys in an endpoint-signed `e2ee.Bundle`:
a handshake identity key and a signed prekey. The corresponding private
material never leaves the device. The initiator also generates an ephemeral
X25519 key and derives the initial secret from these three DH results, in this
order:

1. initiator identity × acceptor signed prekey;
2. initiator ephemeral × acceptor identity; and
3. initiator ephemeral × acceptor signed prekey.

The acceptor is given the initiator's independently fetched, endpoint-signed
public material and computes the reciprocal results. The suite interface
requires both local private material and peer public material on both sides.
That requirement is load-bearing: accepting only a self-declared key from the
initial message would let anyone encrypt while claiming any delegated sender.
The conformance harness now substitutes a third party's prekey and refutes a
candidate that still communicates.

The endpoint signature over the existing bundle authenticates both X25519
keys. This profile therefore does not add another signature inside the suite.
Bundle expiry and device revocation are enforced by the existing binding and
admission layers; an expired bundle starts no new session, while an already
established session remains subject to its outer session lifetime.

## Frozen candidate format

All integers below are unsigned big-endian. Public material is byte `1`, the
32-byte X25519 identity public key, then the 32-byte signed-prekey public key.
The initial message is byte `1` followed by the initiator's 32-byte ephemeral
public key. This implementation's opaque private material uses the analogous
layout with the two private keys; that private encoding is present in the test
vectors for reproducibility, but is not an interoperability format.

Each ciphertext is:

| Field | Bytes |
|---|---:|
| format version (`1`) | 1 |
| current ratchet public key | 32 |
| previous sending-chain length | 4 |
| message number | 4 |
| AES-GCM ciphertext and tag | plaintext + 16 |

The fixed expansion is 57 bytes, below `MaxCiphertextOverheadBytes`. The whole
41-byte header followed by the caller-supplied canonical binding is AES-GCM
associated data. Header substitution, direction changes, conversation changes,
and identity changes therefore fail authentication.

The initial KDF hashes the ASCII label
`x3dh-aes256gcm-dr initial root and chain` followed by the binding to form the
HKDF salt, then expands the concatenated three-DH secret with that label to 64
bytes: root key followed by the initial chain key. A DH-ratchet step expands
the new X25519 secret with the old root as salt and the label
`x3dh-aes256gcm-dr ratchet root and chain`, again producing root then chain.
A chain step is HMAC-SHA-256 under the chain key over byte `1` for the message
key and byte `2` for the next chain key. HKDF-SHA-256 expands the message key
with no salt and label `x3dh-aes256gcm-dr message key and nonce` to the 32-byte
AES key and 12-byte nonce.

An implementation keeps at most 1,024 skipped message keys and refuses a
larger gap before allocating or mutating state. It retains 1,024 recent
ciphertext digests to preserve the distinct `ErrReplayed` result across
ratchet changes; older consumed keys are gone and can never open again. The
persisted state is versioned, strictly decoded, bounded by
`MaxSessionStateBytes`, and carries skipped keys and replay bookkeeping. Its
encoding is implementation-local rather than an interoperability format.

## Evidence in this repository

`pkg/e2ee/conformance` exercises fourteen refutation properties, including
offline establishment, peer-prekey possession, both directions, binding,
tamper and replay refusal, persisted replay state, out-of-order delivery,
bounded expansion and state, past-traffic secrecy, and recovery after a full
exchange. The default candidate clears the complete harness.

`pkg/e2ee/testdata/default-suite-vectors.json` is a deterministic,
implementation-consumable positive and adversarial corpus. It fixes both
parties' entropy, public and private materials, the initial message, three
ciphertexts across two DH-ratchet turns, malformed ciphertexts, the skipped-key
limit, and the replay case. The test reconstructs the artifact and fails loudly
if any wire byte changes. Separate known-answer tests cross-check X25519 against
RFC 7748, HKDF-SHA-256 against RFC 5869, and AES-256-GCM against the published
NIST zero-plaintext example.

Passing these tests is necessary, not a cryptographic proof. Owner ratification
should require an independent review of the composition and consumption of the
committed vectors by a second implementation.

## What ratification commits

Ratifying this candidate freezes the suite identifier, public-material layout,
initial-message and ciphertext formats, DH ordering, KDF labels and output
splits, AEAD and associated data, skipped-key bound, and the error distinctions
the interface exposes. A change to any one of them requires a new algorithm
identifier and new positive and adversarial vectors. Opaque private material
and persisted state may change encoding only when the implementation can
migrate its own durable values without changing those wire results.

Ratification does not freeze a route order, a transport binding, a group suite,
the genesis-hash representation, or a post-quantum migration schedule. This
implementation remains route-independent, and nothing here unblocks M1 before
the M0-R finding exists.

## Deliberate limits

- Header encryption is not included. Ratchet public keys and counters are
  visible to the route carrying the ciphertext; identities and conversation
  remain inside the binding and encrypted event.
- There is no one-time prekey in v1. Signed prekeys are bounded by bundle
  lifetime and rotate with publication. Compromise of a still-retained signed
  prekey can reconstruct a recorded initial handshake, so the publisher must
  erase retired bundle secrets; forward secrecy from the message chain does
  not repair retained bootstrap secrets. Adding one-time prekeys changes both
  public material and first-message consumption semantics and therefore needs
  a new suite.
- The construction is not post-quantum. A hybrid successor must have its own
  identifier and downgrade rules; it cannot replace X25519 under this name.
- Compromise recovery begins only after an uncompromised party contributes a
  fresh DH private key and the resulting exchange completes. No ratchet can
  recover while the attacker continuously controls an endpoint.
