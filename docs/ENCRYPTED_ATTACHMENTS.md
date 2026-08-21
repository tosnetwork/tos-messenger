# Encrypted attachment profile candidate

`pkg/attachments` implements the route-neutral cryptographic core and the
authenticated opaque-storage contract for private Messenger attachments;
`pkg/attachmentapi` and `tos-attachmentd` expose its bounded Unix/HTTPS service
boundary. `OpenForAgent` adds an explicit Linux content-admission boundary and
`tos-attachment-text-scanner` supplies a minimal reference UTF-8 inspector.
`pkg/attachmentadmission`, daemon config v8 and local API v4 keep the Reference,
attachment key and fetch capability out of OpenFox while releasing admitted
`text/plain` plus exact scanner evidence under the Event's application lease.
This does not select a message route, paid retention profile, production
malware product, or parser for arbitrary formats.

Each attachment gets a fresh random 256-bit AES-GCM key, 128-bit attachment ID,
and 32-bit nonce prefix. The 96-bit nonce is that prefix followed by the
big-endian 64-bit chunk index. One key is used for at most 2,048 chunks, and a
fresh key/namespace is mandatory for every call to `Seal`; nonce reuse under a
key is forbidden.

The AEAD associated data binds the profile, attachment ID, committed secret
metadata, total plaintext length, chunk size, chunk count, and exact chunk
index. Reordering, truncating, duplicating, substituting, or moving a chunk to
another attachment therefore fails authentication. Each ciphertext chunk is
also content-addressed, and the ordered manifest has its own domain-separated
digest. An Event carrying `artifact.encrypted` must repeat exactly that digest
in its sole `attachment_references` entry.

The secret Reference — key, display filename, canonical media type, optional
plaintext digest, expiry, and manifest — travels only inside the already-E2EE
Messaging Event. Storage receives opaque ciphertext chunks. The optional
plaintext digest is an explicit equality-disclosure tradeoff and may be left
empty. For a private room, MLS PrivateMessage protection wraps the Reference;
for one-to-one delivery, the existing per-device E2EE fan-out wraps it. No
separate shared storage key is inferred.

Downloads resume by comparing locally held ciphertext digests to the ordered
manifest and fetching only missing objects. The optional local `Store` persists
only opaque ciphertext objects plus expiry/reference leases in a private,
single-writer directory. It verifies hashes on put/fetch, enforces bounded
object/byte/retention quotas before writing, survives restart, refuses corrupt
state, and removes unreferenced objects only after a lease is deleted or
expires. `Open` checks the local size/media
policy, expiry, every content digest, every expected chunk length, and every
AEAD tag before returning any plaintext.

## Authenticated remote storage boundary

An Endpoint signs a bounded grant for one finalized Agent/Endpoint, one exact
storage Ed25519 identity, one independent capability key, one manifest and
ordered chunk set, exact ciphertext bytes, retention time, and a canonical
subset of `upload`, `fetch`, and `delete`. Both genesis hashes remain lowercase
bare hex in JSON and are raw 32-byte fields in the signed preimage. The grant
contains no attachment key, filename, media type, plaintext digest, or other
plaintext metadata.

Every operation uses its own domain-separated body digest and a capability
signature over the exact grant digest, operation, body, two-minute window, and
fresh 256-bit nonce. The store rereads the committed delegation and finalized
Agent state on every operation and persists the nonce before touching storage.
Crashes therefore consume a request rather than reopening it; a retry uses a
fresh nonce against idempotent content-addressed storage. Replay claims survive
restart, and a private fsynced monotonic time watermark refuses wall-clock
rollback before expired claims are collected. A private store-generation
marker prevents a missing clock/claim set from being mistaken for fresh state;
unmarked legacy or substituted state requires explicit migration and never
opens implicitly. Cross-operation, body,
storage-key, Endpoint, network, manifest,
chunk, order, index, byte-count, expiry and signature substitution fail closed.

Uploads are split into at most sixteen chunks per service frame. Objects are
fsynced as inert unleased ciphertext, and the lease becomes visible only after
all grant-named objects exist with the exact aggregate byte count. This gives
interrupted upload recovery without allowing a partial manifest to look
complete. Fetch uses the same sixteen-object bound, requests only exact grant
members, and independently rechecks every returned digest and manifest index.

The storage identity signs a `StoredAck` only for a complete durable lease and
a `DeleteAck` after observing its local lease deletion. These are operational
acknowledgements, not TOS commercial Receipts. A `DeleteAck` cannot prove that a
backup, cache, another operator, recipient, or attacker destroyed its copy.

The `artifact.encrypted` payload is now v3. New emission carries the secret
Reference, the canonical URL, an Endpoint-signed fetch-only grant and its
matching Ed25519 capability private key inside application E2EE. The grant must
name the same sender Agent/Endpoint and network as the Event, be issued no later
than the Event, and match the Reference's manifest, ordered chunk digests,
ciphertext byte count and retention exactly. Its only operation is `fetch`.
V1 and v2 remain explicit read-only history decoders; they cannot be fetched
because they carried no recipient authority. A locator is never promoted into
that missing authority.

The sender should mint a fresh fetch capability distinct from its upload/delete
capability. In a room, the v3 payload is one MLS-protected room message, so the
fetch capability is shared by the recipients of that epoch; it is bounded to
one manifest and expiry but does not provide per-member revocation. Deployments
requiring per-recipient revocation must fan out distinct direct Events instead
of pretending one room Event has recipient-specific bytes.

V3 accepts only the canonical URL

```text
https://<lowercase-host>/.well-known/tos-messenger/attachments/<manifest-sha256-hex>
```

with no userinfo, explicit port, query, fragment, escaped path, or suffix. The
HTTPS client ignores environment proxies, refuses redirects/compression, uses
finite request/connect/header/body budgets, rejects an entire DNS answer set if
any address is loopback, private, link-local, CGNAT, multicast or otherwise
non-public, and dials only the checked address while TLS continues to verify the
original hostname. The locator is an E2EE-authenticated retrieval hint, never a
bearer credential or authority source; capability signatures remain mandatory.

## Content safety and OpenFox integration

`Open` deliberately does not decompress archives, infer media types, render a
filename as a path, parse a document, or invoke a scanner. Display filenames
reject path separators, control-line breaks, surrounding whitespace, invalid
UTF-8, and parent paths. A runtime must keep the returned bytes inert until its
own sandbox/scanner policy admits them; authenticated content is still
untrusted content. Agent integrations must call `OpenForAgent`, not expose the
lower-level `Open` result to a model or tool.

`OpenForAgent` requires a non-empty canonical media allow-list, a nonzero
plaintext ceiling, and an ordered set of one to four scanners. Every scanner
binary, `/usr/bin/bwrap`, and `/usr/bin/prlimit` is pinned by SHA-256 and copied
from its validated open file into one private per-admission directory; later
path replacement cannot change the inode used for that attempt. Writable,
relative, symlinked, substituted, or oversized executables fail closed.
The exact authenticated plaintext is placed in a sealed Linux `memfd` rather
than a persistent file. Bubblewrap receives that descriptor as read-only
`/work/input`, unshares all supported namespaces including the network, drops
all capabilities, clears the environment, exposes only a copied scanner plus
read-only system runtime directories, and gives it fresh `/proc`, `/dev`,
`/tmp`, and `/work` views. The scanner runs behind wall-clock, virtual-address,
CPU, file-descriptor, output-size and `RLIMIT_NPROC` ceilings.

The only accepted stdout is one strict bounded JSON verdict. It must bind the
scanner ID and binary digest, exact plaintext SHA-256 and size, and identical
declared/detected media types. Unknown fields, trailing JSON, a timeout,
nonzero exit, output overflow, any mismatch, or one denial in a multi-scanner
policy releases no plaintext. Scanner stderr is bounded and not returned to
the caller because an untrusted scanner may copy content into an error.

The reference scanner admits only non-empty `text/plain` and `text/markdown`
that are valid UTF-8 and contain no NUL, carriage return, escape, or other
control characters except newline and tab. It is intentionally parser-free.
It is not a malware scanner and gives no safety claim for scripts, prompt
injection, URLs, markup semantics, archives, office documents, PDFs, images,
audio, video, decompression, or parser exploits. Those types remain refused
unless operators install another reviewed, digest-pinned scanner under the
same all-must-allow boundary.

The address-space ceiling bounds virtual mappings, while fixed `GOMEMLIMIT`
and `GOMAXPROCS` values constrain the reference Go scanner. `RLIMIT_NPROC` is a
per-real-user limit on many Linux systems, not an isolated per-scan cgroup
budget. Deployments needing hard RSS, process or I/O isolation must add an
independently reviewed service/cgroup/container boundary; this implementation
does not claim one.

The profile bounds plaintext to 512 MiB, chunks to 1 MiB (256 KiB by default),
and count to 2,048; the recipient may set a smaller plaintext limit and an
allow-list of canonical media types. These bounds stop allocation and content
bombs at the attachment layer, but format-specific decompression ratios and
parser limits belong to the eventual sandbox adapter.

Expiry is enforced on open and by lease GC. `artifact.encrypted` is excluded
from the general runtime listing and claim path, so neither its Reference nor
its capability key crosses the Agent IPC. `attachments.pending` reveals only
Event/Endpoint/conversation metadata. `attachments.claim` atomically takes the
same durable application lease used by ordinary messages, reloads and rechecks
the exact canonical Event, performs strict HTTPS fetch with the v3 capability,
opens every AEAD chunk, runs every pinned scanner, and returns only bounded
UTF-8 `text/plain`, display metadata, plaintext digest/size and scanner IDs and
binary digests. OpenFox independently recomputes the returned body digest,
persists it through the existing Event-ID application result, and only then
calls `inbox.complete`; a crash or persistence failure leaves the stable Event
retryable. Attachment support is an explicit OpenFox channel option.

Authenticated remote operation,
restart replay refusal, interrupted multi-frame upload, signed local deletion
observation, locator/SSRF policy, sealed-input sandboxing, strict verdict
binding, daemon-owned/OpenFox application, Event v2 cross-consumption and the
reference text inspector are implemented and tested locally.
Still open are an independently operated public-TLS deployment, measured
interrupted wide-area transfer, independently audited retention behavior,
a selected production malware scanner and representative hostile corpus, hard
cgroup-level resource evidence, non-text product policy, and commercial
attachment service terms. A content-addressed object may have
been copied, so no storage API promises cryptographic erasure it cannot prove.
