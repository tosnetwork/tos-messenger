# Encrypted attachment profile candidate

`pkg/attachments` implements the route-neutral cryptographic core and the
authenticated opaque-storage contract for private Messenger attachments;
`pkg/attachmentapi` and `tos-attachmentd` expose its bounded Unix/HTTPS service
boundary. `OpenForAgent` adds an explicit Linux content-admission boundary and
`tos-attachment-text-scanner` supplies a minimal reference UTF-8 inspector;
`tos-attachment-clamav-scanner` supplies a production-candidate adapter for a
pinned ClamScan engine and pinned official CVD/CLD snapshots.
`pkg/attachmentadmission`, daemon config v8 and local API v6 keep the Reference,
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

## Daemon-owned outbound emission

`pkg/attachmentops` closes the sender boundary without placing Endpoint or
storage authority in OpenFox. A strict operator document pins one public HTTPS
origin, storage Ed25519 key, external Endpoint signer socket, retention,
plaintext ceiling, media allow-list and network timeouts. Agent, Endpoint and
network fields come from the live finalized delegation/dispatcher instead of
that document or model output.

Local API v5 uses `attachments.outbound.begin`, `.chunk`, and `.commit`.
`begin` commits the fixed conversation/room/session/recipient route, filename,
canonical media type, byte count and plaintext SHA-256 to an idempotency intent.
The daemon draws fresh AES-GCM and distinct upload/fetch capability keys. Each
sequential plaintext chunk is immediately authenticated and encrypted with a
1 MiB protocol chunk size; only a mode-`0600` ciphertext record and restartable
SHA-256 state are fsynced. A crash after ciphertext fsync but before the state
pointer advances is reconciled from that exact record, without a plaintext
staging file.

After the complete stream matches its declared digest, the external signer
signs an upload-only grant and a separate fetch-only grant. The exact v3 Event
is durably prepared before storage I/O but is not queued. Each `.commit` sends
at most one ciphertext chunk with a fresh one-use request nonce and persists
progress; interrupted public transfer therefore resumes across local API and
daemon restarts. Only a verified final storage `StoredAck` permits the prepared
Event to enter the delivery journal. A completed retry returns the original
Event ID without new encryption, signing or upload. The outbox record and
upload private key are removed after queueing; only the fetch key is carried in
E2EE as required by v3. This is durability/order evidence, not a commercial
retention or erasure claim.

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
`/work/input`, unshares user, IPC, PID, network and UTS namespaces, drops all
capabilities, clears the environment, exposes only a copied scanner plus
read-only system runtime directories, and gives it fresh `/proc`, `/dev`,
`/tmp`, and `/work` views. The scanner runs behind wall-clock, virtual-address,
CPU, file-descriptor, output-size and `RLIMIT_NPROC` ceilings. The cgroup
namespace remains shared only so the scanner and acceptance tests can observe
the otherwise unmodifiable kernel membership assigned by the optional hard
profile; cgroupfs is not mounted into the sandbox.

The only accepted stdout is one strict bounded JSON verdict. It must bind the
scanner ID and binary digest, every configured scanner-resource name and
SHA-256, exact plaintext SHA-256 and size, and identical
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

The ClamAV candidate makes that larger supply chain explicit instead of
pretending the adapter executable is the malware product. Each configured
engine or database resource is a canonical named, absolute, bounded regular
file with a SHA-256 pin. `OpenForAgent` copies it from the already validated
open inode into the private scan directory, verifies the copied bytes, mounts
it read-only below `/scanner-resources`, and requires the verdict to repeat the
exact ordered name/digest set. Individual resources are capped at 512 MiB,
eight resources and 1 GiB total. Missing, writable-by-group/world, symlinked,
oversized, reordered, substituted or unreported resources fail closed.

`tos-attachment-clamav-scanner` requires one pinned ClamScan engine, sorted
official `main` and `daily` CVD/CLD snapshots (plus `bytecode` when enabled), a
matching versioned external `.cvd.sign` for every database, and the pinned CVD
root certificate. It invokes only those explicit databases with
`--official-db-only=yes`, requires external-signature verification with
`--fips-limits`, and points `--cvdcertsdir` only at the private pinned resource
directory. Encrypted/broken input and every exceeded engine limit are alerts.
`--max-filesize` is the exact authenticated input size; `--max-scansize` adds a
fixed 1 MiB allowance for ClamAV's internal scan accounting while remaining
bounded. Exit 0 is allow, exit 1 is deny, and every other exit is an admission
error.

Release acceptance on 2026-08-22 exercised this exact outer sandbox with
ClamAV 1.5.3, `daily` version 28099 dated 2026-08-21, `main` version 63 and
`bytecode` version 339. Three consecutive runs admitted inert text, denied a
runtime-constructed EICAR input, and failed closed after independently
corrupting either the daily external signature or the pinned root certificate.
Those exact immutable files and their digests, rather than the mutable
FreshClam directory, form the accepted snapshot. EICAR and signature-failure
checks prove plumbing and supply-chain enforcement, not representative malware
coverage; the approved hostile corpus remains open.

`tos-attachment-corpus` makes that remaining acceptance reproducible without
checking malware into this repository. An external approver signs a strict,
sorted private-sample manifest that commits corpus/revision/scope, approval
time, single-component filenames, size, SHA-256, category, media type and the
expected allow/deny decision. The runner is configured with that approver's
exact Ed25519 public key, so a manifest cannot select its own authority. It
rehashes every non-writable regular sample, requires exactly the
`clamav-official` admission scanner, and exercises `Seal` → `OpenForAgent`
through the same outer sandbox. Only a completed structured scanner deny counts
as detection; missing resources, invalid policy, launch failure, timeout and
engine error abort the run instead of satisfying a deny expectation.

On complete agreement, the runner emits a new mode-`0600` Ed25519-signed report
binding the raw signed-manifest digest, raw admission-policy digest, exact clean
repository commit/toolchain, each result, scanner binary and staged resource
evidence. `verify` independently checks both fixed public keys, both artifact
digests, every approved sample/result and the report signature. This records
who approved which bytes and who ran them; it cannot prove that the parties are
organizationally independent or that the selected corpus is representative.
The same-host plumbing run recorded in
[`ATTACHMENT_CORPUS_PLUMBING_2026-08-22.md`](evidence/ATTACHMENT_CORPUS_PLUMBING_2026-08-22.md)
passed clean/EICAR, missing-resource and runner-key-substitution cases. Its
scope explicitly disclaims external approval and representative coverage. No
qualifying externally approved private-corpus report has yet been returned.

The address-space ceiling bounds virtual mappings, while fixed `GOMEMLIMIT`
and `GOMAXPROCS` values constrain the reference Go scanner. `RLIMIT_NPROC` is a
per-real-user limit on many Linux systems, so it is not by itself an isolated
per-scan process budget. The optional `cgroup` policy therefore pins and stages
`/usr/bin/systemd-run`, creates one unpredictable transient user service per
scan, and fixes kernel-accounted `MemoryMax`, `MemorySwapMax=0`, `TasksMax`,
`LimitCORE=0`, `NoNewPrivileges=yes`, whole-cgroup kill, and a runtime ceiling.
Missing user-systemd authority, an unsafe runtime directory, launcher
substitution, unsupported properties, unit failure, OOM, timeout, or restart
damage releases no plaintext. When this explicit policy is absent, the daemon
continues to make only the prlimit/bubblewrap claim and does not imply hard RSS
or swap isolation.

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
reference text inspector, plus daemon-owned outbound OpenFox streaming,
dual-capability signing, restart recovery, ACK-before-queue ordering, exact
retry, and the optional cgroup hard-isolation profile are implemented and
tested locally. The live cgroup test observes a distinct transient unit and
zero core limit, then proves a memory-exhausting scanner is killed without
releasing plaintext; a separate host probe records exact memory, zero-swap and
task ceilings from cgroup v2.
Still open are an independently operated public-TLS deployment, measured
interrupted wide-area transfer, independently audited retention behavior,
a qualifying externally approved representative hostile-corpus report for the
pinned ClamAV release,
independent hard-isolation review/evidence, non-text product policy, and
commercial attachment service terms. A content-addressed object may have
been copied, so no storage API promises cryptographic erasure it cannot prove.
