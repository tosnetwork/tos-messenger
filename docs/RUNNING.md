# Running the daemon

`tos-messengerd` owns one state directory, always serves separate runtime and
owner sockets, and may serve a third public-only prekey device socket.
It cannot carry a message yet, and it says so on startup rather than looking
like a working installation that happens to be quiet.

```sh
tos-messengerd -config /etc/tos-messengerd/config.json -check   # validate and exit
tos-messengerd -config /etc/tos-messengerd/config.json

# Publish complete public prekey generations through the operator's static
# HTTPS origin, native DHT client, and separately custodied Endpoint signer.
tos-messengerd -config /etc/tos-messengerd/config.json \
  -publication-operator-config /etc/tos-messengerd/publication.json -check
tos-messengerd -config /etc/tos-messengerd/config.json \
  -publication-operator-config /etc/tos-messengerd/publication.json

# Enable daemon-owned encrypted attachment emission. This document contains
# only public/operator policy plus a narrow external signer socket, never the
# Endpoint private key.
tos-messengerd -config /etc/tos-messengerd/config.json \
  -attachment-emission-operator-config /etc/tos-messengerd/attachment-emission.json
```

## Three separated capabilities

The runtime connects to one socket and the owner to another, and the
separation carries one invariant: **the party that asks for an approval must
not be able to grant it.** A single socket with a user check cannot tell an
Agent runtime from the person it is asking, so an Agent deciding that a payment
needs approval could answer itself.

The runtime socket carries inbox draining and event submission and no approval
operation at all. For ordinary text it should use `outbox.compose`: the runtime
supplies conversation/room meaning, text, a fixed route, expiry and a canonical
idempotency key, while the daemon supplies its finalized identity, network,
clock, event kind, payload schema and content-addressed Event ID. The first
complete event and route are persisted before queueing; a retry after a crash
returns the same Event ID, while changed content or recipient under the same
key fails closed. The legacy full-event `outbox.queue` remains a validated
compatibility operation. The owner socket carries the decisions and does no
Agent work.

`tos-messenger-owner` makes the action-decision path operational without
requiring the online machine to load the owner's private key. The challenge is
single-use and expires after two minutes, so the three commands form one short
ceremony:

```sh
# Online, on the Messenger host.
tos-messenger-owner -socket /run/tos-messengerd/owner.sock pending
tos-messenger-owner -socket /run/tos-messengerd/owner.sock \
  prepare-grant act_... > prepared.json

# Offline or on the isolated owner signer. The key file is exactly 128
# lowercase hex digits (the standard 64-byte Ed25519 private key), mode 0600.
tos-messenger-owner sign -key owner.key -decision prepared.json > signed.json

# Back online before the challenge expires.
tos-messenger-owner -socket /run/tos-messengerd/owner.sock \
  submit -decision signed.json
```

Use `prepare-deny -reason TEXT act_...` for a refusal. The prepared envelope
contains the exact domain-separated signing bytes as hex; `sign` recomputes
them from the strict request and refuses any mismatch. `submit` repeats that
check and the daemon finally verifies the signature and consumes its challenge.
Production deployments should replace the file-backed offline example with a
hardware or separately custodied Ed25519 signer. Keeping `owner.key` readable
by the Agent runtime collapses the approval boundary even if its mode is 0600.

First-contact invites use the same offline owner ceremony. The online host
prepares an explicitly expiring, optionally Agent-scoped decision; only after
the signed decision is submitted does the daemon generate and return the
256-bit bearer:

```sh
tos-messenger-owner -socket /run/tos-messengerd/owner.sock \
  prepare-invite -agent agent_... -expires-at 1900000000 > prepared.json
tos-messenger-owner sign -key owner.key -decision prepared.json > signed.json
tos-messenger-owner -socket /run/tos-messengerd/owner.sock \
  submit -decision signed.json
```

Transmit the returned `invite_...` value out of band. The daemon persists only
its domain-separated SHA-256 digest. The first valid authenticated event binds
it durably to that sender and Event ID; an exact retry is idempotent, while any
other event falls back to owner hold. Relay deposit signatures commit the
opaque token, so a Relay cannot substitute it.

A wallet/funding process records the escrow it actually prepared through the
same owner ceremony; configuration is deliberately not accepted as funding
evidence:

```sh
tos-messenger-owner -socket /run/tos-messengerd/owner.sock \
  prepare-escrow-location \
  -commitment tvm-cell-sha256:... -escrow 0:... \
  -capability-class software.audit > prepared.json
tos-messenger-owner sign -key owner.key -decision prepared.json > signed.json
tos-messenger-owner -socket /run/tos-messengerd/owner.sock \
  submit -decision signed.json
```

The decision signs the exact Quote commitment, escrow account and caller-
attested Capability class. An exact funding retry is idempotent; redirecting
one commitment to another account conflicts. This records what the wallet
funded—it neither funds the escrow nor replaces the finalized chain read.

Set both `escrow_code_hash` and the daemon-owned
`escrow_checkpoint_path` to enable runtime `quotes.verify`. After funding has
reached finality, OpenFox submits the commitment, deterministic escrow address,
Capability class, and the complete terms it authorized. The daemon treats the
address only as a candidate and resolves that exact account through the strict chain
adapter and returns transaction/code/checkpoint evidence only when commitment,
provider, capability, manifest, transport, asset, price, escrow/dispute terms,
expiry, network ID, and both bare genesis hashes all match. The operation is
read-only: it cannot create a locator, approve spending, sign, fund, or dispatch
a task or persist a runtime-supplied locator. Thus the funded execution path
does not require a prior owner locator write, while digest-only negotiation may
still use the owner-attested mapping. Omitting both fields disables the
operation; configuring only one is a startup error.

When `publication.mode` is `prekeys`, the third socket exposes only the current
fixed public generation and admission of one already Endpoint-signed public
bundle. It exposes no approval operation, private material, other device's
bundle, or authority to select a roster/window. The v7 config retains the v5
roster/window contract and explicitly states
its clean absolute path, sorted 1–16-device roster (including this
installation's device), algorithm identifier, 60-second-to-30-day lifetime,
positive replenishment lead, and a check interval no longer than that lead.
Use `publication.mode = "none"` with no unused fields to disable it.

The production composition `daemon.OpenWithGenerationPublisher` accepts an
explicit HTTPS object sink, native-DHT locator sink, committed Descriptor
policy/template, bounded publish interval, and `crypto.Signer`. The stock
command assembles that boundary from the strict
`tos.messaging.publication-operator.v1` file shown in
`docs/publication-operator.example.json`. It resolves finalized authority
before connecting the resources, derives all identity/authority fields from
the live delegation, and uses `pkg/signerapi.Client` to pin and verify the
Endpoint public key through a separate Unix signer service. It never loads
private-key bytes. Omitting the flag keeps collection enabled but deliberately
does not claim public network publication.

## What must be stated

Nothing about acceptance has a default, because a default here is a decision
nobody made:

- the **network tuple** the installation belongs to;
- the **registries** whose finalized state it accepts, since typed TVM state is
  only meaningful under the contract that produced it. Each entry carries the
  contract's code as well as its hash, because an Agent's account address is
  recomputed from the code: a resolver could otherwise return the right Agent
  record read from an account of its own choosing. The code must hash to the
  pinned digest, and the example file's value is a placeholder rather than a
  deployed registry;
- **three to eight independent chain JSON-RPC authorities** and a strict
  majority quorum. Remote authorities must use HTTPS and must have distinct
  authorities. The selected Native Registry code hash chooses one of the
  configured registry layouts for deterministic direct Agent reads; it is not
  inferred from the first list entry;
- the daemon-owned **finalized checkpoint file** (exactly
  `state_dir/chain.checkpoint`) and the local **endpoint delegation file**.
  The latter must be a non-empty regular file no larger than 64 KiB;
- the **discovery mode**, separately from transport. `none` carries no unused
  settings. `tos-dht-https` pins one bounded local DHT global configuration and
  a finite peer list mapping every non-local Agent to delegation and committed
  descriptor-policy files, with explicit refresh and HTTPS budgets;
- optional **contact DNS** credentials for human `.tos` recipient input. The
  bearer is read from a bounded regular file and the gateway must be HTTPS
  unless plaintext is explicitly enabled for a test deployment. This layer
  resolves only to AgentID; `tos-dht-https` discovery must then verify the
  configured peer's delegation, descriptor, Endpoint, devices and prekeys.
  Omitting it disables `.tos` input but explicit AgentID resolution still uses
  the same verified directory path; see
  [`DNS_RECIPIENT_CANONICALIZATION.md`](DNS_RECIPIENT_CANONICALIZATION.md);
- **who this installation speaks for** — its Agent, endpoint and device — since
  an outbound event must say it came from here; and
- the **inbox admission policy**, private known/blocked rosters, payload bound,
  and clock-skew bound. The v1 recommended policy is `allow-list` with
  `invite-or-hold`: a known Agent enters normally, a valid invite introduces
  one event, and every other unknown Agent waits for the owner. Startup checks
  that the public rule hashes to the digest in the finalized delegation;
- the **owner's public key**, because the two sockets are not by themselves a
  boundary. Peer credentials establish which Unix user is calling, and the
  Agent runtime commonly runs as that same user, so a runtime that asked for an
  approval could otherwise connect to the owner's socket and grant its own
  request. Every decision on the owner's interface must carry a signature over
  a single-use challenge the daemon issued. **The private half has to live
  somewhere the runtime cannot read** -- a hardware token, another user's
  keyring, another machine. The daemon cannot check that, and if it is not true
  the signature proves nothing;
- the **firewall ceilings**, which say what the Agent may do unattended: one
  for what it reaches on its own initiative, and a tighter one for anything a
  received message drove. Neither may be raised to a key or to this
  installation's own configuration, whatever an operator writes; and
- the **transport**, which today can only be `"none"`; and
- an optional owner-private **Agent Packet receiver socket**. When configured,
  admitted `agent.packet` Events are re-verified against finalized Agent state,
  durably nonce-claimed, and sent to the independently verifying OpenFox
  provider. They are excluded from the general runtime inbox, so packet bytes
  cannot become model instructions by taking the ordinary message path; and
- optional, independent owner-private **A2A and MCP receiver sockets**. Their
  protocol Events are always excluded from general runtime listing and claim,
  even when no receiver exists. Configured receivers get the complete
  canonical Event over fixed bounded endpoints with durable retry/completion;
  see [`FOREIGN_PROTOCOL_BRIDGE.md`](FOREIGN_PROTOCOL_BRIDGE.md).

An unknown key in the configuration is refused rather than ignored. A
misspelled setting that is silently dropped is a setting an operator believes
is in force.

`docs/daemon-config.example.json` is a complete file with placeholder values.
Finalized Quote verification is retained in schema `tos.messaging.daemon-config.v10`;
older files are rejected instead of silently disabling discovery or public
generation planning, applying an inbox policy the endpoint never committed, or
leaving the native buyer without its finalized-Quote check.

`-check` validates all of these bounds, endpoint URLs, code/hash pairs and
paths without contacting the chain. Normal startup is fail-closed: after
taking the state lock, the daemon reads the exact delegation bytes, resolves
the configured Agent through the strict-majority finalized chain adapter, and
requires the live Agent to commit that digest and the delegation to name the
configured Agent and endpoint. Resolver failure, rollback, revocation,
expiry, a foreign network/registry/account, or an endpoint mismatch prevents
the sockets from opening and releases the state lock. The verified
delegation's `allowed_outbound_event_classes` is then installed in the
dispatcher; the runtime cannot queue a valid-but-undelegated event kind.

With `tos-dht-https`, startup also requires a bounded regular DHT bootstrap
file with a cryptographically accepted node, then owns an ephemeral ADNL DHT
client and hardened HTTPS object client. The background refresh chain verifies
each peer's current finalized delegation and exact policy commitment before the
DHT locator, descriptor, and prekeys can update the durable device ledger.
Failures are reported, never extend stale state, and do not become transport.
See [`DISCOVERY_BOOTSTRAP.md`](DISCOVERY_BOOTSTRAP.md).

## Authenticated attachment storage service

`tos-attachmentd` runs the bounded storage protocol on a private Unix socket;
the same authenticated request/response objects are used by the strict HTTPS
adapter. It needs the normal finalized-chain authority configuration, one or
more exact Agent delegation files, a private state directory, and a mode-`0600`
lowercase-hex Ed25519 storage key:

```bash
tos-attachmentd \
  -authority-config /etc/tos-messenger/daemon.json \
  -delegation agent_<64hex>=/etc/tos-messenger/agents/agent.json \
  -storage-key /etc/tos-messenger/attachment-storage.key \
  -state /var/lib/tos-messenger/attachments \
  -socket /run/user/1000/tos-attachmentd.sock
```

Use `-check` to validate the complete authority/key/path assembly without
opening the store or socket. The daemon never receives attachment keys or
plaintext metadata. Its Unix carrier is local deployment plumbing; a public
deployment must use the strict HTTPS locator/client policy and independently
validate TLS, DNS, quotas, retention and restart evidence.

For outbound OpenFox attachments, create a mode-`0600` operator document:

```json
{
  "schema": "tos.messaging.attachment-emission-operator.v1",
  "storage_origin": "https://attachments.example.org",
  "storage_public_key_hex": "<64 lowercase hex>",
  "endpoint_signer_socket": "/run/tos-endpoint-signer/sign.sock",
  "signer_timeout_seconds": 10,
  "retention_seconds": 86400,
  "max_plaintext_bytes": 536870912,
  "allowed_media_types": ["text/plain"],
  "https_request_timeout_seconds": 30,
  "https_connect_timeout_seconds": 5
}
```

The storage and Endpoint keys must be distinct. Startup pins the signer to the
live finalized Endpoint public key. OpenFox streams exact MediaStore files over
local API v7; the daemon encrypts each 1 MiB chunk, durably resumes ingestion
and storage upload, signs separate upload/fetch capabilities, verifies the
final `StoredAck`, and only then queues the v3 Event. The model cannot select
the storage origin, retention, authority keys, network identity or Event ID.

### Agent attachment content admission

Do not pass bytes returned by the lower-level `attachments.Open` API to an
Agent, model, renderer, parser, or tool. On Linux, build the reference text
inspector and record all three executable identities in the local
`attachments.AgentContentPolicy`:

```bash
go build -trimpath -o /usr/local/libexec/tos-attachment-text-scanner \
  ./cmd/tos-attachment-text-scanner
chmod 0555 /usr/local/libexec/tos-attachment-text-scanner
sha256sum /usr/local/libexec/tos-attachment-text-scanner \
  /usr/bin/bwrap /usr/bin/prlimit /usr/bin/systemd-run
```

Prefix each printed lowercase digest with `sha256:`. Configure an absolute,
canonical scanner path, scanner ID `reference-text`, its digest, the bubblewrap
and prlimit digests, a nonzero plaintext ceiling, and only `text/plain` and/or
`text/markdown` in the media allow-list. A package upgrade changing bubblewrap
or prlimit deliberately stops admission until an operator reviews and updates
the pin. A hard-isolation deployment additionally pins `systemd-run`. Scanner
and launcher files must be regular, executable, non-writable and not symlinks.

`tos-attachment-text-scanner` is a parser-free reference inspector, not a
production malware product. It refuses every non-text type. To enable the
daemon-owned OpenFox path, add the following to daemon config v10 after replacing
all digest placeholders with the reviewed lowercase `sha256:` values:

```json
"attachment_admission": {
  "max_plaintext_bytes": 131072,
  "allowed_media_types": ["text/plain"],
  "scanners": [{
    "id": "reference-text",
    "executable": "/usr/local/libexec/tos-attachment-text-scanner",
    "executable_digest": "sha256:<scanner>"
  }],
  "bubblewrap_digest": "sha256:<bubblewrap>",
  "prlimit_digest": "sha256:<prlimit>",
  "cgroup": {
    "systemd_run_digest": "sha256:<systemd-run>",
    "memory_max_bytes": 268435456,
    "tasks_max": 32
  },
  "scanner_timeout_seconds": 30,
  "https_request_timeout_seconds": 30,
  "https_connect_timeout_seconds": 5
}
```

For production-candidate malware scanning, build
`cmd/tos-attachment-clamav-scanner` as a second scanner. Do not point it at a
mutable database directory. Pin one reviewed ClamScan engine and take one
immutable snapshot of the exact FreshClam-produced official `main`, `daily`,
and `bytecode` CVD/CLD files, every matching versioned external `.cvd.sign`,
and the CVD root certificate. `ScannerResourceDigest` uses the same
regular-file, inode, size and SHA-256 checks as admission. The complete shape
occupies the policy's eight-resource maximum:

```json
{
  "id": "clamav-official",
  "executable": "/usr/local/libexec/tos-attachment-clamav-scanner",
  "executable_digest": "sha256:<adapter>",
  "args": [
    "--engine-resource", "clamscan",
    "--certificate-resource", "clamav.crt",
    "--database-resource", "bytecode.cvd",
    "--database-resource", "daily.cvd",
    "--database-resource", "main.cvd",
    "--signature-resource", "bytecode-339.cvd.sign",
    "--signature-resource", "daily-28099.cvd.sign",
    "--signature-resource", "main-63.cvd.sign"
  ],
  "resources": [
    {"name": "bytecode-339.cvd.sign", "path": "/srv/tos-messenger/clamav/bytecode-339.cvd.sign", "digest": "sha256:<bytecode-signature>"},
    {"name": "bytecode.cvd", "path": "/srv/tos-messenger/clamav/bytecode.cvd", "digest": "sha256:<bytecode>"},
    {"name": "clamav.crt", "path": "/srv/tos-messenger/clamav/clamav.crt", "digest": "sha256:<certificate>"},
    {"name": "clamscan", "path": "/usr/bin/clamscan", "digest": "sha256:<engine>", "executable": true},
    {"name": "daily-28099.cvd.sign", "path": "/srv/tos-messenger/clamav/daily-28099.cvd.sign", "digest": "sha256:<daily-signature>"},
    {"name": "daily.cvd", "path": "/srv/tos-messenger/clamav/daily.cvd", "digest": "sha256:<daily>"},
    {"name": "main-63.cvd.sign", "path": "/srv/tos-messenger/clamav/main-63.cvd.sign", "digest": "sha256:<main-signature>"},
    {"name": "main.cvd", "path": "/srv/tos-messenger/clamav/main.cvd", "digest": "sha256:<main>"}
  ]
}
```

Both `args` and `resources` are canonical and sorted. Admission copies each
resource from its validated open inode, verifies the private copy, mounts it
read-only, and requires its name/digest in the verdict. ClamScan runs with
official databases only and `--fips-limits`, so the external signatures and
pinned certificate are mandatory rather than a legacy-validation fallback.
Its exact-file limit equals the authenticated input and its internal scan limit
has only a fixed 1 MiB accounting allowance. Clean is exit 0, detection is exit
1, and every other outcome fails closed. The 2026-08-22 acceptance used ClamAV
1.5.3 and current `daily` 28099 through this exact sandbox and passed three
clean/EICAR/corrupt-signature/corrupt-certificate rounds. A release deployment
must refresh and re-pin one coherent snapshot, size the cgroup for the
documented 3–4 GiB engine requirement, and pass the approved hostile corpus.
EICAR by itself proves plumbing, not production coverage.

For the private representative-corpus gate, build
`cmd/tos-attachment-corpus` from an exact clean commit with VCS metadata. Keep
the corpus bytes outside the repository. The external approver prepares a
strict draft whose `approver_public_key_hex` and `signature_hex` are empty; the
`samples` array is sorted by its single-component `name`, contains at least one
allow and one deny control, and every file is at most the current 128 KiB
OpenFox input ceiling:

```json
{
  "schema": "tos.messaging.attachment-corpus-manifest.v1",
  "corpus_id": "external-release-review-2026",
  "revision": "r1",
  "approved_at_unix": 1787356800,
  "scope": "Private representative controls selected by the named external reviewer.",
  "samples": [
    {"name":"clean-control.txt","sha256":"<64 lowercase hex>","size_bytes":123,"category":"clean-control","media_type":"text/plain","expected_decision":"allow"},
    {"name":"hostile-control.bin","sha256":"<64 lowercase hex>","size_bytes":456,"category":"malware-control","media_type":"text/plain","expected_decision":"deny"}
  ],
  "approver_public_key_hex": "",
  "signature_hex": ""
}
```

The approver generates a separately custodied mode-`0600` canonical Ed25519
private key in the approver's isolated environment, then signs the draft. The
command derives the public key from that key, prints it for out-of-band pinning,
atomically refuses to overwrite either file, and never accepts draft-supplied
authority:

```bash
tos-attachment-corpus keygen -output /review/approver.key
tos-attachment-corpus sign \
  -draft /review/corpus-draft.json \
  -approver-key /review/approver.key \
  -output /review/corpus-manifest.json
```

Copy the exact `attachment_admission` object (not the surrounding daemon
config) into a reviewed policy file. It must name exactly one scanner with ID
`clamav-official`; keep the immutable eight-resource snapshot above. Provision
a different mode-`0600` runner key with `keygen` in the runner's isolated
environment, then run the opt-in target with all paths and both public keys
fixed:

```bash
export TOS_ATTACHMENT_CORPUS_RUNNER=/usr/local/libexec/tos-attachment-corpus
export TOS_ATTACHMENT_CORPUS_MANIFEST=/review/corpus-manifest.json
export TOS_ATTACHMENT_CORPUS_SAMPLES=/review/private-samples
export TOS_ATTACHMENT_CORPUS_POLICY=/review/attachment-admission.json
export TOS_ATTACHMENT_CORPUS_APPROVER_KEY=<64-lowercase-hex-public-key>
export TOS_ATTACHMENT_CORPUS_RUNNER_KEY=/review/runner.key
export TOS_ATTACHMENT_CORPUS_RUNNER_PUBLIC_KEY=<64-lowercase-hex-public-key>
export TOS_ATTACHMENT_CORPUS_REPORT=/review/new-corpus-report.json
make test-attachment-corpus-live
```

The output path must not exist. Samples must be non-symlink regular files and
not group/world writable. A deny expectation passes only for a completed
structured scanner deny; sandbox/resource/engine failure aborts without a
report. Verification binds every approved sample, the raw manifest and policy
digests, the exact scanner/resource verdicts, clean runner commit/toolchain and
both fixed public keys. Key identity makes the claims accountable but does not
prove organizational independence or corpus representativeness; those facts
must be established by the release review. No qualifying external report is
currently recorded.

Startup re-hashes every configured executable before opening the runtime
socket. OpenFox's `tos_messenger` settings must set
`"enable_attachments": true`; it then uses local request v7/response v5 and
receives only admitted `text/plain`, never the Reference or fetch key.
Production deployment still needs a release-pinned scanner selection and representative corpus,
must enable the explicit cgroup block when hard RSS/swap/task isolation is
required, and still needs independently operated evidence.

## What `"transport": "none"` means

Outbound events are queued durably and never sealed. No route has been chosen,
and sealing for a transport that does not exist would spend a message key per
event on nothing. Queued events wait; they are not lost and they are not
delivered.

The local API still works: a runtime can drain the inbox and compose or submit events, and
an owner can admit or refuse an inbound message that is waiting, and release or
abandon a held outbound one. What is missing is the middle,
and it stays missing until the reachability study picks a route.

## State

The state directory holds the journal and the install salt, and one daemon owns
it at a time through a lock file. A second daemon on the same directory fails
immediately rather than interleaving writes with the first.

The install salt is generated once and kept. It is what makes decision records
correlatable within one node and meaningless elsewhere, so a salt regenerated
on each start would stop a node's own records from correlating with themselves.

The socket lives outside the state directory, in a private directory this
daemon creates and verifies. A stale socket from a dead process is removed; a
live one is not, because ownership of the state is decided by the lock and
unlinking another daemon's socket would take its callers without taking its
ownership.

## Shutdown

`SIGINT` and `SIGTERM` both mean stop taking work and release the state. The
daemon closes the socket, removes it, and releases the directory lock before
exiting, so a replacement starts without an operator cleaning up first.

## Maintenance

On its own schedule the daemon settles outbound events that outlived their own
expiry, then removes finished records past the retention floor. Expiry runs
first so that an event which has just expired is removed in the same pass
rather than a maintenance interval later.

Damaged records are reported and kept. A corrupt claim fails closed and blocks
its own event; deleting corrupt files would turn damaging a record into
replaying it.
