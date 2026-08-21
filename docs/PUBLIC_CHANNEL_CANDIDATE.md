# Route-neutral public Agent channel candidate

`pkg/publicchannel` implements the first transport-independent M5 primitives.
It is a candidate, not a frozen Overlay profile and not a production channel.

## Authority and identity

A public channel ID is derived from the complete TOS network identity, one
finalized authority Agent/Endpoint and a non-zero random 32-byte seed. An
authority-signed profile names a bounded, sorted set of finalized Endpoint
principals and independently grants `publisher` and `moderator` powers. The
authority must retain both powers. Every Endpoint delegation must include the
`public.channel` event class; a profile signature cannot mint Agent identity or
extend an Endpoint delegation's validity.

The profile is an explicit epoch so role changes can be serialized without
pretending that Overlay membership grants application authority. Epoch 1 has no
predecessor; every later profile commits the exact prior signed-profile digest.
`VerifySuccessor` accepts only a single adjacent authority-signed transition,
and `ProfilesConflict` identifies non-identical branches at the same epoch and
predecessor without choosing by digest or arrival order. `OpenStore` persists
the exact signed profile before atomically advancing a single-writer checkpoint;
exact replay is idempotent, while lower epochs, gaps and equal-epoch forks are
refused.

## Events and convergence

Each public Event is Ed25519-signed by its finalized publisher Endpoint and is
content-addressed as `pce_<sha256>`. One publisher has one strict sequence:
sequence 1 has no predecessor, every later Event names the prior Event and
includes it in its sorted causal-parent set. Up to 16 parents express
cross-publisher causality without creating a global sequencer. A post contains
at most 64 KiB. A moderation `hide` or `restore` contains no post content and
must name its target post as a causal parent; only a principal holding both
publisher and moderator roles may sign it.

A complete history is bounded to 65,536 Events and 64 MiB of post bytes. It
verifies every role, finalized delegation, signature, per-publisher chain,
causal reference and moderation target. Its digest commits the sorted Event-ID
set, so Relay arrival order cannot change the result. Display order is only the
deterministic `(published_at,event_id)` projection. The latest moderation in
that order controls visibility, while the immutable source Event remains in
history. `MissingReferences` returns exact absent content IDs for gap repair;
it never trusts a Relay's range or completeness claim.

Strict bounded v1 JSON exists for the profile, Event, and compact history head.
A head is not independent authority: a consumer must fetch Events, run
`VerifyHistory`, and compare the derived head. Unknown fields, trailing JSON,
signature/authority substitution, sequence forks, missing/future parents,
unauthorized moderation, Event-ID mismatch and arrival-order divergence fail
closed in the candidate tests.

`testdata/public-channel-vectors.json` freezes the exact profile/Event signing
preimages, signed JSON, profile digest, Event IDs and convergent history head
from deterministic Endpoint seeds. Its decode-positive adversarial entries
separately exercise unknown profile fields, Event-ID and publisher-signature
substitution, a missing causal parent, and a syntactically valid false head.
The package rebuilds and consumes this file on every test run.

## Route-neutral synchronization

A bounded fetch request names at most 64 sorted Event IDs. Its strict response
must account for every requested ID exactly once as either an Event whose
content ID and channel/profile binding reproduce, or a sorted `unavailable`
observation. Unavailability is retryable and never establishes completeness.
Fetched Events independently recheck the finalized profile, publisher
delegation, role and signature before joining local staging.

Synchronization begins with the untrusted head's tips, then recursively asks
for exact missing causal parents. Exact response replay merges idempotently. A
claimed Event count with no discoverable tip/parent fails as a stalled/dishonest
head. Only `VerifySyncedHistory` over the complete bounded set, followed by an
exact derived-head match, permits the durable store to commit it. This protocol
is suitable for an eventual Overlay, RLDP or Sites object source; it does not
select one of them.

## Peer resource guard

`SyncGuard` scopes one channel/profile synchronization attempt to authenticated
native transport peer IDs (`peer_<32-byte-hex>`). Candidate defaults permit at
most eight peers, four distinct heads and 256 fetches per peer, 64 MiB per peer,
256 MiB total, and 256 unavailable results. Limits are explicit and validated;
an adapter must enforce the per-response byte ceiling while reading and then
charge every completed response. Exact head replay is free, but one peer never
counts twice toward independent support.

Heads are ordered for fetch work by distinct-peer support and then a stable
digest tie-break. This grants neither validity nor commit authority: even a
many-peer candidate must reproduce through `VerifySyncedHistory`. The guard
contains transport noise without adding unmeasured PoW, stake or payment rules,
and authorized publication remains governed by the finalized profile. Default
calibration against the real M0-R carrier and abuse measurements is still open.

## Native TOS Overlay/RLDP carrier

`NativeCarrier` binds the candidate to the repository's pinned
`tosutils-go` native stack. The 32-byte digest in `channel_<sha256>` is the
`pub.overlay` key. Its TL-boxed hash is the Overlay short ID used on the wire and in signed DHT
`overlay.node` records. Authenticated ADNL peers exchange live
head/Event hints through signed two-step Overlay broadcast; RLDP carries the
strict fetch request and response when history is larger or missing. Each
connection authorizes only the remote ADNL transport key and caps native
broadcast/FEC state, inbound queries, served bytes, unavailable results and
application callback replay.

The native signature is hop authentication, not publisher authority. Received
Events still recheck the finalized profile, publisher role/delegation and
Ed25519 signature; heads still enter `SyncGuard` as untrusted claims. Incoming
RLDP requests must match the carrier's exact channel/profile, and outbound
fetch attempts are charged before I/O so a silent peer cannot bypass the
request ceiling. Malformed responses consume a pessimistic unavailable budget.

The non-race ADNL gate starts two real UDP Gateways, broadcasts a head and an
authenticated Event in both directions, recursively fetches the history over
RLDP, reproduces its head, tears the transport down, and repeats with the same
transport identities. The race gate covers the carrier's state and codecs;
the live ADNL test runs separately because the pinned TL serializer is not
compatible with race/checkptr. This is same-host native-stack/restart evidence,
not independent-network evidence.

`NativeNode` and `cmd/tos-public-channeld` assemble that carrier into a
runnable replica. The daemon publishes its separately provisioned ADNL address
and signed `overlay.node` through the native TOS DHT, discovers a bounded set
of signed nodes, resolves their owner-signed addresses, and then requires the
ADNL handshake to reproduce the exact discovered public key. It starts one
bounded carrier per authenticated peer, announces a locally committed head,
recursively fetches a different head from an empty staging set, and atomically
commits it only after full history verification. Publisher and moderator
private keys never enter this daemon.

The node integration test uses two real UDP Gateways plus a replaceable
in-memory directory: it starts from one populated and one empty durable store,
discovers and connects both nodes, transfers the history over Overlay/RLDP,
then closes and reopens the receiving Gateway/node/store with the same
identity. The production directory adapter is covered by the same strict
key/short-ID derivation and native DHT types; independently operated TOS DHT
evidence remains an operator acceptance task.

Production invocation requires canonical absolute profile/delegation/state/key
paths and an HTTPS global-config URL. `-check` verifies local authority, key
reproduction, Overlay derivation and lifecycle bounds without network access
or state writes. A typical service invocation is:

```text
tos-public-channeld \
  -profile /etc/tos-messenger/channel/profile.json \
  -authority-delegation /etc/tos-messenger/channel/authority.json \
  -delegation /etc/tos-messenger/channel/publisher-a.json \
  -state /var/lib/tos-messenger/public-channel \
  -transport-key /etc/tos-messenger/channel/adnl.key \
  -listen 0.0.0.0:30303 -public-address 203.0.113.10:30303 \
  -dht-config-url https://config.example/tos-global.config.json \
  -sites-state /var/lib/tos-messenger/public-channel-sites \
  -sites-catchup-state /var/lib/tos-messenger/public-channel-sites-catchup \
  -storage-cli /opt/tos/bin/storage-daemon-cli \
  -storage-daemon 127.0.0.1:5555 \
  -storage-client-key /var/lib/tos-storage/cli.key \
  -storage-server-key /var/lib/tos-storage/server.pub
```

## TOS Sites / Storage Bag mirror and catch-up

`SitesMirror` exports only a complete locally verified history. Its immutable
snapshot contains canonical profile, head, finalized-delegation, Event and
manifest files in deterministic names and order. Loading refuses missing or
extra objects, symlinks, noncanonical JSON, Event/file-name substitution,
delegation substitution and any set that does not reproduce the exact head.
The caller must still supply the current finalized delegations; downloading a
Bag never proves chain authority.

`StorageCLIPublisher` invokes `storage-daemon-cli` directly without a shell,
copies the snapshot into an uploaded TOS Storage Bag, bounds process time and
output, and normalizes the stock CLI's uniform uppercase 256-bit BagID to the
canonical lowercase wire form while refusing mixed case. A private
single-writer receipt makes exact restart replay idempotent and fails closed on
damage. Once a receipt exists, `NativeNode` sends a strict bounded `SitesHint`
over the authenticated Overlay connection. The hint is only an availability
locator: it has a separate replay budget, cannot consume the head budget, and
never grants publication, history or completeness authority.

`SitesCatchUp` is the corresponding single-writer consumer. It accepts only a
hint bound to the locally selected channel/profile, asks `StorageCLIDownloader`
to run the stock `add-by-hash <BagID> -d <isolated-root> --no-upload` command,
and polls `get <BagID>` under bounded time and output. Bag, root and directory
fields must reproduce the request exactly. The downloaded snapshot then passes
the same strict finalized-delegation and complete-head verification before the
durable channel store can commit it. A canonical download receipt makes exact
restart replay download-idempotent; the crash window where the snapshot is
complete but its receipt is absent is recovered only by fully re-verifying the
snapshot. A different BagID claiming an already verified history cannot replace
the durable locator.

The stock CLI prints a directory name with one trailing `/`; the boundary
accepts only the exact expected history-digest directory with or without that
single suffix. It does not accept another basename, nested path or mixed-case
BagID.

The real two-node UDP integration starts with one empty ledger, synchronizes
and commits it over RLDP, exports and passes its snapshot to an injected Bag
publisher, propagates the returned BagID to the other node, then reopens the
node/store/mirror and proves the publisher is not called twice. A separate
process-adapter test proves exact no-shell Storage CLI arguments, bounded
canonical BagID parsing and a snapshot path containing spaces. These are not a
live independently operated storage-daemon upload. A second real-UDP test gives
the sender no RLDP history at all, delivers only the BagID hint over authenticated
Overlay, downloads through an injected Storage adapter, verifies and commits the
history, and then restores the node/store/catch-up locator without a second
download. A separate process fixture proves the exact stock add/get command and
status boundary; it is not a live independently operated storage-daemon
download. Tests also cover second writers, damaged and missing receipts, an
alternative BagID, extra snapshot objects, noncanonical manifests,
finalized-delegation substitution and malformed hints/status fields.

An explicit `make test-storage-live` acceptance goes beyond those fixtures. It
starts two real `storage-daemon` processes, derives a locally signed DHT
bootstrap from the first daemon's generated private identity, publishes the
verified snapshot on daemon A, downloads and re-verifies it on daemon B, then
stops B and proves receipt replay needs no live Storage process. The 2026-08-21
run and exact boundary are recorded in
[`evidence/PUBLIC_CHANNEL_STORAGE_LIVE_2026-08-21.md`](evidence/PUBLIC_CHANNEL_STORAGE_LIVE_2026-08-21.md).
This is same-host real-binary evidence, not independent administration or
public-network evidence.

## Durable local state

The candidate store writes verified Event objects and a canonical immutable
history manifest before atomically replacing that profile epoch's head. A
successor snapshot must contain every previously committed Event. Restart reads
follow only the head, compare it byte-for-byte with its immutable manifest, and
re-run full history verification over every referenced Event; orphan objects,
history shrinkage, corrupted files and a second writer do not become accepted
state. Directories are mode `0700`, records are mode `0600`, and profile epochs
remain readable after a later profile becomes current.

This is local durability, not evidence that an Overlay peer supplied a complete
history. Remote heads and manifests remain untrusted inputs until the locally
derived history matches them.

## Explicitly still open

- measured production calibration of the candidate peer/resource limits;
- live independently operated/public-network Storage and
  convergence/failover evidence;
- independent vector consumption/review and a second implementation.

No transport choice or economic history-Relay profile is made here. The latter
remains Expansion-Gate locked.
