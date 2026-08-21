# Prekey publication and replenishment

This profile closes the route-independent lifecycle for the signed prekey
material used by the v1 one-to-one candidate. It does not select a message
route and does not add one-time prekeys to the approved suite.

## One publication is one generation

An endpoint publishes the complete current device set at once. Every bundle in
that set has the same `issued_at_unix`, `expires_at_unix`, network, Agent,
Endpoint, and algorithm. The Endpoint coordinates that window; each device
generates and retains only its own opaque private material, then contributes an
Endpoint-signed public bundle. `eventlog.PrekeyContributionLedger` first fixes
the sorted roster, suite, and issuance/expiry window, then durably accepts only
matching signed public contributions. It advances
`eventlog.PrekeyPublicationLedger` only after the exact roster is complete;
neither ledger contains a device secret. Device identifiers are sorted before
publication so one digest has one accepted JSON object; the descriptor still
commits the order-independent `e2ee.SetDigest`.

The issuance second is the generation watermark. A different non-retirement
set at an already used watermark is an equivocation, not a value that can be
ordered by arrival time or digest. The local publisher refuses to create it,
and peer succession returns `e2ee.SetEquivocationError` with both conflicting
set digests. An older watermark is a rollback. A pure device retirement remains
the one equal-watermark exception in the peer succession rules because it adds
no key material and only removes authority.

This rule intentionally rotates every retained device when replenishing or
changing membership. Independently rotating only one device would leave no
single publication generation and would make equal-time fork detection depend
on which device happened to carry the largest timestamp.

## Crash order

`eventlog.DevicePrekeyLedger.EnsureDevicePrekey` performs these steps under the
device journal's exclusive writer lock:

1. validate the live delegation, exact delegated Ed25519 signer, suite, local
   Device ID, coordinated window, and replenishment horizon;
2. generate and Endpoint-sign that device's public bundle;
3. atomically persist that bundle and only that device's private answering
   material; and only then
4. return the public contribution to the Endpoint aggregator.

A crash before step 3 exposes nothing. A crash after step 3 reloads the exact
same signature and secret, so retry cannot create a competing contribution at
the same generation. The contribution ledger verifies every bundle before
storage, makes exact retries idempotent, rejects unplanned devices and
same-device conflicts, and refuses to discard any live submitted generation
before finalization. Finalization verifies the complete set again, advances
`PreparePrekeyPublication`, then marks the staged generation finalized. A
crash between those two durable writes is repaired by an exact retry.

`directory.ActivateHTTPSPublication` signs and verifies the Descriptor and
inner locator before mutation, then writes the immutable prekey object first
and the content-addressed Descriptor second. Only after both exist does it
return the signed locator that may be published to the DHT. A failure leaves at
most unreachable immutable objects, never an authoritative dangling pointer.
`directory.HTTPSPublisher` is the production static-origin sink: it uses fixed
same-origin paths, protected non-symlink directories, synced temporary files,
atomic no-overwrite installation, exact idempotent retries, and conflict
refusal.

The publisher asks a narrow `crypto.Signer` for Ed25519 signatures and verifies
every returned signature. It neither loads nor serializes the Endpoint signing
key. Deployment key custody, signer authentication, and availability remain
operator responsibilities.

## Replenishment and private-material lifetime

`DevicePrekeyPlan` gives the Endpoint-coordinated issuance and expiry plus a
strictly shorter replenishment horizon. `EnsureDevicePrekey` returns the exact
durable current contribution while its window matches and covers the horizon.
At the horizon the Endpoint must coordinate a strictly newer window; asking a
device to create different material under the old issuance second is refused
as equivocation.

A sender may have fetched the preceding signed publication shortly before a
routine rotation. The receiver therefore retains a still-current device's old
answering material until its signed expiry and selects it by the exact
per-bundle digest already produced by fan-out planning. A removed device is
different: `RevokeDevicePrekeys` drops that device's current and retired
answering material before recording its local tombstone, while the public
aggregation ledger permanently tombstones its Device ID. A cached bundle
cannot restore bootstrap authority. `PruneDevicePrekeys` removes other expired
private generations. This is logical key erasure; secure deletion of old
filesystem blocks or storage snapshots is an operator/storage property.

Removing a local device creates a permanent tombstone. It may return only as a
new device key with a new identifier. Replenishing unchanged devices does not
revoke them; it merely retires their old answering material at its existing
expiry. Live retired secrets are capped at 32 per local device and public
tombstones at 256, within bounded journal records. At either bound a further
transition fails closed rather than forgetting a still-valid answering key or
an old revocation.

## Daemon scheduling and deliberate boundary

The route-neutral lifecycle now supplies device-local custody, public-only
Endpoint aggregation, durable fixed-roster public-contribution collection,
signer isolation, the production static HTTPS object sink, ordered Descriptor
activation, replenishment, retired-secret selection, pruning, rollback
refusal, and local/peer equivocation classification. `directory.GenerationPublisher`
composes the exact durable generation into prekeys → Descriptor → signed locator
→ native-DHT publication, and `daemon.OpenWithGenerationPublisher` schedules it
at startup and at a bounded interval. Descriptor validity advances in
deterministic half-policy-lifetime buckets within the durable generation; the
publish interval must fit inside that renewal window. Retries inside one bucket
produce the same signed Descriptor and inner locator while the DHT adapter
refreshes its outer cache TTL. Thus a crash retry creates no new immutable
object, a long generation cannot outlive its Descriptor, and a failing
dependency never exposes a dangling locator.

The narrow device-facing submission API exists separately in `pkg/prekeyapi`;
it exposes only the public plan and accepts only matching signed public bundles.
The production DHT adapter keeps native key-description and value signing behind
the selected `crypto.Signer`, including immediate signature verification before
network use. `pkg/signerapi` supplies a strict bounded Unix client for a
separately custodied Endpoint signer and verifies every 64-byte response under
the live 32-byte delegated key; no private bytes enter daemon configuration.

The stock `tos-messengerd` command assembles those resources when passed
`-publication-operator-config`. The strict
`tos.messaging.publication-operator.v1` document names the protected static
HTTPS root, native DHT global configuration, committed Descriptor policy,
external signer socket, bounded timeouts/cadence, and public Descriptor
capabilities. See `docs/publication-operator.example.json`. At startup the
command first resolves the live delegation through the same strict-majority
finalized-chain authority as the daemon. Identity, network, ADNL, admission
policy, delegation digest, and signer public key are derived from that result,
not accepted from the operator publication document. The template and policy
are checked before a DHT connection or HTTPS mutation, and the daemon is then
opened through `OpenWithGenerationPublisher`.

Omitting the flag intentionally retains public-only device collection without
network publication. `-check` validates both strict configuration documents
without claiming that the live chain, DHT, HTTPS root, or signer is available.
Centralizing every device secret or loading an Endpoint seed from daemon JSON
remains forbidden. Live independently operated publication and cross-observer
fork exchange remain deployment evidence.

No canonical preimage or wire schema changed. The existing bundle and
bundle-set vectors remain the applicable interoperation artifacts.
