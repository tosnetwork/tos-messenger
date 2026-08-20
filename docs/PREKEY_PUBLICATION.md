# Prekey publication and replenishment

This profile closes the route-independent lifecycle for the signed prekey
material used by the v1 one-to-one candidate. It does not select a message
route and does not add one-time prekeys to the approved suite.

## One publication is one generation

An endpoint publishes the complete current device set at once. Every bundle in
that set has the same `issued_at_unix`, `expires_at_unix`, network, Agent,
Endpoint, and algorithm. Device identifiers are sorted before generation so a
retry has a stable object representation; the descriptor still commits the
order-independent `e2ee.SetDigest`.

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

`eventlog.LocalPrekeyLedger.EnsurePrekeys` performs these steps under the
journal's exclusive writer lock:

1. validate the live delegation, exact delegated Ed25519 signer, suite,
   devices, lifetime, and replenishment horizon;
2. generate and sign every device bundle through `crypto.Signer`;
3. verify the complete set under the delegation and derive its digest;
4. atomically persist the exact bundle-set JSON and its private answering
   material; and only then
5. return the immutable publication to the caller.

A crash before step 4 exposes nothing. A crash after step 4 reloads the exact
same signatures and JSON, so retry cannot create a second set at the same
generation. `PublishPrekeySet` revalidates that stored artifact and passes a
copy to a route-neutral content-addressed sink. The object must be available
before an endpoint publishes a signed descriptor that names its digest; the
descriptor update must never create a dangling commitment.

The publisher asks a narrow `crypto.Signer` for Ed25519 signatures and verifies
every returned signature. It neither loads nor serializes the Endpoint signing
key. Deployment key custody, signer authentication, and availability remain
operator responsibilities.

## Replenishment and private-material lifetime

`PrekeyPlan` gives a bounded bundle lifetime and a strictly shorter
replenishment horizon. `EnsurePrekeys` returns the durable current generation
unchanged while it covers the requested device set and extends beyond that
horizon. At the horizon it creates a strictly newer complete generation. A
delegation too close to expiry to cover the horizon fails closed instead of
publishing immediately stale material.

A sender may have fetched the preceding signed publication shortly before a
routine rotation. The receiver therefore retains a still-current device's old
answering material until its signed expiry and selects it by the exact
per-bundle digest already produced by fan-out planning. A removed device is
different: all its current and retired answering material is dropped in the
same atomic transition that records its tombstone, so a cached bundle cannot
restore its bootstrap authority. `PrunePrekeys` removes other expired current
and retired private material while retaining public generation and
device-revocation history. This is logical key erasure; secure deletion of old
filesystem blocks or storage snapshots is an operator/storage property.

Removing a local device creates a permanent tombstone. It may return only as a
new device key with a new identifier. Replenishing unchanged devices does not
revoke them; it merely retires their old answering material at its existing
expiry. Live retired secrets are capped at 80 and tombstones at 256, within the
journal's bounded record. At either bound a further rotation fails closed
rather than forgetting a still-valid answering key or an old revocation.

## Deliberate boundary

This round supplies the durable publisher, signer isolation, exact object-sink
contract, replenishment, retired-secret selection, pruning, rollback refusal,
and local/peer equivocation classification. A production daemon still needs an
operator-selected content sink and the endpoint-authorized descriptor update
that exposes the new digest. Live independently operated publication and
cross-observer fork exchange remain deployment evidence, not claims made by
the local state machine.

No canonical preimage or wire schema changed. The existing bundle and
bundle-set vectors remain the applicable interoperation artifacts.
