# HTTPS descriptor and prekey object source

`pkg/directory.HTTPSObjects` completes the network-object half of the
route-neutral refresh chain. It fetches discovery publications only. It does
not choose a direct, tunnel, Relay, ADNL, RLDP, or HTTPS message route.

## Publication profile

The signed DHT locator contains the exact HTTPS descriptor URL. The descriptor
origin also publishes the complete prekey bundle set at:

```text
/.well-known/tos-messenger/prekeys/<lowercase-sha256-hex>.json
```

The path digest is the descriptor's `prekey_bundle_digest`, without the
`sha256:` prefix. The origin is exactly the descriptor locator's HTTPS origin;
no origin advertised inside an untrusted response is followed. Both URLs must
use standard HTTPS port 443 and contain no credentials, query, or fragment.
Redirects are refused, including same-origin redirects, so a signed reference
cannot silently become another retrieval instruction.

New descriptors are published immutably at:

```text
/.well-known/tos-messenger/descriptors/<lowercase-sha256-hex>.json
```

The DHT locator names that exact content-addressed URL. This avoids replacing a
mutable descriptor path before the DHT has replaced its old digest.

The prekey object uses schema
`tos.messaging.prekey-bundle-set.v1` and contains `schema` plus `bundles`.
Each member is an existing strict `tos.messaging.prekey-bundle.v1` object. The
wrapper is bounded to 128 KiB and 1–16 coherent device bundles. It is a
transport container, not a new authority or signed preimage. The descriptor
continues to commit the order-independent canonical bundle-digest set under
the existing `tos.messaging.prekey-bundle-set.v1` domain. Positive vectors now
include the wrapper, canonical set bytes, and resulting digest; adversarial
vectors cover unknown fields, trailing JSON, truncation, and empty input.

`directory.HTTPSPublisher` implements the static-origin write side. It requires
an absolute protected non-symlink root, creates only the fixed directories
above, validates both content addresses, requires the prekey wrapper in sorted
device publication order, syncs a temporary regular file, and installs it with
an atomic no-overwrite link. An exact retry is idempotent; different bytes at
one address are refused.

`ActivateHTTPSPublication` validates and signs the complete dependency graph
before writing, then stores prekeys before the Descriptor and returns the signed
inner locator only after both are durable. DHT publication is deliberately the
last authority-changing step. Native DHT envelope signing and collection of
public contributions from independently custodied devices are not yet wired
into the daemon.

## Network boundary

The production client has finite request, connection, TLS-handshake, response-
header, idle-connection, response-size, and connection-pool bounds. It accepts
only status 200 with `application/json`, disables implicit compression and
environment proxies, and never follows redirects.

Its dialer resolves the hostname itself and pins the connection to the checked
answer. Every DNS answer must be a public global-unicast address. An empty,
private, loopback, link-local, multicast, unspecified, carrier-grade NAT, or
mixed public/private answer set fails closed. This prevents environment-proxy
surprises, DNS rebinding, and cloud-metadata/private-service retrieval.

Fetched bytes are never authority. The refresh chain verifies the descriptor
against the signed DHT locator, verifies it under the finalized Endpoint
delegation, checks every prekey signature, matches the entire set to the
descriptor digest, and durably enforces succession/revocation. A compromised
HTTPS origin can deny service, but cannot substitute identity or key material.

`directory.NetworkRefreshSource` composes an out-of-band delegation and
descriptor-policy source, `TOSDHT`, and `HTTPSObjects`. The daemon's explicit
bounded file bootstrap and lifecycle wiring are documented in
[`DISCOVERY_BOOTSTRAP.md`](DISCOVERY_BOOTSTRAP.md). The Endpoint public key is
needed to derive the DHT key, so the DHT locator still cannot discover that
delegation from only an Agent identifier.
