# Prekey device contribution API

`pkg/prekeyapi` is the local, public-only boundary through which independently
custodied devices learn one coordinated generation and submit their signed
contribution. It is not part of the owner API or Agent runtime API because it
grants neither approval nor message-processing authority.

## Socket boundary

The API uses a distinct Unix socket in a private same-user directory. On Linux
the server also checks peer credentials. Each request is a four-byte
big-endian length followed by at most 16 KiB of strict JSON, and each connection
has a finite deadline. The socket transport is local deployment plumbing, not
a Messenger network route and not M0-R evidence.

The same Unix user may call both operations. That is sufficient because every
returned field is public and the only mutation is admission of an exact
Endpoint-signed bundle under the already fixed plan. Invalid, unplanned, or
conflicting input changes no state. Possession of the socket does not allow a
caller to begin a generation, choose its roster/window, sign for the Endpoint,
or retrieve any contribution or private answering material.

## Strict v1 operations

Requests use `tos.messaging.prekey-device-request.v1`; responses use
`tos.messaging.prekey-device-response.v1`.

- `generation.current` carries no other field. It returns the Endpoint ID,
  sorted Device IDs, algorithm, issuance/expiry, contribution count, complete
  flag, and finalized set digest when present. It never returns collected
  bundles.
- `contribution.submit` carries one canonical existing
  `tos.messaging.prekey-bundle.v1` JSON object. The server strictly decodes it,
  verifies its 64-byte Ed25519 signature under the live delegated 32-byte
  Endpoint public key, and requires an exact roster/suite/window match before
  durable storage.

When the last planned contribution arrives, the server immediately invokes the
crash-recoverable collector-to-publication transition. The response separately
reports whether the contribution and publication were fresh, so an exact retry
after a lost response is unambiguous. Malformed success/refusal responses,
unknown fields, trailing JSON, oversized frames, and unknown operations fail
closed.

## Deliberate remainder

The package is independently composable and fully socket-tested, but the daemon
does not yet create this third listener or select generation plans. Daemon
configuration must state the socket, roster, suite, lifetime, replenishment
horizon, and publication schedule explicitly; it must not infer them from the
owner/runtime APIs or choose any message route.
