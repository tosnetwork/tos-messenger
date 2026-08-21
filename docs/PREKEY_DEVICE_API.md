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
  `tos.messaging.prekey-bundle.v2` JSON object. The server strictly decodes it,
  verifies its 64-byte Ed25519 signature under the live delegated 32-byte
  Endpoint public key, and requires an exact roster/suite/window match before
  durable storage.

When the last planned contribution arrives, the server immediately invokes the
crash-recoverable collector-to-publication transition. The response separately
reports whether the contribution and publication were fresh, so an exact retry
after a lost response is unambiguous. Malformed success/refusal responses,
unknown fields, trailing JSON, oversized frames, and unknown operations fail
closed.

## Daemon lifecycle and deliberate remainder

Daemon config v4 can enable this third listener with `publication.mode =
"prekeys"`. Configuration explicitly fixes its socket, sorted roster, suite,
generation lifetime, replenishment horizon, and check interval. Startup creates
or recovers one durable public plan. The planner repairs interrupted publication
finalization, preserves a live partial generation, rotates a finalized
generation at its configured horizon, and replaces an expired partial
generation. Shutdown closes the listener and removes its socket.

The planner has neither a signer nor a private-key store: devices retain their
own secrets and submit already signed public bundles. Ed25519 here authenticates
the exact bundle only; it is not encryption or key exchange. Configuration never
chooses a message route. Scheduling the finalized public object onto HTTPS and
native DHT publication sinks, and producing live multi-operator publication
evidence, remain deliberate work.
