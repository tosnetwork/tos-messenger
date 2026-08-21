# Running the daemon

`tos-messengerd` owns one state directory, always serves separate runtime and
owner sockets, and may serve a third public-only prekey device socket.
It cannot carry a message yet, and it says so on startup rather than looking
like a working installation that happens to be quiet.

```sh
tos-messengerd -config /etc/tos-messengerd/config.json -check   # validate and exit
tos-messengerd -config /etc/tos-messengerd/config.json
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

When `publication.mode` is `prekeys`, the third socket exposes only the current
fixed public generation and admission of one already Endpoint-signed public
bundle. It exposes no approval operation, private material, other device's
bundle, or authority to select a roster/window. The v5 config explicitly states
its clean absolute path, sorted 1–16-device roster (including this
installation's device), algorithm identifier, 60-second-to-30-day lifetime,
positive replenishment lead, and a check interval no longer than that lead.
Use `publication.mode = "none"` with no unused fields to disable it.

The library-level production composition `daemon.OpenWithGenerationPublisher`
accepts an explicit HTTPS object sink, native-DHT locator sink, committed
Descriptor policy/template, bounded publish interval, and `crypto.Signer`.
`pkg/signerapi.Client` can supply that signer through a separate Unix service
while pinning and verifying the finalized Endpoint public key. The stock
`tos-messengerd` command does not yet infer these operator-specific resources or
load private-key bytes; deployments must assemble the publisher explicitly.

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
  cannot become model instructions by taking the ordinary message path.

An unknown key in the configuration is refused rather than ignored. A
misspelled setting that is silently dropped is a setting an operator believes
is in force.

`docs/daemon-config.example.json` is a complete file with placeholder values.
The typed Agent Packet adapter makes this schema `tos.messaging.daemon-config.v6`;
older files are rejected instead of silently disabling discovery or public
generation planning, or applying an inbox policy the endpoint never committed.

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
