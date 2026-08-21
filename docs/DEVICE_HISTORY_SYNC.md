# Direct multi-device history synchronization

Messenger can backfill an existing direct conversation from one current Device
of an Endpoint to another. This is an application of the existing authenticated
one-to-one Event transport, not a second encryption construction: the
`device.history.segment` Event is sealed under the pair's existing Double
Ratchet session with the same network/conversation/device associated data.

Version 1 deliberately excludes room and MLS history. A new MLS leaf has no
right to old epoch secrets, and importing plaintext room history would silently
override the room's join-history policy. Room backfill therefore needs an
explicit room-authority policy and a separately reviewed design.

## Authority boundary

Export is `device-history.export` on the owner socket only. It consumes the
normal single-use owner challenge, and the Ed25519 decision commits the target
Device, direct Conversation, segment sequence, predecessor digest, stable
`(created_at_unix, event_id)` cursor, page limit, idempotency key and expiry.
The runtime socket has no such operation. The daemon derives the source Agent,
Endpoint and Device, recipient Endpoint and symmetric Device-pair session ID.
Both source and target must occur in the sorted Device roster already committed
by prekey publication configuration, and the live Endpoint delegation must
allow the `device.sync` outbound class (whose v1 Event kind is
`device.history.segment`).

The stock offline-signing workflow is:

```sh
tos-messenger-owner -socket /run/tos-messenger/owner.sock prepare-history \
  -target-device dev_... -conversation conv_... -sequence 1 \
  -idempotency idem_... -expires-at 1900003600 > history.prepare.json
tos-messenger-owner sign -key owner.key -decision history.prepare.json > history.signed.json
tos-messenger-owner -socket /run/tos-messenger/owner.sock submit \
  -decision history.signed.json
```

The response returns the committed segment digest and last Event cursor for the
next page. Exact retries retain the first Event ID and bytes even if newer
messages entered the journal.

## Eligible and imported state

The exporter reads only durable inbound Events in `applied` state and outbound
Events in `delivered` state. Pending, held, rejected, queued, local-only, room,
and recursive history Events are excluded. Pages hold at most 16 Events and 96
KiB of raw canonical Event bytes; a source-target-conversation chain holds at
most 4096 segments.

The daemon owns a dedicated receive adapter. History segments never appear in
the OpenFox/runtime pending list and cannot invoke the Agent loop, tools, owner
approvals, Agent Packet Gate, or commerce adapters. Canonical Events are stored
as immutable content-addressed display objects. An ordered segment manifest is
fsynced before its checkpoint; listing follows only checkpoint-reachable
manifests, deduplicates Event IDs, and fails closed on damaged objects,
manifests, cursors or chain links. A crash may leave an unreachable object, but
cannot make it visible or executable.

This closes the route-neutral direct-history implementation. Actual remote
delivery and independently operated restart/catch-up evidence remain gated by
the M0-R transport decision.
