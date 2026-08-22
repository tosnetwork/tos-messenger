# `.tos` recipient canonicalization audit

Audited 2026-08-22 against `tos-messenger` main `a9a1051` and OpenFox main
`aa02f93e`, before the implementation described below.
Both remotes exposed only `origin/main`; inspection of local refs found no
unmerged recipient/contact implementation. Historical DNS commits already on
main were Messenger `8566051` and OpenFox `2a777b64`.

## Invariant

`.tos` names are human-readable aliases for discovering an Agent. Resolution
terminates at the canonical AgentID. All messaging, authorization, session,
commerce, payment, replay and receipt semantics after that boundary are bound
to AgentID and the existing TOS identity/delegation hierarchy.

A later transfer or reassignment of a `.tos` name MUST NOT retarget an existing
contact, conversation, session, mandate, approval or payment relationship.
Re-resolution affects only a new name lookup.

## Audited call chain

Before this change, `Daemon.ResolveContact` already implemented the safe
in-process chain:

```text
contact.Resolver.Resolve(input)
  -> canonical AgentID: validate directly
  -> canonical *.tos: Native DNS MESSENGER lookup
     -> quorum/category/network/account/lifecycle/checkpoint/path checks
     -> exact finalized Agent state check
  -> directory.Manager.Ensure(AgentID)
     -> finalized Endpoint delegation
     -> signed DHT locator
     -> signed Contact Descriptor
     -> admitted device/prekey succession
  -> contact.Result{AgentID, CanonicalName(display only), Directory}
```

Directory caches and durable device/session records are keyed by AgentID,
EndpointID, DeviceID or SessionID; the alias is not an authority key. Existing
resolver tests cover explicit-AgentID DNS bypass, wrong kind/category/network,
non-Agent targets, expired lifecycle, resolver cycles, quorum/checkpoint and
finalized-state failures, directory substitution and alias transfer.

The missing link was runtime exposure. `ResolveContact` was not a local API
operation. OpenFox's production Messenger `Send` was authenticated-reply-only;
its unrelated Native DNS helper was discovery evidence for Agent/Capability
commerce and was not connected to AgentLoop messaging. There was therefore no
proactive `AgentID -> Messenger` AgentLoop path, and `.tos -> AgentID -> that
path` was not wired.

## Implemented boundary

```text
OpenFox message tool {channel: tos_messenger, recipient, content}
  -> bus.OutboundMessage.Recipient (no route fields)
  -> tos_messenger messages.send-direct over owner-private runtime socket
  -> daemon ResolveContact / finalized directory chain
  -> canonical AgentID
  -> daemon-owned AgentID conversation + verified device/prekey fan-out
  -> daemon-owned pair session bootstrap and durable E2EE copies
  -> configured carrier (none queues; https-bootstrap sends)
```

`CanonicalName` is returned only for optional display. The model cannot submit
conversation, EndpointID, DeviceID, SessionID, relay, ADNL or route fields.
AgentLoop emits an opaque runtime delivery-intent ID; after resolution the
daemon binds idempotency, conversation, sessions and copies to canonical
AgentID and verified Messenger state, so the alias does not influence replay
or routing authority.

The generic AgentID-first path now creates missing device-pair sessions through
the approved asynchronous first-contact construction. With `transport: none`
it queues without sealing. With `transport: https-bootstrap` it uses the exact
signed Descriptor URL and Endpoint-signed acknowledgement described in
[`HTTPS_BOOTSTRAP_TRANSPORT.md`](HTTPS_BOOTSTRAP_TRANSPORT.md). This makes a
bounded real-network fallback available without pretending M0-R selected the
final native production route.

Daemon local API v10 retains `conversations.ensure-direct`. It
accepts the same human recipient input, runs the same finalized resolution
chain, and atomically creates or reloads a direct-conversation record keyed by
the local and remote AgentIDs. The record pins the daemon-generated
conversation ID and monotonic finalized-directory checkpoint; a later verified
Endpoint rotation may advance that evidence but cannot change either AgentID or
the conversation ID. Alias text is not persisted in the record.

This operation returns only `agent_id`, optional display-only
`canonical_name`, daemon-generated `conversation_id`, and the exact readiness
`transport-pending`. It exposes no EndpointID, DeviceID, SessionID, prekey,
Relay or route field. This is a durable first-contact discovery boundary, not a
claim that pair-session bootstrap or network transport exists.

## Production configuration

Daemon config v10 may add an authenticated Native DNS client:

```json
"contact_dns": {
  "base_url": "https://native.example.net",
  "bearer_token_file": "/etc/tos-messengerd/native-dns.token",
  "timeout_seconds": 30
}
```

DNS input requires `discovery.mode: tos-dht-https`; the resolved Agent must
also be present in the operator's verified discovery peers. Without
`contact_dns`, explicit AgentID input still uses the same directory chain and
`.tos` fails closed.

OpenFox needs only its Messenger socket and proactive-lifetime settings. It
does not configure recipient Endpoint, Device, Session or direct routes for
proactive AgentID/alias sends. Alias transfer therefore affects only a new
lookup; it cannot mutate an old AgentID-keyed conversation or session.
