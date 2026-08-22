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
  -> tos_messenger contacts.resolve over owner-private runtime socket
  -> daemon ResolveContact / finalized directory chain
  -> canonical AgentID
  -> operator route selected by RecipientAgentID
  -> durable idempotency key derived with canonical AgentID (never alias)
  -> outbox.compose with canonical RecipientAgentID assertion
  -> daemon re-resolves that AgentID and checks the selected Endpoint
  -> E2EE binding rechecks AgentID/Endpoint/conversation when transport exists
  -> existing durable AgentID/session/endpoint delivery journal
```

`CanonicalName` is returned only for optional display and OpenFox does not pass
it to compose. The model cannot submit conversation, EndpointID, DeviceID,
SessionID, relay, ADNL or route fields. Routes remain explicit operator state
and proactive routes store only canonical `recipient_agent_id`. AgentLoop emits
an opaque runtime delivery-intent ID; after resolution, the Messenger adapter
combines it with canonical AgentID and message content to derive the durable
idempotency key, so the alias does not influence replay authority.

The path deliberately reuses an already established direct route/session. It
does not invent session bootstrap or a transport before M0-R selects one.
Consequently it can queue through `transport: none`, but real network delivery
still requires the post-M0-R production transport.

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

OpenFox direct routes that permit proactive addressing add:

```json
"recipient_agent_id": "agent_<64 lowercase hex>"
```

The route's endpoint is checked again by the daemon against the current
verified descriptor before composition. Alias transfer therefore selects a
different route only on a new lookup; it cannot mutate the old conversation or
session.
