# A2A and MCP local consumption boundary

`a2a.message`, `mcp.call`, and `mcp.result` are protocol inputs, not ordinary
chat text. The daemon therefore always reserves them from the general runtime
pending/claim API. This remains true when no protocol receiver is configured:
an absent consumer leaves the event pending instead of silently placing
foreign bytes in a model instruction path.

Daemon configuration v9 may name two independent owner-private Unix sockets:

- `a2a_receiver_socket` receives `POST /v1/a2a-event`;
- `mcp_receiver_socket` receives `POST /v1/mcp-event`; and
- `protocol_receiver_timeout_seconds` applies to both and defaults to 30.

The sockets must be clean absolute paths, outside `state_dir`, distinct from
each other and every runtime, owner, device, and Agent Packet socket. The HTTP
client has no proxy path, bounds its response to 4096 bytes, accepts only 202,
and sends `application/vnd.tos.messaging.event.v2+json`.

The request body is the complete canonical Event v2 JSON, not just the opaque
foreign body. A consumer must independently decode it, recompute `event_id`,
bind sender/conversation policy, parse the selected A2A or MCP version, and
apply its own execution gate. Messenger repeats strict payload decoding at the
last local boundary and fixes the carriage profiles: A2A requires protocol
`a2a`; MCP call/result require protocol `mcp`.

Delivery uses a kind-specific durable application lease. A non-202 response,
timeout, disconnect, or bounded-response failure leaves the event pending for
retry after lease expiry. A 202 completes it durably, so daemon restart does
not deliver that Event again. This is local protocol consumption only and
does not select or imply a network transport.

Local request v7 adds the reverse, result-only boundary
`outbox.compose-protocol-result`. The runtime supplies the source Event ID,
conversation, exact A2A Task or MCP Output bytes, stable idempotency key and an
already established recipient route. The daemon supplies network, sender
Agent/Endpoint/Device, clock, payload schema and Event ID. Only `a2a.message`
with protocol `a2a` or `mcp.result` with protocol `mcp`, carriage version `1`,
can be composed; `mcp.call`, text/room semantics and cross-profile substitution
are refused. Exact retry returns the same Event ID, while changed bytes under
one idempotency key fail before queueing.
