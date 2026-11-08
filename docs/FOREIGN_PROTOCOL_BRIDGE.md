# A2A and MCP local consumption boundary

`a2a.message`, `mcp.call`, and `mcp.result` are protocol inputs, not ordinary
chat text. The daemon therefore always reserves them from the general runtime
pending/claim API. This remains true when no protocol receiver is configured:
an absent consumer leaves the event pending instead of silently placing
foreign bytes in a model instruction path.

The local A2A and MCP receiver sockets (`a2a_receiver_socket`,
`mcp_receiver_socket`, `protocol_receiver_timeout_seconds`) were removed with
the escrow-gated execution adapters that consumed them. There is no local
consumer: these events stay pending and reserved, and a configuration that
still names a receiver socket is refused as unknown fields.

Local request v7 adds the reverse, result-only boundary
`outbox.compose-protocol-result`. The runtime supplies the source Event ID,
conversation, exact A2A Task or MCP Output bytes, stable idempotency key and an
already established recipient route. The daemon supplies network, sender
Agent/Endpoint/Device, clock, payload schema and Event ID. Only `a2a.message`
with protocol `a2a` or `mcp.result` with protocol `mcp`, carriage version `1`,
can be composed; `mcp.call`, text/room semantics and cross-profile substitution
are refused. Exact retry returns the same Event ID, while changed bytes under
one idempotency key fail before queueing.
