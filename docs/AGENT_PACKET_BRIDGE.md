# Agent Packet carriage bridge

`pkg/agentpacketbridge` carries exact signed Agent Packet V1 JSON inside the
typed `agent.packet` E2EE event. It does not reinterpret or re-sign a packet.
The bridge calls `tos-service-protocol/pkg/agentpacket` for strict decoding,
controller-signature authorization, and finalized sender/recipient resolution.

Messenger adds the invariants the protocol's direct HTTP helper cannot provide:

- the packet sender must equal the already-authenticated E2EE Event sender;
- the recipient must be this installation and finalized/live, not merely found;
- created time is bounded against future skew and maximum age;
- sender + 32-byte nonce is claimed in the single-writer journal before an
  execution adapter sees the packet;
- exact retry resumes a pending receiver attempt or becomes a no-op after
  completion; different bytes under one sender nonce are a conflict;
- replay state and pending/completed delivery survive restart, and expired
  claims are removed only after their packets have become too old to admit.

The service protocol's process-local `ReplayGuard` is instantiated only to run
its complete verifier for one call; it is never treated as durable authority.
The Messenger journal is the replay boundary. Receiver failure leaves a pending
record so durable Event redelivery can retry. If a receiver executes and the
process dies before marking completion, the receiver may see the packet again;
the Native Execution Gate and software-work journal must therefore retain their
existing transport-independent at-most-once claim.

The bridge is compatible with `tos-ai/pkg/agentpacketadapter`, which already
maps purchase-bound packet payloads into the same Native Execution Gate used by
A2A and MCP. This repository does not import `tos-ai` or duplicate that mapping.
`tos-ai` `a3c06d5` and `a9928de` add the A2A/MCP/Agent Packet execution matrix:
all three adapters race one purchase through one shared Gate, exactly one
transport succeeds, all three claims reach the Gate, and the runner executes
once. The four ordered pairs A2A→Packet, MCP→Packet, Packet→A2A and Packet→MCP
also permit only the first transport to execute.

`NewUnixReceiver` now defines the typed local handoff to an OpenFox provider.
It sends only the canonical signed Packet to a clean absolute Unix socket,
uses a proxy-free bounded HTTP client, and treats every non-`202` result as a
receiver failure so the Messenger claim remains pending. The OpenFox peer
socket is owner-private and independently runs the protocol's finalized
signature verifier before the shared Gate; neither side converts packet bytes
to model text or trusts untyped channel metadata.

Daemon config v7 retains the v6 receiver assembly without selecting a network route. A
configured daemon leases admitted `agent.packet` Events only after an atomic
kind check, invokes the receiver, and completes the Event application state
only after packet/provider completion. Receiver failure remains retryable after
lease expiry; completed packet claims close the crash window before Event
completion. The general runtime filters this kind from pending listings and is
also refused at atomic claim time, so guessing an Event ID cannot route packet
bytes into AgentLoop. Live Messenger transport and independent operation remain
blocked on M0-R and external evidence.
