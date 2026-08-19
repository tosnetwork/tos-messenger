# TOS Messenger

Implementation repository for the decentralized Agent-native Messenger described in
[`tosnetwork/tos-service-spec`](https://github.com/tosnetwork/tos-service-spec)
`docs/AGENT_NATIVE_MESSENGER_V1.md` and its conversation-and-commerce profile.

## What this is, and what it is not

This is an **incubation** implementation. It carries no TOS Service Protocol gate
status, consumes no gate capacity, and cannot be cited as acceptance evidence for
any gate. It adds no `tos_service_v1` object and no alternate authority path.

Finalized TOS state remains the sole authority for Agent identity, delegation,
Capability, Accepted Quote, escrow, Receipt, and settlement. Nothing in this
repository creates or overrides any of them. A delivery acknowledgement produced
here is never a Receipt.

## Current scope

The architecture makes the reachability study (M0-R) a prerequisite for freezing
and starting M1, so no transport is implemented and no route order is assumed.
What exists today is the part of the M0 protocol core that is independent of that
decision:

| Package | Responsibility |
|---|---|
| `pkg/identity` | Messaging Endpoint delegation: canonical bytes, digest, strict codec, and the verifier that resolves it against finalized Agent state |
| `pkg/directory` | Signed Messaging Contact Descriptor, bounded DHT locator, and the discovery half of the resolution algorithm |
| `pkg/envelope` | Outer Relay Envelope and inner typed Messaging Event, including content-addressed Event IDs |
| `pkg/eventlog` | Single-writer durable claim and delivery-state journal |
| `internal/canon` | Domain-separated length-prefixed canonical encoding shared by every signed object |
| `internal/dirlock` | Exclusive process ownership of one private state directory |

Deliberately absent, with the reason:

- **application end-to-end encryption** — the cryptographic suite is an M0 freeze
  decision, and this repository must not invent one;
- **any transport** — direct, tunnel, Relay, and HTTPS ordering is frozen only
  after the reachability study;
- **Mailbox Relay, rooms, channels, clients** — later milestones;
- **Relay lease, inbox bond, and any other commercial profile** — locked behind
  the Expansion Gate in the governing roadmap.

## Design rules the code follows

- Canonical form is always a domain-separated, length-prefixed binary preimage.
  JSON is transport only and is never hashed or signed.
- Every decoder rejects unknown fields and trailing data, and re-validates the
  decoded object.
- Identifiers bind what they name: an endpoint identifier commits its key, its
  Agent, and its network; an Event ID commits its content.
- Objects may not outlive their authority: a descriptor cannot outlive its
  delegation, a locator cannot outlive its descriptor.
- Unknown event kinds have no delegated class and are never interpreted as tool
  calls, approvals, or payments.
- The journal reports a claim as fresh only after it is durably on disk.

## Build and test

Go 1.26.5.

```sh
make verify
```

The module builds standalone. `GOWORK=off` in the Makefile keeps a developer
workspace file from silently changing which dependency versions are compiled,
which is the same reason the sibling Go repositories set it.

## Open decisions

Several values here are proposals pending the M0 freeze. They are listed in
[`docs/OPEN_DECISIONS.md`](docs/OPEN_DECISIONS.md) with the exact code that
implements each one.
