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
| `pkg/eventlog` | Single-writer durable journal: stored inbound events with pending recovery and application leases, outbound delivery state, retry schedule, and pruning |
| `pkg/fault` | Typed failures, retry dispositions, and what a peer may be told |
| `pkg/admission` | The lower half of the context firewall: authority, scope, window, inbox policy, and the durable claim |
| `pkg/e2ee` | The contract a candidate encryption suite must satisfy as a pure state transition, message bindings, and published prekey bundles |
| `pkg/e2ee/conformance` | Refutes a candidate suite: ten properties a black-box run can disprove |
| `pkg/reachability` | M0-R study records, predeclared acceptance policy, aggregation, and the route decision |
| `pkg/probe` | M0-R measurement transport: rendezvous coordinator and UDP establishment probe |
| `internal/canon` | Domain-separated length-prefixed canonical encoding shared by every signed object |
| `internal/ids` | Every identifier pattern, defined once |
| `internal/dirlock` | Exclusive process ownership of one private state directory |

The measurement side is deliberately separate from the protocol side. Nothing
in `pkg/probe` is a Messenger transport: it signs nothing, encrypts nothing,
and carries no application content. It exists to produce the evidence the
one-to-one milestone is blocked on. See [`docs/M0R_STUDY.md`](docs/M0R_STUDY.md).

Commands:

| Command | Purpose |
|---|---|
| `cmd/tos-reachability-coordinator` | Rendezvous service for a measured pair |
| `cmd/tos-reachability` | Runs one endpoint of one pair and appends a trial record |
| `cmd/tos-reachability-report` | Aggregates a study log against a predeclared policy; exits non-zero when the study supports no decision |

Deliberately absent, with the reason:

- **any cryptographic construction** — the suite is a protocol-freeze decision
  and the architecture forbids inventing one, so `pkg/e2ee` defines the contract
  a candidate must satisfy and the harness that refutes it, and stops there;
- **any transport** — direct, tunnel, Relay, and HTTPS ordering is frozen only
  after the reachability study, which is why the study tooling is here and the
  transport is not;
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
- The journal reports an event as fresh only after it is durably on disk, and
  stores the event itself, so acceptance means recoverable rather than merely
  remembered.
- Session state and the record it belongs with are committed in one ordered
  step, and the order differs by direction: inbound never loses a message,
  outbound never reuses a key.
- Evidence is judged against thresholds that were fixed before it was
  collected, and a study that misses its own minimums produces no decision.
- A conformance run can only refute. Passing every check clears a floor; it
  does not approve a construction.
- An error code returned to a stranger is an oracle, so peer visibility is a
  property of the code and everything hidden collapses into one refusal.
- A valid signature proves origin, not safety. Admission establishes who sent
  an event and whether it may enter; what the content means is the runtime's
  problem and is deliberately not decided here.
- Every domain separator is registered in one list, because a reused separator
  is signature confusion rather than a merge conflict.

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
