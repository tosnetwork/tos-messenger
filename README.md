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
| `pkg/directory` | Signed Messaging Contact Descriptor, DHT locator/key mapping, and the route-neutral automatic refresh chain with finalized revocation and durable device-set admission |
| `pkg/envelope` | Outer Relay Envelope and inner typed Messaging Event, including content-addressed Event IDs |
| `pkg/mailbox` | Route-neutral offline storage state machine: crash-safe opaque envelope storage, Endpoint-authorized scoped capability grants, operation/body-bound requests with durable replay claims, signed StoredAck, quotas, expiry, retrieval deletion, and independently verified multi-Relay fan-out |
| `pkg/attachments` | Route-neutral AES-256-GCM private attachment chunks, secret E2EE references, ordered ciphertext manifests, resume planning, recipient bounds, and fail-closed authentication |
| `pkg/agentpacketbridge` | Exact Agent Packet V1 carriage through E2EE with finalized protocol verification, authenticated Event-sender binding, durable nonce replay claims, and pending receiver recovery |
| `pkg/eventlog` | Single-writer durable journal: stored inbound events with pending recovery and application leases, outbound delivery state, retry schedule, and pruning |
| `pkg/fault` | Typed failures, retry dispositions, and what a peer may be told |
| `pkg/admission` | The lower half of the context firewall: authority, scope, window, inbox policy, and the durable claim |
| `pkg/firewall` | The upper half: what an Agent may reach unattended, which received content an action came from, and the channel separation that keeps a stranger's words out of the instruction position |
| `pkg/dispatch` | The outbound half: seal once, send, and apply the retry disposition of whatever came back |
| `pkg/localapi` | The owner-private socket an Agent runtime drives, and the only place an owner approval exists |
| `pkg/tosaddr` | Recomputes TOS account addresses through the protocol SDK, so finalized state must come from the account it belongs to |
| `pkg/payload` | A typed body for every event kind, in canonical binary |
| `pkg/daemon` | Assembly: one state directory, one socket, one schedule |
| `pkg/negotiation` | The layer between what an Agent says and what the system may do: mandates, exact amounts, the intent boundary, and the negotiation state machine |
| `pkg/eventlog` (mandates, budgets, negotiations) | The owner's standing authorisations, placed and withdrawn on the owner's socket and resolved from the store when a spend is judged |
| `pkg/e2ee` | The pure-state suite contract, message bindings and published prekeys, plus the approved and implemented default construction awaiting independent review and second-language evidence before wire freeze |
| `pkg/e2ee/conformance` | Refutes a candidate suite against fourteen black-box properties, including peer-prekey possession |
| `pkg/e2ee` (devices) | The multi-device model: device-set succession with rollback and revocation defences, deterministic per-pair session identifiers, and the per-event fan-out to every live device of both parties |
| `pkg/group` | TOS-MLS candidate application adapter: explicit room/MLS clocks, endpoint-authorised per-device leaf credentials, device succession planning, and the boundary for a reviewed RFC 9420 library; no home-grown MLS cryptography |
| `pkg/eventlog` (MLS) | Crash-safe opaque MLS state, commit ancestry, Welcome replay refusal, and installation-wide one-time KeyPackage consumption |
| `pkg/reachability` | M0-R study records, predeclared acceptance policy, aggregation, and the route decision |
| `pkg/probe` | M0-R measurement transport: rendezvous coordinator with cold-source filter probing, the UDP and ADNL collectors with their post-establishment phases, and the tunnel relay the proxy-fallback phase measures against |
| `pkg/evidence` | Deterministic, self-verifying M0 review bundles containing verify logs, dual-arch binaries/build logs, collector manifests, and frozen vectors |
| `pkg/conformance` | Strict signed report consumed from an external implementation that checked the exact committed vector artifacts |
| `internal/canon` | Domain-separated length-prefixed canonical encoding shared by every signed object |
| `internal/ids` | Every identifier pattern, defined once |
| `internal/vectors` | The canonical forms a second implementation checks itself against, and the adversarial corpus of inputs it must refuse |
| `internal/dirlock` | Exclusive process ownership of one private state directory |

The measurement side is deliberately separate from the protocol side. Nothing
in `pkg/probe` is a Messenger transport: it signs nothing, encrypts nothing,
and carries no application content. It exists to produce the evidence the
one-to-one milestone is blocked on. See [`docs/M0R_STUDY.md`](docs/M0R_STUDY.md).

Commands:

| Command | Purpose |
|---|---|
| `cmd/tos-reachability-coordinator` | Rendezvous service for a measured pair, and the cold sources filtering evidence is probed from |
| `cmd/tos-reachability` | Runs one endpoint of one pair and appends a trial record |
| `cmd/tos-reachability-tunnel` | Double-registration UDP forwarder for the study's proxy-fallback phase; measurement infrastructure, never the Relay milestone |
| `cmd/tos-reachability-report` | Aggregates a study log against a predeclared policy; exits non-zero when the study supports no decision |
| `cmd/tos-messengerd` | Runs one installation. See [`docs/RUNNING.md`](docs/RUNNING.md) |
| `cmd/tos-m0-evidence` | Packs and independently verifies the bounded M0 evidence archive |
| `cmd/tos-vector-report` | Verifies a signed external vector-consumer report against the committed artifacts |

Deliberately absent, with the reason:

- **a frozen cryptographic wire suite** — the construction is approved and its
  vectors exist, but independent cryptographic review and second-language
  consumption are still required by [`docs/E2EE_SUITE_DECISION.md`](docs/E2EE_SUITE_DECISION.md);
- **any transport** — direct, tunnel, Relay, and HTTPS ordering is frozen only
  after the reachability study, which is why the study tooling is here and the
  transport is not;
- **a network-bound Mailbox Relay service, rooms, channels, clients** — the
  route-neutral Mailbox store, scoped authentication core, and redundancy
  contract exist, while the finalized-state adapter, listener, and transport
  binding remain;
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
  outbound never reuses a key. An inbound event is not visible to a runtime
  until the session has recorded that its ciphertext was opened, and a process
  that died between the two finishes the job itself on restart rather than
  waiting for the sender to try again.
- Sealing is bound to the attempt that holds the delivery. Leases expire so
  that work can be recovered from a worker that died; an attempt that lost its
  delivery must not still be able to spend a message key for it.
- A retry sends the message that was already sealed. Sealing per attempt would
  spend a message key on every lost packet.
- An installation with no transport queues durably and says so. It does not
  seal for a route that does not exist, and it does not read as one that is
  delivering.
- Natural language communicates meaning and moves nothing. Agreeing in
  conversation is not a Quote, a Quote is not funded escrow, and the only
  signal that means value can move is a commitment read back out of finalized
  state. A well-formed digest is not one.
- An asset is a contract, not a ticker, and an amount is an arbitrary-precision
  count of atomic units. Two contracts may both call themselves USDT, and no
  fixed-width integer holds eighteen decimals of an ordinary token.
- An owner's approval names what it approved: the terms digest, the version of
  the negotiation, and the mandate it was given under. Terms freeze once both
  parties agree, and bargaining on takes an explicit reopening that drops the
  approval and the budget hold.
- Where a structured amount and its rendering disagree, both are shown and
  neither is chosen. Letting a model pick would make the text authoritative
  through a side door.
- Evidence is judged against thresholds that were fixed before it was
  collected, and a study that misses its own minimums produces no decision.
- A conformance run can only refute. Passing every check clears a floor; it
  does not approve a construction.
- An error code returned to a stranger is an oracle, so peer visibility is a
  property of the code and everything hidden collapses into one refusal.
- A valid signature proves origin, not safety. Admission establishes who sent
  an event and whether it may enter; what the content means is the runtime's
  problem and is deliberately not decided here.
- Approval is two things. A counterparty attestation is what the other party
  says it decided, which is information and may travel. An owner approval is
  authority granted here, and it is not expressible on the wire at all: it
  exists on the owner's own socket and nowhere else.
- Stored, delivery, application, and optional read acknowledgements are
  different facts. None is a TOS Receipt, settlement authority, or evidence
  that a user read an event unless it is specifically a `ReadAck`.
- The party that asks for an approval cannot grant it. The runtime and the
  owner speak over separate sockets, the runtime's has no approval operation on
  it, and every decision carries the owner's signature over a single-use
  challenge. Separate sockets alone would not be a boundary: peer credentials
  say which Unix user is calling, and the runtime usually is that user.
- A mandate is the owner's. It is placed on the owner's socket, resolved from
  the store when a spend is judged, and only named by the runtime: a runtime
  that could supply the mandate it is measured against would be setting its own
  ceiling, which is the one thing a mandate exists to prevent.
- An approval names a deed, not a request. The identifier of a proposed action
  is derived from what the action is and what it came from, so a permission
  cannot be moved to a different action, and it is spent the first time it is
  used. Tool calls also require a runtime-supplied `idem_` key: the key is
  durably bound to its first Action ID before a grant exists, so retry is
  idempotent and re-describing one invocation cannot mint another grant.
- Defence against instructions hidden in content is structural, not detective.
  There are no patterns for recognising manipulation, because a filter that
  tries to recognise an attack fails open on the ones it has not seen while
  manufacturing confidence about the rest. What the code enforces instead is
  that provenance cannot be dropped and that received content cannot reach a
  key, a payment, or this installation's own configuration without a person.
- A commitment nobody reads is worse than none, because it implies an
  enforcement that does not exist. The policy digests a delegation carries are
  checked against the documents they name, and an inbox policy is built from
  the document it publishes rather than being asked what its own digest is.
- A queue only a person can drain is bounded, in count, per sender, in bytes
  and in age. A sender who fills it is refused rather than silently dropped,
  and a question nobody answered is recorded as refused rather than kept
  forever.
- Finalized state is re-verified where it is used: which network it came from,
  that it is final, which registry produced it, and that it describes the Agent
  that was asked about.
- A funded quote's local lookup is durable provenance, not configuration: the
  journal binds one quote commitment to its escrow address and capability class
  once, refuses redirects, and supplies that binding to the finalized Quote
  resolver after restart. Only the future funding path may create it.
- Every domain separator is registered in one list, because a reused separator
  is signature confusion rather than a merge conflict.

## Build and test

Go 1.26.5.

```sh
make verify
```

The manual release evidence runs the same checks plus a cross-architecture
build, the fuzz seed corpora, and a check that the committed vectors are
unchanged. Hosted CI and branch protection enforcing those checks before merge
are deferred by owner decision — not in place, and recorded here rather than
left silent; the compensating control is a manually reproduced evidence bundle
for the freeze (verify logs, binary hashes, and collector manifests on amd64
and arm64).
Vectors are rewritten deliberately:

```sh
go test ./internal/vectors -update
go test ./pkg/e2ee -run TestDefaultSuiteInteroperabilityVectors -update-suite-vectors
```

The module builds standalone. `GOWORK=off` in the Makefile keeps a developer
workspace file from silently changing which dependency versions are compiled,
which is the same reason the sibling Go repositories set it.

## Where this has got to

[`docs/ROADMAP.md`](docs/ROADMAP.md) tracks every component in the governing
architecture against the code that implements it, with the commit that carries
each one. It is deliberately conservative: a component counts as done only when
the behaviour it names is implemented and tested, and anything partial is
listed with the gap named.

## Open decisions

Several values here are proposals pending the M0 freeze. They are listed in
[`docs/OPEN_DECISIONS.md`](docs/OPEN_DECISIONS.md) with the exact code that
implements each one.
