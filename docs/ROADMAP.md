# Implementation status

This is the implementation side of the component list in `tosnetwork/tos-service-spec`
`docs/AGENT_NATIVE_MESSENGER_V1.md`. The architecture document is the roadmap; this
file records how far the code has got against it, with the package and the commit
that carries each item.

Status is deliberately conservative. A component is ✅ only when the behaviour it
names is implemented **and** tested; anything with a stated gap is 🟡 with the gap
named, because a table that rounds partial work up hides exactly the parts somebody
would need to finish. Nothing in this file changes gate status: this repository
carries none and consumes no gate capacity.

**Last re-audited against the code: 2026-08-19, at `2d99045`.**

## Milestone gates

| Gate | Status | Where it stands |
|---|---:|---|
| M0 protocol core, route-independent parts | ✅ | Identity, discovery, envelope, journal, admission, dispatch, local API, negotiation, payload typing, context firewall. Frozen values are still proposals: see [`OPEN_DECISIONS.md`](OPEN_DECISIONS.md) |
| M0 protocol freeze | ⬜ | Not declared, and not ready. Five open prerequisites, with evidence, in [`M0_FREEZE_REVIEW.md`](M0_FREEZE_REVIEW.md) |
| M0-R reachability study | 🟡 | Tooling complete, tested, and corrected after review; **no study has been run**, so no route decision exists |
| M1 one-to-one transport | ⬜ | Blocked on M0-R by the architecture, not merely for acceptance |
| M2-T rooms and threads | ⬜ | Event kinds exist; no membership state machine, no group encryption |
| M2-C conversation and commerce | 🟡 | Negotiation, mandates, budgets and the firewall exist and are durable, and a commitment is read back out of finalized state. No transport to carry any of it, and no wallet is attached |

## Components

| Component | Status | Evidence | What is missing |
|---|---:|---|---|
| M0-R measured reachability study and route-strategy decision | 🟡 | `pkg/reachability`, `pkg/probe`, `cmd/tos-reachability*` — `e4e802f`, `84f1539`, `07ac2f4`, `e815646`, `2c87808` | The study itself. The cell model now expresses asymmetric pairs and attestations name a party, so the tooling can record what a real measurement looks like; no evidence has been collected |
| Messaging Endpoint delegation schema and verifier | ✅ | `pkg/identity`, `pkg/tosaddr` — `a77e091`, `ee8e9cc`, `98324f3` | — |
| Messaging Contact Descriptor and DHT locator profile | 🟡 | `pkg/directory` — `a77e091`, `045b205` | No integration test against a live TOS DHT encoder; the locator is checked against the encoding rules as read, not as run |
| One-to-one application-layer E2EE | 🟡 | `pkg/e2ee`, `pkg/e2ee/conformance` — `fa160e5`, `34ab541` | No suite. The architecture forbids inventing one, so this repository defines the contract a candidate must satisfy and the harness that refutes it, and stops |
| Multi-device session and key-rotation model | 🟡 | `pkg/e2ee` prekey bundle sets — `fa160e5` | Devices can publish and be bound to a descriptor. There is no per-device session fan-out and no rotation model — the largest gap in the parts otherwise settled |
| Single-writer durable conversation store and replay journal | ✅ | `pkg/eventlog`, `internal/dirlock` — `a77e091`, `d9b4798`, `fe724e1`, `ea3ba8c` | — |
| Delivery, storage, application, and optional read acknowledgements | ✅ | `pkg/eventlog`, `pkg/payload` — `d9b4798`, `ffcd4a6`, `ea3ba8c` | — |
| Encrypted offline Mailbox Relay | ⬜ | a relay set can be published in a descriptor (`pkg/directory`) | No relay. It is a transport path, and its ordering is frozen after M0-R |
| Multi-Relay redundancy and failover | ⬜ | — | Nothing |
| Private group encryption and membership epochs | ⬜ | `room.*` event kinds in `pkg/payload` — `ffcd4a6` | Only the message shapes. No membership state machine, no group key agreement |
| Public Agent channels over Overlay with history synchronization | ⬜ | — | Nothing |
| Messenger-specific encrypted attachment protocol | ⬜ | `artifact.*` event kinds in `pkg/payload` — `ffcd4a6` | Only references by digest. No attachment format, encryption policy, retention, or collection |
| OpenFox `tos-messenger` channel adapter | ⬜ | — | Nothing here. It needs a transport first |
| Agent message policy engine and prompt-injection firewall | ✅ | `pkg/firewall`, approvals and mandates in `pkg/eventlog`, `pkg/localapi` — `ff15cb2`, `550ab37`, `79fdbf6`, `95f6a61` | — Its limits are stated rather than closed: it governs proposals to act, not what a model concludes from what it reads, and the owner key's custody is a deployment property the daemon cannot check |
| First-contact admission policy and sybil resistance | 🟡 | `pkg/admission` — `5693cab`, `657d104`, `95f6a61` | The policy mechanism is complete, closed, bound to what the endpoint published, and bounded in what may wait. What an unknown sender must *present* — a bond, an invite, nothing — is a freeze decision, and the economic profile is roadmap-locked |
| Agent Packet-to-Execution-Gate adapter and three-transport replay tests | ⬜ | — | Nothing |
| Native desktop, Web, iOS, and Android Messenger clients | ⬜ | — | Nothing |
| Relay, attachment, history, and inbox-bond commercial profiles | 🔒 | — | Locked behind the Expansion Gate in the governing roadmap |
| Cross-implementation positive vectors and adversarial corpus | 🟡 | `internal/vectors`, fuzz seeds in `pkg/{identity,directory,envelope,fault,probe}` — `3120420`, `2c87808` | Positive vectors and fuzz corpora exist, and the corpus no longer freezes an event the protocol would refuse. There is still **no adversarial corpus**: no curated set of inputs a second implementation must refuse |
| Independent multi-operator interoperability evidence | ⬜ | — | Nothing. It needs a second implementation |

## What this repository added beyond the component list

Each of these closed a finding rather than filling a gap in the list.

| Piece | Status | Why it is here |
|---|---:|---|
| Typed payload codecs for every event kind | ✅ `pkg/payload` — `ffcd4a6` | The kind and the schema named a contract nothing parsed, so the body was arbitrary bytes |
| Account-address binding through the protocol SDK | ✅ `pkg/tosaddr` — `98324f3` | A resolver could return a genuine Agent record read from an account of its own choosing |
| Owner authentication on the decision path | ✅ `pkg/localapi` — `79fdbf6` | Two sockets under one Unix user are not a boundary; the runtime could grant its own approval |
| Inbound crypto transaction and send-attempt binding | ✅ `pkg/eventlog` — `ea3ba8c` | An event reached a runtime before the ratchet recorded it, and an expired attempt could still spend a message key |
| Chain-native money and complete terms | ✅ `pkg/negotiation` — `6f77368` | A ticker is not an asset identity, and terms that name only a price hide a change of provider or escrow |
| Owner-side mandate custody, durable budgets and negotiations | ✅ `pkg/eventlog`, `pkg/negotiation` — `550ab37`, `6f77368`, `f84a02c` | A runtime supplying its own mandate sets its own ceiling; state that dies on restart leaves money spoken for by an exchange nobody can find |
| Bounded queues for anything awaiting a person | ✅ `pkg/eventlog` — `95f6a61` | A delegated sender inside its own scope could fill the owner's queue and the disk behind it |
| Daemon assembly, two sockets, one schedule | ✅ `pkg/daemon`, `cmd/tos-messengerd` — `9d6d949` | An installation that runs and states what it cannot do |

## Next, in the order the architecture allows

1. **Run the M0-R study.** It is the only item whose completion unblocks another
   milestone, and the tooling to collect the evidence is finished and corrected.
2. **Multi-device sessions and key rotation.** An M0 decision, independent of
   transport, and the largest remaining gap in the frozen-in-shape parts.
3. **The adversarial corpus.** A second implementation cannot check itself against
   "these inputs are valid" alone; it needs the set it must refuse.
4. **Membership epochs for rooms.** The message shapes exist; the state machine does
   not, and it does not need a transport to be written.

Items 2 to 4 do not require the study. Item 1 does not require them. None of the
four is a substitute for settling the genesis-hash representation, which
[`M0_FREEZE_REVIEW.md`](M0_FREEZE_REVIEW.md) records as the prerequisite that
blocks the freeze itself.
