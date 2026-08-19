# Implementation status

This is the implementation side of the component list in `tosnetwork/tos-service-spec`
`docs/AGENT_NATIVE_MESSENGER_V1.md`. The architecture document is the roadmap; this
file records how far the code has got against it, with the package and the commit
that carries each item. Milestone names and numbering are the governing document's
and are not redefined here.

Status is deliberately conservative. A row is ✅ only when the behaviour it names is
implemented **and** tested end to end; a package that exists but whose behaviour is
not yet closed end to end is 🟡 with the gap named. Nothing in this file changes
gate status: this repository carries none and consumes no gate capacity.

**Last re-audited against the code: 2026-08-19.**

## Milestones (governing numbering)

| Gate | Status | Where it stands |
|---|---:|---|
| Implemented route-independent M0 primitives (non-gate) | ✅ | Identity, envelope, journal, admission, payload codecs, action policy, authenticated owner decision path, negotiation foundations. This row is not the M0 gate: the gate's acceptance also requires a reviewed suite, an adversarial corpus and a second implementation, none of which exist |
| M0 protocol freeze | ⬜ | Four items block the freeze directly (genesis-hash representation, suite selection, multi-device model, second-implementation evidence); see [`M0_FREEZE_REVIEW.md`](M0_FREEZE_REVIEW.md) |
| M0-R reachability and route decision | 🟡 | **M0-R1 UDP feasibility collector: ✅. M0-R2 ADNL route-decision collector: ✅** (`pkg/probe.RunADNL`, `tos-reachability -probe adnl`; one session by construction, done-signalling via the coordinator, end-to-end tested through trial verification). The report tool exits non-zero for any study that supports no route decision. **No study of either kind has been run** |
| M1 one-to-one transport | ⬜ | Blocked on an ADNL M0-R decision and a selected E2EE suite |
| M2-T technical offline Mailbox and multi-Relay failover | ⬜ | No Relay implementation. A descriptor can publish a relay set, which is a declaration, not a service |
| M2-C commercial Relay lease | 🔒 | Expansion Gate locked |
| M3 OpenFox and conversation-to-commerce integration | 🟡 | Foundations only: typed commerce, mandates, budgets, durable negotiations and the verification contract exist. No transport, no concrete finalized-state resolver wired, no wallet, no execution integration |
| M4 multi-device and private rooms | 🟡 | Foundations only: prekey publication and room event shapes exist. No session fan-out, no rotation model, no membership epochs, no group encryption |

## Components

| Component | Status | Evidence | What is missing |
|---|---:|---|---|
| M0-R measured reachability study and route-strategy decision | 🟡 | `pkg/reachability`, `pkg/probe` (UDP and ADNL), `cmd/tos-reachability*` | The study itself: multiple operators, multiple sites, real networks. Both collectors exist and refuse each other's names; ADNL evidence should be cross-checked against the TOS node's own adnl stack before a frozen route decision is acted on |
| Messaging Endpoint delegation schema and verifier | ✅ | `pkg/identity`, `pkg/tosaddr` | — |
| Messaging Contact Descriptor and DHT locator profile | 🟡 | `pkg/directory` | No integration test against a live TOS DHT encoder; the locator is checked against the encoding rules as read, not as run |
| One-to-one application-layer E2EE | 🟡 | `pkg/e2ee`, `pkg/e2ee/conformance` | No suite, by design: the contract and the refutation harness exist, choosing a construction is a freeze decision |
| Multi-device session and key-rotation model | 🟡 | `pkg/e2ee` prekey bundle sets | No per-device session fan-out and no rotation model. Publishing bundles is not a session model |
| Durable local delivery, application and read state | ✅ | `pkg/eventlog` | — |
| DeliveryAck and ApplicationAck payload codecs | ✅ | `pkg/payload` | — |
| StoredAck Relay protocol | ⬜ | — | Needs a Mailbox Relay; the governing design has the Relay issue it |
| Optional ReadAck wire profile | ⬜ | — | Local `ReadAtUnix` is UI state, not a cross-Agent wire profile |
| Encrypted offline Mailbox Relay | ⬜ | — | Nothing. It is a transport path, ordered after M0-R |
| Multi-Relay redundancy and failover | ⬜ | — | Nothing |
| Private group encryption and membership epochs | ⬜ | `room.*` payload shapes | No membership state machine, no group key agreement |
| Public Agent channels over Overlay with history synchronization | ⬜ | — | Nothing |
| Messenger-specific encrypted attachment protocol | ⬜ | `artifact.*` payload shapes | References by digest only |
| OpenFox `tos-messenger` channel adapter | ⬜ | — | Nothing; needs a transport first |
| Agent Packet-to-Execution-Gate adapter and replay tests | ⬜ | — | Nothing |
| Native desktop, Web, iOS, and Android Messenger clients | ⬜ | — | Nothing |
| Relay, attachment, history, and inbox-bond commercial profiles | 🔒 | — | Expansion Gate |
| Cross-implementation positive vectors and adversarial corpus | 🟡 | `internal/vectors`, fuzz seeds | Positive vectors are sound; there is still no adversarial corpus — no curated set a second implementation must refuse |
| Independent multi-operator interoperability evidence | ⬜ | — | Needs a second implementation |

## The policy engine, split honestly

"Agent message policy engine and prompt-injection firewall" is not one row,
because parts of it are closed and parts cannot be closed from inside this
repository, and one ✅ or one 🟡 would misstate both halves.

| Piece | Status | Note |
|---|---:|---|
| Action policy evaluator (effects, ceilings, provenance typing) | ✅ | `pkg/firewall` |
| Authenticated owner decision queue (challenge + signature, bounded, expiring) | ✅ | `pkg/localapi`, `pkg/eventlog` |
| One-shot side-effect authorization | 🟡 | Owner-granted actions and policy-allowed **spends** are spent once. Generic tool calls are still authorised inline: without a runtime-supplied idempotency key, two legitimate identical calls cannot be told apart from a replay |
| OpenFox provenance enforcement | ⬜ | `DerivedFrom` is the runtime's own claim. Until a trusted runtime wrapper binds model context to action provenance, a compromised runtime can under-report and be judged at the looser ceiling |
| Wallet/tool adapter enforcement | ⬜ | Nothing executes through the firewall yet; there is no wallet and no tool adapter |

## Commerce, split honestly

| Piece | Status | Note |
|---|---:|---|
| Chain-native money, complete terms, mandate and approval binding | ✅ | `pkg/negotiation` |
| Durable mandates, budgets, negotiations | ✅ | Every transition persists; crash windows between the budget ledger and a negotiation snapshot reconcile deterministically at journal open |
| Finalized-quote verification contract and term matching | ✅ | `negotiation.QuoteResolver`, `VerifiedAcceptedQuote` |
| Concrete finalized-state resolver and daemon wiring | ⬜ | The resolver is an interface; nothing reads real chain state, and the daemon wires none. Until it exists, `Committed()` is only as strong as the resolver a caller supplies |
| Negative-case resolver tests (wrong network/registry/account/provider/money/escrow) | ⬜ | Belong with the concrete resolver |

## Next, in the order the architecture allows

1. **Run the study.** Both collectors exist; what is missing is evidence — ≥3
   operators, ≥3 sites per required scenario, real networks. The report tool
   refuses to bless anything less as a route decision.
2. **Multi-device sessions and key rotation** — M0 decision, transport-independent.
3. **The adversarial corpus.**
4. **Membership epochs for rooms.**

Items 2–4 do not require the study; none of the four settles the genesis-hash
representation, which blocks the freeze itself.
