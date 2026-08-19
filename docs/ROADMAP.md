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

**Last re-audited against the code: 2026-08-19, at `c0e70c2`** (after room membership epochs, the group-key contract + refutation harness, room-membership enforcement at the gate, the verify- and trial-layer adversarial corpus, and the finalized-quote negative cases).

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
| M4 multi-device and private rooms | 🟡 | Device set succession, session fan-out, room membership epochs, and a group-key contract + refutation harness exist (`pkg/e2ee`, `pkg/room`, `pkg/group`, `pkg/eventlog`). Still missing: a *selected and implemented* group-key scheme (a freeze decision, like the 1:1 suite), and a room-authority model for peer-observed membership beyond single-step local succession |

## Components

| Component | Status | Evidence | What is missing |
|---|---:|---|---|
| M0-R measured reachability study and route-strategy decision | 🟡 | `pkg/reachability`, `pkg/probe` (UDP and ADNL), `cmd/tos-reachability*` | The study itself: multiple operators, multiple sites, real networks. Both collectors exist and refuse each other's names; ADNL evidence should be cross-checked against the TOS node's own adnl stack before a frozen route decision is acted on |
| Messaging Endpoint delegation schema and verifier | ✅ | `pkg/identity`, `pkg/tosaddr` | — |
| Messaging Contact Descriptor and DHT locator profile | 🟡 | `pkg/directory` | No integration test against a live TOS DHT encoder; the locator is checked against the encoding rules as read, not as run |
| One-to-one application-layer E2EE | 🟡 | `pkg/e2ee`, `pkg/e2ee/conformance` | No suite, by design: the contract and the refutation harness exist, choosing a construction is a freeze decision |
| Multi-device session and key-rotation model | 🟡 | `pkg/e2ee` (succession, sessions, fan-out), `pkg/eventlog` (durable device ledger, `AdmitPublishedSet`), `pkg/admission` | The model is durable and **enforced**: succession with rollback/revocation defences, per-pair session derivation, per-event fan-out, and the admission gate refuses a revoked device with `CodeDeviceRevoked`. Still 🟡 because the descriptor-fetch path that calls `AdmitPublishedSet` is driven only by tests — the daemon does not yet fetch peer descriptors on its own, since it has no live transport to fetch them over |
| Durable local delivery, application and read state | ✅ | `pkg/eventlog` | — |
| DeliveryAck and ApplicationAck payload codecs | ✅ | `pkg/payload` | — |
| StoredAck Relay protocol | ⬜ | — | Needs a Mailbox Relay; the governing design has the Relay issue it |
| Optional ReadAck wire profile | ⬜ | — | Local `ReadAtUnix` is UI state, not a cross-Agent wire profile |
| Encrypted offline Mailbox Relay | ⬜ | — | Nothing. It is a transport path, ordered after M0-R |
| Multi-Relay redundancy and failover | ⬜ | — | Nothing |
| Private group encryption and membership epochs | 🟡 | `pkg/room` (membership state machine), `pkg/eventlog` (durable room ledger), `pkg/group` (+ `conformance`) (group-key contract and refutation harness), `pkg/admission` (membership overlay), `room.*` payload shapes | Membership epochs are closed and end-to-end tested: the state machine advances one epoch per change, commits a domain-separated digest over the sorted member set, and the ledger enforces monotonic epoch progression (rollback and gap refused) across restart. Membership is **enforced** at the admission gate: a room-addressed event whose sender this installation does not hold as a member of that room is refused with `CodeNotARoomMember`, as an overlay that refuses only a definitive non-membership (an unknown room is admitted). The group-key layer has a **contract and a refutation harness**, exactly as `pkg/e2ee` does for the 1:1 suite: `group.Scheme` fixes how a scheme rides the room's epochs, and `group/conformance` refutes a candidate on founding agreement, epoch advance, membership binding, re-keying on removal, a joiner having no past, forged-commit refusal, and secret/view soundness — proven to pass a reference example and to catch broken doubles. **Named gap:** no scheme is *selected* (a freeze decision, like the 1:1 suite) and none is implemented; the harness checks protocol structure, not cryptographic secrecy; and the room-authority model (single-step local succession only) is still open |
| Public Agent channels over Overlay with history synchronization | ⬜ | — | Nothing |
| Messenger-specific encrypted attachment protocol | ⬜ | `artifact.*` payload shapes | References by digest only |
| OpenFox `tos-messenger` channel adapter | ⬜ | — | Nothing; needs a transport first |
| Agent Packet-to-Execution-Gate adapter and replay tests | ⬜ | — | Nothing |
| Native desktop, Web, iOS, and Android Messenger clients | ⬜ | — | Nothing |
| Relay, attachment, history, and inbox-bond commercial profiles | 🔒 | — | Expansion Gate |
| Cross-implementation positive vectors and adversarial corpus | 🟡 | `internal/vectors` (positive vectors + adversarial corpus at both layers), fuzz seeds | Positive vectors and a self-verifying adversarial corpus exist at **both** layers. The decode layer covers the JSON and binary decoders (unknown fields, trailing data, truncation, inverted windows, zeroed digests, oversized length prefixes). The verify layer covers refusals owed to claimed authority: a forged prekey-bundle signature, a bundle outliving its delegation, a bundle naming a foreign Agent, a local-only kind arriving over the network, a coordinator attestation whose signature does not verify, and a reachability trial that is either attested by a coordinator outside the policy or carries a broken endpoint signature. Each entry carries its `layer`; verify entries are proven to decode cleanly and be refused only at verify. **Named gap:** there is still no second implementation to check against — the corpus is the artifact one would be measured by, not evidence one exists |
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
| Concrete finalized-state resolver and daemon wiring | 🟡 | A concrete quote resolver exists: `pkg/chainquote` reads a finalized Accepted Quote from TOS chain state by consuming `tos-service-protocol`'s `toschain` (strict-majority finality, checkpoint, rollback) and `nativecore` (quote-cell decode), then maps the decoded proposal onto the Messenger's `Terms` and passes it through the Messenger's own `Validate`. It reimplements no chain logic. Tested end to end against a fake chain reader — locate, read finalized, confirm the account holds the asked-for commitment, decode, map, and reject a mismatch, a reader error, an undecodable cell, or a mapped quote the Messenger's rules refuse. **Named gaps:** (1) the daemon does not yet build the `toschain` adapter or inject the resolver — that needs a `chain_endpoints` config field and a live node; (2) the commitment→escrow-address+class mapping (`EscrowLocator`) is an in-memory `MapLocator`, populated by the funding flow, which does not exist yet; (3) no live-node end-to-end run. The parallel agent-state resolver now also exists: `pkg/chainagent` satisfies `identity.AgentResolver` by consuming `toschain`'s simplified native resolver, tested against a fake reader (pass-through, malformed-id refusal before any read, not-found, error propagation). Both resolvers still await daemon wiring and a live node |
| Negative-case resolver tests (wrong network/registry/account/provider/money/escrow) | 🟡 | The Messenger's half of the contract is covered against a stub resolver: a quote diverging in amount, capability, version, expiry, provider, manifest, or **escrow** is rejected; a quote in a **foreign asset at the same nominal amount** is rejected (money is asset-and-amount, not amount alone); a missing, unfinalized, or wrong-commitment quote is refused; a transient resolver **error** leaves the negotiation retryable rather than rejected. **Named gap:** the wrong-**network/registry/account** cases are state-provenance checks the resolver performs when reading the chain, not the term-matching Finalize does — they belong with the concrete resolver, which does not exist here |

## Next, in the order the architecture allows

1. **Run the study.** Both collectors exist; what is missing is evidence — ≥3
   operators, ≥3 sites per required scenario, real networks. The report tool
   refuses to bless anything less as a route decision. A single-operator dry
   run of the whole chain is scripted in
   [`M0R_PILOT_RUNBOOK.md`](M0R_PILOT_RUNBOOK.md). *(Blocked: needs external
   operators.)*
2. **The adversarial corpus.** *(Done at both the decode and verify layers,
   including the reachability trial layer. The only remaining gap is that no
   second implementation exists to check against — that is item 4's blocker,
   not a corpus gap.)*
3. **Membership epochs for rooms.** *(Done: `pkg/room` state machine +
   durable epoch ledger. Group key agreement is the remaining half of the
   rooms row and is the next codeable rooms work — item 5.)*
4. **Independent multi-operator interoperability evidence.** *(Blocked: needs a
   second implementation and the multi-operator study.)*
5. **A room authority / group key agreement design.** Membership epochs commit
   *who* is in a room, and `pkg/group` now fixes the contract a group-key scheme
   must satisfy and refutes candidates against it. What remains is a freeze-level
   decision, not more scaffolding: *selecting and implementing* a construction
   (MLS/RFC 9420 is the recorded default candidate), and settling the
   room-authority model (single-authority vs. member-consensus) that decides how
   a participant reconciles an epoch another party advanced. Both are recorded in
   [`OPEN_DECISIONS.md`](OPEN_DECISIONS.md).

Item 1 does require the study; none of these settle the genesis-hash
representation, which blocks the freeze itself.
