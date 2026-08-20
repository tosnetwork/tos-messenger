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

**Last re-audited against the code: 2026-08-19, at `c0e70c2`** (after room membership epochs, the group-key contract + refutation harness, room-membership enforcement at the gate, the verify- and trial-layer adversarial corpus, and the finalized-quote negative cases). The M0-R and commerce rows were re-checked 2026-08-20 at `423bee7`, after the post-establishment measurement phases, the tunnel fallback, the filtering evidence, and the network-committed commerce digests. The private-room construction choice was closed on 2026-08-20: **MLS 1.0 (RFC 9420 / TreeKEM)**. The TOS-MLS v1 adaptation below is a selected profile candidate, not a frozen wire profile; implementation, canonical vectors, independent review, and second-implementation evidence remain open.

## Milestones (governing numbering)

| Gate | Status | Where it stands |
|---|---:|---|
| Implemented route-independent M0 primitives (non-gate) | ✅ | Identity, envelope, journal, admission, payload codecs, action policy, authenticated owner decision path, negotiation foundations. This row is not the M0 gate: the adversarial corpus and a default E2EE candidate exist, but the suite still needs owner ratification and independent review, and no second implementation has consumed the vectors |
| M0 protocol freeze | ⬜ | Three items block the freeze directly (genesis-hash representation, suite ratification/review, second-implementation evidence); see [`M0_FREEZE_REVIEW.md`](M0_FREEZE_REVIEW.md). CI branch protection enforcing `verify` before merge is deferred by owner decision — not done, recorded here rather than left silent. The compensating bundle automation is implemented in `pkg/evidence`, `cmd/tos-m0-evidence`, and `scripts/assemble-m0-evidence.sh`: it runs verify, cross-builds amd64/arm64, hashes binaries, and packages collector manifests plus vectors; a clean, reviewed run is still required for each candidate freeze commit |
| M0-R reachability and route decision | 🟡 | **Both collectors are working prototypes; the study itself has not been run.** UDP direct-feasibility collector (`pkg/probe.Run`): 🟡 — measures a datagram path; the NAT mapping class is derived from coordinator-signed bind reflections and a contradicting declaration is refused at verification (`reachability.VerifyTrial`), but the bind test separates only endpoint-independent from destination-dependent mappings, so the finer `address-dependent` and `symmetric` flavours stand as declarations the evidence cannot refute rather than measured classes, and a `none` declaration is never remotely credited. Filtering is measured as its own axis from coordinator-signed cold-source receipts (a second port by default, a second address when configured), which can only loosen the class — the strict class is never derived remotely. ADNL direct-establishment collector (`pkg/probe.RunADNL`): 🟡 — one session by construction, done-signalling via the coordinator, dual-family (IPv4 and IPv6) binding, and it measures past establishment: a hold window with keepalives records session survival (a pair counts only when both halves measured it), the initiator can deliberately drop and time a reconnect, and a configured tunnel relay (`cmd/tos-reachability-tunnel`) gives a failed direct phase a proxy-fallback collection path, so the report's `tunnel-first` branch is reachable from collected evidence. The session phases are decisive, not merely surfaced: the v2 policy predeclares survival and reconnect gates (`min_direct_survival_rate`, `min_tunnel_survival_rate`, `min_reconnect_success_rate`, each with an attempted-sample floor), `direct-first` requires them in every required cell (the reconnect gate in cells exercising a mobility event), `tunnel-first` requires the tunnel-survival gate, and an under-sampled load-bearing gate yields `insufficient-evidence` naming the gate. Still missing: Wi-Fi↔mobile and the other mobility events; reliable-transfer measurement (every phase is ping-based — planned as a bounded ADNL echo-query cross-check first, with RLDP acceptance at the transport milestone); and it rides `tosutils-go`'s ADNL rather than the TOS node's own stack. **Strata: family, reachability, and NAT mapping are cross-checked against coordinator-signed evidence at verify- and pair-time; filtering is evidence-only with no declared counterpart; carrier, UDP policy, mobility, endpoint class, and assistance remain self-declared, being unobservable remotely.** The report tool exits non-zero for any study that supports no route decision (`exitCode`, tested), and each cell now surfaces the filtering class derived from each half's receipts as per-side counts (`CellReport.Filtering`) — evidence for the reader, deliberately feeding no threshold: making it decision-relevant would require a new predeclared, content-addressed policy field. **No study of either kind has been run.** Mobility and reliable-transfer measurement ⬜, TOS-native cross-check ⬜, finer mapping flavours measured rather than declared ⬜, the study itself ⬜ |
| M1 one-to-one transport | ⬜ | Blocked on an ADNL M0-R decision and a selected E2EE suite |
| M2-T technical offline Mailbox and multi-Relay failover | 🟡 | `pkg/mailbox` implements the route-neutral durable store, signed StoredAck, quotas/retention, exact retrieval deletion, and independently verified multi-Relay fan-out. A descriptor can publish a relay set. Network listener, mailbox retrieval authentication, transport binding, live failover, and operator evidence remain open |
| M2-C commercial Relay lease | 🔒 | Expansion Gate locked |
| M3 OpenFox and conversation-to-commerce integration | 🟡 | Foundations only: typed commerce, mandates, budgets, durable negotiations, the verification contract, concrete finalized quote reads, and a crash-safe escrow-location ledger exist. The daemon verifies its own endpoint delegation, but no funding/wallet path populates the locator and the quote resolver is not injected into an execution path. No transport or execution integration |
| M4 multi-device and private rooms | 🟡 | Device succession/fan-out, room epochs, and the TOS-MLS application adapter exist (`pkg/e2ee`, `pkg/room`, `pkg/group`, `pkg/eventlog`). The adapter implements separate room/MLS clocks, endpoint-signed per-device leaf/KeyPackage authority with candidate vectors, succession → leaf operations, and durable KeyPackage/Welcome/commit/state recovery. **Still missing:** a reviewed RFC 9420 `group.Driver`, BasicCredential/group-id freeze after the genesis decision, cryptographic MLS vectors, independent review/second implementation, real Relay catch-up, and the room-authority / authorised-committer rule |

## Components

| Component | Status | Evidence | What is missing |
|---|---:|---|---|
| M0-R measured reachability study and route-strategy decision | 🟡 | `pkg/reachability`, `pkg/probe` (UDP, ADNL, filtering, tunnel relay), `cmd/tos-reachability*` | Tooling gaps (the M0-R milestone row has the specifics): mobility events and reliable transfer are unmeasured (the phases are ping-based; reliable transfer is planned as a bounded ADNL echo-query cross-check first, RLDP acceptance at the transport milestone); the finer NAT-mapping flavours are declarations the evidence cannot refute, not measured classes; the derived filtering class is surfaced per cell as evidence and deliberately feeds no threshold (session survival, reconnect success, and tunnel survival, by contrast, are decisive: predeclared v2-policy gates the route decision reads); the ADNL collector rides `tosutils-go` rather than the TOS node's own ADNL. Beyond the tooling, the study itself — multiple operators, multiple sites, real networks — has not been run |
| Messaging Endpoint delegation schema and verifier | ✅ | `pkg/identity`, `pkg/tosaddr` | — |
| Messaging Contact Descriptor and DHT locator profile | 🟡 | `pkg/directory` | The automatic route-neutral chain now re-resolves finalized delegation, locator, descriptor, and prekeys; refresh deadlines, invalidation, revocation, and durable device succession are tested through interfaces/fakes. No production DHT/descriptor adapters or live TOS DHT encoder test exist |
| One-to-one application-layer E2EE | 🟡 | `pkg/e2ee`, `pkg/e2ee/conformance`, [`E2EE_SUITE_DECISION.md`](E2EE_SUITE_DECISION.md) | The recommended X3DH-shaped X25519 + HKDF-SHA-256 + AES-256-GCM Double Ratchet candidate is implemented, clears the fourteen-property harness, and has committed positive and adversarial wire vectors cross-checked against published primitive vectors. Still partial: owner ratification and independent cryptographic review/second-implementation consumption are freeze gates, so the identifier is not frozen |
| Multi-device session and key-rotation model | 🟡 | `pkg/e2ee` (succession, sessions, fan-out), `pkg/eventlog` (durable device ledger, `AdmitPublishedSet`), `pkg/directory` (refresh manager), `pkg/admission` | The model is durable and **enforced**: succession with rollback/revocation defences, per-pair session derivation, per-event fan-out, and the admission gate refuses a revoked device with `CodeDeviceRevoked`. The route-neutral refresh manager now drives the full verified descriptor/prekey path and rechecks finalized revocation. Still 🟡 because production DHT/descriptor adapters and daemon wiring require the post-M0-R network path |
| Durable local delivery, application and read state | ✅ | `pkg/eventlog` | — |
| DeliveryAck and ApplicationAck payload codecs | ✅ | `pkg/payload` | — |
| StoredAck Relay protocol | ✅ | `pkg/mailbox`, `internal/vectors` | Strict signed codec, canonical vector, adversarial decode corpus, durable issuance, and tamper tests |
| Optional ReadAck wire profile | ✅ | `pkg/payload.ReadAck`, `read.ack` | Strict optional codec names the exact Event ID and user-facing read time; it remains distinct from delivery, application acceptance, authority, and TOS Receipt semantics |
| Encrypted offline Mailbox Relay | 🟡 | `pkg/mailbox` | Route-neutral crash-safe opaque storage, dedupe/conflict detection, retention, quotas, list/delete and recovery tests exist; retrieval authentication, listener, and transport binding remain after M0-R |
| Multi-Relay redundancy and failover | 🟡 | `pkg/mailbox.StoreRedundant` | Distinct pinned Relay identities and exact signed ACKs are required to meet a redundancy threshold; live independently operated Relay failover evidence is missing |
| Private group encryption and membership epochs | 🟡 | `pkg/room` (membership), `pkg/group` (refutation floor + TOS-MLS application adapter), `pkg/eventlog` (room and opaque MLS ledgers), `pkg/admission` (membership overlay), `room.*` payload shapes | Logical membership is enforced and durable. The candidate adapter now has two clocks; strict endpoint-signed device/leaf/KeyPackage authority; deterministic device succession → Add/Remove/Update; and crash-safe opaque state, globally consumed KeyPackages, Welcome receipts and single-parent commit ancestry. These are application invariants, **not MLS cryptography**. **Named gaps:** reviewed RFC 9420 Driver; BasicCredential/group-id freeze; cryptographic conformance/PCS vectors; authenticated real Relay delivery and catch-up; independent review/implementation; authorised commit serialization and room authority |
| Public Agent channels over Overlay with history synchronization | ⬜ | — | Nothing |
| Messenger-specific encrypted attachment protocol | 🟡 | `pkg/attachments`, `artifact.encrypted`, [`ENCRYPTED_ATTACHMENTS.md`](ENCRYPTED_ATTACHMENTS.md) | Route-neutral AES-256-GCM chunks, secret E2EE Reference, ordered content addresses, strict Event binding, expiry/resume policy, vectors, and a private crash-safe local ciphertext store now exist. The store enforces count/byte/retention quotas, exact dedupe, restart recovery, hash-checked fetch, lease deletion and fail-closed unreferenced/expired GC without persisting keys or plaintext metadata. Still missing: authenticated storage transport, locator SSRF policy, **remote** deletion/retention guarantees, sandbox/scanner integration and live interrupted-transfer evidence; commercial storage remains Expansion-Gate locked |
| OpenFox `tos-messenger` channel adapter | ⬜ | — | Nothing; needs a transport first |
| Agent Packet carriage and Execution-Gate bridge | 🟡 | `agent.packet`, `pkg/agentpacketbridge`, durable Agent Packet records in `pkg/eventlog`, [`AGENT_PACKET_BRIDGE.md`](AGENT_PACKET_BRIDGE.md); `tos-ai/pkg/agentpacketadapter` owns the existing Gate mapping | Exact signed bytes are carried under E2EE, verified by the service-protocol implementation against finalized controllers, bound to the authenticated Event sender and live local recipient, durably nonce-deduplicated across restart, and retried from pending receiver state. Still missing: daemon/OpenFox wiring, live transport, and the concurrent three-transport A2A/MCP/Agent Packet execution matrix in `tos-ai` |
| First-contact admission policy and sybil resistance | 🟡 | `pkg/admission` (`ContactPolicy`), `pkg/eventlog` (quota) | The mechanism exists: the gate consults a contact policy and honours its answer (allow, hold for approval, tell the sender to satisfy it, deny), and inbound quota is enforced. **Named gaps:** the concrete unknown-sender credential is a freeze decision (⬜); the economic Inbox Bond profile is Expansion-Gate-locked (🔒); and the governing design's requirement that M0 choose and record the admission boundary for **both** the direct and the Relay path — direct/Relay parity — is not yet met (⬜). This row was previously missing from the table; the mechanism existing and the economic profile being locked does not make the component complete |
| Relay, attachment, history, and inbox-bond commercial profiles | 🔒 | — | Expansion Gate |
| Cross-implementation positive vectors and adversarial corpus | 🟡 | `internal/vectors`, `pkg/conformance`, `cmd/tos-vector-report`, `pkg/evidence` | Positive vectors and a self-verifying adversarial corpus exist at object, verify, StoredAck, and concrete E2EE layers. The deterministic evidence bundle now hands their exact hashes to an external consumer, and the strict signed report verifier proves which implementation key claimed to consume them. **Named gap:** no independent implementation has returned a qualifying report — the harness makes that evidence reproducible but cannot manufacture independence |
| Independent multi-operator interoperability evidence | ⬜ | — | Needs a second implementation |

## Scenario acceptance — what "two agents can talk" actually requires

The component table above tracks parts; a Messenger is accepted by scenarios.
Neither scenario below is close-able by any single component: each names the
exact chain still standing between the parts and a conversation, so progress
on the chain is visible and nothing is quietly assumed. A scenario is ✅ only
when the whole flow runs end to end on a real network between independently
operated agents.

| Scenario | Status | What already stands | The blocking chain, in dependency order |
|---|---:|---|---|
| **S1 — Two OpenFox agents discover each other and hold a one-to-one conversation** | ⬜ | Agent/Endpoint/Device identity; descriptor + locator formats and the route-neutral refresh manager; the default 1:1 E2EE candidate and its vectors; envelopes, payload codecs, durable inbox/outbox with delivery leases; negotiation-to-settlement commerce riding the same events | (1) the multi-operator M0-R study produces a route finding — the architecture forbids building the transport first; (2) the production transport that finding selects, over the native stack; (3) owner ratification freezes the E2EE suite; (4) production DHT/descriptor adapters wired into the daemon (the refresh manager currently drives fakes); (5) the OpenFox `tos-messenger` channel adapter (`pkg/channels/` peer of the existing channels) |
| **S2 — Three OpenFox agents converse in a private room, third member invited by epoch transition** | ⬜ | Everything S1 stands on, plus: membership epochs with durable rollback/gap enforcement; admission-gate membership refusal; the MLS 1.0 selection and the group contract/refutation harness; the route-neutral mailbox store for offline KeyPackage/Welcome delivery | Everything S1 still lacks, plus: (6) the TOS-MLS v1 profile implemented against the two-clock model with canonical encodings and adversarial vectors; (7) the room-authority decision (single-authority vs. member-consensus) recorded and enforced; (8) KeyPackage/Welcome delivery bound to real Relay retrieval, which itself waits on the post-M0-R transport binding |

The chain is deliberately honest about what kind of blocker each link is:
(1) needs external operators, (3) and (7) are owner freeze decisions, and the
rest is buildable code in this repository or in `openfox` once its
predecessors land.

## Private-room cryptography selection — TOS-MLS v1 candidate

**Construction decision (2026-08-20): private rooms use MLS 1.0 (RFC 9420 / TreeKEM).** MLS versus a TOS-specific group ratchet is no longer an open choice. The adaptation below is the profile to implement and test; its wire commitments are not frozen until the canonical encodings, implementation, adversarial vectors, independent review, and second-implementation evidence exist.

### Why MLS is the first-principles fit

The Messenger needs all of these properties at the same time: asynchronous/offline members, groups from a few members to hundreds or thousands, one ciphertext per application message rather than O(n) pairwise fan-out, immediate exclusion after a removal, no history for a joiner, forward secrecy, post-compromise recovery, multi-device revocation, and operation through untrusted/multiple Mailbox Relays. MLS was designed for asynchronous group key establishment and gives tree-based logarithmic membership updates with a single application ciphertext. RFC 9420 explicitly targets groups whose members need not be online at the same time and provides forward secrecy and post-compromise security. Sender-key designs are cheaper initially but require pairwise/out-of-band redistribution on membership changes and provide materially weaker compromise recovery; pairwise fan-out makes every group event O(number of recipient devices) in bandwidth and Relay storage; a single shared room key makes removal, compromise recovery and device revocation depend on a trusted distributor. Those tradeoffs contradict the Messenger's decentralized Agent model.

TOS does **not** delegate room authority to MLS. MLS answers “which cryptographic clients can read this epoch”; `pkg/room` and the future room-authority policy answer “which Agents/devices are allowed to become those clients.” A Relay is only opaque delivery/storage and is never the source of truth for membership.

### Selected TOS-MLS v1 profile candidate — not frozen

1. **Protocol and cipher suite:** MLS 1.0 / RFC 9420. The only v1 cipher suite is `0x0001`, `MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519` (X25519 HPKE, HKDF-SHA-256, AES-128-GCM, Ed25519). It is the MLS 1.0 mandatory-to-implement suite, matches the Messenger's Ed25519 identity ecosystem, and maximises independent-library interoperability. No per-room cipher-suite negotiation is allowed in v1; another suite requires a Messenger protocol-version change or MLS `reinit`, preventing silent downgrade and ecosystem fragmentation.
2. **One device, one MLS leaf:** every currently authorised TOS Device/Endpoint instance is an independent MLS client/leaf. Devices never share MLS leaf private state or a LeafNode signature private key. Revoking one device removes that leaf without forcing the Agent's other devices out. Adding an Agent adds the current authorised device KeyPackages for that Agent; later device succession becomes MLS Add/Remove/Update work.
3. **TOS identity binding:** use the standard MLS BasicCredential form for library interoperability. Each leaf has a distinct Ed25519 LeafNode signature key; it must not reuse the delegated Endpoint key or a key shared by the Agent's other devices. A new endpoint-signed MLS device credential must bind that leaf key and its KeyPackage to `(network, agent_id, endpoint_id, device_id, current device-set/delegation commitment, validity window)`. The application verifies this authority against finalized delegation and current device state before accepting a KeyPackage, Add or Commit. The exact BasicCredential identity bytes, credential schema, canonical preimage, and publication format remain freeze work; a syntactically valid MLS credential is never authority by itself.
4. **Two clocks, not one:** `room_epoch` is the logical Agent-membership epoch already owned by `pkg/room`; `mls_epoch` is the cryptographic MLS group epoch. A logical Agent add/remove advances `room_epoch` and necessarily advances `mls_epoch`, while device succession, leaf updates and PCS refreshes may advance `mls_epoch` with the same `room_epoch`. The current `pkg/group` one-room-epoch/one-secret assumption must therefore change rather than forcing MLS into the wrong model.
5. **Room/network binding:** derive the MLS group identifier from the TOS network identity plus `room_id` under a new Messenger domain separator, so an identical room on another network is another MLS group. The exact preimage cannot freeze before the open genesis-hash representation decision. When that decision lands, the separator must be registered, the schema/domain version stated, and positive plus adversarial vectors committed; an existing canonical preimage is never silently extended. Before accepting any membership-changing MLS commit, the application verifies the resulting leaves against the authorised TOS room membership and current device sets; cross-network, stale-room, revoked-device and foreign-Agent commits fail closed.
6. **Untrusted multi-Relay delivery:** KeyPackages, Welcome messages, proposals, commits and MLS PrivateMessages may be carried/stored by any selected Mailbox Relay. Relays cannot decrypt and cannot authorise membership. Missing MLS epochs are a refresh-state condition: fetch the missing commit chain and apply it in order; never guess or skip an epoch.
7. **Commit serialization is an application rule:** MLS deliberately does not turn an untrusted Delivery Service into consensus. TOS Messenger must prevent two valid children of the same accepted MLS epoch from becoming competing histories. Membership-changing commits are accepted only when authorised by the room-authority policy and chained to the single locally accepted parent; concurrent/conflicting commits are not merged cryptographically. The exact room-authority/authorised-committer rule remains the separate open decision, but Relay arrival order is explicitly **not** authority.
8. **Application messages:** normal private-room events are MLS `PrivateMessage` application data. The outer Messenger envelope/event ID keeps routing, dedupe, causal parents, typed payloads and durable delivery; MLS owns group confidentiality/authentication and epoch key evolution. Delivery/Application/Read ACKs do not advance MLS epochs.
9. **Recovery and persistence:** persist MLS state, consumed KeyPackages, Welcome processing, accepted commit parent and epoch state so restart cannot reuse one-time KeyPackages, resurrect a removed leaf, or accept two children for one parent. Recovery fails closed on an MLS epoch gap, rollback or TOS-membership mismatch.
10. **Post-quantum migration:** do not invent a hybrid MLS construction in v1. When an interoperable, reviewed PQ/hybrid MLS cipher suite exists, migration is an explicit Messenger version / MLS `reinit` event with new vectors. Algorithm agility must not become downgrade agility.

### Implementation / acceptance plan

TOS-MLS v1 remains 🟡 until all of these are true:

- ✅ application adapter uses explicit `room_epoch` + `mls_epoch`; the legacy construction contract remains as the founding/join/removal refutation floor;
- integrate a reviewed RFC 9420 implementation instead of implementing TreeKEM/HPKE from scratch, behind the Messenger group contract;
- ✅ endpoint-signed per-device MLS credential and strict KeyPackage publication codec exist; every leaf key is distinct and Endpoint-key reuse is refused;
- after the genesis-hash representation decision, specify the BasicCredential identity and group-id canonical bytes, register every new domain/schema version, and commit positive plus adversarial vectors before calling any wire value frozen;
- ✅ bind credentials to current TOS Agent → Endpoint → Device authority and reject revoked/absent, stale, expired, foreign-network, foreign-Agent and wrong-key leaves;
- ✅ convert device succession to MLS Add/Remove/Update, including revoking one device while retaining the Agent's other device;
- ✅ persist opaque MLS state, globally consumed KeyPackages, Welcome receipts and commit ancestry across restart; replay, duplicate-Welcome, state tamper, epoch-gap, rollback and concurrent-commit cases fail closed;
- run `pkg/group/conformance` plus MLS-specific vectors for founding agreement, joiner-no-past, removed-member-no-future, forged commit, stale membership digest, wrong network/device set, exporter/secret separation and PCS after an update;
- demonstrate one encrypted application event delivered through multiple untrusted Relays to all current devices, including offline catch-up over several MLS epochs, without any Relay learning group secrets or deciding membership;
- cross-check the selected TOS-MLS profile against a second independent MLS implementation before the group wire profile is called frozen.

## The policy engine, split honestly

"Agent message policy engine and prompt-injection firewall" is not one row,
because parts of it are closed and parts cannot be closed from inside this
repository, and one ✅ or one 🟡 would misstate both halves.

| Piece | Status | Note |
|---|---:|---|
| Action policy evaluator (effects, ceilings, provenance typing) | ✅ | `pkg/firewall` |
| Authenticated owner decision queue (challenge + signature, bounded, expiring) | ✅ | `pkg/localapi`, `pkg/eventlog` |
| One-shot side-effect authorization | ✅ | Owner-granted actions and policy-allowed **spends and tool calls** become durable grants consumed by `actions.claim` exactly once. Tool calls require a canonical runtime-supplied `idem_` key committed into the Action ID: a retry reproduces the spent grant, while two legitimate identical invocations use distinct keys. Low-risk message/local effects remain deliberately inline |
| OpenFox provenance enforcement | ⬜ | `DerivedFrom` is the runtime's own claim. Until a trusted runtime wrapper binds model context to action provenance, a compromised runtime can under-report and be judged at the looser ceiling |
| Wallet/tool adapter enforcement | ⬜ | Nothing executes through the firewall yet; there is no wallet and no tool adapter |

## Commerce, split honestly

| Piece | Status | Note |
|---|---:|---|
| Chain-native money, complete terms, mandate and approval binding | ✅ | `pkg/negotiation` |
| Durable mandates, budgets, negotiations | ✅ | Every transition persists; crash windows between the budget ledger and a negotiation snapshot reconcile deterministically at journal open |
| Finalized-quote verification contract and term matching | ✅ | `negotiation.QuoteResolver`, `VerifiedAcceptedQuote` |
| Concrete finalized-state resolver and daemon wiring | 🟡 | The **local Agent/delegation startup path is wired**: daemon config names 3–8 chain authorities, a strict-majority quorum, bounded client policy, an explicit Native Registry version, a daemon-owned rollback checkpoint, and the exact delegation file. Production `daemon.Open` builds the upstream `toschain` + `nativecore` resolver through `pkg/chainagent`, verifies the delegation against finalized live Agent state, requires its Agent/endpoint to equal the configured installation before opening either socket, and installs its outbound event-class grant in the dispatcher. The quote half has a concrete `pkg/chainquote` finalized resolver plus a daemon-journal-backed `EscrowLocator`: a funding retry is idempotent, a redirect conflicts, damaged records fail closed, and bindings survive restart. **Named gaps:** (1) no funding/wallet flow calls `RecordEscrowLocation`; accepting a config-authored mapping would counterfeit that provenance; (2) quote resolver/execution injection remains absent; (3) no live-node end-to-end run has supplied deployment evidence. These gaps keep the combined row 🟡 |
| Negative-case resolver tests (wrong network/registry/account/provider/money/escrow) | 🟡 | The Messenger's term-matching half rejects divergence in amount, capability, version, expiry, provider, manifest, or **escrow**; a quote in a **foreign asset at the same nominal amount** is rejected; a missing, unfinalized, wrong-commitment, undecodable, or invalid mapped quote is refused; a transient resolver **error** leaves negotiation retryable. The concrete quote bridge confirms the located finalized escrow holds the requested commitment, while upstream `toschain` owns network/account/code/finality checks. **Named gap:** no live-node composition test has exercised those layers together |

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
   durable epoch ledger. TOS-MLS v1 is now selected for the cryptographic half;
   implementation is item 5.)*
4. **Independent multi-operator interoperability evidence.** *(Blocked: needs a
   second implementation and the multi-operator study.)*
5. **Implement the TOS-MLS v1 private-room profile candidate.** The construction
   decision is closed: MLS 1.0 / RFC 9420. Cipher suite `0x0001`, one device per
   leaf, two clocks (`room_epoch` and `mls_epoch`), untrusted Relay carriage,
   and TOS identity/device validation are selected profile details. The
   application adapter, device leaf-key authority, candidate vectors, durable
   recovery, and device succession wiring are implemented. Integrate a reviewed
   MLS library and run the remaining cryptographic/Relay acceptance plan above.
   The **room-authority / authorised-committer
   rule remains a separate decision** in [`OPEN_DECISIONS.md`](OPEN_DECISIONS.md);
   MLS must not accidentally settle it by trusting Relay order.

Item 1 does require the study; none of these settle the genesis-hash
representation, which blocks the freeze itself.
