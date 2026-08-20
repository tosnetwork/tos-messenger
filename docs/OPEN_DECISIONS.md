# Open decisions

The architecture leaves a set of choices to the M0 protocol freeze. Code cannot
wait for all of them, so where an implementation was required a concrete
proposal was made. Each one is recorded here with the code that implements it,
so a freeze decision changes a known place rather than an unknown one.

Changing any item below is a wire-format change. `pkg/identity` carries a fixed
digest vector for exactly this reason: an accidental change breaks a test rather
than silently forking two implementations.

| Decision | Proposal in this repository | Where |
|---|---|---|
| Messaging Endpoint identifier derivation | `mep_` + SHA-256 over a domain-separated preimage of the network tuple, Agent ID, and endpoint public key | `identity.DeriveEndpointID` |
| Delegation authenticity | No separate signature. A delegation is authentic when its canonical digest appears in the finalized Agent's committed delegation digests | `identity.Verify` |
| Resolver contract | returns the outer native state, so the boundary can check network, finality, registry code, and Agent binding instead of trusting a resolver's implicit promise | `identity.AgentResolver` |
| Predeclared registry code | typed TVM state means nothing outside the contract that produced it, so state from an unrecognised registry is a different object with a familiar shape | `identity.ChainPolicy` |
| Delegation lifetime bound | at most 365 days; session lifetime within 60 seconds to 30 days and never longer than the delegation | `identity.validateWindowFields` |
| Descriptor lifetime bound | at most 7 days, and never beyond the delegation expiry | `directory.ValidateDescriptor`, `directory.Bind` |
| DHT key | not ours to choose: TOS Core refuses a key description whose identifier is not the short identifier of the publishing key, so it is `sha256` over the boxed `pub.ed25519`, with the protocol name `tos.messaging.locator` and index 0 | `directory.LocatorKey` |
| DHT update rule | `dht.updateRule.signature`, so the network itself refuses an unauthorized overwrite rather than leaving it for the application to detect | `directory.UpdateRule` |
| Republish rule | a replacement must strictly extend the stored expiry, because the signature rule keeps whichever value has the greater time to live | `directory.Republish` |
| DHT value size bound | 640 bytes encoded against a 768-byte network limit; retrieval reference at most 256 bytes | `directory.MaxLocatorBytes`, `directory.MaxDHTValueBytes` |
| DHT wire format | compact canonical binary; JSON is for debugging and file exchange and is never published or signed | `directory.EncodeLocator` |
| Production DHT boundary | `directory.TOSDHT` uses the pinned `tosutils-go` client and independently rechecks the exact native key, Ed25519 owner, signature update rule, key-description/value signatures, TTL, and inner locator signature. Publication requires the live delegated Endpoint key and verifies the returned native key/replica count | [`TOS_DHT_ADAPTER.md`](TOS_DHT_ADAPTER.md), `directory.TOSDHT` |
| First-contact discovery bootstrap | explicit bounded Agent→delegation and descriptor-policy files. An Agent ID cannot derive the Endpoint-key DHT key; the files provide rendezvous only, while finalized commitment checks remain authority. Every refresh rereads both, and symlink/path substitution fails closed | [`DISCOVERY_BOOTSTRAP.md`](DISCOVERY_BOOTSTRAP.md), `directory.FileDelegations` |
| Descriptor policy retrieval | policy is per Agent, never a daemon-wide constant. Refresh verifies the delegation first, fetches its strict policy document, reproduces the committed digest, and only then evaluates the descriptor | `directory.StagePolicy`, `directory.DecodeDescriptorPolicyJSON` |
| Locator lifetime | at most 24 hours from `issued_at`, now enforced rather than only declared | `directory.MaxLocatorLifetimeSeconds` |
| Locator retrieval schemes | `https`, `adnl`, `rldp`, and `http` on loopback only, with user info, query strings, and fragments refused so no credential is published | `directory.validateDescriptorLocator` |
| Envelope size bounds | advertised maximum between 4 KiB and 1 MiB; stored ciphertext at most 1 MiB | `directory.MinEnvelopeBytes`, `envelope.MaxCiphertextBytes` |
| Relay retention bound | at most 30 days, and never beyond the operator's own bound | `envelope.AcceptedForStorage` |
| Event ID derivation | content addressed: `evt_` + SHA-256 over the canonical event preimage excluding the identifier itself | `envelope.DeriveEventID` |
| Event kind to delegated class mapping | explicit table; an unrecognised kind has no class | `envelope.eventKinds` |
| Payload schema | fixed by the kind and carried explicitly, so a decoder reads a declared shape rather than guessing one from a name | `envelope.PayloadSchemaOf` |
| Human rendering | carried, covered by the event identifier, and never automation input; a disagreement with the payload is not a preference to resolve | `envelope.Event.Rendering` |
| Owner approval | a local-only kind refused on every network route, so a remote party cannot express local authority at all | `envelope.LocalOnly` |
| Negotiation kinds | conversation, not commitment; none of them create, accept, or fund anything | `envelope.eventKinds` |
| Descriptor policy | committed by the Agent and enforced at bind time, which bounds what a delegated key can advertise even after it is taken | `directory.DescriptorPolicy` |
| Relay set | optional, with a defined digest for the empty set so nobody invents a placeholder | `directory.EmptyRelaySetDigest` |
| Prekey set coherence | one network, one Agent, one endpoint, one suite, unique devices, all signed, enforced in the digest rather than left to each caller | `e2ee.ValidateSet` |
| Event body bounds | content at most 128 KiB, 16 causal parents, 16 attachment references | `envelope` constants |
| Durable store format | one JSON record per event in a private directory owned by one process, carrying the event itself so an accepted event survives a crash | `pkg/eventlog` |
| Inbound dimensions | application state (queued, claimed, applied, rejected) and reading are independent, so a read receipt can never block delivery to a runtime | `eventlog.Record` |
| Application lease | one runtime attempt owns an event at a time; an expired lease returns the work, and a superseded lease cannot complete it | `eventlog.ClaimForApplication` |
| Failure taxonomy | four dispositions: permanent, transient, refresh-state, and await-approval, the last never retried on a timer | `pkg/fault` |
| Peer visibility | a per-code decision; hidden codes all become `rejected`, and authentication, replay, and approval outcomes are deliberately indistinguishable | `fault.registry`, `fault.PeerCode` |
| Retry schedule | transient doubles from 1s to a 5m cap over 8 attempts; refresh doubles from 5s to a 15m cap over 4; jitter is the caller's | `pkg/fault/retry.go` |
| Domain separator registry | one list, with a test that scans the repository for unregistered separators | `canon.Domains` |
| Claim retention floor | derived from the envelope retention bound rather than restated, because a claim pruned before a Relay can stop holding the ciphertext reopens the replay window | `eventlog.MinClaimRetention` |
| Damaged record policy | reported and kept, never deleted, so damaging a file cannot become a way to replay its event | `eventlog.Prune` |
| Unprocessed events | never pruned at any age, because deleting one is exactly the accepted-but-never-delivered failure | `eventlog.Prune` |
| Outbound state machine | pending, held, delivered, abandoned; a re-enqueue never resets an attempt count and an approval hold leaves the timer entirely | `pkg/eventlog/delivery.go` |
| Admission check order | policy runs before the durable claim, so a sender told to satisfy an inbox policy can resend the identical event once they have | `admission.Admit` |
| Retry payload | a retry sends the committed ciphertext, never a freshly sealed one, so a lost packet costs no message key | `dispatch.attempt` |
| Send success | a sender reports success only once a recipient device durably accepted the message; "handed to the network" would turn every lost packet into a delivered one | `dispatch.Sender` |
| Sweep isolation | one failing delivery does not stop the others, so an unreachable peer cannot block every message to everyone else | `dispatch.Sweep` |
| Local boundary | a unix socket in a private directory, narrowed to the owner, with the caller's credentials checked where the platform allows it | `localapi.Listen`, `localapi.verifyPeer` |
| Owner authority | expressible on the owner socket only; the matching event kinds are refused on every network route, and the runtime principal has no approval operation | `localapi.Permits`, `envelope.LocalOnly` |
| Inbound admission | a dimension of its own, so an event waiting for the owner is not in the queue a runtime drains | `eventlog.AdmissionState` |
| Local framing | length-prefixed rather than delimited, because a delimited frame is bounded by whatever buffer the reader allocated and that is a bound nobody stated | `localapi.ReadFrame` |
| Session transitions | committed against the generation the caller read, so two concurrent seals cannot both advance one ratchet | `eventlog.ErrSessionConflict` |
| Send attempts | leased, so two sweeps cannot both put the same message on the wire | `eventlog.ClaimForSend` |
| Submission validation | the runtime submits an encoded event which the daemon decodes and validates, because the daemon owns what goes on the wire | `localapi.Server.queue` |
| Transport statement | no default; an installation states `"none"` deliberately, because a daemon that quietly carried nothing would look like a working one | `daemon.Config.Transport` |
| Queue without send | a dispatcher may have a journal and no transport, which is the state this project is in; the sending half is all or nothing | `dispatch.New`, `dispatch.ErrNoTransport` |
| Outbound expiry | applied on a schedule rather than only on an attempt, or an install with no transport would accumulate records that never sweep and never prune | `eventlog.ExpireDeliveries` |
| Unknown configuration keys | refused, because a misspelled setting that is dropped is one an operator believes is in force | `daemon.DecodeConfig` |
| Money representation | integer units and a decimal exponent, never a float; amounts in different assets or precisions are refused rather than compared | `negotiation.Amount` |
| Authority separation | conversation, proposal, and commit are set by the owner before the exchange and cannot be climbed by arguing | `negotiation.Authority` |
| Intent boundary | every field a commitment needs must be present in the candidate; nothing is inferred, including the asset, which would otherwise come from the budget | `negotiation.Compile` |
| Rendering conflict | a named error so a client can display the disagreement, because resolving it in favour of either side is what makes text authoritative | `negotiation.ErrRenderingConflict` |
| Agreement versus commitment | agreeing in conversation creates nothing; only canonical terms matching the agreed terms in every field finalise, and a mismatch ends the exchange | `negotiation.Finalize` |
| Shared budget | held at the moment of agreement rather than the moment money moves, so several conversations each inside their own ceiling cannot together exceed the owner's total | `negotiation.Budget` |
| Decision record contents | event identifier, outcome, code, route, class, and a salted per-install sender reference; no Agent, endpoint, conversation, or device identifier | `admission.Record` |
| Inbox policy interface | the mechanism is fixed and always consulted; what an unknown sender must present is not | `admission.ContactPolicy` |
| Study acceptance policy | content-addressed, and required to cover NAT, consumer ISP, carrier-grade NAT, mobile, two address families, two UDP-policy environments, a low-cost class, and a mobile endpoint | `reachability.Policy.Validate` |
| Finding vocabulary | probe-specific and non-overlapping: a UDP study reports feasibility, only an ADNL study reports a route, and a report names both the probe and the kind of question it answered | `reachability.Finding`, `reachability.Kind` |
| Route rule | every required stratum viable direct → direct-first; none viable but all lifted by a proxy → tunnel-first; some viable → hybrid; otherwise relay-required, which asserts necessity and not that a Relay performs | `reachability.decide` |
| Payload typing | every event kind has a codec in `pkg/payload`; a body that does not parse under its kind is refused inbound and cannot be queued outbound | `payload.Decode`, `admission.Gate.Admit`, `dispatch.Dispatcher.Queue` |
| Payload encoding | canonical binary, domain-separated by the payload's own schema; JSON stays a transport encoding | `payload.Encode` |
| Foreign protocols | a2a and mcp bodies are typed only as a wrapper naming protocol and version; the body stays opaque and untrusted | `payload.Foreign` |
| Unattended ceilings | two ceilings, one for the Agent's own initiative and a tighter one for anything received content drove; no policy may raise either to a key or to this installation's configuration | `firewall.Policy.Validate` |
| Approval identity | derived from the effect, the description, and every origin cited, so an approval cannot be spent on a different action, and it is spent once | `firewall.ActionID`, `eventlog.SpendApproval` |
| Owner authentication | every decision on the owner's interface carries an ed25519 signature over a single-use challenge; peer credentials remain as defence in depth but are not the boundary, because the runtime usually shares the daemon's Unix user | `localapi.DecisionBytes`, `localapi.Server.authoriseDecision` |
| Asset identity | an asset is the network, the master contract, the wallet code and the precision, never a ticker: two contracts may both answer to one name, and the same contract tuple on another network is a different asset | `negotiation.Asset` |
| Amounts | an arbitrary-precision count of atomic units carried as a canonical decimal string, matching what the chain carries; a 64-bit count cannot express eighteen decimals of an ordinary token | `negotiation.Money` |
| Terms completeness | every field a canonical Quote Proposal carries -- provider, manifest, transport binding, escrow terms, dispute policy, price, expiry -- because each changes what was bought while the number stays the same | `negotiation.Terms` |
| Owner approval binding | bound to the terms digest, the negotiation generation and the mandate digest; anything that changes invalidates it | `negotiation.Approval` |
| Agreement freezing | terms freeze at IntentAgreed; bargaining on requires an explicit Reopen that releases the hold, clears the approval and moves the generation | `negotiation.Negotiation.Reopen` |
| Commitment authority | Finalize resolves the Accepted Quote from finalized state and compares it field by field; a well-formed digest is not a commitment | `negotiation.QuoteResolver` |
| Network binding at finalisation | a negotiation is bound to an expected TOS network when it is created, and Finalize accepts a resolved quote only if the quote's network equals that binding -- the network id and both genesis hashes, because the same workchain, account and code hashes can exist on another network and a network id alone is not identity. The binding is persisted and restored so it survives a restart, and a mismatch settles the exchange to rejected | `negotiation.New`, `negotiation.Finalize`, `negotiation.Snapshot` |
| Network in the canonical digests | the deeper half of the binding above, now closed: the asset carries the network identity (id and both genesis hashes, bare hex) and commits it in its canonical form, so the terms, mandate, and budget preimages all inherit it -- identical terms on two networks are two digests, and a cross-network replay fails cryptographically rather than only at the runtime equality check, which is kept as the second lock. The break is marked loudly: the terms, mandate, and both budget domain separators moved to v2, and the payload schemas that carry terms on the wire moved with them. Terms priced on a network other than the negotiation's binding are refused at proposal, counter, snapshot decode, and quote validation | `negotiation.Network`, `negotiation.Asset`, `canon.DomainNegotiationTerms`, `canon.DomainMandate`, `negotiation.bindsNetwork` |
| Canonical genesis-hash representation | 32 raw bytes in canonical preimages and 64 lowercase bare hex in strict JSON. `sha256:` is accepted only at SDK boundaries and normalized before signing or hashing; an existing alternate preimage takes an explicit schema/domain bump rather than reinterpretation | [`FIRST_PRINCIPLES_DECISIONS.md`](FIRST_PRINCIPLES_DECISIONS.md), `tosaddr` |
| Negotiation durability | every transition is written down before it is reported, and a negotiation cannot start without somewhere to survive; a restart that lost the state while the budget hold stayed would leave money spoken for by an exchange nobody could find | `negotiation.Store`, `eventlog.NegotiationStore` |
| Mandate reference | a snapshot names the mandate by digest rather than copying it, so an exchange does not resume under an authority that was withdrawn or replaced | `negotiation.Restore` |
| Budget durability | reservations and spend are written whole to a per-asset ledger, so a restart cannot let the same money back a second commitment; a commit-authority mandate cannot start without one | `negotiation.OpenBudget`, `eventlog.BudgetLedger` |
| Mandate custody | mandates are placed and withdrawn on the owner's socket only, stored under a content-addressed identifier, and resolved from the store when a spend is judged; a runtime names one and never supplies one | `eventlog.PlaceMandate`, `localapi.Server.spendMandate` |
| Withdrawal | a withdrawn mandate is kept rather than deleted, and re-placing the same terms finds the withdrawn record rather than reopening it | `eventlog.RevokeMandate` |
| Channel separation | instructions and received content are different types with no conversion, and quotations are framed by a delimiter derived from their own content | `firewall.Instruction`, `firewall.Quotation` |
| Device-set succession | a successor set may add or retire devices, never lower the freshness watermark, and never readmit a revoked device; the watermark rule alone stops a replayed old set even when it is a strict subset | `e2ee.Succeed`, `eventlog.DeviceLedger` |
| Device sessions | one session per device pair, its identifier derived deterministically and symmetrically so neither end negotiates it; the ratchet inside provides freshness, not session churn | `e2ee.DeviceSessionID` |
| Adversarial corpus scope | the corpus is split into a decode layer and a verify layer, and every entry names its `layer`. A decode entry is refused on shape; a verify entry decodes cleanly and is refused only when measured against the authority it claims (a delegation, a route, a coordinator key). The generator proves a verify entry passes its decoder and fails its verifier, so a semantic refusal can never masquerade as a decode one — refusing for the wrong reason is itself the interop bug the split prevents | `internal/vectors` corpus |
| Device revocation enforcement | the admission gate refuses only a revoked device, not an unknown one: the ledger is a revocation overlay on top of the delegation, and refusing an unseen device would cut off every device a peer added since the last descriptor fetch | `admission.Gate.Admit`, `eventlog.DeviceLedger.Judge` |
| Room membership enforcement | the admission gate refuses only a definitive non-member of a room, judged against the membership this installation currently holds and keyed on the Agent (room members are Agents). An unknown room is not a non-membership — our view may be behind — so it is admitted, and the overlay runs only when a room ledger is configured, because not every installation is in rooms. It is a refresh, not a permanent refusal: a sender removed since it last synchronised, or one we have not caught up to, reconciles rather than gives up | `admission.Gate.Admit`, `eventlog.RoomLedger.JudgeMember` |
| Economic execution identity | a spend's one-shot is keyed on the economic execution — the mandate and the exact terms — not on the action identifier, which also commits the summary and the provenance and so changes when a purchase is re-described. Keyed this way, a re-described replay of one purchase is refused a second authorisation. The identity is `eex_` + a domain-separated digest of the mandate id and the terms digest; it deliberately does not include the on-chain quote commitment, because at the point a spend is authorised no commitment exists yet — the commitment is created when the purchase is finalised, later — so the mandate-and-terms identity is the right key for the pre-finalisation authorisation one-shot | `negotiation.ExecutionID`, `eventlog.ClaimEconomicExecution`, `localapi` spend path |
| Durable budget in the local-API spend path | now closed: each mandate has its own durable budget, keyed by mandate and asset so two mandates sharing an asset cannot draw on each other's total, and every spend that could still happen — auto-authorised or awaiting the owner — holds its slice of `MaxTotal` before it is authorised, keyed by the economic execution so a re-described same purchase reserves once. The hold is committed into spend when the grant is claimed and released when the owner denies it or a pending spend expires; release is idempotent and never frees a committed reservation. A spend that will not fit escalates to the owner without a hold | `eventlog.OpenMandateBudgetLedger`, `localapi.Server.reserveMandateBudget`, `eventlog.CommitMandateReservation`, `eventlog.ReleaseMandateReservation` |
| Quote resolution is address-keyed | the finalized Accepted Quote lives inside the escrow account, so the chain is addressed by account, not by commitment. The Messenger's `QuoteResolver` is digest-keyed, so the bridge maps a commitment to its escrow address through a locally-attested `EscrowLocator`, populated when the escrow is funded by the party that set it up. An unknown commitment is not found, not an error, which the negotiation already treats as "asked too early", and the account read must carry the exact commitment asked for or it is refused | `chainquote.Resolver`, `chainquote.EscrowLocator` |
| Capability class is caller-attested | the canonical on-chain quote (`QuoteProposalV1`) carries no capability class: the capability identifier is a content hash that already determines it, so committing the class again would be redundant. The resolver therefore takes the class from the same `EscrowLocator` that maps the commitment to its escrow, alongside the address, rather than reading it from the chain — the Messenger's commerce core is unchanged, and the class is authorised separately through the mandate | `chainquote.mapTerms`, `chainquote.EscrowLocator` |
| Multi-device fan-out | one logical event, one content-addressed identity, one sealed copy to every live device of the recipient and of the sender; an expired bundle bootstraps nothing but does not close an established session | `e2ee.FanOut` |
| Room membership epoch | membership is a sorted Agent set; every add or remove advances a monotonic epoch by exactly one and commits a domain-separated digest over the room, epoch, count, and members. The epoch inside the preimage is what stops an old membership being replayed as a current one. A removed member is absent, not revoked — an Agent legitimately returns, unlike a device key, so re-adding is an ordinary add at a fresh epoch | `pkg/room`, `eventlog.RoomLedger` |
| Room succession scope | the ledger accepts only strict single-step succession (epoch *n*+1 derived from the members of epoch *n*), because it holds only the current member set and each successor is derived from it; a gapped or peer-observed commit carries no member set to verify. The selected single-authority model refuses concurrent peer-driven membership histories instead of reconciling them; signed authority-transfer enforcement remains implementation work | `eventlog.RoomLedger.Advance`, [`FIRST_PRINCIPLES_DECISIONS.md`](FIRST_PRINCIPLES_DECISIONS.md) |
| Private-room construction choice | MLS 1.0 / RFC 9420 (TreeKEM) is selected instead of a TOS-specific group ratchet. The application-side candidate now implements two clocks, endpoint-authorised per-device Leaf/KeyPackage publication with candidate vectors, succession planning, and durable opaque state/receipt ancestry. The TOS-MLS wire profile is still not frozen: a reviewed RFC 9420 Driver, BasicCredential/group-id canonical bytes, cryptographic MLS vectors, real Relay catch-up, independent review, and second-implementation evidence remain open | [`ROADMAP.md`](ROADMAP.md), [`TOS_MLS_CANDIDATE.md`](TOS_MLS_CANDIDATE.md), `pkg/group` |
| Account binding | the account a finalized Agent record came from is recomputed from the network, object identifier, registry code and workchain, and compared; a chain policy without a locator cannot validate | `identity.ChainPolicy.Locator`, `tosaddr.Locator` |
| Addressing rules | called through the protocol SDK rather than reimplemented, because a second implementation of an addressing rule can drift and a drifted check refuses correct state | `tosaddr` |
| Pending queue bounds | what may wait on an owner is bounded in count, per sender, in bytes and in age; a full queue refuses the sender rather than dropping the event, and expired questions are recorded as refused rather than deleted | `eventlog.Quota`, `eventlog.ExpirePendingAdmissions` |
| Policy implementation | `ContactPolicy` is a closed type built from a published document, so the digest and the behaviour come from the same source; an interface would let one method say what a policy is and another say what it does | `admission.InboxPolicyDocument` |
| Local delegation | this endpoint's own delegation is resolved against finalized state at start-up and required to be this installation's, not taken on the caller's word | `admission.New` |
| Inbox policy binding | the gate refuses to start unless the policy in memory answers to the digest the endpoint published in its delegation; the digest commits the rule, not the roster | `admission.New`, `admission.ContactPolicy.Digest` |
| Measurement cell | an ordered pair of per-endpoint situations, initiator first; each half describes only itself and the joint reachability label is derived, so asymmetric deployments are expressible and matched-pairs-only policies are refused | `reachability.Scenario`, `reachability.Policy.Validate` |
| Attestation scope | a coordinator signs the endpoint key and the probe as well as the address, so a copied attestation cannot be worn by another key to pollute somebody else's pair | `reachability.Observation` |
| Unit of evidence | one measurement is a matched pair of signed halves that agree on cell, probe, outcome and commits; unmatched or contradicting halves are dropped and counted | `reachability.combine` |
| Operator weighting | rates are means over operators, with a per-operator cap on how much of a cell one may contribute, applied in digest order so submission order cannot choose the sample, and drops reported rather than silently truncated | `reachability.summarize` |
| Operator independence | not established; the identifier is self-declared and only shared endpoint keys are detected, so the report says "distinct operator identifiers" | `reachability.CellReport.Operators` |
| Site counting | counted separately from operators, because one operator behind one uplink has measured one network | `reachability.Policy.MinSitesPerCell` |
| Pair identity | both endpoints of one attempt derive the same identifier from their shared session, so one measurement is not counted as two | `reachability.PairID` |
| Evidence integrity | every trial is signed by its endpoint and carries a coordinator attestation of the observed address and peer reachability, the two facts an endpoint cannot check about itself | `reachability.SignTrial`, `reachability.Observation` |
| Collector provenance | every trial commits both endpoints' content-addressed collector manifests — orchestrator repository and commit, ADNL implementation and version, binary hash, toolchain, target, wire profile — learned at pairing like the commits and cross-checked at pair joining, so evidence from different collector implementations can be split into per-implementation reports | `reachability.CollectorManifest`, `reachability.Trial`, `reachability.combine` |
| NAT filtering evidence | filtering is measured, not declared: the coordinator probes the endpoint from cold sources it never contacted, each probe carrying a random token, and echoing the token over the established flow earns a signed receipt. Receipts can only loosen the derived class — silence proves nothing, because a filtered probe and a lost one are the same silence — so the strict class is never derived remotely | `reachability.FilteringObservation`, `reachability.DeriveFiltering`, `probe.MeasureFiltering` |
| No-NAT declaration | consistent but never credited: bind reflections cannot tell a public host from an endpoint-independent NAT, so `none` and `endpoint-independent` occupy one evidentiary bucket — a `none` declaration survives exactly the evidence an endpoint-independent one survives and is refuted by exactly the evidence that refutes it | `reachability.mappingConsistent` |
| Predeclared coordinators | a policy names whose attestations count, because anyone can run a coordinator and a signature from an unnamed one proves only that somebody signed something | `reachability.Policy.Coordinators` |
| Coordinator identity | derived from its key rather than chosen, so a coordinator cannot present itself under a name it does not hold | `reachability.CoordinatorID` |
| Shared-key exclusion | an endpoint key seen under more than one operator has all of its trials dropped and the key reported | `reachability.Aggregate` |
| Operator identity | opaque `op_` prefix over a digest of a local operator name, so diversity is counted without collecting identity | `reachability.OperatorID` |
| Suite identifier form | `tos.messaging.e2ee.<name>.v<n>`, so a suite can be negotiated, deprecated, and upgraded | `e2ee.AlgorithmPattern` |
| Default one-to-one suite construction | `tos.messaging.e2ee.x3dh-aes256gcm-dr.v1`: endpoint-signed X25519 identity + signed-prekey material, a three-DH asynchronous handshake, HKDF/HMAC-SHA-256, AES-256-GCM, and the Double Ratchet. Construction approved on 2026-08-20; wire freeze still requires independent review and second-language vector consumption | `e2ee.NewDefaultSuite`, [`E2EE_SUITE_DECISION.md`](E2EE_SUITE_DECISION.md) |
| Private-room membership authority | one current authority Agent serializes membership; the creator starts as authority and only a current-authority-signed single-step epoch can transfer it. Concurrent children and Relay-order authority are refused; loss creates a new room rather than an implicit consensus protocol | `pkg/room`, `eventlog.RoomLedger`, [`FIRST_PRINCIPLES_DECISIONS.md`](FIRST_PRINCIPLES_DECISIONS.md) |
| First-contact default | allow-list known contacts, one-time invite-token introductions, and owner hold otherwise; the same policy precedes durable acceptance on direct and Relay paths. No PoW without measurements and no Inbox Bond before the Expansion Gate | `admission.ContactPolicy`, [`FIRST_PRINCIPLES_DECISIONS.md`](FIRST_PRINCIPLES_DECISIONS.md) |
| Mailbox operation authority | Endpoint-signed, Relay/mailbox-scoped Ed25519 capability grants with separate deposit/read/delete permissions; every request signs an exact body digest and fresh nonce claimed durably before the operation. Mailbox IDs and StoredAcks are not bearer credentials | `pkg/mailbox`, [`MAILBOX_AUTHENTICATION.md`](MAILBOX_AUTHENTICATION.md) |
| Ciphertext binding | network tuple, suite, conversation, and both sides' Agent, endpoint, and device identifiers, with direction included | `e2ee.Binding` |
| Ciphertext expansion bound | at most 512 bytes over the plaintext | `e2ee.MaxCiphertextOverheadBytes` |
| Prekey bundle bounds | material at most 4 KiB, lifetime at most 30 days, at most 16 devices per published set | `pkg/e2ee` constants |
| Descriptor prekey commitment | digest over the sorted per-device bundle digests, so adding or removing a device changes the descriptor | `e2ee.SetDigest` |
| Suite interface shape | a pure state transition rather than a mutable session, so the caller commits result and next state together and the commit order is this repository's decision rather than a library's | `e2ee.Suite` |
| Persisted session state | opaque, complete, and including replay bookkeeping, so a restart cannot re-accept a message the session already opened | `e2ee.State` |
| Attacker's view | `KeyMaterial` returns keys without replay bookkeeping, so a compromise check cannot be dodged by retaining a seen-list | `e2ee.Suite.KeyMaterial` |
| Inbound transaction | an inbound event is staged with the transition it is waiting for, delivered only once the session records that its ciphertext was opened, and finished by the process itself on restart rather than by the sender retrying | `eventlog.CommitInbound`, `eventlog.Record.Deliverable` |
| Unapplicable transitions | a staged transition the session moved past is abandoned, not delivered: the ciphertext was never consumed and a resend opens normally | `eventlog.recoverStaged` |
| Seal authority | sealing is bound to the send attempt that holds the delivery and refused once a ciphertext exists, so an attempt whose lease expired cannot advance the ratchet for work it lost | `eventlog.CommitSealed` |
| Commit order | inbound commits the event then the session; outbound commits the session then the ciphertext. Each order is decided by what a crash between the two writes would cost | `e2ee.CommitOrder`, `eventlog.CommitInbound`, `eventlog.CommitSealed` |
| Stored ciphertext | a retry sends the committed ciphertext rather than sealing again, because sealing per network retry would consume a message key each time | `eventlog.Delivery.Ciphertext` |
| Probe amplification floor | requests padded to 896 bytes; a response larger than its request is never sent, and the cold-source filter probes one request draws are together bounded by that request's own size and go only to the observed source of the requesting flow | `probe.MinRequestBytes`, `probe.CheckNoAmplification`, `probe.Coordinator.sendFilterProbes` |
| Coordinator limits | 5 minute pairing TTL, 4096 pairings, 600 requests per source address per minute | `probe.CoordinatorOptions` defaults |
| Tunnel relay limits | 2 minute idle session TTL, 4096 sessions, 1 MiB forwarded per session; a registration completes only by echoing a token the relay sent to the claimed source address, control requests are padded to a 128-byte floor no response exceeds, and forwarding is verbatim between the two proven endpoints of one session | `probe.TunnelRelayOptions` defaults, `probe.TunnelRequestFloor` |

## Closed representation decision and still-unestablished boundaries

The firewall governs proposals to act. It cannot govern what a model concludes
from text it reads, and nothing in it should be read as preventing prompt
injection. What it prevents is a conclusion becoming a payment, a signature, or
a configuration change without a person.

Genesis hashes now have one canonical meaning: raw 32 bytes in preimages and
bare lowercase hex in strict JSON. SDK-prefixed input is boundary syntax only.
Applying that decision to every candidate preimage, regenerating vectors, and
versioning any preimage that previously committed another representation is
implementation work, not a remaining design choice.

## Not proposed here

These remain entirely open, and this repository deliberately contains no
implementation of them:

- final wire freeze of the approved one-to-one construction, which still needs
  independent review and second-language vector evidence. A hybrid
  post-quantum successor and its downgrade rules remain a separate version;
- the TOS-MLS v1 cryptographic implementation and wire freeze. MLS 1.0 / RFC
  9420 is selected, and `pkg/group` now supplies the application-side two-clock
  adapter, distinct endpoint-authorised device leaf credentials/KeyPackages,
  candidate vectors and succession plan; `eventlog.MLSLedger` durably records
  opaque state, globally consumed KeyPackages, Welcomes and commit ancestry.
  Still open are an OpenMLS-backed RFC 9420 Driver, BasicCredential and group-id
  bytes applying the canonical network decision, real cryptographic/Relay acceptance vectors,
  independent review, and second-implementation evidence;
- enforcement of the selected single-authority room model, including signed
  authority transfer and offline reconciliation;
- private-room transport, beyond the per-device fan-out default;
- concrete one-time invite-token encoding and direct/Relay parity tests for the
  selected allow-list/invite/owner-hold first-contact default;
- prekey publication, replenishment, and equivocation detection;
- Mailbox Relay sender privacy, quota tokens, and anti-spam model;
- mobile push privacy within the contentless wake-up constraint; and
- public channel ordering and moderation policy; and
- the sample sizes and viability rates a real study will predeclare, for which
  `docs/reachability-policy.example.json` is an illustration and not a
  commitment.
