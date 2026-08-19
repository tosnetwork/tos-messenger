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
| Mandate custody | mandates are placed and withdrawn on the owner's socket only, stored under a content-addressed identifier, and resolved from the store when a spend is judged; a runtime names one and never supplies one | `eventlog.PlaceMandate`, `localapi.Server.spendMandate` |
| Withdrawal | a withdrawn mandate is kept rather than deleted, and re-placing the same terms finds the withdrawn record rather than reopening it | `eventlog.RevokeMandate` |
| Channel separation | instructions and received content are different types with no conversion, and quotations are framed by a delimiter derived from their own content | `firewall.Instruction`, `firewall.Quotation` |
| Account binding | the account a finalized Agent record came from is recomputed from the network, object identifier, registry code and workchain, and compared; a chain policy without a locator cannot validate | `identity.ChainPolicy.Locator`, `tosaddr.Locator` |
| Addressing rules | called through the protocol SDK rather than reimplemented, because a second implementation of an addressing rule can drift and a drifted check refuses correct state | `tosaddr` |
| Inbox policy binding | the gate refuses to start unless the policy in memory answers to the digest the endpoint published in its delegation; the digest commits the rule, not the roster | `admission.New`, `admission.ContactPolicy.Digest` |
| Unit of evidence | one measurement is a matched pair of signed halves that agree on cell, probe, outcome and commits; unmatched or contradicting halves are dropped and counted | `reachability.combine` |
| Operator weighting | rates are means over operators, with a per-operator cap on how much of a cell one may contribute, applied in digest order so submission order cannot choose the sample, and drops reported rather than silently truncated | `reachability.summarize` |
| Operator independence | not established; the identifier is self-declared and only shared endpoint keys are detected, so the report says "distinct operator identifiers" | `reachability.CellReport.Operators` |
| Site counting | counted separately from operators, because one operator behind one uplink has measured one network | `reachability.Policy.MinSitesPerCell` |
| Pair identity | both endpoints of one attempt derive the same identifier from their shared session, so one measurement is not counted as two | `reachability.PairID` |
| Evidence integrity | every trial is signed by its endpoint and carries a coordinator attestation of the observed address and peer reachability, the two facts an endpoint cannot check about itself | `reachability.SignTrial`, `reachability.Observation` |
| Predeclared coordinators | a policy names whose attestations count, because anyone can run a coordinator and a signature from an unnamed one proves only that somebody signed something | `reachability.Policy.Coordinators` |
| Coordinator identity | derived from its key rather than chosen, so a coordinator cannot present itself under a name it does not hold | `reachability.CoordinatorID` |
| Shared-key exclusion | an endpoint key seen under more than one operator has all of its trials dropped and the key reported | `reachability.Aggregate` |
| Operator identity | opaque `op_` prefix over a digest of a local operator name, so diversity is counted without collecting identity | `reachability.OperatorID` |
| Suite identifier form | `tos.messaging.e2ee.<name>.v<n>`, so a suite can be negotiated, deprecated, and upgraded | `e2ee.AlgorithmPattern` |
| Ciphertext binding | network tuple, suite, conversation, and both sides' Agent, endpoint, and device identifiers, with direction included | `e2ee.Binding` |
| Ciphertext expansion bound | at most 512 bytes over the plaintext | `e2ee.MaxCiphertextOverheadBytes` |
| Prekey bundle bounds | material at most 4 KiB, lifetime at most 30 days, at most 16 devices per published set | `pkg/e2ee` constants |
| Descriptor prekey commitment | digest over the sorted per-device bundle digests, so adding or removing a device changes the descriptor | `e2ee.SetDigest` |
| Suite interface shape | a pure state transition rather than a mutable session, so the caller commits result and next state together and the commit order is this repository's decision rather than a library's | `e2ee.Suite` |
| Persisted session state | opaque, complete, and including replay bookkeeping, so a restart cannot re-accept a message the session already opened | `e2ee.State` |
| Attacker's view | `KeyMaterial` returns keys without replay bookkeeping, so a compromise check cannot be dodged by retaining a seen-list | `e2ee.Suite.KeyMaterial` |
| Commit order | inbound commits the event then the session; outbound commits the session then the ciphertext. Each order is decided by what a crash between the two writes would cost | `e2ee.CommitOrder`, `eventlog.CommitInbound`, `eventlog.CommitSealed` |
| Stored ciphertext | a retry sends the committed ciphertext rather than sealing again, because sealing per network retry would consume a message key each time | `eventlog.Delivery.Ciphertext` |
| Probe amplification floor | requests padded to 512 bytes; a response larger than its request is never sent | `probe.MinRequestBytes`, `probe.CheckNoAmplification` |
| Coordinator limits | 5 minute pairing TTL, 4096 pairings, 600 requests per source address per minute | `probe.CoordinatorOptions` defaults |

## Named but not established

The firewall governs proposals to act. It cannot govern what a model concludes
from text it reads, and nothing in it should be read as preventing prompt
injection. What it prevents is a conclusion becoming a payment, a signature, or
a configuration change without a person.

The genesis hashes in a network domain are carried here as bare hex and by the
protocol SDK with a `sha256:` prefix. Both describe the same 32 bytes, and
`tosaddr.normalize` converts at the boundary rather than reinterpreting either
side's field. Which form the protocol freezes on is open, and settling it is a
prerequisite for freezing the network domain's canonical preimage.

## Not proposed here

These remain entirely open, and this repository deliberately contains no
implementation of them:

- the one-to-one end-to-end encryption suite and library, and the hybrid
  post-quantum migration schedule. `pkg/e2ee` fixes what a candidate must
  provide and how it is refuted; it selects nothing and implements no
  cryptography;
- the group key-management protocol, where MLS (RFC 9420) is the recorded
  default candidate that an alternative must be justified against;
- private-room transport, beyond the per-device fan-out default;
- first-contact admission parameters, including whether an economic bond is
  used, which the current fixed-price software-work escrow cannot express.
  `admission.ContactPolicy` fixes that a policy is consulted and its answer
  honoured, and leaves the answer itself open;
- prekey publication, replenishment, and equivocation detection;
- Mailbox Relay sender privacy, quota tokens, and anti-spam model;
- mobile push privacy within the contentless wake-up constraint; and
- public channel ordering and moderation policy; and
- the sample sizes and viability rates a real study will predeclare, for which
  `docs/reachability-policy.example.json` is an illustration and not a
  commitment.
