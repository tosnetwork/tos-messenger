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
| Delegation lifetime bound | at most 365 days; session lifetime within 60 seconds to 30 days and never longer than the delegation | `identity.validateWindowFields` |
| Descriptor lifetime bound | at most 7 days, and never beyond the delegation expiry | `directory.ValidateDescriptor`, `directory.Bind` |
| DHT key derivation | SHA-256 over a domain-separated preimage of the network-bound Agent digest and endpoint identifier | `directory.LookupKey` |
| DHT value size bound | 1024 bytes encoded; retrieval reference at most 512 bytes | `directory.MaxLocatorBytes` |
| Locator retrieval schemes | `https`, `adnl`, `rldp`, and `http` on loopback only | `directory.validateDescriptorLocator` |
| Envelope size bounds | advertised maximum between 4 KiB and 1 MiB; stored ciphertext at most 1 MiB | `directory.MinEnvelopeBytes`, `envelope.MaxCiphertextBytes` |
| Relay retention bound | at most 30 days, and never beyond the operator's own bound | `envelope.AcceptedForStorage` |
| Event ID derivation | content addressed: `evt_` + SHA-256 over the canonical event preimage excluding the identifier itself | `envelope.DeriveEventID` |
| Event kind to delegated class mapping | explicit table; an unrecognised kind has no class | `envelope.eventClasses` |
| Event body bounds | content at most 128 KiB, 16 causal parents, 16 attachment references | `envelope` constants |
| Durable store format | one JSON record per event in a private directory owned by one process, forward-only state machine | `pkg/eventlog` |
| Failure taxonomy | four dispositions: permanent, transient, refresh-state, and await-approval, the last never retried on a timer | `pkg/fault` |
| Peer visibility | a per-code decision; hidden codes all become `rejected`, and authentication, replay, and approval outcomes are deliberately indistinguishable | `fault.registry`, `fault.PeerCode` |
| Retry schedule | transient doubles from 1s to a 5m cap over 8 attempts; refresh doubles from 5s to a 15m cap over 4; jitter is the caller's | `pkg/fault/retry.go` |
| Domain separator registry | one list, with a test that scans the repository for unregistered separators | `canon.Domains` |
| Claim retention floor | derived from the envelope retention bound rather than restated, because a claim pruned before a Relay can stop holding the ciphertext reopens the replay window | `eventlog.MinClaimRetention` |
| Damaged record policy | reported and kept, never deleted, so damaging a file cannot become a way to replay its event | `eventlog.Prune` |
| Outbound state machine | pending, held, delivered, abandoned; a re-enqueue never resets an attempt count and an approval hold leaves the timer entirely | `pkg/eventlog/delivery.go` |
| Study acceptance policy | content-addressed, and required to cover NAT, consumer ISP, carrier-grade NAT, mobile, two address families, two UDP-policy environments, a low-cost class, and a mobile endpoint | `reachability.Policy.Validate` |
| Route decision rule | every required stratum viable direct → direct-first; none viable but all lifted by a proxy → tunnel-first; some viable → hybrid; otherwise relay-first | `reachability.decide` |
| Operator identity | opaque `op_` prefix over a digest of a local operator name, so diversity is counted without collecting identity | `reachability.OperatorID` |
| Suite identifier form | `tos.messaging.e2ee.<name>.v<n>`, so a suite can be negotiated, deprecated, and upgraded | `e2ee.AlgorithmPattern` |
| Ciphertext binding | network tuple, suite, conversation, and both sides' Agent, endpoint, and device identifiers, with direction included | `e2ee.Binding` |
| Ciphertext expansion bound | at most 512 bytes over the plaintext | `e2ee.MaxCiphertextOverheadBytes` |
| Prekey bundle bounds | material at most 4 KiB, lifetime at most 30 days, at most 16 devices per published set | `pkg/e2ee` constants |
| Descriptor prekey commitment | digest over the sorted per-device bundle digests, so adding or removing a device changes the descriptor | `e2ee.SetDigest` |
| Snapshot contract | key material only, excluding replay bookkeeping, so a compromise check cannot be dodged by retaining a seen-list | `e2ee.Session.Snapshot` |
| Probe amplification floor | requests padded to 512 bytes; a response larger than its request is never sent | `probe.MinRequestBytes`, `probe.CheckNoAmplification` |
| Coordinator limits | 5 minute pairing TTL, 4096 pairings, 600 requests per source address per minute | `probe.CoordinatorOptions` defaults |

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
  used, which the current fixed-price software-work escrow cannot express;
- prekey publication, replenishment, and equivocation detection;
- Mailbox Relay sender privacy, quota tokens, and anti-spam model;
- mobile push privacy within the contentless wake-up constraint; and
- public channel ordering and moderation policy; and
- the sample sizes and viability rates a real study will predeclare, for which
  `docs/reachability-policy.example.json` is an illustration and not a
  commitment.
