# M0 freeze readiness

This is the material for an M0 freeze review, not a freeze. Nothing here
declares the protocol frozen, and this repository has no standing to: it is an
incubation implementation, carries no gate status, and the decision belongs to
the governing roadmap.

What it does is state, in one place and checkably, what a freeze would be
committing to, what is now true, and what is not. The last column of every
table is the one that matters, because a readiness document that only lists
what was finished is an advertisement.

**Verdict from this side: not ready.** Five things below cannot be closed by
writing more code here, and one of them (the reachability study) blocks a
milestone rather than a review.

## What a freeze would fix

Freezing `tos.messaging.*.v1` fixes every canonical preimage: a delegation
digest, an endpoint identifier, a descriptor, a DHT locator, an Event
identifier, an end-to-end binding, a payload body, a set of terms. After a
freeze, changing any of those is a new version rather than an edit, and every
published object made under the old one has to keep verifying.

## Closed since the last review

Each of these was a finding rather than a plan, and each is bound to the commit
that closed it so a reviewer can check the code instead of the claim.

| Finding | Where it stood | Commit |
|---|---|---|
| A measurement cell required both endpoints to declare the same situation, so the asymmetric deployments the study exists to answer were discarded as disagreements | `reachability.Scenario` is an ordered pair of per-endpoint situations; the joint label is derived | `2c87808` |
| A coordinator attestation named a session but not a party, so a copied one could be worn by a third key and discard an honest pair | the attestation binds the endpoint key and the probe | `2c87808` |
| The vector corpus froze an event whose body did not parse under its own kind | the corpus builds a real payload and asserts it passes the checks the protocol runs | `2c87808` |
| Four domain separators were declared and never registered; the uniqueness check skipped the file they live in | the check reads the declarations; the reused reachability pair separator is split in two | `2c87808` |
| Two sockets, one Unix user: a runtime could grant its own approval | every owner decision carries an ed25519 signature over a single-use challenge | `79fdbf6` |
| An inbound event was visible to a runtime before the session recorded that its ciphertext was opened | events are staged and become deliverable only on commit; a restart finishes the transaction | `ea3ba8c` |
| Sealing checked the session generation but not the send attempt, so an attempt whose lease expired could still spend a message key | sealing is bound to the holding attempt and refused once a ciphertext exists | `ea3ba8c` |
| An asset was a ticker and a `uint64` | asset identity is the master contract, wallet code and precision; amounts are arbitrary-precision atomic counts | `6f77368` |
| Terms named the capability and the price, so the canonical form could differ in provider, manifest, escrow, dispute policy and transport binding | terms carry every field a canonical Quote Proposal carries | `6f77368` |
| An owner approval was a boolean and survived a change of terms | approval binds the terms digest, the generation and the mandate digest; terms freeze at agreement and reopening is explicit | `6f77368` |
| `Finalize` accepted any well-formed digest | it resolves the Accepted Quote from finalized state and compares field by field | `6f77368` |
| The budget was optional and in memory | required for commit authority, and its holds are durable | `6f77368` |
| Anything waiting on a person was unbounded and never expired | bounded in count, per sender, in bytes and in age, and retired rather than kept | `95f6a61` |
| An inbox policy declared its own digest | `ContactPolicy` is closed and built from the published document | `95f6a61` |
| This endpoint's own delegation was taken on the caller's word | it is resolved against finalized state and required to be this installation's | `95f6a61` |
| A negotiation lost its state on restart while its budget hold stayed | every transition is durable, and the mandate is referenced rather than copied | `f84a02c` |

## Not closed, and why

### 1. Two representations of a network domain — blocks the freeze directly

Genesis hashes are bare hex here and `sha256:`-prefixed in the protocol SDK.
`tosaddr.normalize` converts at the boundary and both sides work, but the
network domain is committed by a delegation digest, an endpoint identifier, a
descriptor, an Event identifier, an end-to-end binding and an account address.
Whichever form is frozen, the other set of vectors is wrong. **This has to be
decided before anything is frozen, and it is not this repository's decision to
make alone.**

### 2. The reachability study has never been run — blocks M1, not the freeze

`pkg/reachability` and `pkg/probe` are finished and refuse to produce a
decision from evidence they do not have. No evidence has been collected, so
there is no route decision, and the architecture makes that a prerequisite for
*starting* M1 rather than for accepting it. Nothing about transport should be
frozen on the strength of tooling that has never been pointed at a network.

### 3. No encryption suite

`pkg/e2ee` defines the contract a candidate must satisfy and a harness that can
refute one. Choosing a construction is a freeze decision the architecture
reserves, and inventing one here is forbidden. The message binding and the
commit order are frozen in shape; the cipher is not chosen.

### 4. Multi-device sessions and key rotation

Devices can publish prekey bundles and be bound to a descriptor. There is no
per-device session fan-out and no rotation model. This is an M0 decision,
independent of transport, and it is the largest gap in the parts that are
otherwise settled.

### 5. Nothing has checked this against a second implementation

The positive vectors exist. The adversarial corpus — the set of inputs a second
implementation must *refuse* — does not, and no second implementation exists,
so there is no interoperability evidence at all. A freeze without it fixes a
format that exactly one program has ever agreed with.

## Limits that are stated rather than fixed

These are not defects to close. They are boundaries this implementation cannot
move, recorded so that nobody reads more into the code than it does.

- **The context firewall governs proposals to act, not conclusions.** It cannot
  govern what a model infers from text it reads. What it prevents is an
  inference becoming a payment, a signature, or a configuration change without
  a person.
- **The owner key must live where the runtime cannot read it.** The daemon
  checks the signature; it cannot check custody. If the private half sits in a
  file the Agent can open, the boundary is decoration.
- **The budget is not a balance.** What can be spent is decided by the wallet
  and by finalized state. The local budget is a stricter ceiling on top, and is
  never authority over funds.
- **Operator diversity in the study is not established.** The identifier is
  self-declared; only shared endpoint keys are detected. The report says
  "distinct operator identifiers" and means exactly that.
- **A conformance run can only refute.** Passing every check clears a floor.

## What must not happen before a freeze review concludes

- freezing `tos.messaging.*.v1`;
- deciding a route strategy from a study that has not been run;
- letting an Agent create real transactions through `Negotiation.Finalize`, or
  attaching a real wallet to automatic payment;
- describing the owner socket as reliable human approval on a deployment where
  the runtime can read the owner key;
- reading `Committed()` as a commercial guarantee rather than as what it is: a
  quote that was found in finalized state and matched the terms agreed.
