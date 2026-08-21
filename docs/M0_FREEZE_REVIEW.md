# M0 freeze readiness

This is the material for an M0 freeze review, not a freeze. Nothing here
declares the protocol frozen, and this repository has no standing to: it is an
incubation implementation, carries no gate status, and the decision belongs to
the governing roadmap.

What it does is state, in one place and checkably, what a freeze would be
committing to, what is now true, and what is not. The last column of every
table is the one that matters, because a readiness document that only lists
what was finished is an advertisement.

**Verdict from this side: not ready.** The genesis-hash representation and the
one-to-one construction choice were decided on 2026-08-20, and the canonical
representation migration is now implemented with explicit version advances.
Two evidence items still block the freeze directly: independent cryptographic
review and a second-language implementation report. The reachability study is
separate and blocks M1 scope freeze and start rather than this review; it needs
independent operators and networks.

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
| A mandate-placement owner signature omitted the asset network and both genesis hashes after those fields were added, allowing a cross-network substitution before the daemon derived the mandate | the decision preimage now binds the network id and both genesis hashes, decodes the hashes from strict bare hex to raw 32-byte values, and carries field-substitution tests | `0541723` |
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
| Candidate preimages committed 64-character genesis display hashes despite the raw-32-byte decision | Endpoint delegation/ID, Descriptor, Event, prekey bundle/set, E2EE binding, negotiation terms, mandate and budget domains advance explicitly; all encode raw bytes, vectors are regenerated, and a repository audit rejects future `canon.Text(...Genesis*Hash)` uses | `internal/canon.Hash32`, `TestGenesisHashesNeverUseTextCanonicalEncoding` |

## Not closed, and why

### 1. Canonical network representation — decision and migration closed

Genesis hashes are raw 32-byte values in canonical preimages and lowercase bare
hex in strict JSON. `sha256:` is SDK boundary syntax only. The candidate audit
found and migrated Endpoint delegation/ID, Descriptor, Event, prekey
bundle/set, E2EE binding, negotiation terms, mandate and budget preimages. Each
already-versioned object advanced its domain or schema rather than silently
reinterpreting old bytes, and all affected positive/adversarial vectors were
regenerated. `internal/canon.Hash32` is the shared encoder/decoder boundary and
a source audit fails if a production preimage writes either genesis hash with
`canon.Text`. The single-writer journal also persists a private canonical-state
generation marker: an unmarked nonempty tree or substituted/future marker is
refused without mutation, preventing changed Event, mandate or budget IDs from
silently resetting durable authority. This closes migration work, not
independent review or the second-implementation gate.

### 2. The reachability study has never been run — blocks M1, not the freeze

Both collectors now exist — UDP feasibility and the ADNL session probe a
route decision actually turns on — and the report tool exits non-zero for
anything that supports no route decision. What does not exist is evidence:
**no study of either kind has been run**, and a study needs at least three
operators on at least three sites per required scenario, which one
implementer cannot supply. A single-operator dry run of the chain is
scripted in [`M0R_PILOT_RUNBOOK.md`](M0R_PILOT_RUNBOOK.md) and is expected
to end `insufficient-evidence`. The architecture makes the route decision a
prerequisite for *starting* M1 rather than for accepting it.

### 3. Encryption construction approved; independent review remains

`pkg/e2ee` now implements the candidate recommended in
[`E2EE_SUITE_DECISION.md`](E2EE_SUITE_DECISION.md): an endpoint-authenticated,
X3DH-shaped X25519 prekey handshake, HKDF/HMAC-SHA-256, AES-256-GCM, and the
Double Ratchet. It clears the fourteen-property refutation harness and carries
deterministic positive and adversarial wire vectors, with the primitives
cross-checked against published RFC and NIST known answers. This closes
algorithm selection and the codeable implementation gap, not the wire freeze:
independent review is incomplete and no independent implementation has consumed
its vectors.

### 4. No second implementation report exists

The positive vectors and adversarial corpus exist at the object, verification,
and concrete E2EE-suite layers. The suite vector test is also deterministic.
`pkg/conformance`, `cmd/tos-vector-report`, and
[`M0_EVIDENCE_BUNDLE.md`](M0_EVIDENCE_BUNDLE.md) now freeze the handoff and
signed-report verification path an external consumer uses, while
`scripts/assemble-m0-evidence.sh` packages the exact artifacts with dual-arch
build evidence. No independent implementation has returned such a report, so
there is still no interoperability evidence. A freeze without it would fix
formats that exactly one program has ever agreed with.

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
