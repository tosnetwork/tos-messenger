# Route-neutral public Agent channel candidate

`pkg/publicchannel` implements the first transport-independent M5 primitives.
It is a candidate, not a frozen Overlay profile and not a production channel.

## Authority and identity

A public channel ID is derived from the complete TOS network identity, one
finalized authority Agent/Endpoint and a non-zero random 32-byte seed. An
authority-signed profile names a bounded, sorted set of finalized Endpoint
principals and independently grants `publisher` and `moderator` powers. The
authority must retain both powers. Every Endpoint delegation must include the
`public.channel` event class; a profile signature cannot mint Agent identity or
extend an Endpoint delegation's validity.

The profile is an explicit epoch so role changes can be serialized without
pretending that Overlay membership grants application authority. Epoch 1 has no
predecessor; every later profile commits the exact prior signed-profile digest.
`VerifySuccessor` accepts only a single adjacent authority-signed transition,
and `ProfilesConflict` identifies non-identical branches at the same epoch and
predecessor without choosing by digest or arrival order. `OpenStore` persists
the exact signed profile before atomically advancing a single-writer checkpoint;
exact replay is idempotent, while lower epochs, gaps and equal-epoch forks are
refused.

## Events and convergence

Each public Event is Ed25519-signed by its finalized publisher Endpoint and is
content-addressed as `pce_<sha256>`. One publisher has one strict sequence:
sequence 1 has no predecessor, every later Event names the prior Event and
includes it in its sorted causal-parent set. Up to 16 parents express
cross-publisher causality without creating a global sequencer. A post contains
at most 64 KiB. A moderation `hide` or `restore` contains no post content and
must name its target post as a causal parent; only a principal holding both
publisher and moderator roles may sign it.

A complete history is bounded to 65,536 Events and 64 MiB of post bytes. It
verifies every role, finalized delegation, signature, per-publisher chain,
causal reference and moderation target. Its digest commits the sorted Event-ID
set, so Relay arrival order cannot change the result. Display order is only the
deterministic `(published_at,event_id)` projection. The latest moderation in
that order controls visibility, while the immutable source Event remains in
history. `MissingReferences` returns exact absent content IDs for gap repair;
it never trusts a Relay's range or completeness claim.

Strict bounded v1 JSON exists for the profile, Event, and compact history head.
A head is not independent authority: a consumer must fetch Events, run
`VerifyHistory`, and compare the derived head. Unknown fields, trailing JSON,
signature/authority substitution, sequence forks, missing/future parents,
unauthorized moderation, Event-ID mismatch and arrival-order divergence fail
closed in the candidate tests.

`testdata/public-channel-vectors.json` freezes the exact profile/Event signing
preimages, signed JSON, profile digest, Event IDs and convergent history head
from deterministic Endpoint seeds. Its decode-positive adversarial entries
separately exercise unknown profile fields, Event-ID and publisher-signature
substitution, a missing causal parent, and a syntactically valid false head.
The package rebuilds and consumes this file on every test run.

## Durable local state

The candidate store writes verified Event objects and a canonical immutable
history manifest before atomically replacing that profile epoch's head. A
successor snapshot must contain every previously committed Event. Restart reads
follow only the head, compare it byte-for-byte with its immutable manifest, and
re-run full history verification over every referenced Event; orphan objects,
history shrinkage, corrupted files and a second writer do not become accepted
state. Directories are mode `0700`, records are mode `0600`, and profile epochs
remain readable after a later profile becomes current.

This is local durability, not evidence that an Overlay peer supplied a complete
history. Remote heads and manifests remain untrusted inputs until the locally
derived history matches them.

## Explicitly still open

- Overlay/RLDP/TOS Sites publication, fetch, peer limits and anti-spam policy;
- independently operated convergence/failover evidence;
- independent vector consumption/review and a second implementation.

No transport choice or economic history-Relay profile is made here. The latter
remains Expansion-Gate locked.
