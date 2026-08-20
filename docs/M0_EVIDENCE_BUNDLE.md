# M0 evidence bundle and vector-consumer report

This is the reproducible handoff format for an M0 freeze review. It automates
collection; it does not declare a freeze, approve a cryptographic construction,
or manufacture independent evidence.

## Build bundle

Start from a clean checkout at the commit under review and supply the collector
manifests used by the measurement tooling:

```sh
scripts/assemble-m0-evidence.sh /absolute/path/m0-evidence.zip \
  /absolute/path/collector-a.json /absolute/path/collector-b.json
```

The script runs `make verify`, cross-builds every command for Linux amd64 and
arm64 with `CGO_ENABLED=0` and `-trimpath`, copies the committed object,
adversarial, and E2EE vector artifacts, packages the supplied collector
manifests, verifies the resulting archive, and prints its SHA-256.

`tos-m0-evidence verify -in bundle.zip` independently reopens every archive
entry and refuses missing classes, uncommitted files, duplicate/traversing
paths, oversized artifacts, unsorted manifests, or a size/digest mismatch.
The bundle is deterministic for identical inputs. Its manifest records the
source commit and toolchain and hashes every byte it contains.

The bundle requires at least one collector manifest because a freeze packet
that omits which collector builds produced its measurement artifacts is
incomplete. Presence does not mean that a real M0-R study ran; the signed trial
records and the predeclared study policy decide that separately.

## Independent vector consumption

An implementation that did not use this repository's encoders consumes these
three exact files from the bundle:

- `vectors/objects.json`;
- `vectors/adversarial.json`; and
- `vectors/e2ee.json`.

It emits a strict `tos.messaging.conformance-report.v1` JSON report naming its
implementation, commit, toolchain, run time, positive/adversarial check counts,
and the SHA-256 of all three artifacts. The artifact array is sorted by name:
`adversarial`, `e2ee`, `objects`. The consumer signs the canonical report with
its own Ed25519 evidence key.

The canonical preimage begins with
`tos.messaging.conformance-report.v1\x00`, then length-prefixes the schema,
implementation, implementation commit, and toolchain, followed by the
big-endian run time, positive and adversarial counts, sorted artifact
name/digest pairs, and the raw 32-byte consumer public key. Integer widths are
the `internal/canon` widths: `uint64` for time and `uint32` for counts.

Verify a returned report against the repository's committed artifacts:

```sh
tos-vector-report -report independent-report.json
```

The verifier proves that the named key signed a report over the exact artifact
set. It cannot prove that the signer is organizationally independent, that its
implementation was written without sharing code, or that its check counts are
honest. Those are review and provenance questions. Until a qualifying report
and its source/build evidence exist, the roadmap remains 🟡.
