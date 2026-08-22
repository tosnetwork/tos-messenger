# Signed attachment-corpus plumbing acceptance — 2026-08-22

This record covers a same-host, self-operated clean/EICAR run through the real
attachment admission sandbox. It proves the signed-manifest/report mechanism
and failure taxonomy. It is **not** an externally approved representative
hostile corpus and does not close that release gate.

## Inputs

- The runner was built from Messenger commit
  `87c6288945f4032ab23a7bc52c37e0ebba7c49b9` with Go 1.26.5 and reported
  `vcs.modified=false`.
- Runner SHA-256:
  `98cc1e88427c5dbf5008bea733b18d228be74d6deb48c11943deb3526428e9c6`.
- ClamAV adapter SHA-256:
  `73e1e87cee2ec662bc6d9c8d69c41008527082948ec9f0a36b2ffce72d7de8f7`.
- ClamAV 1.5.3 used `daily` 28099, `main` 63 and `bytecode` 339 with the
  previously recorded exact external signatures and root certificate.
- The manifest scope explicitly said local plumbing only. It committed a
  43-byte inert text control with SHA-256
  `ba82d8f306f19dc22dbd2b61710d23eec84755b0aeaa8ccc35fc33cfcd43e2c5`
  and a 69-byte newline-terminated EICAR control with SHA-256
  `131f95c51cc819465fa1797f6ccacf9d494aaaff46fa3eac73ae63ffbdfd8267`.
  The private sample files and signing keys were not committed.
- Separately generated local approver and runner public keys were
  `458d8dae947001d84e0e464b3102d7de58b4e4c6b8093ccda23bc1ab8dd3b6da`
  and `a76b0fe9cfaa86919ad4cd0530e501a412b8f8c377efc4c0275d67338d6f3705`.

## Result

The signed manifest file SHA-256 was
`7ca520e60c38d2970324e800714b05dfb3bb684a6d3c53e482e98f0b2f9440ec`.
The exact admission-policy SHA-256 was
`58c78eb29746cd3fc81a142aa69abcb6244b5629fd12561e848068d549068c6c`.
The signed mode-`0600` report SHA-256 was
`255eae67d927ce49841cda3ce479f180691935c6a854ca58e36c66dd52ecbc32`.
Independent `verify` accepted it against both fixed public keys and the raw
manifest/policy files. Its two results were:

```text
clean-control.txt  expected=allow observed=allow reason=clamav_clean       resources=8
eicar-control.bin  expected=deny  observed=deny  reason=malware_detected   resources=8
```

Replacing the policy's pinned `main.cvd` path with a missing file caused a
scanner-infrastructure error on the clean control and produced no report; it
did not count as a deny. Verifying the valid report with the approver key in
place of the runner key failed with `corpus report has another runner`.

## Boundary

This proves strict draft signing, authority pinning, exact sample/policy
identity, real outer-sandbox execution, structured detection versus
infrastructure failure, eight-resource verdict binding, signed result
generation, independent verification, private output modes and key-role
substitution refusal. The same local operator generated both test keys and
selected EICAR, so this evidence makes no claim of organizational independence,
external approval, representative malware coverage, non-text product safety,
or production release acceptance.
