# TOS-MLS v1 application adapter (candidate)

This repository now implements the route-neutral, application-side invariants
around an RFC 9420 implementation. It does **not** implement TreeKEM, HPKE, the
MLS key schedule, or MLS message parsing. Those operations must come from a
reviewed RFC 9420 library through `group.Driver`; passing the application tests
does not make a Driver cryptographically sound.

The implemented boundary consists of:

- suite `0x0001` only, and a Driver hook that must parse the KeyPackage and
  match its LeafNode signing key;
- an endpoint-signed per-device credential binding the exact network tuple,
  Agent, Endpoint, Device, current device-set digest, distinct Ed25519 leaf
  signing public key, exact KeyPackage bytes, and validity window;
- strict JSON publication plus a domain-separated canonical signature preimage
  and committed positive/adversarial vectors;
- explicit `room_epoch` and `mls_epoch` clocks. Agent membership advances both;
  device churn and PCS refresh may advance only `mls_epoch`;
- deterministic conversion of an accepted device-set succession to MLS leaf
  Add/Remove/Update work. Removing one device leaves the Agent's other devices
  present;
- a crash-safe ledger for opaque library state, current clocks, membership
  commitment, accepted commit parent, globally consumed one-time KeyPackages,
  and processed Welcomes. Exact replay is idempotent; rollback, gaps, state
  substitution, duplicate Welcomes, KeyPackage reuse, and competing children
  fail closed.

## Required call order

For a published KeyPackage, resolve and verify the finalized Endpoint
delegation and current device set first. Decode and bind the credential with
`group.BindDeviceCredential`, then require the selected Driver to validate the
RFC 9420 KeyPackage against suite `0x0001` and the credential's leaf key. A
syntactically valid MLS credential or KeyPackage is never TOS authority by
itself.

After `Join`, atomically install the returned opaque state with
`eventlog.MLSLedger.InstallWelcome`. After `Commit` or `Apply`, validate the
application transition and durably install the next opaque state with
`Advance` before exposing membership or plaintext dependent on that state.
Relays may deliver these bytes, but Relay order never chooses a commit.

## Still open — why this remains 🟡

- integrate and review OpenMLS behind a concrete `group.Driver`; suite `0x0001`
  is selected, but the cryptographic Driver is not yet integrated;
- specify the BasicCredential identity bytes and network-bound MLS group
  identifier using the decided raw-32-byte canonical genesis hashes and commit
  new domains, schemas, and positive/adversarial vectors;
- enforce the selected single current-authority Agent rule and its explicit,
  current-authority-signed, single-step transfer;
- real MLS founding, join/no-past, remove/no-future, exporter separation and
  PCS vectors executed through the selected Driver;
- offline multi-Relay catch-up using the eventual post-M0-R transport;
- independent cryptographic review and a second MLS implementation cross-check.

The committed device-credential vector is a candidate-profile change detector,
not freeze evidence. A future decision that changes its preimage must use a new
schema/domain version and replace the candidate vector loudly.
