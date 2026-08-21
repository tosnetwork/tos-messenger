# Private-room prior-history policy

Version 1 is **join-forward only**. A new MLS leaf starts at the epoch carried
by its authenticated Welcome and receives no room plaintext, exporter secret,
or application secret from an earlier epoch. Replacing a device creates a new
leaf with the same rule; replacement is not authority to copy the old device's
room history.

This is a protocol policy, not a user-interface default. No administrator,
moderator, OpenFox runtime, Relay, or local owner API can override it in v1.

## Allowed catch-up

An existing leaf may fetch and process ordered opaque MLS traffic that was
addressed to it while it was a member. It must begin from its durable Relay
cursor and apply every authenticated Commit in order. This is ordinary
offline catch-up within the leaf's own membership interval; it does not reveal
an epoch for which the leaf never held secrets.

A removed leaf stops at its durably authenticated removal boundary. Continued
Relay delivery is harmless only when later ciphertext remains undecryptable.

## Forbidden backfill

The following are rejected rather than treated as migration conveniences:

- exporting a Room ID through the direct-device history API;
- placing a room Event inside `device.history.segment`;
- copying decrypted room transcripts to a new or replacement leaf;
- exporting old MLS epoch or exporter secrets; and
- asking a Relay or OpenFox process to reinterpret stored ciphertext as
  plaintext history.

The direct-device history path remains limited to a `conv_` identifier and
canonical Events with an empty Room ID. Imported segments are display-only,
but that safety property does not make room plaintext backfill acceptable.

## Evidence

The pinned OpenMLS integration proves that a joiner cannot decrypt a message
sealed before its Welcome and that a replacement device cannot decrypt a
message sealed before its replacement Commit. The event-log suite proves both
directions of the application boundary: a Room ID cannot address an export and
a room Event inside an imported direct-history segment is rejected.

Changing this policy requires a new version with separate authority, privacy,
retention, moderation-projection, transcript-integrity, and cryptographic
review. It must not weaken MLS no-past secrecy by transferring old epoch keys.
