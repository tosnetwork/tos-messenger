# Private room role policy

Private-room membership answers who may receive and post encrypted room
events. It must not silently answer who may administer the room. The v1 role
policy therefore grants only elevated powers and treats an unlisted current
member as an ordinary member.

## Bounded policy

- `administrator`: may request membership changes, role changes, authority
  transfer, and moderation;
- `moderator`: may request moderation only;
- ordinary current member: may post only;
- removed Agent: has no power, even if an older signed policy named it.

One policy contains at most four administrators and sixteen moderators. The
current single room authority must remain an administrator. The policy is
bound to the network, Room ID, exact membership epoch and digest, monotonic
role-policy revision, current authority Agent/Endpoint, and a maximum 24-hour
signature window.

`pkg/room` owns the strict codec, Ed25519 signing preimage, validation, and
authorization questions. `pkg/eventlog.RoomRoleLedger` owns crash-safe
single-writer persistence. Every authorization rechecks the signed policy
against the current durable membership and live finalized Endpoint
delegation. A membership transition therefore makes the old policy stale
without copying privilege into the new epoch; the authority must sign the
next revision for the new member set.

This policy does not let transport arrival, MLS leaf ownership, or Relay order
grant a role. It also does not yet define moderation-event effects or public
channel roles; those remain separate work.
