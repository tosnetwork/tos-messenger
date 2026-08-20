# Private room moderation

Private-room moderation is an authenticated presentation overlay, not message
deletion. The immutable encrypted Event and its application history remain
available for audit; the latest authorized decision determines whether a
queued `room.message` is offered to an Agent runtime.

`room.moderation` carries the Room ID, membership epoch, role-policy revision,
target Event ID, per-target decision revision, `hide` or `restore`, and a
bounded reason. The Event is content-addressed and authenticated through the
ordinary Messenger ingress. `eventlog.ModerationLedger` additionally requires:

- a live sender Endpoint delegation authorized for the `room` class;
- the current durable membership epoch and role-policy revision;
- a current Administrator or Moderator assignment;
- an existing immutable `room.message` target in the same room; and
- exact next-revision succession for that target.

The first decision is revision 1. Exact Event retry is idempotent; rollback,
revision gaps, ordinary-member attempts, stale roles after member removal,
cross-room targets, and damaged durable decisions fail closed. `hide` removes
a queued target from `Journal.ListPending` without deleting it. `restore`
makes it eligible again. A target already consumed by a runtime cannot be
unseen; downstream user interfaces need an explicit retraction presentation
if they display applied history.

This is the private-room effect. Public-channel moderation, independent Relay
ordering, and transport delivery remain separate milestones.
