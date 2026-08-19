# Running the daemon

`tos-messengerd` owns one state directory and serves two owner-private sockets.
It cannot carry a message yet, and it says so on startup rather than looking
like a working installation that happens to be quiet.

```sh
tos-messengerd -config /etc/tos-messengerd/config.json -check   # validate and exit
tos-messengerd -config /etc/tos-messengerd/config.json
```

## Two sockets

The runtime connects to one socket and the owner to another, and the
separation carries one invariant: **the party that asks for an approval must
not be able to grant it.** A single socket with a user check cannot tell an
Agent runtime from the person it is asking, so an Agent deciding that a payment
needs approval could answer itself.

The runtime socket carries inbox draining and event submission and no approval
operation at all. The owner socket carries the decisions and does no Agent
work.

## What must be stated

Nothing about acceptance has a default, because a default here is a decision
nobody made:

- the **network tuple** the installation belongs to;
- the **registries** whose finalized state it accepts, since typed TVM state is
  only meaningful under the contract that produced it. Each entry carries the
  contract's code as well as its hash, because an Agent's account address is
  recomputed from the code: a resolver could otherwise return the right Agent
  record read from an account of its own choosing. The code must hash to the
  pinned digest, and the example file's value is a placeholder rather than a
  deployed registry;
- **who this installation speaks for** — its Agent, endpoint and device — since
  an outbound event must say it came from here; and
- the **firewall ceilings**, which say what the Agent may do unattended: one
  for what it reaches on its own initiative, and a tighter one for anything a
  received message drove. Neither may be raised to a key or to this
  installation's own configuration, whatever an operator writes; and
- the **transport**, which today can only be `"none"`.

An unknown key in the configuration is refused rather than ignored. A
misspelled setting that is silently dropped is a setting an operator believes
is in force.

`docs/daemon-config.example.json` is a complete file with placeholder values.

## What `"transport": "none"` means

Outbound events are queued durably and never sealed. No route has been chosen,
and sealing for a transport that does not exist would spend a message key per
event on nothing. Queued events wait; they are not lost and they are not
delivered.

The local API still works: a runtime can drain the inbox and submit events, and
an owner can admit or refuse an inbound message that is waiting, and release or
abandon a held outbound one. What is missing is the middle,
and it stays missing until the reachability study picks a route.

## State

The state directory holds the journal and the install salt, and one daemon owns
it at a time through a lock file. A second daemon on the same directory fails
immediately rather than interleaving writes with the first.

The install salt is generated once and kept. It is what makes decision records
correlatable within one node and meaningless elsewhere, so a salt regenerated
on each start would stop a node's own records from correlating with themselves.

The socket lives outside the state directory, in a private directory this
daemon creates and verifies. A stale socket from a dead process is removed; a
live one is not, because ownership of the state is decided by the lock and
unlinking another daemon's socket would take its callers without taking its
ownership.

## Shutdown

`SIGINT` and `SIGTERM` both mean stop taking work and release the state. The
daemon closes the socket, removes it, and releases the directory lock before
exiting, so a replacement starts without an operator cleaning up first.

## Maintenance

On its own schedule the daemon settles outbound events that outlived their own
expiry, then removes finished records past the retention floor. Expiry runs
first so that an event which has just expired is removed in the same pass
rather than a maintenance interval later.

Damaged records are reported and kept. A corrupt claim fails closed and blocks
its own event; deleting corrupt files would turn damaging a record into
replaying it.
