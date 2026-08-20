# Peer discovery bootstrap and daemon wiring

The production route-neutral discovery chain is now assembled by
`tos-messengerd` when configuration selects `"discovery": {"mode":
"tos-dht-https"}`. This is independent of `"transport": "none"`: discovering
verified identity and prekeys neither selects a message route nor sends a
message.

## Why bootstrap is explicit

A Messenger locator's DHT key is derived from the delegated Endpoint public
key. An Agent ID alone therefore cannot locate the delegation needed to derive
that key. Pretending otherwise would hide a central Agent→Endpoint directory
inside the implementation.

The daemon instead requires an operator-provisioned mapping for each bounded
peer:

- Agent ID → delegation JSON file; and
- Agent ID → descriptor-policy JSON file.

These files are rendezvous, not authority. Every refresh rereads them, verifies
the delegation digest against the current finalized Agent, checks revocation
and validity, and requires the strict policy document to reproduce the digest
the delegation committed. Only then is the Endpoint-derived DHT locator read,
followed by the locator-committed descriptor and descriptor-committed signed
prekey set.

Files must be absolute, clean, non-empty bounded regular files. The reader
compares the path object with the opened file before consuming it, so a symlink
or replacement between inspection and open fails rather than redirecting the
daemon. Atomic regular-file replacement remains the supported rotation path.

## Daemon lifecycle

Daemon configuration schema v3 states discovery separately from transport. In
production mode it requires a bounded local TOS global configuration, 1–4096
distinct non-local peers, absolute delegation and policy paths, bounded HTTPS
timeouts, a 30-second to 24-hour refresh interval, and a refresh lead no longer
than that interval. `-check` validates shape without reading files or opening
the network.

Normal startup reads the bounded DHT configuration, requires 1–256 parsed and
at least one cryptographically accepted bootstrap node, starts an ephemeral
ADNL client identity, constructs the TOS DHT and hardened HTTPS sources, builds
the finalized Agent resolver, and opens the durable device ledger. Any failure
prevents sockets from opening and releases state/network resources.

The refresh manager runs with the daemon context. Failures are observable and
never extend an old snapshot's expiry. Shutdown cancels refreshes, closes HTTPS
idle connections and DHT/ADNL state, then releases the journal. The daemon does
not publish peer delegation documents, select routes, seal events, or turn a
successful discovery fetch into transport authority.

## Network representation boundary

Messenger JSON and canonical objects use bare lowercase genesis hash hex. The
upstream Native locator API requires `sha256:`-prefixed boundary syntax. The
daemon adds the prefix only when constructing that SDK locator; `chainagent`
first verifies returned Native state still names that exact prefixed network,
then copies it into the bare Messenger representation before identity checks.
It never overwrites an unverified foreign network into the local one.
