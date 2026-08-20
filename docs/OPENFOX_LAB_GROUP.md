# OpenFox local group-chat acceptance carrier

`tos-messenger-lab-group` plus `tos-messenger-openfox-mls` close a development
feedback loop without making a premature M0-R route decision. They let three
OpenFox processes create a room, invite members with real OpenMLS transitions,
exchange encrypted messages, and resume from durable per-Agent state.

This is not the production Messenger route. Each Agent proxy has its own
mode-`0600` Unix socket and private OpenMLS snapshot; only that proxy sees its
OpenFox plaintext. The shared lab Hub sees room metadata and ciphertext, never
plaintext or private snapshots. The `lab` suffix remains because real-network,
independent-operator, review, and second-implementation evidence remain open.

## Security and durability boundary

- Every HTTP server listens only on a mode `0600` Unix socket and refuses to
  replace a non-socket filesystem object.
- Every request binds a canonical `agent_` identifier to a bearer token. Only
  token hashes are persisted; callers should still use random test-only
  tokens because this is not a password-hardening store.
- Room identifiers and message identifiers are domain-separated SHA-256
  content addresses. Members are sorted and unique; non-members cannot read or
  write a room.
- Message submission is idempotent per `(sender, client_id)`. Reusing that key
  for different content is a conflict; exact retries reuse the persisted MLS
  ciphertext and do not advance the sender ratchet twice.
- Bootstrap creates distinct KeyPackages and sequential Welcome/Commit epochs.
  Runtime MLS state is persisted before ciphertext publication or plaintext
  release. Room, sender, and retry-stable client ID are authenticated data.
- A modified ciphertext is refused without advancing durable receiver state.
- The Relay file contains base64 MLS PrivateMessages, not conversation text or
  any Agent's opaque private snapshot.
- The bounded state file is replaced atomically and fsynced with its directory.
  On restart, room/message commitments are re-derived so tampering fails
  closed.
- OpenFox advances and fsyncs a per-room cursor only after publishing an
  inbound message to its native bus. A crash may therefore redeliver the last
  message, but cannot silently skip it.

## Three-OpenFox acceptance run

Build both commands:

```sh
cd ~/tos-messenger
GOWORK=off go build -o /tmp/tos-messenger-lab-group ./cmd/tos-messenger-lab-group
GOWORK=off go build -o /tmp/tos-messenger-openfox-mls ./cmd/tos-messenger-openfox-mls

cd ~/openfox
CGO_ENABLED=0 GOWORK=off go build -tags goolm,stdjson \
  -o /tmp/openfox-messenger-lab-demo ./cmd/openfox-messenger-lab-demo
```

First run `tos-messenger-openfox-mls -mode bootstrap` with a creator, label and
three repeated `-member` values. Start the opaque carrier, then one
`tos-messenger-openfox-mls -mode serve` process per Agent with distinct state
and socket paths. Pass those paths as repeated `agent_id=socket` `-proxy`
values to `openfox-messenger-lab-demo -encrypted`. The demo has the creator
send, both peers reply, and exits non-zero unless the creator receives both.
Reusing both state directories after stopping every process proves restart.

The successful result is one JSON object with `ok: true`, the deterministic
room ID, all three members, and the three-line transcript. Its `mode` is
`local-unix-openmls-ciphertext-relay`, making both encryption and the
non-production boundary machine-visible. Direct legacy Hub connections remain
available only as the explicitly marked `local-unix-plaintext-lab` fixture.
