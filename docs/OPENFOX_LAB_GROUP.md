# OpenFox local group-chat acceptance carrier

`tos-messenger-lab-group` closes a development feedback loop without making a
premature M0-R route decision. It lets multiple OpenFox processes create a
room, enforce a fixed member set, exchange messages, and resume from durable
per-Agent cursors over an owner-private Unix socket.

This is not the production Messenger transport and is not MLS. The carrier is
plaintext, same-host, and explicitly named `lab`; it supplies no S1/S2 gate
evidence. Its purpose is to test the OpenFox channel/bus/session integration
while the real-network study, selected native transport, reviewed MLS Driver,
and independent evidence remain open.

## Security and durability boundary

- The HTTP server listens only on a mode `0600` Unix socket and refuses to
  replace a non-socket filesystem object.
- Every request binds a canonical `agent_` identifier to a bearer token. Only
  token hashes are persisted; callers should still use random test-only
  tokens because this is not a password-hardening store.
- Room identifiers and message identifiers are domain-separated SHA-256
  content addresses. Members are sorted and unique; non-members cannot read or
  write a room.
- Message submission is idempotent per `(sender, client_id)`. Reusing that key
  for different content is a conflict.
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

cd ~/openfox
CGO_ENABLED=0 GOWORK=off go build -tags goolm,stdjson \
  -o /tmp/openfox-messenger-lab-demo ./cmd/openfox-messenger-lab-demo
```

Start the carrier with three canonical test Agents and distinct tokens, then
pass the same credentials to `openfox-messenger-lab-demo`. The demo starts
three independent OpenFox channel instances, has the first create the room and
send a message, has both peers reply, and exits non-zero unless the creator
receives both replies. Reusing `-state-dir` exercises restart cursors and
offline history rather than starting a fresh view.

The successful result is one JSON object with `ok: true`, the deterministic
room ID, all three members, and the three-line transcript. Its `mode` is
`local-unix-plaintext-lab`, making the non-production boundary machine-visible
as well as documented.
