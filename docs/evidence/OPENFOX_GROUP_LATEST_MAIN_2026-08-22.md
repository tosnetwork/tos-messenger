# Three-OpenFox latest-main restart acceptance — 2026-08-22

This is reproducible same-host operator evidence for the local encrypted group
composition. It does not satisfy M0-R, selected-route, public-network,
independent-operator, or independent OpenMLS review gates.

## Source and deployed artifacts

- `tos-messenger`: `856605168e23c0fa4df05b1cfa6db98058f23428`
- OpenFox: `6b997b638b7a99dd95f56bf6f35e91557f1cf7cf`
- `tos-messenger-lab-group` SHA-256:
  `f49ff691f1ce564db9c5b65cb017aebca10217516ef8c2015ed45c6605227a88`
- `tos-messenger-openfox-mls` SHA-256:
  `16763dba65050ce93949ce3ed3ad0b43a2f6c63c68bcb72b0cc1a1d1cde45dbe`
- `tos-openmls-driver` SHA-256:
  `4abfcc49acb24481b0b51319b8ca2f9cbe906c90fbccb156946f76e651111ceb`
- `openfox-messenger-lab-agent` SHA-256:
  `9ae8e4803aa20cbbeefe242ef90486437170c54681ff0cb8ae8aee0fac81960a`
- `openfox-messenger-lab-deploy` SHA-256:
  `ba0bbd80d98e1912d4598bca9b8fc3c3c3188132182e88b4515f5d9b4f71c6fc`

The Messenger group/MLS packages and pinned Rust driver passed their focused
tests. The OpenFox channel, long-running Agent and deployment packages passed
their focused tests. The binaries above were rebuilt from those exact commits
and installed before the run.

## Process and message evidence

Systemd-user supervised seven independent processes: one opaque Relay, three
owner-private MLS proxies, and three OpenFox processes using the real
`AgentLoop.Run` path. All health responses reported the same room
`room_2f58a0e48fd6ff8f52653abc51cf3b87762f604a7af903bed5a110d8073d4fd5`,
their exact distinct Agent identity, `active_member: true`, and
`reply_mode: agent-loop`.

Alice submitted stable request `acceptance-20260822-latest-main-v1` with the
explicit acceptance trigger. Its Event was:

`msg_61e4b1b4f1c1ca6177a25a7f9b79aa98a0bb55e2bb44747ebe63287fe3d0617c`

Bob and Carol each ran their own AgentLoop and emitted exactly one reply bound
to that Event:

- Bob: `msg_9af95022575bdf0e9e800cf4481aacee2ee5ffe90992136df07b9ac75ab8518e`
- Carol: `msg_3f00fde1893400fa7ecd7e795b79c93b7768dcd4f493543390f0ed3327b470f8`

Every Agent transcript converged on exactly those three IDs. The two producers
marked their outbound reply with `runtime: openfox-agent-loop`; recipients
retained the authenticated `reply_to_event_id`.

## Full restart and replay

All seven units were restarted together. Each control socket became healthy,
retained the same room and active membership, and the exact same request/body
returned the byte-identical response and original Event ID. Every transcript
still contained exactly three matching records and three unique IDs, proving
no second Agent turn or duplicate reply was introduced by restart/replay.

The Relay state was mode `0600`. An exact search found none of the submitted
plaintext. The Relay therefore retained only opaque MLS carriage for this run;
the private MLS snapshots and OpenFox transcripts remained in their separate
owner-private state paths.

At `2026-08-22T04:58:55Z`, all seven units were `active/running` after the
restart. This evidence proves the local runnable/restartable OpenFox group-chat
precursor on the then-current repositories. It deliberately does not claim an
accepted live route or independent operation.
