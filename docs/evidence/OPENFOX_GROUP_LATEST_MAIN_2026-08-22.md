# Three-OpenFox latest-main restart acceptance — 2026-08-22

This is reproducible same-host operator evidence for the local encrypted group
composition. It does not satisfy M0-R, selected-route, public-network,
independent-operator, or independent OpenMLS review gates.

## Source and deployed artifacts

- `tos-messenger`: `74e7cc2ce783660702a0a89a7019598d3d857db2`
- OpenFox: `aa02f93e4eeaad5cfb30322880373fbd7cb04f32`
- `tos-messenger-lab-group` SHA-256:
  `ac7a9fd9f4addeaa1edc47a4e52b77fd71b8385c2c6a347862d6dda3abda9bd0`
- `tos-messenger-openfox-mls` SHA-256:
  `8f4dfeaeceb64499eb380c154760413b67ac6888ecf0cb418ad2e11540c2a74f`
- `tos-openmls-driver` SHA-256:
  `4abfcc49acb24481b0b51319b8ca2f9cbe906c90fbccb156946f76e651111ceb`
- `openfox-messenger-lab-agent` SHA-256:
  `84cfb1b2b0b4bd43e8bb1a055c7875a18356b43e70b7a0dde433596af8a5d3d2`
- `openfox-messenger-lab-deploy` SHA-256:
  `ffb59d56a905919e3354f8cd32a729a05a111110ee80f0e03f54421f9fb8c2d1`
- `openfox-messenger-lab-verify` SHA-256:
  `29515e03cf3a95562a93775cb22457583fcac5eb549fdc9d7a356d40e0b419b6`

The Messenger group/MLS packages, commands and pinned Rust driver passed
`make test-openmls` and
`GOWORK=off go test -race -count=1 ./pkg/labgroup ./pkg/mlslab
./cmd/tos-messenger-lab-group ./cmd/tos-messenger-openfox-mls`. The OpenFox
channel, long-running Agent, deployment and verifier packages passed
`GOWORK=off go test -race -count=1 ./pkg/channels/tosmessengerlab
./cmd/openfox-messenger-lab-agent ./cmd/openfox-messenger-lab-deploy
./cmd/openfox-messenger-lab-verify`. OpenFox's complete `make check`, strict
golangci-lint v2.10.1 gate, security scan and integration CI also passed.
Messenger binaries were rebuilt from a clean detached worktree at exact commit
`74e7cc2ce783660702a0a89a7019598d3d857db2`; OpenFox binaries were rebuilt
from its clean `main` checkout. Those artifacts were installed before the
acceptance round.

## Process and message evidence

Systemd-user supervised seven independent processes: one opaque Relay, three
owner-private MLS proxies, and three OpenFox processes using the real
`AgentLoop.Run` path. All health responses reported the same room
`room_2f58a0e48fd6ff8f52653abc51cf3b87762f604a7af903bed5a110d8073d4fd5`,
their exact distinct Agent identity, `active_member: true`, and
`reply_mode: agent-loop`.

Alice submitted stable request `acceptance-aa02f93e-20260822-v1` with content
`process-probe: final OpenFox main aa02f93e restart acceptance 2026-08-22`.
Alice's durable outbound record also bound that exact request ID before the
verifier was allowed to replay it. Its Event was:

`msg_e387831755d1aad4ccaeb6e198f2c9ed8081ab8644b0453f0cb90fdab6cc15c5`

Bob and Carol each ran their own AgentLoop and emitted exactly one reply bound
to that Event:

- Bob: `msg_82e86a102fe79950291fd01792eb48032938121dccc1769b7b63a2c522aaaffa`
- Carol: `msg_70fe4912aa5996b4a5a955baee5513f2d9ec9f511885900522f6143271497eea`

Every Agent transcript converged on exactly those three IDs. The two producers
marked their outbound reply with `runtime: openfox-agent-loop`; recipients
retained the authenticated `reply_to_event_id`.

## Full restart and replay

All seven units were restarted together. Each control socket became healthy,
retained the same room, exact Agent identity, active membership and
`agent-loop` mode. The exact same request/body returned the original Event ID.
Each transcript contained 123 total records and exactly the same three matching
acceptance records with three unique IDs. Bob and Carol each retained exactly
one outbound record for their reply, proving no second Agent turn or duplicate
reply was introduced by restart/replay.

The verifier compared each complete pre/post transcript, not only its count or
the three selected records. It also proved the Relay file identity and bytes did
not change during replay. The Relay state was mode `0600`, 152,784 bytes, with
SHA-256 `c2a3761d517febdacde3d17a9af9363c8848897b642c39cd7f4c04632a4caf50`.
An exact search found none of the opening or reply plaintexts. The Relay
therefore retained only opaque MLS carriage for this run; the private MLS
snapshots and OpenFox transcripts remained in separate owner-private paths.

At `2026-08-22 07:45:45 UTC`, all seven units entered their current
`active/running` generation after the clean-artifact redeployment. Their seven
main PIDs were distinct, each unit reported `NRestarts=0`, and hashing every
`/proc/<pid>/exe` reproduced the pinned Agent, proxy or Relay artifact digest.
At `2026-08-22T07:46:26.591434907Z`, the installed verifier reproduced all
facts above and emitted the machine-readable report in
[`OPENFOX_GROUP_LATEST_MAIN_2026-08-22.json`](OPENFOX_GROUP_LATEST_MAIN_2026-08-22.json).
This evidence proves the local runnable/restartable OpenFox group-chat precursor
on those repository commits. It deliberately does not claim an accepted live
route, public-network result, independent operation, independent OpenMLS review,
or a second interoperable implementation.
