# Three-OpenFox latest-main restart acceptance — 2026-08-22

This is reproducible same-host operator evidence for the local encrypted group
composition. It does not satisfy M0-R, selected-route, public-network,
independent-operator, or independent OpenMLS review gates.

## Source and deployed artifacts

- `tos-messenger`: `74e7cc2ce783660702a0a89a7019598d3d857db2`
- OpenFox: `6b997b638b7a99dd95f56bf6f35e91557f1cf7cf`
- `tos-messenger-lab-group` SHA-256:
  `ac7a9fd9f4addeaa1edc47a4e52b77fd71b8385c2c6a347862d6dda3abda9bd0`
- `tos-messenger-openfox-mls` SHA-256:
  `8f4dfeaeceb64499eb380c154760413b67ac6888ecf0cb418ad2e11540c2a74f`
- `tos-openmls-driver` SHA-256:
  `4abfcc49acb24481b0b51319b8ca2f9cbe906c90fbccb156946f76e651111ceb`
- `openfox-messenger-lab-agent` SHA-256:
  `9ae8e4803aa20cbbeefe242ef90486437170c54681ff0cb8ae8aee0fac81960a`
- `openfox-messenger-lab-deploy` SHA-256:
  `478fa67c52684fec6c000e1ca6c7b439103d427b326ecbe81c162c3041ed08aa`

The Messenger group/MLS packages, commands and pinned Rust driver passed
`make test-openmls` and
`GOWORK=off go test -race -count=1 ./pkg/labgroup ./pkg/mlslab
./cmd/tos-messenger-lab-group ./cmd/tos-messenger-openfox-mls`. The OpenFox
channel, long-running Agent and deployment packages passed
`GOWORK=off go test -race -count=1 ./pkg/channels/tosmessengerlab
./cmd/openfox-messenger-lab-agent ./cmd/openfox-messenger-lab-deploy`.
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

Alice submitted stable request `acceptance-20260822-main-74e7cc2-v1` with
content `process-probe: Messenger 74e7cc2 and OpenFox 6b997b63 latest-main
acceptance`. Its Event was:

`msg_fceeaf99b9eb548722b6f7e7cc9c245ad35caffd89de4c370c33eedffd3e5be9`

Bob and Carol each ran their own AgentLoop and emitted exactly one reply bound
to that Event:

- Bob: `msg_4eb9058f5c8b8980444f51e23c557339711b75bb36aaec646c54f1fb606b85e3`
- Carol: `msg_5f9eb35211859e0b71316f15a61e4563d066c89949f1fecde3800574b9f11b85`

Every Agent transcript converged on exactly those three IDs. The two producers
marked their outbound reply with `runtime: openfox-agent-loop`; recipients
retained the authenticated `reply_to_event_id`.

## Full restart and replay

All seven units were restarted together. Each control socket became healthy,
retained the same room, exact Agent identity, active membership and
`agent-loop` mode. The exact same request/body returned the original Event ID.
Each transcript contained 120 total records and exactly the same three matching
acceptance records with three unique IDs. Bob and Carol each retained exactly
one outbound record for their reply, proving no second Agent turn or duplicate
reply was introduced by restart/replay.

The Relay state was mode `0600`. An exact search found none of the submitted
plaintext. The Relay therefore retained only opaque MLS carriage for this run;
the private MLS snapshots and OpenFox transcripts remained in their separate
owner-private state paths.

At `2026-08-22 06:36:38 UTC`, all seven units entered their current
`active/running` generation after the clean-artifact redeployment. A subsequent
health, transcript and exact-request retry check reproduced the facts above.
This evidence proves the local runnable/restartable OpenFox group-chat precursor
on those repository commits. It deliberately does not claim an accepted live
route, public-network result, independent operation, independent OpenMLS review,
or a second interoperable implementation.
