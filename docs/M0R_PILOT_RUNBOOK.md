# M0-R pilot runbook

This runs the entire measurement chain — coordinator, both probes, report —
with **one operator and two endpoints**, end to end, against real machines.

Be clear about what that is before starting. A pilot validates the
*operational* path: that the binaries run where they need to run, that the
evidence chain verifies, that the logs aggregate. It produces **no route
evidence whatsoever**, and the tooling will say so itself: the report must
come out `insufficient-evidence` with exit code 1, because one operator on
one or two networks is below every predeclared minimum, and those minimums
exist precisely so that a laboratory result cannot read as a study. **Exit
code 1 with clean per-cell data is this pilot's success, not its failure.**

The pilot exists so that when three or more operators run the real study,
they are debugging networks, not tooling.

## What you need

| Piece | Requirement |
|---|---|
| Coordinator host | One machine with a public IP and two open inbound UDP ports (defaults below use 7691 and 7692). A cheap VPS is fine |
| Endpoint A | Any machine with outbound UDP — ideally behind ordinary home NAT |
| Endpoint B | A second machine in a *different* network situation — ideally the datacenter host itself, or a phone hotspot, so the pair is asymmetric like the pairs the study is about |
| Build | Go 1.26.5, built from a **clean git checkout** — the trial records the commit from build information, and a record that cannot name what it measured is refused |

Two coordinator instances are not decoration: NAT mapping behavior is
classified by comparing the address each one observes, and with a single
vantage point every endpoint behind NAT reports `undetermined`. Both
instances must be reachable — an endpoint that cannot bind against every
listed coordinator refuses to classify itself and records `udp-blocked`.

## 1. Build

On every machine, from the repository root:

```sh
git status            # must be clean; the commit goes into every trial
GOWORK=off go build ./cmd/tos-reachability-coordinator ./cmd/tos-reachability ./cmd/tos-reachability-report
```

## 2. Run the coordinators (public host)

```sh
./tos-reachability-coordinator -listen :7691 -key /var/lib/tos-reachability/coordinator.key
./tos-reachability-coordinator -listen :7692 -key /var/lib/tos-reachability/coordinator.key
```

Each prints one line at start:

```
coordinator_id=srv_… public_key=… listening=…
```

**Record the `coordinator_id`.** It goes into the policy, and a study only
counts attestations from coordinators the policy predeclared — this line is
the thing that has to travel out of band before any measurement is worth
anything. The key file keeps the identity stable across restarts; both
instances may share one key, so one `srv_` identifier covers both ports.

Long-running deployments should use a systemd unit rather than a shell:

```ini
[Unit]
Description=TOS reachability coordinator (%i)
After=network-online.target

[Service]
ExecStart=/usr/local/bin/tos-reachability-coordinator -listen :%i -key /var/lib/tos-reachability/coordinator.key
DynamicUser=yes
StateDirectory=tos-reachability
Restart=on-failure

[Install]
WantedBy=multi-user.target
```

installed as `tos-reachability-coordinator@.service` and started with
`systemctl enable --now tos-reachability-coordinator@7691
tos-reachability-coordinator@7692` (adjust `-key` to
`/var/lib/tos-reachability/coordinator.key`, which `StateDirectory` creates).

## 3. Write the pilot policy

Copy `docs/reachability-policy.example.json` and change exactly one thing:
replace the `coordinators` array with your real `srv_` identifier(s).

Do not shrink the thresholds to make the pilot "pass". The example policy's
minimums are the point; a policy weak enough for one operator to satisfy is
refused by the tooling anyway, and editing thresholds after seeing data is
the failure mode the content-addressed policy digest exists to prevent.

## 4. One UDP pair

Generate one session identifier and give it to **both** endpoints:

```sh
SESSION="ses_$(openssl rand -hex 16)"
```

Both endpoints must start within the pair window (30s by default; the
coordinator remembers a pairing for 5 minutes). On endpoint A:

```sh
./tos-reachability \
  -coordinators host:7691,host:7692 \
  -session "$SESSION" -role a \
  -identity ./endpoint-a.key \
  -operator "your-name" -site "home-fiber" \
  -carrier consumer-isp -endpoint-class desktop \
  -out ./trials-a.jsonl
```

On endpoint B, the same with `-role b`, **its own key file**, its own honest
labels (for a datacenter host: `-carrier datacenter -endpoint-class server`,
`-site` naming that network), writing to its own log.

Three rules that are easy to break and quietly ruin the evidence:

- **Each endpoint has its own identity file.** The two halves of a
  measurement must be signed by two different keys; a pair signed by one key
  is one assertion wearing two hats, and aggregation discards it.
- **Labels describe only the endpoint's own side.** Carrier, class,
  mobility, assistance — each end declares itself; the cell is the ordered
  pair. Never describe the peer.
- **Operator and site names are hashed into opaque identifiers** — they
  never leave the machine in the clear, so use real, stable names. The same
  operator name on both endpoints is correct for a pilot: that *is* the fact
  the report will refuse to decide from.

Each run prints `outcome=… failure=… establish_ms=…` to stderr and appends
one signed JSON trial to `-out`.

## 5. One ADNL pair

Same shape, new session, plus `-probe adnl` on **both** sides:

```sh
SESSION="ses_$(openssl rand -hex 16)"
./tos-reachability -probe adnl -coordinators host:7691,host:7692 \
  -session "$SESSION" -role a -identity ./endpoint-a.key \
  -operator "your-name" -site "home-fiber" \
  -carrier consumer-isp -endpoint-class desktop \
  -out ./trials-a.jsonl
```

The coordinator refuses to pair two endpoints measuring different probes, so
a mixed pair fails at pairing time with a reason, not at report time. Role
`a` initiates the ADNL session; role `b` never dials — both still run the
same command.

Run a few sessions of each probe. Repetition is cheap and exercises the
retry and rate-limit paths a single lucky run skips.

## 6. Aggregate

Collect both logs onto one machine and concatenate:

```sh
cat trials-a.jsonl trials-b.jsonl > study.jsonl
./tos-reachability-report -policy pilot-policy.json -log study.jsonl -probe udp
./tos-reachability-report -policy pilot-policy.json -log study.jsonl -probe adnl
```

Exit codes are the contract: `0` = the report supports a route decision,
`1` = valid report, no route decision, `2` = malformed input or tooling
failure. **A pilot that exits 0 is a bug report, not a success** — file it.

## 7. Success criteria

The pilot is operationally validated when all of these hold, for both
probes:

- [ ] every run produced a trial record without manual intervention;
- [ ] `outcome=direct-established` on paths where it plausibly should be
      (and a *classified* failure, never `internal-error`, elsewhere);
- [ ] the report exits `1` with finding `insufficient-evidence`;
- [ ] `unverified_trials` is 0 — every signature and attestation held;
- [ ] `incomplete_pairs` is 0 — every session produced both halves and they
      agreed;
- [ ] each cell in the report shows the ordered pair of endpoint strata you
      actually declared, with `samples` matching the sessions you ran;
- [ ] the ADNL report's kind is `route-decision` and the UDP report's is
      `network-feasibility`.

## 8. Troubleshooting

| Symptom | Likely cause |
|---|---|
| `failure=udp-blocked` immediately | a listed coordinator is unreachable — both must be up, and the endpoint refuses to classify itself from a partial view |
| `failure=no-candidate` | the peer never paired: session identifiers differ, the peer started outside the window, or it spoke to a different coordinator |
| `the two endpoints are measuring different probes` | one side forgot `-probe adnl` |
| `failure=handshake-timeout` on ADNL where UDP succeeded | genuinely interesting — the datagram path passes and the session does not; re-run to confirm, then keep the record. This divergence is the reason the ADNL probe exists |
| `unverified_trials > 0` | the policy's `coordinators` entry does not name the coordinator that actually attested — rebuild the policy from the startup line |
| `incomplete_pairs > 0` | both endpoints used the same identity file, or one side's record never made it into the combined log |
| report exit `2` | truncated or hand-edited JSONL, or a policy the tooling refuses — read the stderr line |
| coordinator silent | it answers only well-formed probe datagrams and never amplifies; check the port with the endpoint tool itself, not with netcat |

## 9. After the pilot

What stands between this and a real study is not tooling:

1. **≥3 operators, ≥3 sites** per required scenario, each with their own
   keys and their own honest labels, coordinators predeclared in one shared
   policy whose digest everyone records;
2. scenario coverage per the policy: home NAT, carrier-grade NAT, mobile,
   datacenter, in the asymmetric pairs the policy names;
3. before a route decision frozen on ADNL evidence is **acted on**, a
   cross-check of the collector against the TOS node's own adnl stack (every
   trial names the collector commit, so the provenance is already recorded).

A pilot log must never be mixed into a real study log. The policy digest in
every report says which policy judged it; keep the pilot's artifacts, and
start the real study with a fresh log.
