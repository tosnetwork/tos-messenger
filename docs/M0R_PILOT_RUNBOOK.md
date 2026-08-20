# M0-R pilot runbook

This runs the entire measurement chain — coordinators, both probes, the
tunnel relay, report — with **one operator and two endpoints**, end to end,
against real machines.

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
| Coordinator host | One machine with a public IP and three open inbound UDP ports (defaults below use 7691 and 7692 for the coordinators and 7693 for the tunnel relay). A cheap VPS is fine. The coordinators' cold filter sockets need no inbound rule — they only ever send |
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
GOWORK=off go build ./cmd/tos-reachability-coordinator ./cmd/tos-reachability ./cmd/tos-reachability-tunnel ./cmd/tos-reachability-report
```

## 2. Run the coordinators (public host)

```sh
./tos-reachability-coordinator -listen :7691 -key /var/lib/tos-reachability/coordinator-7691.key
./tos-reachability-coordinator -listen :7692 -key /var/lib/tos-reachability/coordinator-7692.key
```

Each prints one line at start:

```
coordinator_id=srv_… public_key=… listening=… filter_port_source=…
```

`filter_port_source` is the cold second-port socket the NAT filtering
receipts are probed from; it is on by default (`-filter-listen`, which must
share the primary address). If the host holds a second public address, add
`-filter-secondary-listen` on one instance to also exercise the
`other-address` cold source — a pilot without one still validates the
second-port path, which is all a single-address host can honestly measure.
The cold sockets are write-only, so no inbound firewall rule is needed for
them.

**Record the `coordinator_id`.** It goes into the policy, and a study only
counts attestations from coordinators the policy predeclared — this line is
the thing that has to travel out of band before any measurement is worth
anything. The key file keeps the identity stable across restarts. Give each
instance **its own key** and predeclare both `srv_` identifiers: the verifier
derives the NAT mapping class from bind reflections of *distinct*
coordinators, so two instances wearing one identity leave that derivation
`undetermined` and the cross-check idle. Sharing one key still runs, but it
validates less of the evidence chain than a pilot is for.

Long-running deployments should use a systemd unit rather than a shell:

```ini
[Unit]
Description=TOS reachability coordinator (%i)
After=network-online.target

[Service]
ExecStart=/usr/local/bin/tos-reachability-coordinator -listen :%i -key /var/lib/tos-reachability/coordinator-%i.key
DynamicUser=yes
StateDirectory=tos-reachability
Restart=on-failure

[Install]
WantedBy=multi-user.target
```

installed as `tos-reachability-coordinator@.service` and started with
`systemctl enable --now tos-reachability-coordinator@7691
tos-reachability-coordinator@7692` (the per-instance key lives under
`/var/lib/tos-reachability/`, which `StateDirectory` creates).

## 3. Write the pilot policy

Copy `docs/reachability-policy.example.json` and change exactly one thing:
replace the `coordinators` array with your real `srv_` identifier(s).

Do not shrink the thresholds to make the pilot "pass". The example policy's
minimums are the point; a policy weak enough for one operator to satisfy is
refused by the tooling anyway, and editing thresholds after seeing data is
the failure mode the content-addressed policy digest exists to prevent. The
same goes for the session gates the v2 policy predeclares — the survival and
reconnect rates and their attempted-sample floors — which the route decision
reads alongside the establishment rates.

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

Each run prints `outcome=… failure=… establish_ms=… survival_s=…
reconnect_ms=…` to stderr and appends one signed JSON trial to `-out`. The
trial also carries the coordinator-signed bind reflections and filtering
receipts (`bind_observations`, `filtering_observations`) the verifier derives
the NAT classes from.

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

Then run at least one ADNL session with a short hold and a reconnect, which
exercises the post-establishment phases. Add `-hold 30s` on **both** sides —
survival needs both halves, and a pair where only one end held contributes
nothing to the survival percentile — and `-reconnect` on role `a` only, since
only the initiator can deliberately drop and re-dial (`-reconnect` without
`-hold` is refused, `-reconnect` on role `b` is refused rather than silently
ignored — a run that measured nothing the operator asked for must not look
like one that did — and all three phase flags are refused with `-probe udp`):

```sh
SESSION="ses_$(openssl rand -hex 16)"
./tos-reachability -probe adnl -hold 30s -reconnect \
  -coordinators host:7691,host:7692 \
  -session "$SESSION" -role a -identity ./endpoint-a.key \
  … # labels and -out as before
```

Role `b` runs the same with `-role b` and **without** `-reconnect`. Expect
both halves to report `survival_s=30` (or the measured shorter span) and the
initiator's half a nonzero `reconnect_ms`; the responder's `reconnect_ms=0`
means "not measured", which is correct. Keepalives are paced by `-keepalive`
(2s when unset), so the run takes the hold window plus margins — start both
sides inside the pair window as usual and let them finish.

## 6. One tunnel fallback pair

The proxy-fallback path runs only when the direct phase ends without a
session, so a pilot has to make the direct path fail while leaving the
coordinators and the relay reachable. Manufacturing that failure is fine
here, for exactly the reason the pilot contributes nothing to a study: this
run validates the fallback tooling, not any network.

Start the relay on the public host (it needs no key — it attests to nothing,
and a trial that went through it is recognisable by its own outcome):

```sh
./tos-reachability-tunnel -listen :7693
```

On endpoint A, block direct UDP toward the public host except the
coordinator and relay ports, so the ADNL handshake toward the peer's
rendezvous port is dropped while the measurement infrastructure stays
reachable:

```sh
sudo iptables -I OUTPUT -p udp -d <host-ip> -m multiport ! --dports 7691,7692,7693 -j DROP
```

Then run one ADNL pair as in step 5 (a fresh session, no `-hold` or
`-reconnect` — survival and reconnect are direct-session properties and are
never measured over the tunnel), adding `-tunnel host:7693` on **both**
sides: the fallback is a double registration, so a side without the flag
never registers and the relay forwards nothing. Expect
`outcome=proxy-fallback` with `failure=handshake-timeout` on both halves —
the fallback keeps the failure class of the direct phase it fell back from,
which is what the trial schema requires of that outcome. Remove the firewall
rule afterwards:

```sh
sudo iptables -D OUTPUT -p udp -d <host-ip> -m multiport ! --dports 7691,7692,7693 -j DROP
```

The adnl probe can also speak through the node's own ADNL stack instead of
the in-process gateway: `-adnl-probe /path/to/tos-adnl-probe` runs the native
sidecar (JSON over stdin/stdout, protocol `tos-adnl-probe/1`), and the trial's
collector manifest then names `tos-native-adnl`, the sidecar's own commit and
toolchain, and the sha256 of the sidecar binary. The sidecar runner refuses
`-tunnel` and IPv6 sockets — the native transport supports neither, and those
cells stay with the gateway runner. `-echo-sizes 1024,8176` (adnl only, each
size 1..8176) adds sized echo round trips after the measured phases; their
verdicts appear on the stderr summary as `echo=1024:ok:3ms,...` and are
cross-check harness evidence, never part of the signed trial.

## 7. Aggregate

Collect both logs onto one machine and concatenate:

```sh
cat trials-a.jsonl trials-b.jsonl > study.jsonl
./tos-reachability-report -policy pilot-policy.json -log study.jsonl -probe udp
./tos-reachability-report -policy pilot-policy.json -log study.jsonl -probe adnl
```

Exit codes are the contract: `0` = the report supports a route decision,
`1` = valid report, no route decision, `2` = malformed input or tooling
failure. **A pilot that exits 0 is a bug report, not a success** — file it.

## 8. Success criteria

The pilot is operationally validated when all of these hold, for both
probes:

- [ ] every run produced a trial record without manual intervention;
- [ ] `outcome=direct-established` on paths where it plausibly should be
      (and a *classified* failure, never `internal-error`, elsewhere);
- [ ] the held ADNL pair carries a nonzero `survival_seconds` on **both**
      halves and a nonzero `reconnect_millis` on the initiator's;
- [ ] the forced-fallback pair reports `outcome=proxy-fallback` carrying the
      direct phase's failure class, on both halves;
- [ ] trials carry `filtering_observations` from the `same-address-other-port`
      cold source (and from `other-address` if a secondary address was
      configured) — an endpoint the coordinator could not probe back is a
      finding about that NAT, not automatically a tooling failure, so judge
      this one against where the endpoint sits;
- [ ] the report exits `1` with finding `insufficient-evidence`;
- [ ] `unverified_trials` is 0 — every signature and attestation held;
- [ ] `incomplete_pairs` is 0 — every session produced both halves and they
      agreed;
- [ ] each cell in the report shows the ordered pair of endpoint strata you
      actually declared, with `samples` matching the sessions you ran;
- [ ] the ADNL report's kind is `route-decision` and the UDP report's is
      `network-feasibility`.

## 9. Troubleshooting

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
| `reconnect requires a hold window`, `reconnect measurement belongs to the initiating role` (or a phase flag refused with `-probe udp`) | `-reconnect` needs `-hold` and role `a` — the responder never dials, so it has nothing to re-establish — and the udp probe has no session to hold, reconnect, or tunnel: the phase flags belong to `-probe adnl` |
| `survival_s=0` on one half of a held pair | that side ran without `-hold`; both sides must hold, or the pair drops out of the survival percentile |
| fallback run stays `outcome=failed` | one side is missing `-tunnel` (registration is double, so half a registration forwards nothing), the relay is unreachable, or the direct block also cut the relay port — the fallback runs inside its own bounded window, so a relay that never answers leaves the direct failure standing |
| no `filtering_observations` in a trial | the coordinator ran with `-filter-listen` set empty, or the cold probes were filtered or lost — silence is not evidence, and the trial stays valid with filtering `undetermined` |

## 10. After the pilot

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
