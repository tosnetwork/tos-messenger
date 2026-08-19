# M0-R reachability study

The Messenger architecture assumes direct sessions are the normal path and that
Mailbox Relays cover an offline minority. That assumption decides the milestone
order, and it has never been measured. This study measures it.

Until it produces a decision, the one-to-one milestone has no frozen scope: an
implementation built direct-first and justified afterwards by a report is
exactly what the architecture forbids.

## What the tooling guarantees

Three properties are enforced by the code rather than by convention.

**Thresholds are predeclared.** The acceptance policy is content-addressed and
every report names the policy digest it was judged against. Thresholds invented
after seeing the data produce a different digest, which is visible in the
report.

**A weak study yields no finding.** If any required stratum was never measured,
or was measured with too few samples, too few independent operators, or from
too few independent networks, the report's finding is `insufficient-evidence`
and the tool exits non-zero. It never degrades into a weak preference, because
a weak preference is what the implementation would then be built on.

**Nothing counts until it verifies.** Each trial is signed by the endpoint that
produced it and carries an attestation, signed by a coordinator, of the address
that coordinator observed and whether the peer was publicly addressable. Those
two facts place a trial in its stratum and no endpoint can check either about
itself, so left unsigned they are the operator's own claim about which cell
their result should count towards. A policy predeclares whose attestations
count: without that list a signature proves only that somebody signed
something, since anyone can run a coordinator.

A trial altered after signing, or attested by a coordinator the policy never
named, is not weak evidence. It is dropped and counted in `unverified_trials`.

**One host cannot answer to several names.** Endpoint keys are stable per host,
and a key seen under more than one operator identifier has every one of its
trials excluded and the key reported. The operator minimum means nothing if one
machine can satisfy it alone.

**No operator decides a cell alone.** Rates are means over operators, not over
trials, so running more attempts buys no influence. Each operator's
contribution to a cell is also capped, and anything past the cap is dropped and
reported rather than silently truncated. Sites are counted separately from
operators, because one operator with twenty hosts behind one uplink has
measured one network.

**A policy that a laboratory pair could satisfy is refused.** `Policy.Validate`
requires the predeclared strata to cover a network behind NAT, consumer ISP,
carrier-grade NAT and mobile carriers, more than one address family, more than
one UDP-policy environment, a low-cost endpoint class, and a mobile endpoint.
Two publicly addressable servers cannot satisfy it.

## What is measured and what is declared

The tool measures the address family, the pair's public reachability, the NAT
mapping behavior, the latency, the byte counts, and the commits both endpoints
were running. None of these are flags.

The operator declares only what the tool cannot observe: the carrier class, the
UDP policy of the environment, the mobility event being exercised, the endpoint
hardware class, and any port-mapping assistance in use.

A single coordinator cannot separate an endpoint-independent mapping from an
address-dependent one, so one coordinator reports `undetermined` rather than
guessing. Run at least two coordinators on separate addresses to classify NAT
behavior.

## Running it

Start a coordinator somewhere both endpoints can reach. Its identity comes
from a key file, so restarting does not change who it is:

```sh
tos-reachability-coordinator -listen :7691 -key coordinator.key
# coordinator_id=srv_... public_key=... listening=:7691
```

The printed identifier goes into the policy's `coordinators` list, out of band.
A study counts attestations only from coordinators it predeclared, so a policy
carrying somebody else's identifier predeclares nothing.

Run both endpoints of a pair with a shared session identifier:

```sh
SESSION=ses_$(openssl rand -hex 16)

# endpoint A
tos-reachability -coordinators host-1:7691,host-2:7691 -session "$SESSION" \
  -role a -operator "your-lab" -site "tokyo-uplink" -identity endpoint.key \
  -carrier consumer-isp -endpoint-class desktop \
  -out study.jsonl

# endpoint B
tos-reachability -coordinators host-1:7691,host-2:7691 -session "$SESSION" \
  -role b -operator "other-lab" -site "osaka-cgnat" -identity endpoint.key \
  -carrier carrier-grade-nat -endpoint-class edge-arm \
  -out study.jsonl
```

Operator and site names are hashed into opaque identifiers. The report counts
how many independent operators and networks contributed to a cell; it never
needs to know which. Both endpoints of one attempt derive the same pair
identifier from the session they share, so the two halves are recognisable as
one measurement rather than two independent successes.

Aggregate the log against the predeclared policy:

```sh
tos-reachability-report -policy reachability-policy.json -log study.jsonl -probe udp
```

Exit status `0` carries a route decision, `1` means the study does not support
one, and `2` is a tooling error.

## Two studies, two vocabularies

The study is split, because the two questions have different answers and only
one of them can freeze a transport.

**M0-R1, network feasibility.** The UDP probe measures whether a datagram path
can be established between two endpoints under a given NAT and carrier class.
It reports `udp-direct-viable` or `udp-direct-not-viable`, and it cannot report
anything else. A datagram getting through says nothing about whether an ADNL
handshake completes, whether a channel stays up, whether keepalives survive a
NAT, or whether a session recovers after a network change.

**M0-R2, route decision.** An ADNL probe exercises the real handshake, session,
keepalive, and reliable transfer, and only its evidence produces
`direct-first`, `tunnel-first`, `hybrid-by-network-class`, or `relay-required`.

Trials are aggregated per probe and never mixed, and the report names both the
probe and the kind of question it answered. `Report.SupportsRouteDecision`
is the single check a caller makes before freezing anything.

`relay-required` means a Relay is necessary. It does not mean a Relay works:
its latency, retention, redundancy, and failover are the technical Relay
milestone's own acceptance, and nothing in this study measures them.

Nothing in `pkg/probe` is a Messenger transport. It signs nothing, encrypts
nothing, and carries no application content.

## What signatures do and do not establish

An endpoint signature makes a trial unrewritable and makes one host reporting
under several names detectable. It does not make the endpoint honest: an
operator who runs genuinely separate machines and reports honestly about each
one is indistinguishable from one who runs genuinely separate machines and
reports selectively. Choosing which measurements to keep is not addressed here,
and the sample and cap rules exist partly because it is not.

## Amplification

The coordinator speaks UDP, so it could be used as a traffic amplifier by
anyone willing to spoof a source address. Two rules prevent it: requests are
padded to a floor, and a response larger than the request that produced it is
never sent. Anything that cannot be answered within that rule is dropped
silently.
