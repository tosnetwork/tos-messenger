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

**A weak study yields no decision.** If any required stratum was never measured,
or was measured with too few samples or by too few independent operators, the
report's decision is `insufficient-evidence` and the tool exits non-zero. It
never degrades into a weak preference for a route, because a weak preference is
what the implementation would then be built on.

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

Start a coordinator somewhere both endpoints can reach:

```sh
tos-reachability-coordinator -listen :7691
```

Run both endpoints of a pair with a shared session identifier:

```sh
SESSION=ses_$(openssl rand -hex 16)

# endpoint A
tos-reachability -coordinators host-1:7691,host-2:7691 -session "$SESSION" \
  -role a -operator "your-lab" -carrier consumer-isp -endpoint-class desktop \
  -out study.jsonl

# endpoint B
tos-reachability -coordinators host-1:7691,host-2:7691 -session "$SESSION" \
  -role b -operator "other-lab" -carrier carrier-grade-nat -endpoint-class edge-arm \
  -out study.jsonl
```

The operator name is hashed into an opaque identifier. The report counts how
many independent operators contributed to a cell; it never needs to know which.

Aggregate the log against the predeclared policy:

```sh
tos-reachability-report -policy reachability-policy.json -log study.jsonl -probe udp
```

Exit status `0` carries a route decision, `1` means the study does not support
one, and `2` is a tooling error.

## Probe scope

The UDP probe measures the network factor: whether a datagram path can be
established between two endpoints under a given NAT and carrier class. That is
the factor the route decision turns on, and it is protocol-independent.

Whether ADNL's handshake and keepalive survive such a path is a separate
question, recorded under the `adnl` probe kind. Trials are aggregated per probe
and are never mixed, so an ADNL result can never be satisfied by UDP evidence.

Nothing in `pkg/probe` is a Messenger transport. It signs nothing, encrypts
nothing, and carries no application content.

## Amplification

The coordinator speaks UDP, so it could be used as a traffic amplifier by
anyone willing to spoof a source address. Two rules prevent it: requests are
padded to a floor, and a response larger than the request that produced it is
never sent. Anything that cannot be answered within that rule is dropped
silently.
