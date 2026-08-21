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
report. The session gates are predeclared the same way: the policy names the
minimum direct- and tunnel-survival rates, reconnect, paired sized-echo, RLDP
large-transfer and same-transfer-recovery rates, their attempted-sample floors,
and the exact payload/interruption profiles, all folded into the digest. At
least the native 8176-byte ADNL maximum and one interrupted RLDP response of at
least 4,000,001 bytes (three pinned parts) must be exercised, so neither a
tiny-packet result nor an application retry can qualify a direct route.

**A weak study yields no finding.** If any required stratum was never measured,
or was measured with too few samples, too few distinct operator identifiers, or from
too few independent networks — or a survival or reconnect gate the finding
depends on lacks its predeclared minimum of attempted samples — the report's
finding is `insufficient-evidence`
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

**A measurement is what two endpoints agree happened.** Both ends of an attempt
report, each signing with its own key, and the two halves are joined by a pair
identifier derived from the session rather than declared. A pair counts as one
sample only when the halves agree on the cell, the probe, the outcome, and
which commit each side was running, and only when they come from two different
keys in the two different roles. Latency takes the slower half and session
survival the shorter one, because a session exists only while both ends have
it. A sized echo exists as bidirectional evidence only when both halves report
the same payload: its success is the conjunction and its latency the slower
half; an unpaired size is missing evidence, not a success. A half whose peer never reported, and a pair whose halves contradict each other
about the probe, the outcome or the commits, are dropped and counted in
`incomplete_pairs`. Describing different situations is not a contradiction: it
is the measurement. Improving a result
therefore takes both keys, and the keys are what the operator minimum counts.

Each half describes **only its own end**. An endpoint knows its own carrier,
its own hardware, what its own network does to UDP and what mapping assistance
it has; it knows none of that about its peer. A cell is therefore an ordered
pair of endpoint situations, not a single label both sides have to agree on.
Requiring agreement would have made the interesting deployments impossible to
express -- a home node against a datacenter Agent, a phone against a machine
behind carrier-grade NAT differ on every field by definition -- and a policy of
matched pairs only is refused for that reason.

The order is the initiating direction, and it is kept rather than normalised.
Which side opens the session decides whether a mapping exists when the first
packet arrives, so a phone calling a server and a server calling a phone are
two measurements rather than one measured twice.

The joint label a route decision reads -- both public, one public, neither -- is
**derived** from the two ends rather than declared by either, because neither
end can observe it.

**An attestation names a party, not only a session.** The coordinator signs the
endpoint key that will sign the trial and the probe being measured, alongside
the address it observed. Without that, a published attestation could be copied
and worn by a third key: a bystander could add a third half to somebody else's
pair, and a pair is exactly two, so the honest measurement would be discarded.
The attestation would have become a way to delete other people's evidence.

**Session survival needs both halves.** A zero from one side means "not
measured", not "the other side's number speaks for both", so a pair contributes
to the survival percentile only when both ends measured it, and the report says
how many did.

**One host cannot answer to several names.** Endpoint keys are stable per host,
and a key seen under more than one operator identifier has every one of its
trials excluded and the key reported. The operator minimum means nothing if one
machine can satisfy it alone.

**No operator decides a cell alone.** Rates are means over operators, not over
measurements, so running more attempts buys no influence. Each operator's
contribution to a cell is also capped, and the cap is applied in digest order
rather than arrival order, so an operator cannot choose which of their
measurements survive by choosing when to submit them. Anything past the cap is
dropped and reported rather than silently truncated. Sites are counted
separately from operators, because one operator with twenty hosts behind one
uplink has measured one network.

The operator identifier is self-declared. It makes repeated submissions from
one operator recognisable as one operator; it is not proof that two identifiers
are two parties, and the report says "distinct operator identifiers" rather
than claiming independence it cannot establish.

**A policy that a laboratory pair could satisfy is refused.** `Policy.Validate`
requires the predeclared strata to cover a network behind NAT, consumer ISP,
carrier-grade NAT and mobile carriers, more than one address family, more than
one UDP-policy environment, a low-cost endpoint class, and a mobile endpoint.
Two publicly addressable servers cannot satisfy it.

Operational instructions for a single-operator dry run live in
[`M0R_PILOT_RUNBOOK.md`](M0R_PILOT_RUNBOOK.md). A pilot validates the tooling
chain and is expected to end `insufficient-evidence`; it contributes nothing
to a study.

## The ADNL probe

A UDP trial answers whether datagrams pass. Only an ADNL trial can feed a
route decision, because the route is about sessions, not datagrams: a
handshake is several packets in both directions with sizes and timing a
middlebox may treat differently from a probe datagram. The ADNL collector
reuses the coordinator rendezvous, then hands the rendezvous port to a real
ADNL gateway (the `tosutils-go` implementation of the protocol TOS inherits).

Three design decisions carry the correctness:

**Exactly one session ever exists.** If both sides dialled, their handshakes
would cross, and a crossed handshake leaves the two ends holding different
channel states — packets pass one way and silently vanish the other, and which
side suffers is a race. So the initiator dials with retries, and the responder
never dials: its half of the NAT punch is a burst of raw datagrams sent from
the rendezvous socket before the gateway takes the port. The responder's
establishment is measured over the inbound session; a session has no preferred
direction.

**Establishment is a ping round trip.** ADNL answers pings at the protocol
level, below any handler registration, so a completed round trip proves the
handshake, the channel, and both directions of the path while requiring
nothing from the peer beyond its gateway being up.

**The done signal travels through the coordinator, not over the session under
test.** Each endpoint holds its gateway open until the peer reports done or
the window ends — closing early would strand the slower endpoint, and that
error lands systematically on the slower side, which is exactly the bias a
success rate must not carry. The signal is not carried over the measured ADNL
session, because a layer must not carry its own test's control plane: "the
session failed" and "the signalling failed" have to stay distinguishable.

The collector can measure past establishment. A hold window keeps both ends
pinging the confirmed session and records how long it survived (a pair counts
only when both halves measured it), and the initiator can deliberately drop
its channel state and time the reconnect. Every phase also records its status
-- attempted, and completed or succeeded -- because the measurements alone are
ambiguous at zero: a reconnect the network refused and a reconnect nobody
asked for both leave the latency unmeasured, and only the status booleans keep
a failed phase from vanishing into the percentiles. When a tunnel relay
(`tos-reachability-tunnel`, a double-registration UDP forwarder bound by the
same amplification rules as the coordinator) is configured and the direct
phase fails, the collector establishes the same session through the relay and
the trial files as a proxy fallback carrying the direct phase's failure class
-- which is what gives the `tunnel-first` route decision evidence to read.
After a confirmed direct session's hold/reconnect phases, the collector also
runs the policy's bounded sized ADNL echo queries. Each endpoint signs the
payload size, outcome, and measured latency into its v4 trial. The report reads
only paired directions and requires every predeclared size to meet both its
sample floor and operator-balanced success threshold before `direct-first` can
qualify. A failed maximum-size echo can therefore veto a path that only carries
small control traffic.
The collector then runs each predeclared RLDPv2 plan. Responses are
deterministic and digest-checked, bounded to 16 MiB, and must exceed the pinned
2,000,000-byte FEC part size. For an interrupted plan, the receiver first
observes a complete part, suppresses both inbound and outbound RLDP custom
messages for the predeclared window, records how many messages were actually
suppressed, and accepts recovery only when the original `DoQuery` completes
after the window with the exact payload. It never issues an application retry.
The two directions occupy separate bounded slots so one endpoint's induced
outage cannot masquerade as the other's. Pairing again requires both signed
directions; success and same-transfer recovery join by AND, latency by the
slower half. The native sidecar now runs the canonical decision-bearing plan
through the node's real RLDPv2 actor: its observer is bound to the exact
complementary response transfer ID, its dedicated UDP manager counts packets
suppressed in both directions, and the Go driver rejects substituted or
internally inconsistent completions before trial signing. Native-native local
acceptance covers both directions; the real multi-operator study and public
network execution remain unperformed. Mixed native/in-process peers remain an
ADNL/echo matrix, not qualifying RLDP evidence, because their probe-query
encodings differ.
With a hold window configured the hold phase also runs over the tunneled
session, reported through its own status booleans; the survival span stays a
direct-session measurement, because a relayed lifetime would measure the
relay.

Two honest caveats. Establishment latency includes the rendezvous hand-off
(the responder's punch burst and gateway rebind), so absolute latencies carry
a small tooling offset that is identical across scenarios; comparisons between
cells are unaffected. And the collector speaks the TON lineage of ADNL through
`tosutils-go`; before a route decision frozen on this evidence is acted on,
the trials should be cross-checked against the TOS node's own adnl stack —
every trial records the commit and the content-addressed collector manifest
(orchestrator repository and commit, ADNL implementation and version, binary
hash, toolchain, target, wire profile) of both endpoints, so the provenance
survives and evidence from different collector implementations can be told
apart.

## What is measured and what is declared

The tool measures the address family, the pair's public reachability, the NAT
mapping behavior, the filtering receipts, the latency, the byte counts, the
session survival and reconnect latency when the hold phase is run, and the
commits both endpoints were running. None of these are flags.

The operator declares only what the tool cannot observe: the carrier class, the
UDP policy of the environment, the mobility event being exercised, the endpoint
hardware class, and any port-mapping assistance in use.

A single coordinator cannot separate an endpoint-independent mapping from an
address-dependent one, so one coordinator reports `undetermined` rather than
guessing. Run at least two coordinators on separate addresses to classify NAT
behavior.

Mapping and filtering are independent axes, and each has its own evidence. The
mapping class is derived from coordinator-signed bind reflections. The
filtering class is derived from coordinator-signed receipts: during the bind
phase the coordinator probes the endpoint from cold sources — a second port on
its own address and, when configured, a secondary address — each probe carrying
a random token, and the endpoint proves receipt by echoing the token back over
its established flow. Nothing is taken from the endpoint's own claim: the token
travels only through the path under test, so holding it is having received it.
A receipt shows the filter admitted that source; silence shows nothing, because
a dropped probe and a lost probe are the same silence, so the strict filtering
class is never derived remotely and an unprobed endpoint is `undetermined`.

A `none` (no NAT) declaration is never remotely credited either: bind
reflections cannot distinguish a truly public endpoint from one behind an
endpoint-independent NAT, since both reflect one address everywhere. `none`
and `endpoint-independent` therefore share one evidentiary bucket — left
standing by the same evidence, refuted by the same evidence — and nothing that
reads the derived class may treat a surviving `none` as verified public
addressability.

## Running it

Start a coordinator somewhere both endpoints can reach. Its identity comes
from a key file, so restarting does not change who it is:

```sh
tos-reachability-coordinator -listen :7691 -key coordinator.key
# coordinator_id=srv_... public_key=... listening=:7691 filter_port_source=...
```

The printed identifier goes into the policy's `coordinators` list, out of band.
A study counts attestations only from coordinators it predeclared, so a policy
carrying somebody else's identifier predeclares nothing.

The `filter_port_source` line names the cold second-port socket the filtering
receipts come from; `-filter-listen` places it (on by default, and it must
share the primary address), and `-filter-secondary-listen` adds a cold source
on a second address the host holds, which is what a receipt proving
endpoint-independent filtering requires. The cold sockets are write-only —
probes leave through them and nothing is read from or answered on them.

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

These examples run the default `udp` probe; `-probe adnl` selects the session
probe a route decision needs, and it alone accepts the post-establishment
flags — `-hold` (paced by `-keepalive`) for the survival phase, `-reconnect`
for the initiator's deliberate drop, `-rldp-transfers` for exact segmented
response/interruption plans, and `-tunnel` naming the relay of the
fallback phase. The udp probe refuses all three, because it has no session to
hold, reconnect, or tunnel.

Operator and site names are hashed into opaque identifiers. The report counts
how many distinct self-declared operator identifiers and networks contributed
to a cell; it never
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

**M0-R2, route decision.** An ADNL probe exercises the real handshake and
session establishment, keepalive survival, and reconnect, and only its
evidence produces `direct-first`, `tunnel-first`, `hybrid-by-network-class`,
or `relay-required`. The session phases are decisive, not merely surfaced:
`direct-first` additionally requires every required cell to clear the
predeclared direct-survival, per-payload sized-echo, segmented RLDP transfer,
and same-transfer recovery gates (and every cell
exercising a mobility event the reconnect gate), `tunnel-first` requires the tunnel-survival gate, and a
cell that cannot show the predeclared minimum of attempted pair samples for a
gate its finding depends on makes the finding `insufficient-evidence`, with the
missing gate named. A study where every session establishes and then dies, or
where no reconnect ever succeeds, therefore cannot freeze direct-first.
The bounded ADNL query path is measured through the protocol maximum and the
RLDPv2 path through a three-part response plus observable mid-transfer loss.
This is executable local/tooling acceptance, not evidence about public network
conditions: the multi-operator study must still run these exact predeclared
plans on the real scenarios before it may freeze a route.

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
