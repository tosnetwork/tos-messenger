# Public-channel local resource calibration — 2026-08-21

This record measures the candidate's complete-history verification, causal
fetch walk, and deterministic TOS Storage snapshot paths. It is a local
single-machine calibration, not an independent-operator capacity claim.

## Method

The benchmark fixture creates one valid Endpoint-signed publisher chain with a
256-byte text body per Event. Every Event has the previous publisher Event as
its causal parent, which is the worst case for round count because each fetch
reveals only the next ID. Fixture generation is outside the timed region.

The reproducible command is:

```text
make calibrate-public-channel
```

The recorded run used:

- Go `1.26.5`, `linux/amd64`, `GOMAXPROCS=1`;
- Intel Xeon Platinum 8455C, two sockets, 48 cores per socket, 192 logical
  CPUs;
- 125 GiB RAM; and
- load averages `1.99, 2.15, 2.47` immediately before measurement.

Each reported operation used `-benchtime=1x`. The in-memory paths were repeated
three times where practical; the 65,536-file Storage paths ran once because
they deliberately exercise per-object durable filesystem work. `B/op` is
cumulative allocation, not peak resident memory.

## Results

| Operation | Events | Time per operation | Allocated bytes |
|---|---:|---:|---:|
| complete `VerifyHistory` | 256 | 41.9–42.6 ms | 4,459,368 |
| complete `VerifyHistory` | 4,096 | 369–696 ms | 72,604,208–72,604,344 |
| complete `VerifyHistory` | 65,536 | 6.186 s | 1,187,600,320 |
| incremental `FetchCursor` walk | 256 | 6.16–6.62 ms | 1,257,176–1,257,312 |
| incremental `FetchCursor` walk | 1,024 | 14.0–25.7 ms | 5,018,704–5,018,840 |
| incremental `FetchCursor` walk | 4,096 | 56.7–101.5 ms | 20,065,464–20,065,600 |
| incremental `FetchCursor` walk | 65,536 | 0.993–1.038 s | 321,039,032–321,039,168 |
| legacy compatibility walk | 256 | 0.635–0.770 s | 276,545,776–276,547,464 |
| legacy compatibility walk | 1,024 | 10.526–10.659 s | 4,388,990,400–4,389,047,152 |
| TOS Storage snapshot export | 256 | 224.8 ms | 7,393,912 |
| TOS Storage snapshot load | 256 | 66.1 ms | 8,734,408 |
| TOS Storage snapshot export | 4,096 | 2.878 s | 118,931,240 |
| TOS Storage snapshot load | 4,096 | 581.9 ms | 140,296,616 |
| TOS Storage snapshot export | 65,536 | 45.985 s | 1,929,482,384 |
| TOS Storage snapshot load | 65,536 | 13.278 s | 2,273,977,064 |

## Finding and correction

The original `NativeNode` loop called the compatibility `NextFetch` and
`MergeFetchedEvents` functions for every response. Both rebuilt, rehashed and
sorted the entire known set, so a linear causal chain performed quadratic
work. At only 1,024 Events that path already took about 10.6 seconds and
allocated about 4.39 GB. At the same size the cursor takes 14.0–25.7 ms and
about 5.02 MB: at least 400 times faster in these runs with roughly 875 times
less cumulative allocation.

`FetchCursor` now owns one bounded incremental `known`/`pending` index for the
attempt. It accepts only exact requested IDs, rejects duplicates, wrong
bindings and count overflow atomically, and sorts once when returning the
complete set. It grants no validity: `NativeNode` still performs the mandatory
full publisher/finalized-authority verification and exact head reproduction
before commit. At the full 65,536-Event protocol bound, discovery itself is
about one second on this host.

The Storage maximum is operationally significant but bounded: exporting
65,536 independently durable files took about 46 seconds and loading plus
strict re-verification took about 13.3 seconds. Both fit the current two-minute
publisher and five-minute synchronization budgets on this host. No protocol
maximum or timeout is changed from one high-end machine measurement.

## Boundary and next evidence

This closes the missing **local measured-candidate** calibration and supplies a
repeatable benchmark at every important scale, including the protocol maximum.
It does not establish production capacity on low-cost/mobile hardware, public
network latency, multi-operator Storage behaviour, or a safe universal
timeout. Those claims require the same target on representative devices and
independently administered nodes, with peak RSS, disk class, available space,
network conditions and concurrent-channel load recorded before production
parameters are frozen.
