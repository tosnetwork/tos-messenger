# Public-channel concurrent-peer calibration — 2026-08-22

This is same-host engineering evidence, not representative-device,
independent-operator or public-network capacity evidence.

## Defect found and corrected

A valid 65,536-Event history can be one causal chain whose head reveals only
one new parent per response. The native peer budget was 1,024 fetches, so that
valid protocol-maximum history was deterministically truncated. The server
also copied and scanned the complete history for every exact-ID request,
making this shape quadratic even though the client already used an incremental
cursor.

The native ceiling now equals `MaxHistoryEvents` while the independent
response-byte, total-byte, unavailable-result and five-minute attempt bounds
remain. `NativeNode` builds an immutable exact-ID index whenever verified
history is loaded or committed and returns cloned Events, so caller mutation
cannot alter the served ledger. Tests consume all 65,536 fetch claims and
require the next claim to fail.

## Reproducible commands

```text
make calibrate-public-channel-concurrent
GOMAXPROCS=1 GOWORK=off go test -run '^$' \
  -bench '^BenchmarkPublicChannelNativeProviderIndex/events-(1024|65536)$' \
  -benchmem -benchtime=100x -count=3 ./pkg/publicchannel
```

The run used Go 1.26.5 on `linux/amd64`, an Intel Xeon Platinum 8455C, and
`GOMAXPROCS=8` for the concurrent benchmark. Each peer traversed an identical
valid 1,024-Event linear chain through strict response JSON encode/decode,
resource charging, fetched-Event verification, cursor merge and final head
reproduction. Fixture generation was outside the timed region.

| Concurrent peers | Time | Throughput | Cumulative allocation |
|---:|---:|---:|---:|
| 1 | 654.7 ms | 0.40 MB/s | 66,820,512 B |
| 8 | 830.1 ms | 2.53 MB/s | 533,829,328 B |
| 32 | 2.170 s | 3.87 MB/s | 2,133,994,512 B |

The indexed provider lookup used fixed `848 B/op` and six allocations. Across
three 100-operation repetitions it took 510.6–726.1 ns/op with 1,024 Events
and 494.6–548.4 ns/op with 65,536 Events. Lookup cost therefore no longer
grows with total history size in this run.

## Boundary

Allocation above is cumulative rather than peak RSS. Thirty-two goroutines on
one high-end host are a stress calibration, not the stock node's eight-peer
deployment claim. Public latency, slow disks, simultaneous channels, peak RSS,
low-cost hardware and hostile-but-authenticated peers still require measured
external calibration. Large histories should continue to use the verified TOS
Storage snapshot path where available; raising the fetch-count ceiling does
not freeze a preferred production route before M0-R.

## Follow-up scheduling correction

The measurement also made duplicate work visible: several authenticated peers
claiming one exact Head could each start the complete wire, verification and
commit walk. `NativeNode` now canonicalizes the full Head and permits one
active peer for it. Up to `MaxSyncPeers * MaxCandidateHeadsPerPeer` candidates
remain bounded and exact-replay idempotent. A failed active peer selects the
first still-connected same-Head waiter as its preferred fallback, while
independently ready distinct Heads may proceed; a successful peer removes all
redundant waiters. Distinct Heads remain distinct,
including a History-digest reuse with substituted tips, so a malicious false
Head cannot suppress the canonical one. Stale completion, disconnected peers,
queue overflow, caller mutation and node shutdown fail closed under focused and
race tests.

## Native three-node single-flight proof

`TestNativeNodeSingleFlightsSameHeadAcrossADNLPeers` closes the gap between the
scheduler model and the live carrier. Two independently keyed providers and
one empty client establish authenticated carriers over three real local UDP
Gateways. After carrier assembly, both providers receive the same verified
one-Event history. The first provider's real RLDP request is held before its
history lookup while the second provider broadcasts the identical canonical
Head. At that boundary the client has exactly one active synchronization and
one waiting claimant, and the two server carriers report exactly one served
fetch in total. Releasing the provider yields one verified durable commit,
clears active and pending work, and never contacts the redundant provider.

The exact test passed 20 consecutive runs, the complete `pkg/publicchannel`
suite, its race build, and `make test-adnl`. The test uses existing private
package counters and locks; it adds no production hook or public API. It proves
same-host scheduling across real ADNL/Overlay/RLDP carriers, not public-network
latency, independent operation, or failover after a real network fault.
