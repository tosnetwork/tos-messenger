# Cross-observer device fork evidence

Two observers can see different DHT/HTTPS publications from the same
Messaging Endpoint. Comparing only bundle signatures is insufficient: an
Endpoint may sign device contributions that it never publishes together as a
complete set. Portable evidence therefore contains two complete public chains:

1. an Endpoint-signed Contact Descriptor;
2. the exact bundle set committed by that Descriptor; and
3. a second signed Descriptor and committed set for the same Endpoint and
   freshness watermark.

`directory.NewDeviceForkEvidence` verifies both chains under one finalized
delegation and its committed Descriptor policy before emitting strict bounded
`tos.messaging.device-fork-evidence.v1` JSON. Pair arrival order and bundle
order produce identical bytes. `VerifyDeviceForkEvidence` accepts no authority
from the evidence: the verifier supplies its own current finalized delegation,
committed policy, and clock. Signatures and validity are checked at the earliest
signed instant covered by both publication chains, so waiting for a short-lived
Descriptor cache entry to expire cannot erase proof; the verifier's clock still
rejects future-issued evidence.

A pair is evidence only when the set digests differ, their newest bundle
issuance seconds match, and neither set is a subset of the other. A subset can
be a legitimate pure device retirement, while unequal watermarks are ordered
rotations; neither is a portable fork accusation. Both Descriptor signatures,
both Descriptor→set commitments, every bundle signature, network/Agent/Endpoint
binding, validity window, policy and protocol-version grant are rechecked.

The stock command resolves authority through the daemon's strict-majority
finalized chain configuration:

```sh
tos-device-fork-evidence -mode assemble \
  -config /etc/tos-messengerd/config.json \
  -policy /etc/tos-messengerd/descriptor-policy.json \
  -first-descriptor observer-a/descriptor.json \
  -first-set observer-a/prekeys.json \
  -second-descriptor observer-b/descriptor.json \
  -second-set observer-b/prekeys.json > fork-evidence.json

tos-device-fork-evidence -mode verify \
  -config /etc/tos-messengerd/config.json \
  -policy /etc/tos-messengerd/descriptor-policy.json \
  -evidence fork-evidence.json
```

The verification result normalizes the two set digests lexically, so observer
arrival order cannot make one branch appear authoritative. This format enables
cross-observer exchange and local proof verification; independently operated
public exchange evidence is still required before claiming deployment
acceptance.
