# TOS DHT locator adapter

`pkg/directory.TOSDHT` is the production bridge between the route-neutral
Messenger locator profile and `tosutils-go/adnl/dht`. It does not select a
message route and does not fetch message ciphertext.

## Authority checks

A retrieved locator is accepted only when all of these agree:

1. the requested key is the Endpoint public-key short identifier with name
   `tos.messaging.locator` and index `0`;
2. the native DHT key description names that exact key and an Ed25519 owner
   whose live TL hash equals the requested identifier;
3. the update rule is `dht.updateRule.signature`;
4. the native key-description and value signatures both verify under that
   owner key;
5. the outer DHT cache TTL is live and inside the native bound;
6. the value is a strict bounded Messenger locator; and
7. the inner locator signature verifies under the same Endpoint key.

The later `directory.Refresher` still resolves finalized Agent state and checks
that this Endpoint remains delegated. DHT signatures prove control of an
Endpoint key, not current Agent authorization.

## Publication

Publication accepts only a locator already valid under a live delegation and
the exact corresponding Endpoint private key. It calls the native DHT client
with `pub.ed25519`, the signature update rule, and a cache TTL no longer than
one hour. The returned native DHT key and positive replica count are checked
before publication is reported as successful.

The inner locator may remain valid for up to its protocol lifetime. It can be
republished inside freshly signed native DHT envelopes before their shorter
cache TTLs expire. This separates protocol validity from network cache
retention and stays inside the native DHT's 3660-second upper bound.

## Composition and deliberate remainder

The adapter supplies the DHT locator operation of `RefreshSource`.
`HTTPSObjects` now supplies the bounded descriptor and digest-bound prekey-set
operations under the versioned publication profile documented in
[`HTTPS_OBJECT_SOURCE.md`](HTTPS_OBJECT_SOURCE.md), and
`NetworkRefreshSource` composes both with explicit delegation and committed
descriptor-policy bootstrap. Daemon config v3 now builds and owns that chain;
see [`DISCOVERY_BOOTSTRAP.md`](DISCOVERY_BOOTSTRAP.md). Live independently
operated multi-node deployment evidence remains separate work.
