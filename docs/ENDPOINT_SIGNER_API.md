# Endpoint signer client boundary

`pkg/signerapi.Client` is the narrow `crypto.Signer` bridge used when the
delegated Messaging Endpoint key is held by a separate local service or
hardware-backed process. The Messenger daemon receives an absolute Unix socket
path and the already finalized 32-byte Endpoint public key. It never accepts a
seed or private-key file.

Each connection carries one bounded length-prefixed strict JSON request using
`tos.messaging.endpoint-sign-request.v1`. `message_base64` is the exact raw,
domain-separated preimage supplied to Ed25519; pre-hashed signing modes are
refused. The strict `tos.messaging.endpoint-sign-response.v1` response is either
a 64-byte signature or a non-empty refusal. Unknown fields, trailing JSON,
wrong schemas, malformed shapes, timeouts, connection failures, and invalid
signatures fail closed. The client verifies every signature under the pinned
delegated key before returning it and copies signer-owned bytes.

The protocol is intentionally a signing boundary, not a general key service.
It performs no encryption or key exchange, and the Endpoint seed must not be
reused for X25519, device prekeys, MLS leaves, Agent controllers, wallets, or
execution keys. Socket permissions, signer-side request authorization, hardware
custody, audit, and availability are deployment responsibilities. The repository
provides the strict client and adversarial fake-server tests; it does not provide
a software service that loads an exportable production key.
