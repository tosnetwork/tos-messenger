# Descriptor-bound HTTPS bootstrap transport

`transport: "https-bootstrap"` is a bounded, deployable fallback for direct
encrypted messages while the multi-operator M0-R study remains incomplete. It
does not select the eventual native production route and grants HTTPS no
protocol authority.

The sender first resolves a canonical AgentID through the normal finalized
delegation, DHT locator, signed Contact Descriptor and signed device-prekey
chain. A durable E2EE session fixes the peer AgentID, EndpointID and DeviceID.
Only then does the carrier read the exact HTTPS URL from the verified
Descriptor. That URL must use public HTTPS port 443 and the exact path:

```text
/v1/tos-messenger/messages
```

User information, query strings, fragments, redirects, environment proxies,
non-public DNS answers and descriptor/session authority mismatches fail
closed. TLS authenticates the hostname. The recipient additionally signs each
bounded acknowledgement with the finalized Endpoint Ed25519 authority; the
signature commits the EventID, SessionID, target EndpointID and DeviceID,
ciphertext digest, outcome, fault code and acceptance time. An HTTP 200 without
that exact signature is not delivery evidence.

The request contains only public first-contact evidence, opaque admission
material and E2EE ciphertext. The receiver independently refreshes sender
authority, verifies the exact signed prekey bundle, opens the ratchet, applies
admission, and atomically persists the ratchet transition and Event before
acknowledging it. HTTPS cannot choose or rewrite an Agent, Endpoint, Device,
Session, conversation or payment authority.

## Configuration

The daemon config must select all three cooperating facilities:

```json
{
  "discovery": { "mode": "tos-dht-https" },
  "publication": { "mode": "prekeys" },
  "transport": "https-bootstrap"
}
```

The omitted discovery and publication fields remain mandatory as documented
in the main example. The publication operator document must advertise an
endpoint such as:

```json
"https_endpoint": "https://alice.example/v1/tos-messenger/messages"
```

Start the daemon with the publication resources and TLS listener:

```sh
tos-messengerd \
  -config /etc/tos-messengerd/config.json \
  -publication-operator-config /etc/tos-messengerd/publication.json \
  -https-listen :8443 \
  -https-cert /etc/tos-messengerd/tls/fullchain.pem \
  -https-key /etc/tos-messengerd/tls/private.key
```

When a reverse proxy owns public port 443, it must forward only this exact path
to the private listener without rewriting the request. The daemon still serves
TLS on that hop so an accidental plaintext internal deployment is not silently
accepted. The advertised Descriptor URL remains the public port-443 URL.

## Evidence boundary

Package tests exercise real TLS sockets, strict wire decoding, Endpoint-signed
acknowledgements, forged acknowledgement rejection and peer rejection mapping.
The two-daemon acceptance exercises independent identities, state directories
and ratchets on one host. Those are implementation evidence, not independent
public-network or multi-operator M0-R evidence. A final production route claim
still requires the study and evidence package defined in `M0R_STUDY.md`.
