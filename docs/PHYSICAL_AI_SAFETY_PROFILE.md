# Physical AI safety profile

Status: route-neutral local profile implemented; production hardware
certification remains deployment-specific.

This profile separates raw physical I/O from an ordinary external tool call.
It applies when OpenFox uses the built-in `i2c`, `spi`, or `serial` tools while
TOS Messenger action authorization is enabled.

## Authority and execution

Enabling a hardware tool is not authority to use it. Before execution, all of
the following must be true:

1. OpenFox has Messenger action authorization enabled and the private runtime
   socket is available.
2. Local owner configuration maps the exact hardware tool to a canonical
   `cap_<64 lowercase hex>` Capability ID and a closed operation allow-list.
3. The proposed action is classified as `physical-io` and commits the
   Capability ID, tool, operation, at most 8 KiB of owner-reviewable canonical
   JSON arguments, their SHA-256, complete authenticated provenance, and
   retry-stable invocation key.
4. `tos-messengerd` stores that exact structure, exposes it only on the owner
   socket, and obtains a one-shot owner grant.
5. OpenFox claims the grant once before calling the tool. Exact replay cannot
   claim it twice; rewording or substituting Capability, tool, operation, or
   arguments produces a different action while the invocation-key ledger
   refuses rebinding.

`physical-io` is never allowed inline, regardless of either configured effect
ceiling or whether the action has remote provenance. Missing Capability
configuration, an operation outside the allow-list, incomplete provenance, a
missing policy daemon, malformed evidence, denial, timeout, restart damage, or
replay fails before the hardware tool's `Execute` method.

## Safety boundary

Messenger is not a real-time controller, watchdog, emergency stop, or safety
interlock. Its grant authorizes only one software invocation; it does not prove
that a device, register, voltage, motion envelope, or surrounding environment
is safe. Production deployments must retain hardware limits and independently
validated local controllers below OpenFox. Blockchain finality and network
availability must never sit in a real-time physical control loop.

This v1 profile treats reads and writes alike because raw bus reads may clear
registers, acknowledge interrupts, disclose sensitive sensor data, or otherwise
change device state. A future device-specific profile may safely distinguish
operations only with a new schema and explicit review; it must not reinterpret
this profile.
