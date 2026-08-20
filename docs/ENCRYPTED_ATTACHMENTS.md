# Encrypted attachment profile candidate

`pkg/attachments` implements the route-neutral cryptographic core of private
Messenger attachments. It does not select a transport, storage operator, paid
retention profile, parser, or malware scanner.

Each attachment gets a fresh random 256-bit AES-GCM key, 128-bit attachment ID,
and 32-bit nonce prefix. The 96-bit nonce is that prefix followed by the
big-endian 64-bit chunk index. One key is used for at most 2,048 chunks, and a
fresh key/namespace is mandatory for every call to `Seal`; nonce reuse under a
key is forbidden.

The AEAD associated data binds the profile, attachment ID, committed secret
metadata, total plaintext length, chunk size, chunk count, and exact chunk
index. Reordering, truncating, duplicating, substituting, or moving a chunk to
another attachment therefore fails authentication. Each ciphertext chunk is
also content-addressed, and the ordered manifest has its own domain-separated
digest. An Event carrying `artifact.encrypted` must repeat exactly that digest
in its sole `attachment_references` entry.

The secret Reference — key, display filename, canonical media type, optional
plaintext digest, expiry, and manifest — travels only inside the already-E2EE
Messaging Event. Storage receives opaque ciphertext chunks. The optional
plaintext digest is an explicit equality-disclosure tradeoff and may be left
empty. For a private room, MLS PrivateMessage protection wraps the Reference;
for one-to-one delivery, the existing per-device E2EE fan-out wraps it. No
separate shared storage key is inferred.

Downloads resume by comparing locally held ciphertext digests to the ordered
manifest and fetching only missing objects. `Open` checks the local size/media
policy, expiry, every content digest, every expected chunk length, and every
AEAD tag before returning any plaintext.

## Content safety and remaining integration

`Open` deliberately does not decompress archives, infer media types, render a
filename as a path, parse a document, or invoke a scanner. Display filenames
reject path separators, control-line breaks, surrounding whitespace, invalid
UTF-8, and parent paths. A runtime must keep the returned bytes inert until its
own sandbox/scanner policy admits them; authenticated content is still
untrusted content.

The profile bounds plaintext to 512 MiB, chunks to 1 MiB (256 KiB by default),
and count to 2,048; the recipient may set a smaller plaintext limit and an
allow-list of canonical media types. These bounds stop allocation and content
bombs at the attachment layer, but format-specific decompression ratios and
parser limits belong to the eventual sandbox adapter.

Expiry is enforced on open. Actual remote deletion, retention guarantees,
locator authentication/SSRF policy, storage garbage collection, scanning, and
commercial attachment service terms remain separate work. A content-addressed
object may have been copied, so no storage API may promise cryptographic erasure
it cannot prove.
