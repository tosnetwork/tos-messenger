# Public-channel Storage live acceptance — 2026-08-21

This record covers a same-host, two-process TOS Storage acceptance. It is
stronger than a process fixture and weaker than independent-operator or public
network evidence.

## Inputs

- `storage-daemon`, `storage-daemon-cli`, and `generate-random-id` reported
  build commit `38084a156095d484f66ff30529313ca7663ef028` dated
  `2026-08-15 15:00:31 +0000`.
- The TOS source checkout was at
  `de2278c4c5e8ce5582faa51bec95e200da255964`.
- Both daemon databases, control keys, downloaded objects, and the locally
  signed DHT bootstrap lived under one fresh mode-`0700` test directory.
- The test allocated distinct loopback ADNL and control ports for each daemon.

## Reproducible command

```text
TOS_STORAGE_LIVE_DAEMON=/absolute/path/to/storage-daemon \
TOS_STORAGE_LIVE_CLI=/absolute/path/to/storage-daemon-cli \
TOS_STORAGE_LIVE_KEY_TOOL=/absolute/path/to/generate-random-id \
TOS_STORAGE_LIVE_GLOBAL_CONFIG=/absolute/path/to/global.config.json \
make test-storage-live
```

`TestStorageCLILiveTwoDaemonCatchUp` performs the assembly rather than trusting
an operator-prepared Bag:

1. start daemon A once to generate its private DHT/control identities;
2. reproduce A's DHT public identity from its private keyring and generate a
   signed loopback DHT node entry with the stock key tool;
3. restart A and start daemon B against that local DHT bootstrap;
4. export an independently re-verifiable public-channel snapshot and publish
   it through `StorageCLIPublisher` on A;
5. send the resulting canonical lowercase BagID to `SitesCatchUp` backed by
   `StorageCLIDownloader` on B;
6. download all snapshot objects, re-verify finalized delegations, Profile,
   Events and the exact head, and persist the download receipt; and
7. stop B and prove exact catch-up replay still succeeds from the verified
   snapshot/receipt without any Storage process available.

## Result

The acceptance passed in 12.39 seconds:

```text
live_storage_two_daemon_bag_id=19b59eda5002a39a15e519565882bcee6f2769a1cfedeec6effe1f07d378e0ed
history_digest=sha256:a6d573f2e4a0a587b8275a169b83bae7fd3621e251e13f6299092bc48ee9a238
PASS
```

The live run exposed two stock CLI representations absent from the original
fixture: `Bits256::to_hex()` prints uppercase and `Dir name` has a trailing
slash. The adapter now accepts only uniform uppercase or lowercase CLI BagIDs,
normalizes them to the lowercase wire form, accepts only the exact expected
directory with an optional single trailing slash, and still rejects mixed case
or path substitution.

## Boundary

This proves real local binary compatibility, two-daemon Bag transfer, local DHT
discovery, strict application verification, crash/restart durability, and
offline receipt replay. It does **not** prove public Internet reachability,
independent administration, multi-operator failover, production capacity, or
economic Storage terms.
