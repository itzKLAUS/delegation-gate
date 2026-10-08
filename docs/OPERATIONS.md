# Operations

Deploy the library inside a trusted tool gateway. It has no public HTTP server or deployment endpoint. Host authentication, TLS, request limits, per-tenant routing and metrics belong to that gateway.

1. Provision the root public key and exact audience through trusted configuration. Keep root private keys outside worker processes.
2. Provision a separate persistent receipt-signing key through a secret manager or restricted key store. The demo's temporary keys must not be used for persistent deployments.
3. Place the ledger on reliable local storage with restrictive filesystem permissions and a single authoritative file. Do not use ephemeral containers, independent database copies, NFS or object storage as a shared ledger.
4. Ensure all gateway processes point to that file. Constructor metadata checks prevent accidental reuse with another root, audience or receipt key.
5. Keep a reliable system clock. Time changes affect grant validity; monitor drift.
6. Apply ingress rate limits before proof processing. Catch availability failures and stop execution. Surface quota exhaustion, revocation and replay as distinct application events without logging private keys or raw tool arguments.

SQLite serializes writes with `BEGIN IMMEDIATE`, a ten-second busy timeout and full synchronization. This supports multiple local processes; it is not designed for separate hosts. Instrument lock contention and disk capacity at the host level before load. The library sets no automatic receipt retention; blindly deleting counters or revocations can restore authority and must not be used as cleanup.

## Backup and recovery

Use SQLite's backup API or stop all writers before copying the file. Back up keys separately with equivalent access controls. After restoring an older database, already-consumed authority may appear available again. Do not resume execution from a stale backup: revoke affected root grants, reconcile admissions with the external system, and issue new grants under a reviewed recovery procedure. A new database is a new ledger identity, not a safe reset of an old budget.

The constructor rejects a different receipt key for an existing ledger. Rotation requires an explicitly designed migration and verifier key history; version 0.2 has no rotation command. Preserve existing signed receipts and public verification keys.

## Release checks

Run the locked lint, type, test, demo and build commands from the README. Verify wheel contents and install the wheel in a clean environment. CI contains a Linux/Windows and Python 3.11â€“3.14 matrix, pinned action commits, read-only permissions and disabled persisted checkout credentials. Do not claim that unobserved CI jobs or deployment exercises passed.

## Bounded operational APIs

`gate.receipt_page(after=0, limit=100)` returns signed receipts in ascending sequence order. Save the last returned `receipt.sequence` as the next cursor. The maximum page is 1000; an empty page ends the current scan. New receipts can arrive during pagination. This does not delete receipts.

`gate.grant_status(grant_id)` reports consumed units and direct revocation in a consistent local read. An unknown identity has zero observed usage; this does not mean it is valid or authorized. Parent revocation and grant expiry still require full chain admission checks.

`gate.backup("new-snapshot.sqlite")` takes an integrity-checked online snapshot and refuses overwrites. It preserves replay history, quota and revocation at the snapshot instant. Restrict the destination directory: POSIX files are created as 0600, while Windows inherits directory ACLs. A stale restore still resurrects authority consumed after the snapshot; follow the recovery procedure above.
