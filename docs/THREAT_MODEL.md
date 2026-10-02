# Threat model

## Checked invariants

An untrusted worker cannot expand a signed parent's exact permission set, lifetime, quota or delegation depth. It cannot replace the issuer, skip an ancestor, change the leaf's subject key, alter the signed action or submit a proof outside its validity window. The gateway rejects a request identifier already admitted for that subject, even through another child grant.

All admissions and ancestor quota charges commit in one SQLite transaction. Thread and process concurrency on the same local file cannot admit more declared units than an ancestor permits. A rejected admission rolls back its quota changes and receipt. Signed receipts permit independent verification of their contents against a pinned gateway key.

## Trusted components

- Root issuer policy and key custody.
- Gateway code, clock, filesystem and durable SQLite state.
- Receipt-signing key and pinned verifier configuration.
- Tool adapters enforcing resolved destinations, argument binding and declared cost bounds.
- Host authentication and authorization for administration and exports.

## Outside the boundary

Compromised signing keys can exercise all remaining authority granted to those keys. Revocation requires the original ledger; disconnected verifiers cannot learn new revocations. A malicious issuer can mint independent roots. Unrestricted agents can bypass a cooperative gateway and call external tools directly.

An administrator able to rewrite the database can reset counters, remove revocations or replay history. Individual receipt signatures do not prove completeness: an administrator can delete receipts, truncate history or replace the entire ledger. Export checkpoints to an independently controlled system when completeness is required.

The library does not enforce spending measured by a provider, external exactly-once effects, network sandboxing, distributed consensus, identity recovery, automatic key rotation, rate limits or tenant administration. A worker can create many distinct valid zero-cost requests; quotas do not replace request-rate limits. Invalid proofs consume verification and database-lock resources; ingress rate limiting remains necessary.

## Maturity

The cryptographic primitive is provided by the maintained `cryptography` package; this project's delegation protocol and integration remain unaudited. Before sensitive workloads, commission an independent protocol and application review, perform load and recovery exercises, define key rotation and incident handling, and verify the host's complete enforcement path. Passing unit tests is not a security certification.
