# Integration contract

## Roles

The issuer holds the root signing key. The gateway pins its public key from trusted configuration, never from request input. A root grant names a subject's public key and an audience. That subject may sign child grants if the parent permits further delegation. The final worker signs invocation proofs with the private key corresponding to the leaf subject. The gateway holds a separate receipt-signing key.

`sign_grant` is a signing helper, not an authorization decision. It can sign an invalid or expanding grant. The gateway rejects that chain; validating a signature alone is insufficient.

## Wire format

Serialize each `SignedGrant` with `model_dump(mode="json")` and send a JSON array ordered root first, leaf last. Serialize `SignedInvocation` with `model_dump_json().encode()`. Both inputs have a 64 KiB byte limit. Chains have at most nine grants; each grant has at most 32 distinct permissions.

Version 1 signatures cover a canonical JSON object: ASCII JSON with sorted keys, compact separators, explicit model defaults and no NaN. Grants, invocations and receipts have separate versioned signing-domain prefixes. Grant identifiers hash the entire signed grant under another domain. This is a project-specific format, not JWT, UCAN or an interoperable standard implementation. Cross-language implementations must replicate canonicalization exactly and should use shared test vectors before deployment.

## Gateway call

```python
receipt = gate.admit(
    chain_json,
    invocation_json,
    operation=resolved_operation,
    resource=resolved_tenant_resource,
    arguments_digest=sha256(exact_adapter_input).hexdigest(),
    units=trusted_worst_case_cost,
)
result = trusted_adapter(exact_adapter_input)
```

Derive the resource after tenant resolution; do not resolve a different destination after admission. Supply the exact bytes or deterministic representation consumed by the adapter when hashing arguments. Use integer units with an explicit contract (for example, microcurrency units or bounded requests); the library does not provide exchange rates or price tables. Zero-unit actions are allowed and are not bounded in count by the quota.

Every ancestor's `max_units` is a cumulative bound across all admitted descendants and direct invocations. Child issuance itself does not reserve quota. Two children can each have a cap equal to their parent, but combined admitted use still cannot exceed the parent. Independently issued root grants have independent budgets.

The invocation lifetime is at most 60 seconds; the gateway checks its own clock after acquiring the write lock. There is no clock-skew allowance. A proof must be within the leaf grant's time window and bind the gateway's exact audience.

## Failure handling

`Rejected` means no admission occurred for that call. Signature errors, malformed inputs, policy violations, revocation, replay and exhausted quota reject. SQLite availability or I/O failures propagate and must fail closed. Never interpret an exception as permission to execute.

After an admission, do not automatically refund or retry a failed action. A crash can occur after the external effect but before its result is recorded by the host. This library records admission only. Integrate with the external system's idempotency or reconciliation mechanism.

Do not treat a receipt as another execution capability. To verify a receipt, independently pin the gateway receipt public key, ledger identity and audience. A receipt can be replayed as evidence; it does not grant authority to execute again.

`revoke` is an administrative API. Authenticate and authorize the caller in the host application. Revocation and admission serialize through SQLite; if admission commits first, later revocation cannot undo it. Do not expose receipt export to arbitrary tenants.
