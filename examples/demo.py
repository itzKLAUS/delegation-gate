"""Local, synthetic integration: issuer -> supervisor -> worker -> gateway."""

import hashlib
import json
import tempfile
import time
from pathlib import Path
from uuid import uuid4

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from delegation_gate import (
    Gate,
    Grant,
    Invocation,
    Permission,
    Rejected,
    grant_id,
    public_key,
    sign_grant,
    sign_invocation,
    verify_receipt,
)


def main() -> None:
    issuer, supervisor, worker, receipt_signer = (Ed25519PrivateKey.generate() for _ in range(4))
    now = int(time.time())
    scope = Permission(operation="report.read", resource="tenant:alpha")
    root = sign_grant(
        issuer,
        Grant(
            subject_key=public_key(supervisor),
            audience="reports",
            permissions=(scope,),
            not_before=now,
            expires_at=now + 300,
            max_units=10,
            remaining_delegations=1,
            nonce=uuid4().hex,
        ),
    )
    child = sign_grant(
        supervisor,
        Grant(
            subject_key=public_key(worker),
            audience="reports",
            permissions=(scope,),
            not_before=now,
            expires_at=now + 300,
            max_units=4,
            remaining_delegations=0,
            parent=grant_id(root),
            nonce=uuid4().hex,
        ),
    )
    chain = json.dumps([root.model_dump(mode="json"), child.model_dump(mode="json")]).encode()
    # The gateway derives these from the real action; the caller cannot choose a cheaper cost.
    arguments = b'{"report":"quarterly-summary"}'
    digest = hashlib.sha256(arguments).hexdigest()

    def proof() -> bytes:
        return (
            sign_invocation(
                worker,
                Invocation(
                    grant=grant_id(child),
                    request_id=uuid4().hex,
                    audience="reports",
                    operation=scope.operation,
                    resource=scope.resource,
                    arguments_digest=digest,
                    units=3,
                    issued_at=now,
                    expires_at=now + 30,
                ),
            )
            .model_dump_json()
            .encode()
        )

    with tempfile.TemporaryDirectory() as folder:
        gate = Gate(
            Path(folder) / "ledger.sqlite",
            root_key=public_key(issuer),
            audience="reports",
            receipt_key=receipt_signer,
        )
        first = proof()
        receipt = gate.admit(
            chain,
            first,
            operation=scope.operation,
            resource=scope.resource,
            arguments_digest=digest,
            units=3,
        )
        verified = verify_receipt(
            receipt.model_dump_json().encode(),
            key=public_key(receipt_signer),
            ledger_id=gate.ledger_id,
            audience="reports",
        )
        print(f"ADMITTED: report.read; charged {verified.units} units; receipt {verified.sequence}")
        # Only this branch invokes the trusted adapter. Receipts record admission, not completion.
        print("RESULT: synthetic quarterly report")
        for label, attempt in (("replay", first), ("child quota", proof())):
            try:
                gate.admit(
                    chain,
                    attempt,
                    operation=scope.operation,
                    resource=scope.resource,
                    arguments_digest=digest,
                    units=3,
                )
            except Rejected as exc:
                print(f"REJECTED {label}: {exc}")
            else:
                raise RuntimeError(f"unexpected admission: {label}")
        gate.revoke(grant_id(root))
        try:
            gate.admit(
                chain,
                proof(),
                operation=scope.operation,
                resource=scope.resource,
                arguments_digest=digest,
                units=3,
            )
        except Rejected as exc:
            print(f"REJECTED revoked ancestor: {exc}")
        else:
            raise RuntimeError("unexpected admission after revocation")
        assert len(json.loads(gate.export_receipts())) == 1


if __name__ == "__main__":
    main()
