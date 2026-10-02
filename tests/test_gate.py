import json
import multiprocessing
import sqlite3
from concurrent.futures import ThreadPoolExecutor
from contextlib import closing
from uuid import uuid4

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from pydantic import ValidationError

from delegation_gate import (
    Gate,
    Grant,
    Invocation,
    Permission,
    Rejected,
    SignedGrant,
    grant_id,
    public_key,
    sign_grant,
    sign_invocation,
    verify_receipt,
)
from delegation_gate.signing import canonical

NOW = 1000
PERMISSION = Permission(operation="report.read", resource="tenant:alpha")
DIGEST = "a" * 64


@pytest.fixture
def keys():
    return tuple(Ed25519PrivateKey.generate() for _ in range(4))


def make_grant(signer, subject, parent_grant=None, **changes):
    fields = dict(
        subject_key=public_key(subject),
        audience="reports",
        permissions=(PERMISSION,),
        not_before=900,
        expires_at=1200,
        max_units=10,
        remaining_delegations=2,
        parent=grant_id(parent_grant) if parent_grant else None,
        nonce=uuid4().hex,
    )
    fields.update(changes)
    return sign_grant(signer, Grant(**fields))


def make_gate(path, keys, **changes):
    return Gate(
        path,
        root_key=public_key(keys[0]),
        audience="reports",
        receipt_key=keys[3],
        clock=lambda: NOW,
        **changes,
    )


def invoke(gate, chain, subject, units=1, request_id=None, **changes):
    fields = dict(
        grant=grant_id(chain[-1]),
        request_id=request_id or uuid4().hex,
        audience="reports",
        operation=PERMISSION.operation,
        resource=PERMISSION.resource,
        arguments_digest=DIGEST,
        units=units,
        issued_at=NOW,
        expires_at=NOW + 30,
    )
    fields.update(changes)
    signed = sign_invocation(subject, Invocation(**fields))
    return gate.admit(
        json.dumps([entry.model_dump(mode="json") for entry in chain]).encode(),
        canonical(signed),
        operation=PERMISSION.operation,
        resource=PERMISSION.resource,
        arguments_digest=DIGEST,
        units=units,
    )


def test_root_and_delegation_receipts(tmp_path, keys):
    gate = make_gate(tmp_path / "ledger.sqlite", keys)
    root = make_grant(keys[0], keys[1])
    child = make_grant(keys[1], keys[2], root, remaining_delegations=1, max_units=5)
    receipt = invoke(gate, (root, child), keys[2], units=5)
    verified = verify_receipt(
        canonical(receipt),
        key=public_key(keys[3]),
        ledger_id=gate.ledger_id,
        audience="reports",
    )
    assert verified.units == 5
    assert verified.grants == (grant_id(root), grant_id(child))
    assert verified.sequence == 1
    assert json.loads(gate.export_receipts())[0] == receipt.model_dump(mode="json")


@pytest.mark.parametrize(
    "changes",
    [
        {"permissions": (Permission(operation="report.write", resource="tenant:alpha"),)},
        {"permissions": (Permission(operation="report.read", resource="tenant:beta"),)},
        {"max_units": 11},
        {"not_before": 899},
        {"expires_at": 1201},
        {"remaining_delegations": 2},
        {"audience": "another"},
        {"parent": "b" * 64},
    ],
)
def test_child_cannot_expand_authority(tmp_path, keys, changes):
    gate = make_gate(tmp_path / "ledger.sqlite", keys)
    root = make_grant(keys[0], keys[1])
    child = make_grant(keys[1], keys[2], root, **{"remaining_delegations": 1, **changes})
    with pytest.raises(Rejected):
        invoke(gate, (root, child), keys[2])
    assert json.loads(gate.export_receipts()) == []


def test_non_delegating_parent(tmp_path, keys):
    root = make_grant(keys[0], keys[1], remaining_delegations=0)
    child = make_grant(keys[1], keys[2], root, remaining_delegations=0)
    with pytest.raises(Rejected, match="delegation forbidden"):
        invoke(make_gate(tmp_path / "ledger.sqlite", keys), (root, child), keys[2])


@pytest.mark.parametrize(
    "change",
    [
        {"audience": "another"},
        {"resource": "tenant:beta"},
        {"operation": "report.write"},
        {"arguments_digest": "b" * 64},
        {"grant": "b" * 64},
        {"issued_at": NOW + 1},
        {"issued_at": NOW - 30, "expires_at": NOW},
        {"issued_at": 890, "expires_at": 910},
    ],
)
def test_proof_binds_action_and_time(tmp_path, keys, change):
    root = make_grant(keys[0], keys[1])
    with pytest.raises(Rejected):
        invoke(make_gate(tmp_path / "ledger.sqlite", keys), (root,), keys[1], **change)


def test_wrong_root_and_wrong_subject(tmp_path, keys):
    gate = make_gate(tmp_path / "ledger.sqlite", keys)
    with pytest.raises(Rejected):
        invoke(gate, (make_grant(keys[2], keys[1]),), keys[1])
    with pytest.raises(Rejected):
        invoke(gate, (make_grant(keys[0], keys[1]),), keys[2])


def test_permission_is_exact_not_a_pattern(tmp_path, keys):
    root = make_grant(
        keys[0], keys[1], permissions=(Permission(operation="*", resource="tenant:*"),)
    )
    with pytest.raises(Rejected, match="permission denied"):
        invoke(make_gate(tmp_path / "ledger.sqlite", keys), (root,), keys[1])


@pytest.mark.parametrize(
    "validity",
    [
        {"not_before": NOW + 1},
        {"expires_at": NOW},
    ],
)
def test_grant_time_boundaries(tmp_path, keys, validity):
    root = make_grant(keys[0], keys[1], **validity)
    with pytest.raises(Rejected, match="validity interval"):
        invoke(make_gate(tmp_path / "ledger.sqlite", keys), (root,), keys[1])


def test_replay_does_not_charge_twice(tmp_path, keys):
    path = tmp_path / "ledger.sqlite"
    root = make_grant(keys[0], keys[1], max_units=2)
    gate = make_gate(path, keys)
    request_id = uuid4().hex
    invoke(gate, (root,), keys[1], request_id=request_id)
    with pytest.raises(Rejected):
        invoke(gate, (root,), keys[1], request_id=request_id)
    restarted = make_gate(path, keys)
    invoke(restarted, (root,), keys[1])
    with pytest.raises(Rejected, match="quota exhausted"):
        invoke(restarted, (root,), keys[1])
    assert len(json.loads(restarted.export_receipts())) == 2


def test_siblings_share_parent_budget_and_failed_admission_rolls_back(tmp_path, keys):
    gate = make_gate(tmp_path / "ledger.sqlite", keys)
    root = make_grant(keys[0], keys[1], max_units=10)
    first = make_grant(keys[1], keys[2], root, remaining_delegations=0, max_units=6)
    second = make_grant(keys[1], keys[2], root, remaining_delegations=0, max_units=6)
    invoke(gate, (root, first), keys[2], units=6)
    with pytest.raises(Rejected):
        invoke(gate, (root, second), keys[2], units=5)
    # Failed admission must leave the second child's full quota untouched.
    invoke(gate, (root, second), keys[2], units=4)
    assert sum(row["receipt"]["units"] for row in json.loads(gate.export_receipts())) == 10


@pytest.mark.parametrize("revoke_parent", [False, True])
def test_revocation_blocks_descendants_after_restart(tmp_path, keys, revoke_parent):
    path = tmp_path / "ledger.sqlite"
    gate = make_gate(path, keys)
    root = make_grant(keys[0], keys[1])
    child = make_grant(keys[1], keys[2], root, remaining_delegations=0)
    gate.revoke(grant_id(root if revoke_parent else child))
    with pytest.raises(Rejected, match="revoked"):
        invoke(make_gate(path, keys), (root, child), keys[2])


def test_thread_race_cannot_overspend(tmp_path, keys):
    gate = make_gate(tmp_path / "ledger.sqlite", keys)
    root = make_grant(keys[0], keys[1], max_units=5)

    def attempt(_):
        try:
            invoke(gate, (root,), keys[1])
            return True
        except Rejected:
            return False

    with ThreadPoolExecutor(max_workers=12) as pool:
        assert sum(pool.map(attempt, range(24))) == 5
    assert len(json.loads(gate.export_receipts())) == 5


def _process_attempt(path, root, subject_hex, receipt_hex, signed_json):
    gate = Gate(
        path,
        root_key=root,
        audience="reports",
        receipt_key=Ed25519PrivateKey.from_private_bytes(bytes.fromhex(receipt_hex)),
        clock=lambda: NOW,
    )
    chain = (SignedGrant.model_validate_json(signed_json),)
    try:
        invoke(gate, chain, Ed25519PrivateKey.from_private_bytes(bytes.fromhex(subject_hex)))
        return True
    except Rejected:
        return False


def test_separate_processes_share_quota(tmp_path, keys):
    path = str(tmp_path / "ledger.sqlite")
    make_gate(path, keys)
    root = make_grant(keys[0], keys[1], max_units=3)
    args = (
        path,
        public_key(keys[0]),
        keys[1].private_bytes_raw().hex(),
        keys[3].private_bytes_raw().hex(),
        canonical(root),
    )
    with multiprocessing.get_context("spawn").Pool(4) as pool:
        assert sum(pool.starmap(_process_attempt, [args] * 12)) == 3


def test_receipt_tampering_and_wrong_ledger(tmp_path, keys):
    gate = make_gate(tmp_path / "ledger.sqlite", keys)
    receipt = invoke(gate, (make_grant(keys[0], keys[1]),), keys[1])
    raw = json.loads(canonical(receipt))
    raw["receipt"]["units"] = 0
    with pytest.raises(Rejected):
        verify_receipt(
            json.dumps(raw).encode(),
            key=public_key(keys[3]),
            ledger_id=gate.ledger_id,
            audience="reports",
        )
    with pytest.raises(Rejected):
        verify_receipt(
            canonical(receipt), key=public_key(keys[3]), ledger_id="b" * 64, audience="reports"
        )


@pytest.mark.parametrize(
    "field,value",
    [
        ("max_units", -1),
        ("max_units", True),
        ("max_units", "1"),
        ("max_units", 1.5),
        ("max_units", 2**53),
        ("subject_key", "bad"),
    ],
)
def test_strict_schema(keys, field, value):
    with pytest.raises(ValidationError):
        make_grant(keys[0], keys[1], **{field: value})


def test_malformed_and_oversized_input(tmp_path, keys):
    gate = make_gate(tmp_path / "ledger.sqlite", keys)
    for raw in (b"[]", b"not-json", b"[" + b" " * 65536):
        with pytest.raises(Rejected):
            gate.admit(
                raw,
                b"{}",
                operation="report.read",
                resource="tenant:alpha",
                arguments_digest=DIGEST,
                units=1,
            )


def test_ledger_configuration_cannot_change(tmp_path, keys):
    path = tmp_path / "ledger.sqlite"
    make_gate(path, keys)
    with pytest.raises(ValueError, match="configuration mismatch"):
        Gate(path, root_key=public_key(keys[2]), audience="reports", receipt_key=keys[3])
    with pytest.raises(ValueError, match="durable"):
        make_gate(":memory:", keys)


def test_ledger_contains_no_private_keys_or_arguments(tmp_path, keys):
    path = tmp_path / "ledger.sqlite"
    gate = make_gate(path, keys)
    invoke(gate, (make_grant(keys[0], keys[1]),), keys[1])
    with closing(sqlite3.connect(path)) as db:
        dump = "\n".join(db.iterdump())
    for key in keys:
        assert key.private_bytes_raw().hex() not in dump
    assert DIGEST in dump


@pytest.mark.parametrize("version", [True, "1", 1.0, 2])
def test_wire_version_is_exact(keys, version):
    with pytest.raises(ValidationError):
        make_grant(keys[0], keys[1], version=version)


def test_schema_rejects_duplicate_permissions_and_long_proof(keys):
    with pytest.raises(ValidationError, match="duplicate"):
        make_grant(keys[0], keys[1], permissions=(PERMISSION, PERMISSION))
    with pytest.raises(ValidationError, match="expires_at"):
        make_grant(keys[0], keys[1], expires_at=900)
    with pytest.raises(ValidationError, match="lifetime"):
        Invocation(
            grant=DIGEST,
            request_id=uuid4().hex,
            audience="reports",
            operation="report.read",
            resource="tenant:alpha",
            arguments_digest=DIGEST,
            units=1,
            issued_at=NOW,
            expires_at=NOW + 61,
        )


def test_three_level_chain_and_missing_ancestor(tmp_path, keys):
    gate = make_gate(tmp_path / "ledger.sqlite", keys)
    root = make_grant(keys[0], keys[1])
    child = make_grant(keys[1], keys[2], root, remaining_delegations=1)
    leaf = make_grant(keys[2], keys[1], child, remaining_delegations=0)
    invoke(gate, (root, child, leaf), keys[1])
    with pytest.raises(Rejected):
        invoke(gate, (root, leaf), keys[1])
    with pytest.raises(Rejected):
        invoke(gate, (child, leaf), keys[1])


def test_grant_tampering_unknown_fields_and_invalid_units(tmp_path, keys):
    gate = make_gate(tmp_path / "ledger.sqlite", keys)
    signed = make_grant(keys[0], keys[1])
    raw = signed.model_dump(mode="json")
    raw["grant"]["max_units"] = 999
    altered = SignedGrant.model_validate_json(json.dumps(raw))
    with pytest.raises(Rejected):
        invoke(gate, (altered,), keys[1])
    raw["grant"]["unknown"] = "ignored?"
    with pytest.raises(ValidationError):
        SignedGrant.model_validate_json(json.dumps(raw))
    with pytest.raises(Rejected, match="invalid units"):
        gate.admit(
            b"[]",
            b"{}",
            operation="report.read",
            resource="tenant:alpha",
            arguments_digest=DIGEST,
            units=True,
        )


def test_child_exhaustion_rolls_back_parent_charge(tmp_path, keys):
    gate = make_gate(tmp_path / "ledger.sqlite", keys)
    root = make_grant(keys[0], keys[1], max_units=2)
    child = make_grant(keys[1], keys[2], root, max_units=0, remaining_delegations=0)
    with pytest.raises(Rejected, match="quota exhausted"):
        invoke(gate, (root, child), keys[2], units=2)
    invoke(gate, (root,), keys[1], units=2)


def test_cross_child_replay_same_subject_is_rejected(tmp_path, keys):
    gate = make_gate(tmp_path / "ledger.sqlite", keys)
    root = make_grant(keys[0], keys[1])
    first = make_grant(keys[1], keys[2], root, remaining_delegations=0)
    second = make_grant(keys[1], keys[2], root, remaining_delegations=0)
    request_id = uuid4().hex
    invoke(gate, (root, first), keys[2], request_id=request_id)
    with pytest.raises(Rejected):
        invoke(gate, (root, second), keys[2], request_id=request_id)


def test_receipt_invalid_signature_audience_and_size(tmp_path, keys):
    gate = make_gate(tmp_path / "ledger.sqlite", keys)
    signed = invoke(gate, (make_grant(keys[0], keys[1]),), keys[1])
    for raw, key, audience in (
        (canonical(signed), public_key(keys[0]), "reports"),
        (canonical(signed), public_key(keys[3]), "other"),
        (b" " * 65537, public_key(keys[3]), "reports"),
    ):
        with pytest.raises(Rejected):
            verify_receipt(raw, key=key, ledger_id=gate.ledger_id, audience=audience)
