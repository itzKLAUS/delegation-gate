import sqlite3

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from test_gate import invoke, make_gate, make_grant

from delegation_gate import Rejected, grant_id, public_key, verify_receipt
from delegation_gate.signing import canonical


@pytest.fixture
def keys():
    return tuple(Ed25519PrivateKey.generate() for _ in range(4))


def test_pagination_and_quota_observation(tmp_path, keys):
    gate = make_gate(tmp_path / "gate.sqlite", keys)
    root = make_grant(keys[0], keys[1])
    identity = grant_id(root)
    assert gate.grant_status(identity) == {"used_units": 0, "revoked": False}
    for _ in range(3):
        invoke(gate, (root,), keys[1])
    first = gate.receipt_page(limit=2)
    second = gate.receipt_page(after=first[-1].receipt.sequence)
    assert [r.receipt.sequence for r in first + second] == [1, 2, 3]
    assert gate.receipt_page(after=3) == ()
    for receipt in first + second:
        verify_receipt(
            canonical(receipt),
            key=public_key(keys[3]),
            ledger_id=gate.ledger_id,
            audience="reports",
        )
    assert gate.grant_status(identity)["used_units"] == 3
    gate.revoke(identity)
    assert gate.grant_status(identity)["revoked"] is True


@pytest.mark.parametrize(
    "arguments",
    [
        {"after": True},
        {"after": -1},
        {"after": 2**63},
        {"limit": False},
        {"limit": 0},
        {"limit": 1001},
    ],
)
def test_bounded_queries(tmp_path, keys, arguments):
    gate = make_gate(tmp_path / "gate.sqlite", keys)
    with pytest.raises(ValueError):
        gate.receipt_page(**arguments)


def test_backup_preserves_replay_quota_revocation_and_identity(tmp_path, keys):
    gate = make_gate(tmp_path / "gate.sqlite", keys)
    root = make_grant(keys[0], keys[1])
    invoke(gate, (root,), keys[1], request_id="already-admitted")
    gate.revoke(grant_id(root))
    restored = make_gate(gate.backup(tmp_path / "snapshot.sqlite"), keys)
    assert restored.ledger_id == gate.ledger_id
    assert restored.export_receipts() == gate.export_receipts()
    assert restored.grant_status(grant_id(root)) == {"used_units": 1, "revoked": True}
    with pytest.raises(Rejected):
        invoke(restored, (root,), keys[1], request_id="already-admitted")
    with pytest.raises(Rejected):
        invoke(restored, (root,), keys[1])


def test_existing_destination_and_failure(tmp_path, keys, monkeypatch):
    gate = make_gate(tmp_path / "gate.sqlite", keys)
    with pytest.raises(FileExistsError):
        gate.backup(gate.database)
    target = tmp_path / "snapshot.sqlite"

    def unavailable(*args, **kwargs):
        raise sqlite3.OperationalError("disk unavailable")

    monkeypatch.setattr(gate, "_connect", unavailable)
    with pytest.raises(sqlite3.OperationalError):
        gate.backup(target)
    assert not target.exists()


def test_invalid_identity(tmp_path, keys):
    gate = make_gate(tmp_path / "gate.sqlite", keys)
    with pytest.raises(ValueError):
        gate.grant_status("bad")
