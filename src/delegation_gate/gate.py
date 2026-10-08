"""Verify authority, then atomically charge every ancestor and burn the invocation."""

import hashlib
import os
import re
import secrets
import sqlite3
import time
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from pydantic import TypeAdapter, ValidationError

from .model import Permission, Receipt, SignedGrant, SignedInvocation, SignedReceipt
from .signing import canonical, grant_id, public_key, sign, verify

_CHAIN = TypeAdapter(tuple[SignedGrant, ...])
_MAX_BYTES = 65536


class Rejected(ValueError):
    """The invocation cannot be admitted; no authority or quota was consumed."""


def _require(condition: bool, reason: str) -> None:
    if not condition:
        raise Rejected(reason)


def _now() -> int:
    return int(time.time())


class Gate:
    """One audience and trust root, backed by a single local SQLite ledger.

    All workers enforcing these grants must share this exact ledger. This is not
    a distributed consensus service and does not enforce external side effects.
    """

    def __init__(
        self,
        database: str | Path,
        *,
        root_key: str,
        audience: str,
        receipt_key: Ed25519PrivateKey,
        clock: Callable[[], int] = _now,
    ) -> None:
        if not re.fullmatch(r"[0-9a-f]{64}", root_key):
            raise ValueError("root_key must be a raw Ed25519 public key in lowercase hex")
        if not 1 <= len(audience) <= 128:
            raise ValueError("invalid audience")
        if str(database) == ":memory:":
            raise ValueError("a durable database file is required")
        self.database = str(database)
        self.root_key = root_key
        self.audience = audience
        self.receipt_key = receipt_key
        self.clock = clock
        with self._connect() as db:
            db.executescript("""
                CREATE TABLE IF NOT EXISTS metadata (key TEXT PRIMARY KEY, value TEXT NOT NULL);
                CREATE TABLE IF NOT EXISTS usage (
                    grant_id TEXT PRIMARY KEY, units INTEGER NOT NULL
                );
                CREATE TABLE IF NOT EXISTS revoked (grant_id TEXT PRIMARY KEY);
                CREATE TABLE IF NOT EXISTS receipts (
                    sequence INTEGER PRIMARY KEY AUTOINCREMENT,
                    subject TEXT NOT NULL,
                    request_id TEXT NOT NULL,
                    body TEXT NOT NULL,
                    UNIQUE(subject, request_id)
                );
            """)
            db.execute("BEGIN IMMEDIATE")
            expected = {
                "root_key": root_key,
                "audience": audience,
                "receipt_key": public_key(receipt_key),
                "schema_version": "1",
            }
            for name, value in expected.items():
                db.execute("INSERT OR IGNORE INTO metadata VALUES (?, ?)", (name, value))
                row = db.execute("SELECT value FROM metadata WHERE key = ?", (name,)).fetchone()
                if row is None or row[0] != value:
                    raise ValueError(f"ledger configuration mismatch: {name}")
            db.execute(
                "INSERT OR IGNORE INTO metadata VALUES ('ledger_id', ?)",
                (hashlib.sha256(secrets.token_bytes(32)).hexdigest(),),
            )
            row = db.execute("SELECT value FROM metadata WHERE key = 'ledger_id'").fetchone()
            if row is None:
                raise RuntimeError("missing ledger identity")
            self.ledger_id: str = row[0]

    @contextmanager
    def _connect(self) -> Iterator[sqlite3.Connection]:
        db = sqlite3.connect(self.database, timeout=10)
        try:
            db.execute("PRAGMA synchronous = FULL")
            with db:
                yield db
        finally:
            db.close()

    def _check_chain(self, chain: tuple[SignedGrant, ...], now: int) -> tuple[str, ...]:
        _require(1 <= len(chain) <= 9, "invalid chain length")
        ids: list[str] = []
        signer = self.root_key
        for index, signed in enumerate(chain):
            grant = signed.grant
            _require(grant.audience == self.audience, "audience mismatch")
            _require(grant.not_before <= now < grant.expires_at, "grant outside validity interval")
            verify(signer, signed.signature, b"delegation-gate/grant/v1", grant)
            if index == 0:
                _require(grant.parent is None, "root grant must not have a parent")
            else:
                parent = chain[index - 1].grant
                _require(grant.parent == ids[-1], "broken parent link")
                _require(parent.remaining_delegations > 0, "delegation forbidden")
                _require(
                    grant.remaining_delegations < parent.remaining_delegations,
                    "delegation depth expanded",
                )
                _require(set(grant.permissions) <= set(parent.permissions), "permissions expanded")
                _require(grant.max_units <= parent.max_units, "quota expanded")
                _require(
                    grant.not_before >= parent.not_before and grant.expires_at <= parent.expires_at,
                    "validity interval expanded",
                )
            ids.append(grant_id(signed))
            signer = grant.subject_key
        return tuple(ids)

    def admit(
        self,
        chain_json: bytes,
        invocation_json: bytes,
        *,
        operation: str,
        resource: str,
        arguments_digest: str,
        units: int,
    ) -> SignedReceipt:
        """Admit exactly this trusted gateway request, burning proof and quota.

        Pass parameters computed by the gateway from the actual action, not copied
        from untrusted proof fields. Retry with the same proof always rejects.
        """
        _require(len(chain_json) <= _MAX_BYTES, "chain too large")
        _require(len(invocation_json) <= _MAX_BYTES, "invocation too large")
        _require(type(units) is int and 0 <= units <= 2**53 - 1, "invalid units")
        try:
            chain = _CHAIN.validate_json(chain_json)
            signed = SignedInvocation.model_validate_json(invocation_json)
            invocation = signed.invocation
            leaf = chain[-1].grant if chain else None
            with self._connect() as db:
                db.execute("BEGIN IMMEDIATE")
                now = self.clock()
                ids = self._check_chain(chain, now)
                if leaf is None:
                    raise Rejected("empty chain")
                _require(invocation.grant == ids[-1], "proof binds another grant")
                _require(invocation.audience == self.audience, "proof audience mismatch")
                _require(
                    (
                        invocation.operation,
                        invocation.resource,
                        invocation.arguments_digest,
                        invocation.units,
                    )
                    == (operation, resource, arguments_digest, units),
                    "proof does not match the requested action",
                )
                _require(
                    invocation.issued_at <= now < invocation.expires_at, "proof expired or future"
                )
                _require(
                    invocation.issued_at >= leaf.not_before
                    and invocation.expires_at <= leaf.expires_at,
                    "proof outside grant interval",
                )
                _require(
                    Permission(operation=operation, resource=resource) in leaf.permissions,
                    "permission denied",
                )
                verify(
                    leaf.subject_key, signed.signature, b"delegation-gate/invocation/v1", invocation
                )
                _require(
                    db.execute(
                        "SELECT 1 FROM receipts WHERE subject = ? AND request_id = ?",
                        (leaf.subject_key, invocation.request_id),
                    ).fetchone()
                    is None,
                    "replayed request",
                )
                for identity, entry in zip(ids, chain, strict=True):
                    _require(
                        db.execute(
                            "SELECT 1 FROM revoked WHERE grant_id = ?", (identity,)
                        ).fetchone()
                        is None,
                        "grant revoked",
                    )
                    db.execute("INSERT OR IGNORE INTO usage VALUES (?, 0)", (identity,))
                    spent = db.execute(
                        "SELECT units FROM usage WHERE grant_id = ?", (identity,)
                    ).fetchone()
                    if spent is None:
                        raise RuntimeError("missing quota counter")
                    _require(spent[0] + units <= entry.grant.max_units, "quota exhausted")
                cursor = db.execute(
                    "INSERT INTO receipts(subject, request_id, body) VALUES (?, ?, '')",
                    (leaf.subject_key, invocation.request_id),
                )
                if cursor.lastrowid is None:
                    raise RuntimeError("missing receipt sequence")
                receipt = Receipt(
                    ledger_id=self.ledger_id,
                    sequence=cursor.lastrowid,
                    request_id=invocation.request_id,
                    subject_key=leaf.subject_key,
                    grants=ids,
                    audience=self.audience,
                    operation=operation,
                    resource=resource,
                    arguments_digest=arguments_digest,
                    units=units,
                    admitted_at=now,
                )
                result = SignedReceipt(
                    receipt=receipt,
                    signature=sign(self.receipt_key, b"delegation-gate/receipt/v1", receipt),
                )
                db.execute(
                    "UPDATE receipts SET body = ? WHERE sequence = ?",
                    (canonical(result).decode("ascii"), receipt.sequence),
                )
                for identity in ids:
                    db.execute(
                        "UPDATE usage SET units = units + ? WHERE grant_id = ?", (units, identity)
                    )
                # The context manager commits before this receipt is returned to the caller.
            return result
        except (InvalidSignature, ValidationError, sqlite3.IntegrityError) as exc:
            raise Rejected("invalid signature, malformed input, or replayed request") from exc

    def revoke(self, identity: str) -> None:
        """Administrative operation; do not expose without independent authorization."""
        if not re.fullmatch(r"[0-9a-f]{64}", identity):
            raise ValueError("invalid grant identity")
        with self._connect() as db:
            db.execute("INSERT OR IGNORE INTO revoked VALUES (?)", (identity,))

    def export_receipts(self) -> bytes:
        """Export signed admission receipts in sequence order as a JSON array."""
        with self._connect() as db:
            rows = db.execute("SELECT body FROM receipts ORDER BY sequence").fetchall()
        return ("[" + ",".join(row[0] for row in rows) + "]").encode("ascii")

    def receipt_page(self, *, after: int = 0, limit: int = 100) -> tuple[SignedReceipt, ...]:
        """Bounded, ordered export for trusted operational consumers."""
        if type(after) is not int or not 0 <= after <= 2**63 - 1:
            raise ValueError("after must be a nonnegative SQLite integer")
        if type(limit) is not int or not 1 <= limit <= 1000:
            raise ValueError("limit must be an integer from 1 to 1000")
        with self._connect() as db:
            rows = db.execute(
                "SELECT body FROM receipts WHERE sequence > ? ORDER BY sequence LIMIT ?",
                (after, limit),
            ).fetchall()
        return tuple(SignedReceipt.model_validate_json(row[0]) for row in rows)

    def grant_status(self, identity: str) -> dict[str, int | bool]:
        """Local usage and direct revocation only, not a grant authorization check."""
        if not re.fullmatch(r"[0-9a-f]{64}", identity):
            raise ValueError("invalid grant identity")
        with self._connect() as db:
            db.execute("BEGIN")
            usage = db.execute("SELECT units FROM usage WHERE grant_id = ?", (identity,)).fetchone()
            revoked = db.execute("SELECT 1 FROM revoked WHERE grant_id = ?", (identity,)).fetchone()
        return {"used_units": 0 if usage is None else usage[0], "revoked": revoked is not None}

    def backup(self, destination: str | Path) -> Path:
        """Online snapshot; never restore stale quotas into an active gateway."""
        target = Path(destination).resolve()
        descriptor = os.open(target, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        os.close(descriptor)
        try:
            with self._connect() as source:
                snapshot = sqlite3.connect(target)
                try:
                    source.backup(snapshot)
                    if snapshot.execute("PRAGMA integrity_check").fetchone()[0] != "ok":
                        raise RuntimeError("Backup integrity check failed")
                finally:
                    snapshot.close()
        except BaseException:
            target.unlink()
            raise
        return target


def verify_receipt(receipt_json: bytes, *, key: str, ledger_id: str, audience: str) -> Receipt:
    _require(len(receipt_json) <= _MAX_BYTES, "receipt too large")
    try:
        signed = SignedReceipt.model_validate_json(receipt_json)
        _require(signed.receipt.ledger_id == ledger_id, "receipt belongs to another ledger")
        _require(signed.receipt.audience == audience, "receipt audience mismatch")
        verify(key, signed.signature, b"delegation-gate/receipt/v1", signed.receipt)
        return signed.receipt
    except (InvalidSignature, ValidationError) as exc:
        raise Rejected("invalid receipt") from exc
