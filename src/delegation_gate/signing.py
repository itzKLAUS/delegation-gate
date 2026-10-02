"""Domain-separated Ed25519 signatures over deterministic JSON."""

import hashlib
import json

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from .model import Grant, Invocation, SignedGrant, SignedInvocation, WireModel


def canonical(model: WireModel) -> bytes:
    return json.dumps(
        model.model_dump(mode="json"),
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        allow_nan=False,
    ).encode("ascii")


def public_key(key: Ed25519PrivateKey | Ed25519PublicKey) -> str:
    public = key.public_key() if isinstance(key, Ed25519PrivateKey) else key
    return public.public_bytes_raw().hex()


def sign(key: Ed25519PrivateKey, domain: bytes, model: WireModel) -> str:
    return key.sign(domain + b"\x00" + canonical(model)).hex()


def verify(key: str, signature: str, domain: bytes, model: WireModel) -> None:
    Ed25519PublicKey.from_public_bytes(bytes.fromhex(key)).verify(
        bytes.fromhex(signature), domain + b"\x00" + canonical(model)
    )


def grant_id(grant: SignedGrant) -> str:
    return hashlib.sha256(b"delegation-gate/grant-id/v1\x00" + canonical(grant)).hexdigest()


def sign_grant(key: Ed25519PrivateKey, grant: Grant) -> SignedGrant:
    return SignedGrant(grant=grant, signature=sign(key, b"delegation-gate/grant/v1", grant))


def sign_invocation(key: Ed25519PrivateKey, invocation: Invocation) -> SignedInvocation:
    return SignedInvocation(
        invocation=invocation,
        signature=sign(key, b"delegation-gate/invocation/v1", invocation),
    )
