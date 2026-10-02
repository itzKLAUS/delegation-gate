"""Versioned, immutable wire models; unknown fields and coercion are rejected."""

from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

Name = Annotated[str, Field(min_length=1, max_length=128)]
Digest = Annotated[str, Field(pattern=r"^[0-9a-f]{64}$")]
Signature = Annotated[str, Field(pattern=r"^[0-9a-f]{128}$")]
Units = Annotated[int, Field(ge=0, le=2**53 - 1)]
Timestamp = Annotated[int, Field(ge=0, le=2**53 - 1)]


class WireModel(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid", strict=True)

    @field_validator("version", mode="before", check_fields=False)
    @classmethod
    def exact_version(cls, value: object) -> object:
        if type(value) is not int or value != 1:
            raise ValueError("unsupported wire version")
        return value


class Permission(WireModel):
    operation: Name
    resource: Name


class Grant(WireModel):
    version: Literal[1] = 1
    subject_key: Digest
    audience: Name
    permissions: Annotated[tuple[Permission, ...], Field(min_length=1, max_length=32)]
    not_before: Timestamp
    expires_at: Timestamp
    max_units: Units
    remaining_delegations: Annotated[int, Field(ge=0, le=8)] = 0
    parent: Digest | None = None
    nonce: Annotated[str, Field(min_length=16, max_length=128)]

    @model_validator(mode="after")
    def valid_interval(self) -> "Grant":
        if self.expires_at <= self.not_before:
            raise ValueError("expires_at must follow not_before")
        if len(set(self.permissions)) != len(self.permissions):
            raise ValueError("duplicate permissions")
        return self


class SignedGrant(WireModel):
    grant: Grant
    signature: Signature


class Invocation(WireModel):
    version: Literal[1] = 1
    grant: Digest
    request_id: Annotated[str, Field(min_length=16, max_length=128)]
    audience: Name
    operation: Name
    resource: Name
    arguments_digest: Digest
    units: Units
    issued_at: Timestamp
    expires_at: Timestamp

    @model_validator(mode="after")
    def short_lifetime(self) -> "Invocation":
        if not 0 < self.expires_at - self.issued_at <= 60:
            raise ValueError("invocation lifetime must be between 1 and 60 seconds")
        return self


class SignedInvocation(WireModel):
    invocation: Invocation
    signature: Signature


class Receipt(WireModel):
    version: Literal[1] = 1
    ledger_id: Digest
    sequence: Annotated[int, Field(ge=1)]
    request_id: Name
    subject_key: Digest
    grants: Annotated[tuple[Digest, ...], Field(min_length=1, max_length=9)]
    audience: Name
    operation: Name
    resource: Name
    arguments_digest: Digest
    units: Units
    admitted_at: Timestamp


class SignedReceipt(WireModel):
    receipt: Receipt
    signature: Signature
