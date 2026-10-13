"""Credential reference schemas. Input never carries a path, provider or
secret: the admin names a single secret segment and the server derives
the full reference (<prefix>/assets/<secret_name>). Output never carries
a secret value — there is no field for one."""

from datetime import datetime
from enum import Enum
from typing import Optional
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, field_validator

from app.secret_providers import InvalidSecretReferenceError
from app.secret_providers.paths import validate_secret_name


class SecretType(str, Enum):
    PASSWORD = "PASSWORD"
    SSH_KEY = "SSH_KEY"
    API_KEY = "API_KEY"
    CERTIFICATE = "CERTIFICATE"


class CredentialRefSet(BaseModel):
    # forbid: a client-supplied vault_path/provider is rejected, not ignored.
    model_config = ConfigDict(use_enum_values=True, extra="forbid")

    secret_name: str = Field(min_length=1, max_length=128, description="e.g. test-linux-01")
    secret_type: SecretType = SecretType.PASSWORD
    username: Optional[str] = Field(default=None, max_length=255)
    secret_version: Optional[int] = Field(default=None, ge=1)

    @field_validator("secret_name")
    @classmethod
    def safe_name(cls, v: str) -> str:
        try:
            return validate_secret_name(v)
        except InvalidSecretReferenceError as e:
            raise ValueError(str(e))


class CredentialRefOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    asset_id: UUID
    provider: str
    vault_path: str
    secret_type: str
    username: Optional[str]
    secret_version: Optional[int]
    is_active: bool
    last_rotated: Optional[datetime]
    created_at: datetime
    updated_at: datetime
