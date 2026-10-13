"""
SSH Host-Key Verification Service — SecurePAM Member 10 (SSH Gateway).

Enforces strict, fail-closed SSH host key verification using AsyncSSH.
Mitigates Machine-in-the-Middle (MitM) attacks by ensuring target hosts are
authenticated before credentials are exchanged.

Security Controls:
- Fail-Closed: Unknown host keys and mismatched keys are strictly rejected.
- No Automatic TOFU: Blind trust-on-first-use is disallowed; keys must be pre-provisioned.
- Never Insecure: Disabling verification (`known_hosts=None`) or trusting client-supplied
  fingerprints is forbidden.
- Zero Migrations: Utilizes OpenSSH known_hosts format, filesystem paths, and Redis key
  registries without requiring PostgreSQL schema alterations.
"""

import os
from typing import Optional, Union

import asyncssh
from redis.exceptions import RedisError

from app.models.asset import Asset


class SSHHostKeyError(Exception):
    """Base exception for host key verification failures."""


class SSHHostKeyUnknownError(SSHHostKeyError):
    """Host is not in the trusted known-hosts registry (fail-closed)."""


class SSHHostKeyMismatchError(SSHHostKeyError):
    """Presented host key does not match the pinned, trusted key."""


class SSHHostKeyStorageError(SSHHostKeyError):
    """Storage or known-hosts configuration failure."""


class SSHHostKeyValidator:
    """
    Validates upstream SSH host keys against an explicitly provisioned OpenSSH
    known-hosts configuration or trusted Redis registry.
    """

    REDIS_KEY_PREFIX = "ssh:known_hosts:"

    def __init__(
        self,
        *,
        known_hosts_data: Optional[str] = None,
        known_hosts_path: Optional[str] = None,
        redis_client=None,
    ) -> None:
        self._known_hosts_data = known_hosts_data
        self._known_hosts_path = known_hosts_path
        self._redis = redis_client
        self._cached_known_hosts: Optional[asyncssh.SSHKnownHosts] = None

        if known_hosts_data:
            try:
                self._cached_known_hosts = asyncssh.import_known_hosts(known_hosts_data)
            except Exception as exc:
                raise SSHHostKeyStorageError(f"Failed to parse known_hosts data: {exc}") from exc

    def _get_file_known_hosts(self) -> Optional[asyncssh.SSHKnownHosts]:
        if self._cached_known_hosts is not None:
            return self._cached_known_hosts

        path = self._known_hosts_path or os.environ.get("SECUREPAM_KNOWN_HOSTS_PATH")
        if path and os.path.isfile(path):
            try:
                with open(path, "r", encoding="utf-8") as f:
                    content = f.read()
                self._cached_known_hosts = asyncssh.import_known_hosts(content)
                return self._cached_known_hosts
            except Exception as exc:
                raise SSHHostKeyStorageError(f"Failed to read known_hosts file at {path}: {exc}") from exc

        return None

    async def _get_redis_known_hosts(self, asset: Asset) -> Optional[asyncssh.SSHKnownHosts]:
        if self._redis is None:
            return None

        key = f"{self.REDIS_KEY_PREFIX}{asset.id}"
        try:
            raw_entry = await self._redis.get(key)
        except RedisError as exc:
            raise SSHHostKeyStorageError(f"Redis unavailable while querying host key: {exc}") from exc

        if raw_entry:
            try:
                return asyncssh.import_known_hosts(raw_entry)
            except Exception as exc:
                raise SSHHostKeyStorageError(f"Malformed host key entry in Redis: {exc}") from exc

        return None

    async def get_trusted_known_hosts_for_asset(self, asset: Asset) -> asyncssh.SSHKnownHosts:
        """
        Resolve the trusted known-hosts configuration for an asset.
        Fails closed with SSHHostKeyUnknownError if no trusted key entry exists.
        """
        # 1. Check in-memory / file-based known hosts
        kh = self._get_file_known_hosts()
        if kh is not None:
            matches, _, _, _, _, _, _ = kh.match(asset.hostname, asset.ip_address, asset.port)
            if matches:
                return kh

        # 2. Check Redis trusted host key registry
        redis_kh = await self._get_redis_known_hosts(asset)
        if redis_kh is not None:
            matches, _, _, _, _, _, _ = redis_kh.match(asset.hostname, asset.ip_address, asset.port)
            if matches:
                return redis_kh

        # 3. Fail closed: No trusted key registered for this asset
        raise SSHHostKeyUnknownError(
            f"No trusted host key configured for target asset '{asset.name}' "
            f"({asset.hostname}:{asset.port}). Connection rejected."
        )

    def verify_server_key(
        self,
        known_hosts: asyncssh.SSHKnownHosts,
        host: str,
        addr: str,
        port: int,
        server_key: asyncssh.SSHKey,
    ) -> bool:
        """
        Explicit check to verify an SSHKey against known_hosts.
        Raises SSHHostKeyUnknownError if unknown, or SSHHostKeyMismatchError if differing.
        """
        matches, revoked, certificate_authorities, _, _, _, _ = known_hosts.match(host, addr, port)
        if revoked:
            raise SSHHostKeyMismatchError(f"Host key for {host} has been explicitly revoked.")

        if not matches:
            raise SSHHostKeyUnknownError(f"No trusted host key matches {host}:{port}.")

        # Check if the presented key matches any of the trusted keys for this host
        server_pub = (
            server_key.convert_to_public()
            if hasattr(server_key, "convert_to_public")
            else server_key
        )
        for trusted_key in matches:
            trusted_pub = (
                trusted_key.convert_to_public()
                if hasattr(trusted_key, "convert_to_public")
                else trusted_key
            )
            if trusted_pub == server_pub or trusted_pub.export_public_key() == server_pub.export_public_key():
                return True

        raise SSHHostKeyMismatchError(
            f"Host key mismatch for {host}:{port}. Presented key does not match trusted key."
        )
