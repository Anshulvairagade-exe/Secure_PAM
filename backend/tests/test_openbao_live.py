"""
Live OpenBao integration — OPT-IN, skipped unless OPENBAO_LIVE_TEST=1.

Point it at a dev server with the RESTRICTED application token (never a
root token — test_restricted_token_is_not_privileged fails if you do):

    OPENBAO_LIVE_TEST=1 \
    OPENBAO_LIVE_ADDR=http://127.0.0.1:8200 \
    OPENBAO_LIVE_TOKEN="$SECUREPAM_BAO_TOKEN" \
    pytest tests/test_openbao_live.py -v

Optional: OPENBAO_LIVE_MOUNT (default "secret"), OPENBAO_LIVE_PATH
(default "securepam/assets/test-linux-01"). Secret values are asserted on
shape only and never printed.

Non-destructive by construction: write/delete probes target a sibling
probe path inside the same policy scope (never the real secret), and the
whole module refuses to run if the token turns out to be privileged — so a
root token pasted here by mistake can't overwrite or destroy anything.
"""

import os

import httpx
import pytest
from pydantic import SecretStr

from app.secret_providers import OpenBaoSecretProvider, SecretAccessDeniedError

pytestmark = [
    pytest.mark.openbao_live,
    pytest.mark.skipif(os.environ.get("OPENBAO_LIVE_TEST") != "1", reason="set OPENBAO_LIVE_TEST=1 to run"),
]

ADDR = os.environ.get("OPENBAO_LIVE_ADDR", "http://127.0.0.1:8200").rstrip("/")
TOKEN = os.environ.get("OPENBAO_LIVE_TOKEN", "")
MOUNT = os.environ.get("OPENBAO_LIVE_MOUNT", "secret")
PATH = os.environ.get("OPENBAO_LIVE_PATH", "securepam/assets/test-linux-01")
PROBE = PATH.rsplit("/", 1)[0] + "/securepam-write-probe"  # same policy glob, never the real secret


@pytest.fixture
def provider() -> OpenBaoSecretProvider:
    if not TOKEN:
        pytest.fail("OPENBAO_LIVE_TOKEN is not set")
    return OpenBaoSecretProvider(
        addr=ADDR, token=SecretStr(TOKEN), mount_point=MOUNT, path_prefix=PATH.split("/")[0],
        connect_timeout=3, request_timeout=5,
    )


def _status(method: str, path: str, json=None) -> int:
    headers = {"X-Vault-Token": TOKEN}
    if method == "PATCH":
        headers["Content-Type"] = "application/merge-patch+json"
    with httpx.Client(base_url=ADDR, timeout=5, trust_env=False) as c:
        return c.request(method, f"/v1/{path}", headers=headers, json=json).status_code


@pytest.fixture(scope="module", autouse=True)
def _refuse_privileged_token():
    """Abort before any probe if the token can administer the server."""
    if TOKEN and _status("GET", "sys/mounts") != 403:
        pytest.fail("OPENBAO_LIVE_TOKEN is privileged (can read sys/mounts) — use the restricted app token")


async def test_health(provider):
    assert (await provider.health()).healthy


async def test_restricted_token_can_read_test_secret(provider):
    record = await provider.read_secret(PATH)
    assert {"username", "password"} <= set(record.data)
    assert isinstance(record.version, int)


async def test_read_outside_policy_denied(provider):
    prefix = PATH.split("/")[0]
    with pytest.raises(SecretAccessDeniedError):
        await provider.read_secret(f"{prefix}/not-in-policy/x")


@pytest.mark.parametrize(
    "method, path, body",
    [
        ("POST", f"{MOUNT}/data/{PROBE}", {"data": {"username": "x", "password": "x"}}),
        ("PUT", f"{MOUNT}/data/{PROBE}", {"data": {"username": "x", "password": "x"}}),
        ("PATCH", f"{MOUNT}/data/{PROBE}", {"data": {"x": "y"}}),
        ("DELETE", f"{MOUNT}/data/{PROBE}", None),
        ("POST", f"{MOUNT}/delete/{PROBE}", {"versions": [1]}),
        ("POST", f"{MOUNT}/destroy/{PROBE}", {"versions": [1]}),
        ("DELETE", f"{MOUNT}/metadata/{PROBE}", None),
        ("POST", f"{MOUNT}/metadata/{PROBE}", {"max_versions": 1}),
    ],
)
def test_write_and_delete_denied(method, path, body):
    assert _status(method, path, body) == 403


@pytest.mark.parametrize(
    "method, path",
    [("GET", "sys/mounts"), ("GET", "sys/policies/acl"), ("LIST", "sys/policies/acl"),
     ("POST", "auth/token/create"), ("GET", "sys/auth")],
)
def test_restricted_token_is_not_privileged(method, path):
    assert _status(method, path, {} if method == "POST" else None) == 403
