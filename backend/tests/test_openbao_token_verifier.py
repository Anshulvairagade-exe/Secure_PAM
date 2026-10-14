"""Scoped OpenBao token verification: every failure class is reported accurately and nothing secret leaks."""

import json

import httpx
import pytest

from scripts import verify_openbao_token as v

ADMIN, APP = "admin-canary-token", "app-canary-token"
SECRET_VALUE = "SECRET-VALUE-CANARY-not-real"
PATHS = ["securepam/assets/kali", "securepam/assets/win11-lab"]


class FakeBao:
    """Just enough of OpenBao: sys/health, token lookups, sys/capabilities, KV v2 reads/writes."""

    def __init__(self, **kw):
        self.sealed = kw.get("sealed", False)
        self.admin_ok = kw.get("admin_ok", True)
        self.app_exists = kw.get("app_exists", True)
        self.policies = kw.get("policies", ["securepam-read"])
        self.ttl, self.renewable = kw.get("ttl", 3600), kw.get("renewable", False)
        self.extra_caps = kw.get("extra_caps", {})          # path -> capabilities override
        self.read_status = kw.get("read_status", 200)
        self.fields = kw.get("fields", {"username": "u", "password": SECRET_VALUE})
        self.allow_write_probe = kw.get("allow_write_probe", False)
        self.cleaned = False
        self.requests = []

    def __call__(self, request: httpx.Request) -> httpx.Response:
        path, token = request.url.path, request.headers.get("X-Vault-Token", "")
        self.requests.append((request.method, path))
        if path == "/v1/sys/health":
            return httpx.Response(200, json={"initialized": True, "sealed": self.sealed})
        if path == "/v1/auth/token/lookup-self":
            return httpx.Response(200 if (token == ADMIN and self.admin_ok) else 403, json={})
        if path == "/v1/auth/token/lookup":
            if token != ADMIN or not self.app_exists:
                return httpx.Response(403, json={})
            return httpx.Response(200, json={"data": {"policies": self.policies, "ttl": self.ttl, "renewable": self.renewable}})
        if path == "/v1/sys/capabilities":
            paths = json.loads(request.content)["paths"]
            data = {}
            for p in paths:
                data[p] = self.extra_caps.get(p, ["read"] if p.startswith("secret/data/securepam/assets/")
                                              and p.rsplit("/", 1)[1] in ("kali", "win11-lab") else ["deny"])
            return httpx.Response(200, json={"data": data})
        if path.startswith("/v1/secret/data/") and request.method == "GET":
            name = path.rsplit("/", 1)[1]
            if name in ("kali", "win11-lab"):
                if self.read_status != 200:
                    return httpx.Response(self.read_status, json={"errors": ["x"]})
                return httpx.Response(200, json={"data": {"data": self.fields, "metadata": {"version": 1}}})
            return httpx.Response(403, json={"errors": ["permission denied"]})
        if path.startswith("/v1/secret/data/") and request.method == "PUT":
            return httpx.Response(200 if self.allow_write_probe else 403, json={})
        if path.startswith("/v1/secret/metadata/") and request.method == "DELETE":
            self.cleaned = True
            return httpx.Response(204)
        return httpx.Response(404)


def run(fake: FakeBao):
    client = httpx.Client(base_url="http://127.0.0.1:18200", transport=httpx.MockTransport(fake))
    return v.verify(client, ADMIN, APP, PATHS)


def failed(checks):
    return [c for c in checks if not c.ok]


def test_policy_file_declares_exactly_the_registered_paths():
    assert v.required_data_paths(v.POLICY_FILE.read_text()) == PATHS


def test_policy_file_grants_read_only_and_no_wildcards():
    text = v.POLICY_FILE.read_text()
    grants = [l.strip() for l in text.splitlines() if l.strip().startswith("capabilities")]
    assert grants == ['capabilities = ["read"]'] * 2
    assert "*" not in "\n".join(l for l in text.splitlines() if l.strip().startswith("path"))
    for forbidden in ("create", "update", "delete", "list", "sudo", "patch"):
        assert f'"{forbidden}"' not in text


def test_correct_token_passes_every_check():
    checks = run(FakeBao())
    assert not failed(checks) and len(checks) >= 20
    assert any("fields=['password', 'username']" in c.detail for c in checks)


def test_lookup_endpoint_not_capabilities_self_is_used():
    """A -no-default-policy token cannot call sys/capabilities-self; the verifier must never rely on it."""
    fake = FakeBao()
    run(fake)
    assert all("capabilities-self" not in p for _, p in fake.requests)


@pytest.mark.parametrize("kwargs, needle", [
    ({"sealed": True}, "OPENBAO_SEALED_OR_UNINITIALISED"),
    ({"admin_ok": False}, "ADMIN_TOKEN_REJECTED"),
    ({"app_exists": False}, "SCOPED_TOKEN_INVALID_OR_EXPIRED"),
    ({"policies": ["default", "securepam-read"]}, "POLICY_NOT_ATTACHED_OR_TOO_BROAD"),
    ({"policies": []}, "POLICY_NOT_ATTACHED_OR_TOO_BROAD"),
    ({"renewable": True}, "renewable=True"),
    ({"ttl": 30 * 24 * 3600}, "ttl="),
    ({"read_status": 403}, "KV_READ_DENIED"),
    ({"read_status": 404}, "SECRET_NOT_FOUND"),
    ({"fields": {"username": "u"}}, "MISSING_FIELDS=['password']"),
])
def test_each_failure_class_is_named_accurately(kwargs, needle):
    problems = failed(run(FakeBao(**kwargs)))
    assert problems and any(needle in c.detail for c in problems), [c.line() for c in problems]


def test_extra_capabilities_on_a_registered_path_are_too_broad():
    path = "secret/data/securepam/assets/win11-lab"
    problems = failed(run(FakeBao(extra_caps={path: ["read", "update"]})))
    assert any("POLICY_TOO_BROAD" in c.detail for c in problems)


def test_delete_or_destroy_access_is_a_failure():
    problems = failed(run(FakeBao(extra_caps={"secret/destroy/securepam/assets/kali": ["update"]})))
    assert any("destroy" in c.name for c in problems)


def test_unregistered_read_allowed_is_a_failure_and_write_probe_is_cleaned_up():
    fake = FakeBao(allow_write_probe=True)
    problems = failed(run(fake))
    assert any("write" in c.name for c in problems) and fake.cleaned


def test_nothing_secret_is_ever_in_the_report():
    for fake in (FakeBao(), FakeBao(read_status=403), FakeBao(fields={"username": "u"})):
        report = "\n".join(c.line() for c in run(fake))
        for secret in (ADMIN, APP, SECRET_VALUE):
            assert secret not in report


def test_unreachable_server_is_reported():
    def boom(request):
        raise httpx.ConnectError("refused")
    client = httpx.Client(base_url="http://127.0.0.1:1", transport=httpx.MockTransport(boom))
    (check,) = v.verify(client, ADMIN, APP, PATHS)
    assert not check.ok and "OPENBAO_UNREACHABLE" in check.detail


@pytest.mark.parametrize("addr, ok", [
    ("http://127.0.0.1:18200", True), ("https://bao.internal", True),
    ("[http://127.0.0.1:18200](http://127.0.0.1:18200)", False), ("http://127.0.0.1:18200/v1", False),
    ("http://user:pass@127.0.0.1:18200", False), ("127.0.0.1:18200", False), ("", False),
])
def test_address_must_be_a_literal_url(addr, ok):
    assert v.valid_addr(addr) is ok


def test_aws_policy_name_is_accepted_when_requested():
    client = httpx.Client(base_url="http://127.0.0.1:18200", transport=httpx.MockTransport(FakeBao(policies=["securepam-app"])))
    assert not failed(v.verify(client, ADMIN, APP, PATHS, policy_name="securepam-app"))
    # ...and the lab default still refuses it (exact policy, no silent widening)
    assert failed(v.verify(client, ADMIN, APP, PATHS))


def test_unstored_registered_secret_is_pending_only_when_explicitly_allowed():
    fake = FakeBao(read_status=404)
    client = httpx.Client(base_url="http://127.0.0.1:18200", transport=httpx.MockTransport(fake))
    assert any("SECRET_NOT_FOUND" in c.detail for c in failed(v.verify(client, ADMIN, APP, PATHS)))
    checks = v.verify(client, ADMIN, APP, PATHS, allow_unstored=PATHS)
    assert not failed(checks) and sum("PENDING" in c.detail for c in checks) == 2


class FakeWriterBao(FakeBao):
    def __init__(self, **kw):
        super().__init__(policies=kw.pop("policies", ["securepam-writer"]), **kw)
        self.writer_caps = kw.get("writer_caps", ["create", "update"])

    def __call__(self, request):
        if request.url.path == "/v1/sys/capabilities":
            paths = json.loads(request.content)["paths"]
            return httpx.Response(200, json={"data": {
                p: (self.writer_caps if p.startswith("secret/data/securepam/assets/") and p.rsplit("/", 1)[1] in ("kali", "win11-lab")
                    else ["deny"]) for p in paths}})
        if request.url.path.startswith("/v1/secret/data/") and request.method == "GET":
            return httpx.Response(403, json={"errors": ["permission denied"]})
        return super().__call__(request)


def test_writer_verifier_requires_exactly_create_and_update():
    client = httpx.Client(base_url="http://127.0.0.1:18200", transport=httpx.MockTransport(FakeWriterBao()))
    checks = v.verify_writer(client, ADMIN, APP, PATHS)
    assert checks and not failed(checks)
    for caps in (["update"], ["create", "read", "update"], ["create", "delete", "update"]):
        client = httpx.Client(base_url="http://127.0.0.1:18200", transport=httpx.MockTransport(FakeWriterBao(writer_caps=caps)))
        assert failed(v.verify_writer(client, ADMIN, APP, PATHS)), caps
    probe = FakeWriterBao(allow_write_probe=True)
    client = httpx.Client(base_url="http://127.0.0.1:18200", transport=httpx.MockTransport(probe))
    assert failed(v.verify_writer(client, ADMIN, APP, PATHS)) and probe.cleaned
    assert all(APP not in c.line() and SECRET_VALUE not in c.line() for c in checks)
