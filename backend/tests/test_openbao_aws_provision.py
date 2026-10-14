"""AWS OpenBao provisioning: idempotency, least-privilege policies, safe
token handling, rotation and TLS wiring — all hermetic (MockTransport only).

Nothing here touches the running local dev server or any cloud account.
Secret-shaped values below are canaries; tests additionally assert they
never appear in reports, state files, or exception text.
"""

import json
import re
import sys
import types

import httpx
import pytest
from pydantic import SecretStr

from scripts import openbao_aws_provision as p
from app.core.config import Settings
from app.secret_providers import SecretAccessDeniedError, build_secret_provider

ADMIN = "admin-canary-token"
APP = "app-canary-token-value"
SECRET_VALUE = "SECRET-VALUE-CANARY-not-real"

LAB_POLICY = (p.REPO_ROOT / "infrastructure" / "openbao" / "policies" / "securepam-read.hcl").read_text()
APP_HCL = p.APP_POLICY_FILE.read_text()
WRITER_HCL = p.WRITER_POLICY_FILE.read_text()


class FakeBao:
    """Enough of OpenBao for provision flows: seal/init, mounts, audit,
    policies, orphan-token lifecycle, KV writes."""

    def __init__(self, **kw):
        self.initialized = kw.get("initialized", False)
        self.sealed = kw.get("sealed", True)
        self.seal_type = kw.get("seal_type", "shamir")
        self.mounts = kw.get("mounts", {})
        self.audits = kw.get("audits", {})
        self.policies = kw.get("policies", {})
        self.tokens = {}   # accessor -> {"policies": [...], "revoked": bool}
        self.n = 0
        self.requests = []
        self.kv = {}
        self.kv_versions = {}
        self.roles = kw.get("roles", {})
        self.admin_is_root = kw.get("admin_is_root", True)
        self.minted_via_role = []
        self.init_body = None

    def __call__(self, request: httpx.Request) -> httpx.Response:
        path = request.url.path
        self.requests.append((request.method, path))
        body = {}
        if request.content:
            try:
                body = json.loads(request.content)
            except ValueError:
                body = {}
        if path == "/v1/sys/seal-status":
            return httpx.Response(200, json={"initialized": self.initialized, "sealed": self.sealed})
        if path == "/v1/sys/init" and request.method == "PUT":
            self.init_body = body
            self.initialized, self.sealed = True, True
            keys = ["RECOVERY-KEY-CANARY-1", "RECOVERY-KEY-CANARY-2", "RECOVERY-KEY-CANARY-3"]
            return httpx.Response(200, json={"recovery_keys": keys, "root_token": "ROOT-CANARY"})
        if path == "/v1/sys/unseal":
            self.sealed = False
            return httpx.Response(200, json={"sealed": False})
        if path == "/v1/sys/mounts":
            if request.method == "GET":
                return httpx.Response(200, json=self.mounts)
            return httpx.Response(400)
        if path.startswith("/v1/sys/mounts/"):
            self.mounts[path.rsplit("/v1/sys/mounts/", 1)[1].rstrip("/") + "/"] = {"type": "kv"}
            return httpx.Response(204)
        if path == "/v1/sys/audit":
            return httpx.Response(200, json=self.audits)
        if path == "/v1/sys/audit/file/":
            self.audits["file/"] = {}
            return httpx.Response(204)
        if path.startswith("/v1/sys/policies/acl/"):
            name = path.rsplit("/", 1)[1]
            if request.method == "GET":
                if name in self.policies:
                    return httpx.Response(200, json={"data": {"policy": self.policies[name]}})
                return httpx.Response(404)
            self.policies[name] = body.get("policy", "")
            return httpx.Response(204)
        if path.startswith("/v1/auth/token/roles/"):
            name = path.rsplit("/", 1)[1]
            if request.method == "GET":
                return httpx.Response(200, json={"data": self.roles[name]}) if name in self.roles else httpx.Response(404)
            self.roles[name] = body
            return httpx.Response(204)
        if path == "/v1/auth/token/lookup-self":
            return httpx.Response(200, json={"data": {"policies": ["root"] if self.admin_is_root else ["default", "securepam-admin"]}})
        if path.startswith("/v1/auth/token/create/"):
            role = path.rsplit("/", 1)[1]
            self.n += 1
            acc = f"accessor-{self.n}"
            self.tokens[acc] = {"policies": [role], "revoked": False}
            self.minted_via_role.append(role)
            return httpx.Response(200, json={"auth": {"client_token": f"TOKEN-CANARY-{self.n}",
                                                      "accessor": acc}})
        if path == "/v1/auth/token/create-orphan":
            self.n += 1
            acc = f"accessor-{self.n}"
            self.tokens[acc] = {"policies": body.get("policies", []), "revoked": False}
            return httpx.Response(200, json={"auth": {"client_token": f"TOKEN-CANARY-{self.n}",
                                                      "accessor": acc}})
        if path == "/v1/auth/token/lookup":  # takes a token secret, never an accessor
            return httpx.Response(400, json={"errors": ["missing client token"]})
        if path == "/v1/auth/token/lookup-accessor":
            meta = self.tokens.get(body.get("accessor", ""))
            if not meta or meta["revoked"]:
                return httpx.Response(403, json={"errors": ["denied"]})
            return httpx.Response(200, json={"data": {"policies": meta["policies"]}})
        if path == "/v1/auth/token/revoke-accessor":
            meta = self.tokens.get(body.get("accessor", ""))
            if meta:
                meta["revoked"] = True
            return httpx.Response(204)
        if path.startswith("/v1/secret/data/") and request.method == "PUT":
            version = self.kv_versions.get(path, 0) + 1
            self.kv_versions[path] = version
            self.kv[path] = body
            return httpx.Response(200, json={"data": {"version": version}})
        return httpx.Response(404)


def ctx_for(fake: FakeBao, tmp_path, **kw) -> p.Ctx:
    client = httpx.Client(base_url="https://bao.test", transport=httpx.MockTransport(fake))
    return p.Ctx(client=client, admin_headers={"X-Vault-Token": ADMIN}, mount="secret",
                 state_file=tmp_path / "state.json", out_dir=tmp_path, **kw)


def posted(fake: FakeBao, method: str, path: str):
    return [1 for m, q in fake.requests if m == method and q == path]


# --- init / unseal idempotency ------------------------------------------------

def test_init_body_matches_the_seal_type(tmp_path):
    """Auto-unseal (awskms) splits RECOVERY keys; sending secret_shares there is rejected by the server."""
    fake = FakeBao()
    p.initialize(ctx_for(fake, tmp_path), 5, 3, tmp_path / "k", tmp_path / "r", seal="awskms")
    assert fake.init_body == {"recovery_shares": 5, "recovery_threshold": 3}
    fake = FakeBao()
    p.initialize(ctx_for(fake, tmp_path), 5, 3, tmp_path / "k2", tmp_path / "r2", seal="shamir")
    assert fake.init_body == {"secret_shares": 5, "secret_threshold": 3}


def test_init_skipped_when_already_initialized(tmp_path):
    fake = FakeBao(initialized=True, sealed=False)
    checks = p.initialize(ctx_for(fake, tmp_path), 5, 3, tmp_path / "k", tmp_path / "r")
    assert checks[0].ok and "skipped" in checks[0].name
    assert not posted(fake, "PUT", "/v1/sys/init")


def test_initialize_writes_protected_files_and_reports_no_secrets(tmp_path, capsys):
    fake = FakeBao()
    ctx = ctx_for(fake, tmp_path)
    checks = p.initialize(ctx, 3, 2, tmp_path / "keys", tmp_path / "root")
    assert all(c.ok for c in checks)
    keys = (tmp_path / "keys").read_text()
    assert "RECOVERY-KEY-CANARY" in keys  # the secret IS in the 0600 file...
    import os
    assert oct(os.stat(tmp_path / "keys").st_mode & 0o777) == "0o600"
    assert oct(os.stat(tmp_path / "root").st_mode & 0o777) == "0o600"
    for c in checks:  # ...but never in the report
        print(c.line())
    out = capsys.readouterr().out
    assert "RECOVERY-KEY-CANARY" not in out and "ROOT-CANARY" not in out


def test_unseal_until_unsealed(tmp_path):
    fake = FakeBao(initialized=True, sealed=True)
    (tmp_path / "keys").write_text("K1\n")
    assert p.unseal(ctx_for(fake, tmp_path), tmp_path / "keys")[0].ok
    assert not fake.sealed


def test_unseal_missing_key_file_fails_closed(tmp_path):
    assert not p.unseal(ctx_for(FakeBao(), tmp_path), tmp_path / "nope")[0].ok


# --- mounts, audit, policies ----------------------------------------------------

def test_mount_audit_policy_are_kept_when_exact(tmp_path):
    fake = FakeBao(mounts={"secret/": {"type": "kv"}}, audits={"file/": {}},
                   policies={p.APP_POLICY: APP_HCL})
    ctx = ctx_for(fake, tmp_path)
    assert p.ensure_kv_mount(ctx, "secret").ok
    assert p.ensure_audit_device(ctx).ok
    assert "kept" in p.ensure_policy(ctx, p.APP_POLICY, APP_HCL).name
    assert not posted(fake, "POST", "/v1/sys/mounts/secret")
    assert not posted(fake, "PUT", "/v1/sys/policies/acl/securepam-app")


def test_mount_and_policy_created_when_missing_but_audit_device_is_declarative(tmp_path):
    # OpenBao 2.x answers "cannot enable audit device via API; use declarative, config-based audit
    # device management" (verified on 2.7.1): a missing device is a FAIL pointing at bao-config.hcl,
    # and the provisioner never tries the API.
    fake = FakeBao()
    ctx = ctx_for(fake, tmp_path)
    assert p.ensure_kv_mount(ctx, "secret").ok
    audit = p.ensure_audit_device(ctx)
    assert not audit.ok and "AUDIT_DEVICE_MISSING" in audit.detail and "bao-config.hcl" in audit.detail
    assert not [1 for m, q in fake.requests if m in ("PUT", "POST") and q.startswith("/v1/sys/audit")]
    assert p.ensure_policy(ctx, p.APP_POLICY, APP_HCL).ok
    assert fake.mounts["secret/"]["type"] == "kv"


def test_aws_server_config_declares_audit_and_plugin_directory():
    hcl = (p.AWS_DIR / "bao-config.hcl").read_text()
    code = "\n".join(l for l in hcl.splitlines() if not l.strip().startswith("#"))
    assert 'audit "file" "file"' in code and "/openbao/audit/audit.log" in code
    assert 'plugin_directory = "${PLUGIN_DIR}"' in code and 'command = "openbao-plugin-kms-awskms"' in code
    assert "disable_mlock" not in code and "tls_disable" not in code


def test_changed_policy_is_rewritten(tmp_path):
    fake = FakeBao(policies={p.APP_POLICY: "path \"secret/data/x\" { capabilities = [\"read\"] }"})
    assert p.ensure_policy(ctx_for(fake, tmp_path), p.APP_POLICY, APP_HCL).ok
    assert fake.policies[p.APP_POLICY] == APP_HCL


# --- app policy parity + writer least privilege (static, repo files) -------------

def _caps(hcl: str):
    return [l.strip() for l in hcl.splitlines() if l.strip().startswith("capabilities")]


def _paths(hcl: str, mount: str = "secret"):
    return sorted(set(re.findall(r'path\s+"%s/data/([^"*]+)"' % mount, hcl)))


def test_app_policy_matches_lab_and_declares_exact_registered_paths():
    assert _paths(APP_HCL) == ["securepam/assets/kali", "securepam/assets/wazuh-dashboard",
                               "securepam/assets/win11-lab"]
    # Lab stays a strict subset: the Wazuh credential lives in AWS OpenBao
    # only (web sessions never check credentials out).
    assert set(_paths(LAB_POLICY)) < set(_paths(APP_HCL))
    assert _caps(APP_HCL) == ['capabilities = ["read"]'] * 3
    assert "*" not in "\n".join(l for l in APP_HCL.splitlines() if l.strip().startswith("path"))
    for forbidden in ("create", "update", "delete", "list", "sudo", "patch"):
        assert f'"{forbidden}"' not in APP_HCL


def test_writer_policy_is_create_update_only_on_registered_paths():
    # KV v2 needs "create" for the FIRST write of a key (403 with "update" alone - verified live
    # against OpenBao 2.7.1) and "update" for later versions. Nothing else.
    assert _paths(WRITER_HCL) == ["securepam/assets/kali", "securepam/assets/wazuh-dashboard",
                                 "securepam/assets/win11-lab"]
    assert _caps(WRITER_HCL) == ['capabilities = ["create", "update"]'] * 3
    code = "\n".join(l for l in WRITER_HCL.splitlines() if l.strip() and not l.strip().startswith("#"))
    assert "*" not in "\n".join(l for l in code.splitlines() if l.strip().startswith("path"))
    for forbidden in ("sys/", "auth/token", "metadata", "destroy", "delete_", '"read"', '"delete"', '"list"'):
        assert forbidden not in code
    assert '"read"' not in WRITER_HCL and '"delete"' not in WRITER_HCL and '"list"' not in WRITER_HCL


# --- token lifecycle ------------------------------------------------------------

def test_token_minted_with_safe_params_and_state_keeps_accessor_only(tmp_path):
    fake = FakeBao(initialized=True, sealed=False)
    ctx = ctx_for(fake, tmp_path)
    out = p.ensure_token(ctx, kind="app", policies=[p.APP_POLICY], ttl=p.APP_TOKEN_TTL,
                         display_name="securepam-backend", token_file=tmp_path / "app-token",
                         state_key="app")
    assert all(c.ok for c in out)
    # Minted through the securepam-app token ROLE, which is orphan (never a child of the bootstrap
    # token), non-renewable and pins the policy - so the admin identity can rotate without root.
    assert [q for m, q in fake.requests if q == "/v1/auth/token/create/securepam-app"]
    state = json.loads((tmp_path / "state.json").read_text())
    assert state["tokens"]["app"]["accessor"].startswith("accessor-")
    assert "TOKEN-CANARY" not in json.dumps(state)  # secret never in state
    import os
    assert oct(os.stat(tmp_path / "app-token").st_mode & 0o777) == "0o600"


def test_valid_token_reused_without_minting(tmp_path):
    fake = FakeBao(initialized=True, sealed=False)
    ctx = ctx_for(fake, tmp_path)
    kw = dict(kind="app", policies=[p.APP_POLICY], ttl=p.APP_TOKEN_TTL,
              display_name="securepam-backend", token_file=tmp_path / "app-token", state_key="app")
    p.ensure_token(ctx, **kw)
    n = len([q for _, q in fake.requests if q == "/v1/auth/token/create-orphan"])
    out = p.ensure_token(ctx, **kw)
    assert out[0].ok and "reused" in out[0].name
    assert len([q for _, q in fake.requests if q == "/v1/auth/token/create-orphan"]) == n


def test_revoked_token_is_replaced(tmp_path):
    fake = FakeBao(initialized=True, sealed=False)
    ctx = ctx_for(fake, tmp_path)
    kw = dict(kind="app", policies=[p.APP_POLICY], ttl=p.APP_TOKEN_TTL,
              display_name="securepam-backend", token_file=tmp_path / "app-token", state_key="app")
    p.ensure_token(ctx, **kw)
    old = json.loads((tmp_path / "state.json").read_text())["tokens"]["app"]["accessor"]
    fake.tokens[old]["revoked"] = True  # rotation aftermath on the server side
    out = p.ensure_token(ctx, **kw)
    assert all(c.ok for c in out) and "reused" not in out[0].detail
    new = json.loads((tmp_path / "state.json").read_text())["tokens"]["app"]["accessor"]
    assert new != old


def _fake_verifier(ok: bool, calls=None):
    mod = types.ModuleType("scripts.verify_openbao_token")
    mod.CREDENTIAL_PATHS = []

    def verify(client, admin, secret, paths, mount, **kw):
        from scripts.openbao_aws_provision import Check
        if calls is not None:
            calls.append(("app", secret, kw))
        return [Check("replacement verifies", ok, "ttl=86400s renewable=False")]

    def verify_writer(client, admin, secret, paths, mount, **kw):
        from scripts.openbao_aws_provision import Check
        if calls is not None:
            calls.append(("writer", secret, kw))
        return [Check("replacement writer verifies", ok)]

    mod.verify, mod.verify_writer = verify, verify_writer
    return mod


def test_rotate_verifies_then_revokes_predecessor(tmp_path, monkeypatch):
    fake = FakeBao(initialized=True, sealed=False)
    ctx = ctx_for(fake, tmp_path)
    kw = dict(kind="app", policies=[p.APP_POLICY], ttl=p.APP_TOKEN_TTL,
              display_name="securepam-backend", token_file=tmp_path / "app-token", state_key="app")
    p.ensure_token(ctx, **kw)
    old = json.loads((tmp_path / "state.json").read_text())["tokens"]["app"]["accessor"]
    monkeypatch.setitem(sys.modules, "scripts.verify_openbao_token", _fake_verifier(True))
    out = p.rotate_token(ctx, **kw)
    assert all(c.ok for c in out)
    assert fake.tokens[old]["revoked"]  # predecessor dead only after replacement proved healthy
    new = json.loads((tmp_path / "state.json").read_text())["tokens"]["app"]["accessor"]
    assert new != old


def test_rotate_keeps_old_token_when_replacement_fails_verification(tmp_path, monkeypatch):
    fake = FakeBao(initialized=True, sealed=False)
    ctx = ctx_for(fake, tmp_path)
    kw = dict(kind="app", policies=[p.APP_POLICY], ttl=p.APP_TOKEN_TTL,
              display_name="securepam-backend", token_file=tmp_path / "app-token", state_key="app")
    p.ensure_token(ctx, **kw)
    old = json.loads((tmp_path / "state.json").read_text())["tokens"]["app"]["accessor"]
    live_before = (tmp_path / "app-token").read_text()
    monkeypatch.setitem(sys.modules, "scripts.verify_openbao_token", _fake_verifier(False))
    out = p.rotate_token(ctx, **kw)
    assert not all(c.ok for c in out)
    assert not fake.tokens[old]["revoked"]
    assert json.loads((tmp_path / "state.json").read_text())["tokens"]["app"]["accessor"] == old
    # The working token's secret file is untouched, and the failed replacement is revoked and gone.
    assert (tmp_path / "app-token").read_text() == live_before
    assert not (tmp_path / "app-token.pending").exists()
    assert [a for a, m in fake.tokens.items() if a != old and not m["revoked"]] == []


def test_rotate_app_uses_aws_policy_name_and_writer_uses_writer_verifier(tmp_path, monkeypatch):
    fake = FakeBao(initialized=True, sealed=False)
    ctx = ctx_for(fake, tmp_path)
    calls = []
    monkeypatch.setitem(sys.modules, "scripts.verify_openbao_token", _fake_verifier(True, calls))
    for kind, policy, state_key in (("app", p.APP_POLICY, "app"), ("writer", p.WRITER_POLICY, "writer")):
        kw = dict(kind=kind, policies=[policy], ttl="1h", display_name=kind,
                  token_file=tmp_path / f"{kind}-token", state_key=state_key)
        p.ensure_token(ctx, **kw)
        assert all(c.ok for c in p.rotate_token(ctx, **kw))
        # the live file now holds the VERIFIED replacement
        assert (tmp_path / f"{kind}-token").read_text().strip() == calls[-1][1]
    assert calls[0][0] == "app" and calls[0][2]["policy_name"] == "securepam-app"
    assert calls[1][0] == "writer" and calls[1][2]["policy_name"] == "securepam-writer"


# --- credential writes ------------------------------------------------------------

def test_store_credential_uses_writer_and_registered_path_only(tmp_path):
    fake = FakeBao(initialized=True, sealed=False)
    ctx = ctx_for(fake, tmp_path)
    ok = p.store_credential(ctx, "WRITER-CANARY", "kali", "kali-user", SECRET_VALUE)
    assert ok.ok and " created " in ok.name
    again = p.store_credential(ctx, "WRITER-CANARY", "kali", "kali-user", SECRET_VALUE)
    assert again.ok and "updated to version 2" in again.name and SECRET_VALUE not in again.line()
    assert fake.kv["/v1/secret/data/securepam/assets/kali"]["data"] == {
        "username": "kali-user", "password": SECRET_VALUE}
    bad = p.store_credential(ctx, "WRITER-CANARY", "evil", "u", SECRET_VALUE)
    assert not bad.ok
    traversal = p.store_credential(ctx, "WRITER-CANARY", "../sys", "u", SECRET_VALUE)
    assert not traversal.ok
    assert sorted(fake.kv) == ["/v1/secret/data/securepam/assets/kali"]


def test_store_wazuh_dashboard_credential_uses_its_registered_path(tmp_path):
    """The Wazuh reference is allowlisted end to end: provision name ->
    securepam/assets/wazuh-dashboard, written with username+password fields
    via the writer identity. Nothing is stored by this test run itself."""
    fake = FakeBao(initialized=True, sealed=False)
    ctx = ctx_for(fake, tmp_path)
    ok = p.store_credential(ctx, "WRITER-CANARY", "wazuh-dashboard", "wazuh-user", SECRET_VALUE)
    assert ok.ok and "wazuh-dashboard" in ok.name
    assert fake.kv["/v1/secret/data/securepam/assets/wazuh-dashboard"]["data"] == {
        "username": "wazuh-user", "password": SECRET_VALUE}


# --- provider: TLS wiring + revoked-token fail-closed -------------------------------

def _settings(**overrides):
    base = dict(_env_file=None, SECRET_PROVIDER="openbao",
                OPENBAO_ADDR="https://bao.test:8200", OPENBAO_TOKEN="t")
    base.update(overrides)
    return Settings(**base)


def test_ca_cert_reaches_the_http_client_and_verification_is_never_disabled():
    assert build_secret_provider(_settings(OPENBAO_CA_CERT="/etc/openbao/ca.pem"))._verify == "/etc/openbao/ca.pem"
    assert build_secret_provider(_settings())._verify is True


def test_revoked_or_expired_token_fails_closed_without_leaking():
    def denied(request: httpx.Request) -> httpx.Response:
        return httpx.Response(403, json={"errors": ["permission denied"]})

    async def read():
        from app.secret_providers import OpenBaoSecretProvider
        provider = OpenBaoSecretProvider(
            addr="https://bao.test:8200", token=SecretStr(APP), mount_point="secret",
            path_prefix="securepam", connect_timeout=1, request_timeout=2,
            transport=httpx.MockTransport(denied))
        with pytest.raises(SecretAccessDeniedError) as exc:
            await provider.read_secret("securepam/assets/kali")
        assert APP not in str(exc.value) and exc.value.__cause__ is None

    import asyncio
    asyncio.run(read())



# --- token roles, administrator identity, root retirement ---------------------------

def test_tokens_are_minted_through_their_roles_not_create_orphan(tmp_path):
    fake = FakeBao(initialized=True, sealed=False)
    ctx = ctx_for(fake, tmp_path)
    p.ensure_token(ctx, kind="app", policies=[p.APP_POLICY], ttl=p.APP_TOKEN_TTL, display_name="x",
                   token_file=tmp_path / "t", state_key="app")
    assert fake.minted_via_role == ["securepam-app"]
    assert not posted(fake, "POST", "/v1/auth/token/create-orphan")


def test_token_roles_written_by_root_and_only_checked_by_admin(tmp_path):
    fake = FakeBao(initialized=True, sealed=False)
    ctx = ctx_for(fake, tmp_path)
    assert p.ensure_token_role(ctx, p.APP_POLICY, "24h", can_write=True).ok
    role = fake.roles["securepam-app"]
    assert role["allowed_policies"] == ["securepam-app"] and role["orphan"] is True
    assert role["renewable"] is False and role["token_no_default_policy"] is True
    assert role["token_explicit_max_ttl"] == "24h"
    # a non-root admin never writes roles; a missing role is a precise FAIL
    missing = p.ensure_token_role(ctx, p.WRITER_POLICY, "1h", can_write=False)
    assert not missing.ok and "bootstrap" in missing.detail
    assert "securepam-writer" not in fake.roles


def test_admin_user_requires_a_strong_password_and_is_never_reset_silently(tmp_path):
    class Users(FakeBao):
        def __call__(self, request):
            if request.url.path.startswith("/v1/auth/userpass/users/"):
                self.requests.append((request.method, request.url.path))
                if request.method == "GET":
                    return httpx.Response(200 if self.user_exists else 404, json={})
                self.user_body = json.loads(request.content)
                return httpx.Response(204)
            return super().__call__(request)

    fake = Users(initialized=True, sealed=False)
    fake.user_exists = False
    ctx = ctx_for(fake, tmp_path)
    assert not p.ensure_admin_user(ctx, "short").ok
    ok = p.ensure_admin_user(ctx, SECRET_VALUE)
    assert ok.ok and SECRET_VALUE not in ok.line()
    assert fake.user_body["token_policies"] == ["securepam-admin"] and fake.user_body["token_max_ttl"] == "12h"
    fake.user_exists = True
    fake.user_body = None
    kept = p.ensure_admin_user(ctx, SECRET_VALUE)
    assert kept.ok and "unchanged" in kept.name and fake.user_body is None


def test_admin_policy_cannot_escalate():
    hcl = p.ADMIN_POLICY_FILE.read_text()
    code = "\n".join(l for l in hcl.splitlines() if not l.strip().startswith("#"))
    for forbidden in ('"sys/policies/acl/*" {\n  capabilities = ["create"', 'path "sys/auth/*"', 'path "sys/mounts/*"',
                      'path "auth/token/create"', "create-orphan", "sys/generate-root/", 'path "auth/token/roles/*" {\n  capabilities = ["create"',
                      "snapshot-force", 'path "sys/audit/*"', "sys/seal", '"root"', "secret/data/*"):
        assert forbidden not in code, forbidden
    assert 'path "auth/token/create/securepam-app"' in code and 'path "auth/token/create/securepam-writer"' in code


def test_retire_root_refuses_without_a_verified_admin(tmp_path, monkeypatch):
    fake = FakeBao(initialized=True, sealed=False)
    ctx = ctx_for(fake, tmp_path)
    root_file = tmp_path / "root"
    root_file.write_text("ROOT-CANARY")
    monkeypatch.setattr(p, "verify_admin_token", lambda client, token: [p.Check("admin", False)])
    out = p.retire_root(ctx, root_file, "admin-token")
    assert not out[0].ok and root_file.exists()
    assert not posted(fake, "POST", "/v1/auth/token/revoke-self")



def test_generate_root_decodes_with_the_server_otp_and_never_prints(tmp_path, capsys):
    import base64
    otp = "OTP-CANARY-0123456789abcd"
    secret = "s.NEWROOTCANARY0123456789"
    encoded = base64.b64encode(bytes(a ^ b for a, b in zip(secret.encode(), otp.encode()))).decode().rstrip("=")
    state = {"progress": 0}

    def handler(request):
        path = request.url.path
        if path == "/v1/sys/generate-root/attempt" and request.method == "GET":
            return httpx.Response(200, json={"started": False, "required": 2})
        if path == "/v1/sys/generate-root/attempt" and request.method == "PUT":
            return httpx.Response(200, json={"nonce": "n1", "otp": otp, "required": 2})
        if path == "/v1/sys/generate-root/update":
            state["progress"] += 1
            body = {"progress": state["progress"]}
            if state["progress"] == 2:
                body["encoded_token"] = encoded
            return httpx.Response(200, json=body)
        if path == "/v1/auth/token/lookup-self":
            ok = request.headers.get("X-Vault-Token") == secret
            return httpx.Response(200 if ok else 403, json={})
        return httpx.Response(404)

    ctx = p.Ctx(client=httpx.Client(base_url="https://bao.test", transport=httpx.MockTransport(handler)),
                state_file=tmp_path / "s.json", out_dir=tmp_path)
    out = p.generate_root(ctx, tmp_path / "root.txt", ["KEY-CANARY-1", "KEY-CANARY-2"])
    assert all(c.ok for c in out)
    assert (tmp_path / "root.txt").read_text().strip() == secret
    for c in out:
        print(c.line())
    printed = capsys.readouterr().out
    assert secret not in printed and otp not in printed and "KEY-CANARY" not in printed


def test_generate_root_reports_the_disabled_endpoint_precisely(tmp_path):
    ctx = p.Ctx(client=httpx.Client(base_url="https://bao.test",
                                    transport=httpx.MockTransport(lambda r: httpx.Response(403, json={}))),
                state_file=tmp_path / "s.json", out_dir=tmp_path)
    (check,) = p.generate_root(ctx, tmp_path / "root.txt", ["k"])
    assert not check.ok and "disable_unauthed_generate_root_endpoints" in check.detail
