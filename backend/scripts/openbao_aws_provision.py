"""
Idempotent provisioning for a NEW AWS OpenBao instance (SecurePAM production).

    python -m scripts.openbao_aws_provision --addr https://bao.securepam.internal \
        --seal awskms

What it does, in order (every step checks current state first, so re-running
is safe and never reinitializes, overwrites, or duplicates):
  1. Detect initialization via sys/seal-status. Uninitialized -> initialize
     (Shamir shares/threshold; with awskms the server self-unseals and init
     returns recovery keys, never unseal keys).
  2. Unseal when sealed (Shamir path only; keys read from protected files).
  3. Enable the KV v2 mount and a file audit device when absent.
  4. Write the securepam-app (read-only, exact registered paths) and
     securepam-writer (create+update only, same paths) policies when missing/changed.
  5. Mint the application + writer identities as short-lived, non-renewable,
     orphan tokens with no default policy. Existing valid tokens are reused;
     only the token ACCESSOR (never the secret) is recorded in the state file.
  6. Optionally store one credential (Windows/Kali) from a hidden prompt or
     env var via the WRITER identity — never the browser, never argv.

Secrets handling (hard rules, enforced by tests):
  - Root/recovery keys, unseal keys and tokens are written ONLY to 0600 files
    outside the repository (defaults under ~/.securepam/) and optionally
    pushed to AWS Secrets Manager with --push-secrets (value travels via a
    0600 temp file + `file://`, never argv).
  - stdout/stderr carry PASS/FAIL lines with names, HTTP statuses, counts and
    file paths only — no token, password, key or response body, ever.
  - Rotation (`--rotate app|writer`) mints the replacement, re-verifies it
    with scripts.verify_openbao_token, then revokes the predecessor by
    accessor. No restart, no reinit.

Exit codes: 0 all checks pass; 1 a check failed (see FAIL lines); 2 usage /
unreachable / missing input.
"""

import argparse
import base64
import getpass
import json
import os
import stat
import subprocess
import sys
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional

import httpx

REPO_ROOT = Path(__file__).resolve().parents[2]
AWS_DIR = REPO_ROOT / "infrastructure" / "openbao" / "aws"
APP_POLICY = "securepam-app"
WRITER_POLICY = "securepam-writer"
ADMIN_POLICY = "securepam-admin"
APP_POLICY_FILE = AWS_DIR / "policies" / "securepam-app.hcl"
WRITER_POLICY_FILE = AWS_DIR / "policies" / "securepam-writer.hcl"
ADMIN_POLICY_FILE = AWS_DIR / "policies" / "securepam-admin.hcl"
ADMIN_USER = "securepam-admin"
ADMIN_TOKEN_TTL, ADMIN_TOKEN_MAX_TTL = "8h", "12h"
MIN_ADMIN_PASSWORD_LENGTH = 16
# Registered credential paths (relative to the mount), single source of
# truth shared with the policies and the verifier.
CREDENTIAL_PATHS = ["securepam/assets/win11-lab", "securepam/assets/kali",
                      "securepam/assets/wazuh-dashboard"]

APP_TOKEN_TTL = "24h"      # short-lived; rotated by --rotate (verifier caps at 7d)
WRITER_TOKEN_TTL = "1h"    # single-purpose: mint, store the secret, let it die


@dataclass
class Check:
    name: str
    ok: bool
    detail: str = ""

    def line(self) -> str:
        return f"{'PASS' if self.ok else 'FAIL'} {self.name}" + (f" - {self.detail}" if self.detail else "")


@dataclass
class Ctx:
    client: httpx.Client
    admin_headers: Dict[str, str] = field(default_factory=dict)
    mount: str = "secret"
    state_file: Path = Path.home() / ".securepam" / "openbao-aws-state.json"
    out_dir: Path = Path.home() / ".securepam"


def _write_protected(path: Path, content: str) -> Check:
    """Atomic 0600 write outside the repo. Reports path + byte count only."""
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(content, encoding="utf-8")
    os.chmod(tmp, 0o600)
    os.replace(tmp, path)
    return Check(f"stored protected file {path}", True, f"{path.stat().st_size} bytes, mode 600")


def _load_state(ctx: Ctx) -> dict:
    try:
        return json.loads(ctx.state_file.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}


def _save_state(ctx: Ctx, state: dict) -> None:
    ctx.state_file.parent.mkdir(parents=True, exist_ok=True)
    tmp = ctx.state_file.with_suffix(".tmp")
    tmp.write_text(json.dumps(state, indent=2), encoding="utf-8")
    os.chmod(tmp, 0o600)
    os.replace(tmp, ctx.state_file)


def seal_status(ctx: Ctx) -> Check:
    try:
        info = ctx.client.get("/v1/sys/seal-status").json()
    except (httpx.HTTPError, ValueError) as exc:
        return Check("OpenBao reachable", False, f"OPENBAO_UNREACHABLE ({type(exc).__name__})")
    if not info.get("initialized"):
        return Check("OpenBao initialised", False, "UNINITIALISED (provision will initialise)")
    if info.get("sealed"):
        return Check("OpenBao unsealed", False, "SEALED (provision will unseal)")
    return Check("OpenBao initialised and unsealed", True)


def initialize(ctx: Ctx, shares: int, threshold: int, key_file: Path, root_file: Path,
               seal: str = "shamir") -> List[Check]:
    """Initialize exactly once. Keys + initial root token go to 0600 files;
    only counts and paths are reported. With an auto-unseal seal (awskms)
    the server rejects secret_shares/secret_threshold: the split applies to
    RECOVERY keys instead (recovery_shares/recovery_threshold)."""
    try:
        status = ctx.client.get("/v1/sys/seal-status").json()
    except (httpx.HTTPError, ValueError) as exc:
        return [Check("OpenBao reachable", False, f"OPENBAO_UNREACHABLE ({type(exc).__name__})")]
    if status.get("initialized"):
        return [Check("initialise (already initialised — skipped)", True)]
    body = ({"recovery_shares": shares, "recovery_threshold": threshold} if seal == "awskms"
            else {"secret_shares": shares, "secret_threshold": threshold})
    r = ctx.client.put("/v1/sys/init", json=body)
    if r.status_code != 200:
        return [Check("initialise", False, f"INIT_FAILED (HTTP {r.status_code})")]
    body = r.json()
    keys = body.get("keys") or body.get("recovery_keys") or []
    root = body.get("root_token", "")
    if not keys or not root:
        return [Check("initialise", False, "INIT_RESPONSE_MISSING_KEYS (retry or check seal type)")]
    out = [_write_protected(key_file, "\n".join(keys) + "\n"),
           _write_protected(root_file, root + "\n")]
    return [Check("initialise", True, f"{len(keys)} shares, threshold {threshold}; root to protected file")] + out


def unseal(ctx: Ctx, key_file: Path) -> List[Check]:
    """Feed Shamir shares from a protected file until unsealed. With awskms
    auto-unseal there is nothing to do (still verified unsealed)."""
    try:
        keys = key_file.read_text(encoding="utf-8").split()
    except OSError:
        return [Check("unseal keys readable", False, f"cannot read {key_file}")]
    for key in keys:
        try:
            info = ctx.client.put("/v1/sys/unseal", json={"key": key}).json()
        except (httpx.HTTPError, ValueError) as exc:
            return [Check("unseal", False, f"UNSEAL_REQUEST_FAILED ({type(exc).__name__})")]
        if not info.get("sealed", True):
            return [Check("unseal", True, "unsealed")]
    return [Check("unseal", False, "STILL_SEALED (wrong/insufficient shares?)")]


def ensure_kv_mount(ctx: Ctx, mount: str) -> Check:
    try:
        mounts = ctx.client.get("/v1/sys/mounts", headers=ctx.admin_headers).json()
    except (httpx.HTTPError, ValueError) as exc:
        return Check("KV mount present", False, f"MOUNT_LIST_FAILED ({type(exc).__name__})")
    if f"{mount}/" in mounts:
        return Check(f"KV mount {mount}/ present (kept)", True)
    r = ctx.client.post(f"/v1/sys/mounts/{mount}", headers=ctx.admin_headers,
                        json={"type": "kv", "options": {"version": "2"}})
    if r.status_code not in (200, 204):
        return Check(f"KV mount {mount}/", False, f"MOUNT_CREATE_FAILED (HTTP {r.status_code})")
    return Check(f"KV mount {mount}/ enabled", True)


def ensure_audit_device(ctx: Ctx, path: str = "file/", log_path: str = "/openbao/audit/audit.log") -> Check:
    """OpenBao 2.x refuses API-created audit devices ("use declarative, config-based audit device
    management"), so the device is declared in bao-config.hcl and this only VERIFIES it is active."""
    try:
        r = ctx.client.get("/v1/sys/audit", headers=ctx.admin_headers)
        body = r.json()
    except (httpx.HTTPError, ValueError) as exc:
        return Check("audit device active", False, f"AUDIT_LIST_FAILED ({type(exc).__name__})")
    devices = body.get("data", body) if isinstance(body, dict) else {}
    if not isinstance(devices, dict) or path not in devices:
        return Check("audit device active", False,
                     f"AUDIT_DEVICE_MISSING: declare audit \"file\" \"{path.rstrip('/')}\" in bao-config.hcl and restart")
    got = ((devices[path] or {}).get("options") or {}).get("file_path", "")
    return Check(f"audit device {path} active (declarative, -> {got or log_path})", True)


def _normalise_hcl(text: str) -> str:
    return "\n".join(l.strip() for l in text.splitlines() if l.strip() and not l.strip().startswith("#"))


def ensure_policy(ctx: Ctx, name: str, hcl_text: str) -> Check:
    r = ctx.client.get(f"/v1/sys/policies/acl/{name}", headers=ctx.admin_headers)
    if r.status_code == 200:
        current = (r.json().get("data") or {}).get("policy", "")
        if _normalise_hcl(current) == _normalise_hcl(hcl_text):
            return Check(f"policy {name} already exact (kept)", True)
    w = ctx.client.put(f"/v1/sys/policies/acl/{name}", headers=ctx.admin_headers,
                       json={"policy": hcl_text})
    if w.status_code not in (200, 204):
        return Check(f"policy {name} written", False, f"POLICY_WRITE_FAILED (HTTP {w.status_code})")
    return Check(f"policy {name} written", True)


def _token_lookup(ctx: Ctx, accessor: str) -> Optional[dict]:
    # By ACCESSOR: /auth/token/lookup takes a token secret, not an accessor (it answers 400 here,
    # which silently re-minted a token on every run - found against a real 2.7.1 server).
    r = ctx.client.post("/v1/auth/token/lookup-accessor", headers=ctx.admin_headers, json={"accessor": accessor})
    if r.status_code != 200:
        return None
    return r.json().get("data", {})


def ensure_token(ctx: Ctx, *, kind: str, policies: List[str], ttl: str, display_name: str,
                 token_file: Path, state_key: str) -> List[Check]:
    """Mint-or-reuse an orphan, non-renewable, no-default-policy token. The
    secret is written to a 0600 file; state keeps the accessor only. A token
    is reused only while it is valid AND its secret file still exists."""
    state = _load_state(ctx)
    accessor = (state.get("tokens") or {}).get(state_key, {}).get("accessor", "")
    if accessor and token_file.exists():
        meta = _token_lookup(ctx, accessor)
        if meta and sorted(meta.get("policies", [])) == sorted(policies):
            return [Check(f"{kind} token already valid (reused, nothing minted)", True,
                          f"policies={policies}")]
    # Through the token ROLE (policy, orphan, non-renewable and max TTL pinned by the role), so the
    # least-privilege administrator can mint/rotate without root or sudo.
    r = ctx.client.post(f"/v1/auth/token/create/{policies[0]}", headers=ctx.admin_headers, json={
        "ttl": ttl, "renewable": False, "no_default_policy": True, "display_name": display_name,
    })
    if r.status_code != 200:
        return [Check(f"{kind} token minted", False, f"TOKEN_CREATE_FAILED (HTTP {r.status_code})")]
    data = (r.json().get("auth") or {})
    secret, new_accessor = data.get("client_token", ""), data.get("accessor", "")
    if not secret or not new_accessor:
        return [Check(f"{kind} token minted", False, "TOKEN_RESPONSE_MISSING_SECRET")]
    out = [_write_protected(token_file, secret + "\n")]
    del secret
    state.setdefault("tokens", {})[state_key] = {"accessor": new_accessor, "policies": policies, "ttl": ttl}
    _save_state(ctx, state)
    return [Check(f"{kind} token minted", True, f"ttl={ttl}, renewable=False, orphan")] + out


def store_credential(ctx: Ctx, writer_token: str, name: str, username: str, password: str) -> Check:
    """Write one credential via the WRITER identity. Password arrives from a
    hidden prompt or env var — never argv — and is never printed or logged."""
    from app.secret_providers.paths import asset_secret_path, validate_secret_name  # noqa: E402
    try:
        rel = asset_secret_path("securepam", validate_secret_name(name))
    except Exception:
        return Check(f"credential {name} stored", False, "INVALID_SECRET_NAME")
    if name not in ("win11-lab", "kali", "wazuh-dashboard"):
        return Check(f"credential {name} stored", False,
                     "NOT_A_REGISTERED_PATH (win11-lab|kali|wazuh-dashboard only)")
    try:
        r = ctx.client.put(f"/v1/{ctx.mount}/data/{rel}",
                           headers={"X-Vault-Token": writer_token},
                           json={"data": {"username": username, "password": password}})
    finally:
        del password
    if r.status_code not in (200, 204):
        hint = " (writer policy lacks create/update on this path?)" if r.status_code == 403 else ""
        return Check(f"credential {name} stored", False, f"KV_WRITE_FAILED (HTTP {r.status_code}){hint}")
    try:
        version = (r.json().get("data") or {}).get("version")
    except ValueError:
        version = None
    action = "created" if version == 1 else (f"updated to version {version}" if version else "written")
    return Check(f"credential {name} {action} at {ctx.mount}/{rel}", True, "fields=[password, username]")


def rotate_token(ctx: Ctx, *, kind: str, policies: List[str], ttl: str, display_name: str,
                 token_file: Path, state_key: str) -> List[Check]:
    """Mint replacement -> re-verify it -> only then swap it into the live
    token file and revoke the predecessor by accessor. The replacement is
    minted into a separate .pending file, so a replacement that fails
    verification never overwrites the working token. No restart, no reinit."""
    import importlib  # import_module honours sys.modules, so tests can fake the verifier
    verifier = importlib.import_module("scripts.verify_openbao_token")
    state = _load_state(ctx)
    old_accessor = (state.get("tokens") or {}).get(state_key, {}).get("accessor", "")
    pending_file = token_file.with_name(token_file.name + ".pending")
    pending_key = f"{state_key}-pending"
    state.get("tokens", {}).pop(pending_key, None)  # never reuse a stale half-finished rotation
    _save_state(ctx, state)
    minted = ensure_token(ctx, kind=f"{kind} (replacement)", policies=policies, ttl=ttl,
                          display_name=display_name, token_file=pending_file, state_key=pending_key)
    if not minted or not minted[0].ok:
        return minted
    secret = pending_file.read_text(encoding="utf-8").strip()
    admin_token = ctx.admin_headers.get("X-Vault-Token", "")
    if kind == "writer":
        report = verifier.verify_writer(ctx.client, admin_token, secret, CREDENTIAL_PATHS, ctx.mount,
                                        policy_name=WRITER_POLICY)
    else:
        report = verifier.verify(ctx.client, admin_token, secret, CREDENTIAL_PATHS, ctx.mount,
                                 policy_name=APP_POLICY, allow_unstored=CREDENTIAL_PATHS)
    del secret
    ok = bool(report) and all(c.ok for c in report)
    redacted = [Check(f"replacement {kind} token verifies: {c.name}", c.ok, c.detail) for c in report]
    if not ok:
        new_accessor = (_load_state(ctx).get("tokens") or {}).get(pending_key, {}).get("accessor", "")
        if new_accessor:  # the failed replacement must not stay alive
            ctx.client.post("/v1/auth/token/revoke-accessor", headers=ctx.admin_headers,
                            json={"accessor": new_accessor})
        pending_file.unlink(missing_ok=True)
        state = _load_state(ctx)
        state.get("tokens", {}).pop(pending_key, None)
        _save_state(ctx, state)
        return [Check(f"rotate {kind} token", False, "REPLACEMENT_FAILED_VERIFICATION (old token kept, replacement revoked)")] + redacted
    os.replace(pending_file, token_file)
    checks = [Check(f"rotate {kind} token: replacement verified and installed", True)] + redacted
    if old_accessor:
        r = ctx.client.post("/v1/auth/token/revoke-accessor", headers=ctx.admin_headers,
                            json={"accessor": old_accessor})
        checks.append(Check(f"predecessor {kind} token revoked", r.status_code in (200, 204),
                            f"HTTP {r.status_code}"))
    state = _load_state(ctx)
    state.setdefault("tokens", {})[state_key] = state["tokens"].pop(pending_key)
    _save_state(ctx, state)
    return checks


# --- Administrator identity, token roles, root escrow/retirement --------------------------------

def token_is_root(ctx: Ctx) -> bool:
    r = ctx.client.get("/v1/auth/token/lookup-self", headers=ctx.admin_headers)
    return r.status_code == 200 and "root" in (r.json().get("data") or {}).get("policies", [])


def ensure_token_role(ctx: Ctx, name: str, ttl: str, *, can_write: bool) -> Check:
    """Role that pins exactly one policy, orphan, non-renewable, no default policy, hard max TTL."""
    want = {"allowed_policies": [name], "orphan": True, "renewable": False,
            "token_no_default_policy": True, "token_explicit_max_ttl": ttl}
    r = ctx.client.get(f"/v1/auth/token/roles/{name}", headers=ctx.admin_headers)
    if r.status_code == 200:
        cur = r.json().get("data") or {}
        ok = (sorted(cur.get("allowed_policies") or []) == [name] and cur.get("orphan") is True
              and cur.get("renewable") is False and cur.get("token_no_default_policy") is True
              and _seconds(cur.get("token_explicit_max_ttl")) == _seconds(ttl))
        if ok:
            return Check(f"token role {name} already exact (kept)", True)
    if not can_write:
        return Check(f"token role {name}", False,
                     f"ROLE_MISSING_OR_DIFFERENT (HTTP {r.status_code}): run the bootstrap with the root token")
    w = ctx.client.post(f"/v1/auth/token/roles/{name}", headers=ctx.admin_headers, json=want)
    return Check(f"token role {name} written", w.status_code in (200, 204), f"HTTP {w.status_code}")


def _seconds(value) -> int:
    if isinstance(value, int):
        return value
    text = str(value or "0").strip()
    units = {"s": 1, "m": 60, "h": 3600, "d": 86400}
    try:
        return int(text[:-1]) * units[text[-1]] if text and text[-1] in units else int(text)
    except (ValueError, KeyError):
        return -1


def ensure_userpass(ctx: Ctx, *, can_write: bool) -> Check:
    r = ctx.client.get("/v1/sys/auth", headers=ctx.admin_headers)
    methods = (r.json().get("data") or r.json()) if r.status_code == 200 else {}
    if "userpass/" in methods:
        return Check("userpass auth method present (kept)", True)
    if not can_write:
        return Check("userpass auth method", False, "MISSING: run the bootstrap with the root token")
    w = ctx.client.post("/v1/sys/auth/userpass", headers=ctx.admin_headers,
                        json={"type": "userpass", "description": "SecurePAM administrator logins"})
    return Check("userpass auth method enabled", w.status_code in (200, 204), f"HTTP {w.status_code}")


def ensure_admin_user(ctx: Ctx, password: Optional[str], *, reset: bool = False) -> Check:
    """Create (or, with reset, re-password) the administrator. The password comes from a hidden
    prompt or OPENBAO_ADMIN_PASSWORD and is never stored by this tool, printed, or put in argv."""
    path = f"/v1/auth/userpass/users/{ADMIN_USER}"
    exists = ctx.client.get(path, headers=ctx.admin_headers).status_code == 200
    if exists and not reset:
        return Check(f"administrator {ADMIN_USER} present (kept; password unchanged)", True)
    if not password or len(password) < MIN_ADMIN_PASSWORD_LENGTH:
        return Check(f"administrator {ADMIN_USER}", False,
                     f"PASSWORD_REQUIRED: at least {MIN_ADMIN_PASSWORD_LENGTH} characters via hidden prompt or OPENBAO_ADMIN_PASSWORD")
    try:
        w = ctx.client.post(path, headers=ctx.admin_headers, json={
            "password": password, "token_policies": [ADMIN_POLICY],
            "token_ttl": ADMIN_TOKEN_TTL, "token_max_ttl": ADMIN_TOKEN_MAX_TTL})
    finally:
        del password
    action = "password reset" if exists else "created"
    return Check(f"administrator {ADMIN_USER} {action}", w.status_code in (200, 204),
                 f"HTTP {w.status_code}; token ttl {ADMIN_TOKEN_TTL}, max {ADMIN_TOKEN_MAX_TTL}")


def verify_admin_token(client: httpx.Client, token: str) -> List[Check]:
    """Prove the administrator identity is usable AND least-privilege, with its own token."""
    h = {"X-Vault-Token": token}
    me = client.get("/v1/auth/token/lookup-self", headers=h)
    if me.status_code != 200:
        return [Check("administrator token valid", False, f"HTTP {me.status_code}")]
    data = me.json().get("data") or {}
    policies = sorted(data.get("policies") or [])
    checks = [Check("administrator token carries default + securepam-admin, not root",
                    policies == ["default", ADMIN_POLICY], f"policies={policies}"),
              Check("administrator token is time-limited", 0 < int(data.get("ttl") or 0) <= _seconds(ADMIN_TOKEN_MAX_TTL),
                    f"ttl={data.get('ttl')}s")]
    probe = {
        "secret/data/securepam/assets/kali": {"create", "read", "update"},
        f"auth/token/create/{APP_POLICY}": {"create", "update"},
        f"auth/token/create/{WRITER_POLICY}": {"create", "update"},
        "sys/storage/raft/snapshot": {"read"},
        "sys/generate-root-token/attempt": {"update"},  # break-glass start; completion needs the key quorum
    }
    denied = ["sys/policies/acl/securepam-app", "sys/auth/userpass", "sys/mounts/secret", "sys/audit/file",
              "auth/token/create", "auth/token/create-orphan", "auth/token/roles/securepam-app",
              "sys/generate-root/attempt", "sys/storage/raft/snapshot-force", "secret/data/other/x", "sys/seal"]
    r = client.post("/v1/sys/capabilities-self", headers=h, json={"paths": list(probe) + denied})
    body = (r.json().get("data") or r.json()) if r.status_code == 200 else {}
    for path, need in probe.items():
        got = set(body.get(path) or [])
        checks.append(Check(f"administrator can use {path}", need <= got, f"capabilities={sorted(got)}"))
    for path in denied:
        got = set(body.get(path) or [])
        writes = got & {"create", "update", "delete", "sudo", "root"}
        checks.append(Check(f"administrator cannot change {path}", not writes, f"capabilities={sorted(got)}"))
    return checks


def admin_login(client: httpx.Client, password: str) -> Optional[str]:
    r = client.post(f"/v1/auth/userpass/login/{ADMIN_USER}", json={"password": password})
    return (r.json().get("auth") or {}).get("client_token") if r.status_code == 200 else None


def retire_root(ctx: Ctx, root_file: Path, admin_token: str) -> List[Check]:
    """Revoke the bootstrap root token AFTER a working least-privilege administrator is proven. A new
    root can later be generated with the recovery-key quorum (bao operator generate-root)."""
    checks = verify_admin_token(ctx.client, admin_token)
    if not checks or not all(c.ok for c in checks):
        return [Check("retire root", False, "ADMIN_IDENTITY_NOT_VERIFIED (root kept)")] + checks
    try:
        root = root_file.read_text(encoding="utf-8").strip()
    except OSError:
        return checks + [Check("retire root", False, f"cannot read {root_file}")]
    r = ctx.client.post("/v1/auth/token/revoke-self", headers={"X-Vault-Token": root})
    gone = ctx.client.get("/v1/auth/token/lookup-self", headers={"X-Vault-Token": root}).status_code == 403
    del root
    if not gone:
        return checks + [Check("root token revoked", False, f"HTTP {r.status_code}; still valid")]
    try:
        subprocess.run(["shred", "-u", str(root_file)], timeout=30, check=True)
    except Exception:
        root_file.unlink(missing_ok=True)
    return checks + [Check("root token revoked and its file removed", True,
                           "regenerate only with the recovery-key quorum (see docs)")]


def _decode_root(encoded: str, otp: str) -> str:
    raw = base64.b64decode(encoded + "=" * (-len(encoded) % 4))
    return bytes(a ^ b for a, b in zip(raw, otp.encode())).decode()


def generate_root(ctx: Ctx, root_file: Path, keys: List[str]) -> List[Check]:
    """Break-glass: a NEW root token from the recovery-key quorum (unseal keys with Shamir). Uses the
    unauthenticated legacy endpoint sys/generate-root/*, which OpenBao 2.x disables unless the listener
    sets disable_unauthed_generate_root_endpoints = false (the bundled CLI uses the authenticated
    sys/generate-root-token/* path instead). The OTP is generated by the server and only ever held in
    memory; the decoded token goes to a 0600 file and is never printed. Cancels on any failure."""
    status = ctx.client.get("/v1/sys/generate-root/attempt")
    if status.status_code in (403, 404, 405):  # 2.7.1 answers 403 or 405 while the endpoints are disabled
        return [Check("root generation available", False,
                      "UNAUTHENTICATED_GENERATE_ROOT_DISABLED: set disable_unauthed_generate_root_endpoints = false "
                      "in the listener (temporarily, over SSM), restart, unseal/auto-unseal, retry; revert afterwards")]
    if status.status_code != 200:
        return [Check("root generation available", False, f"HTTP {status.status_code}")]
    if status.json().get("started"):
        ctx.client.delete("/v1/sys/generate-root/attempt")  # never resume someone else's attempt
    init = ctx.client.put("/v1/sys/generate-root/attempt", json={})
    body = init.json() if init.status_code == 200 else {}
    nonce, otp, required = body.get("nonce", ""), body.get("otp", ""), int(body.get("required") or 0)
    if not nonce or not otp:
        return [Check("root generation started", False, f"HTTP {init.status_code}")]
    checks = [Check("root generation started", True, f"{required} key(s) required")]
    encoded = ""
    for i, key in enumerate(keys[:required], 1):
        r = ctx.client.put("/v1/sys/generate-root/update", json={"key": key, "nonce": nonce})
        if r.status_code != 200:
            ctx.client.delete("/v1/sys/generate-root/attempt")
            return checks + [Check(f"recovery key {i} accepted", False, f"HTTP {r.status_code} (attempt cancelled)")]
        encoded = r.json().get("encoded_token") or r.json().get("encoded_root_token") or ""
        checks.append(Check(f"recovery key {i} of {required} accepted", True))
    if not encoded:
        ctx.client.delete("/v1/sys/generate-root/attempt")
        return checks + [Check("root generation complete", False, "NOT_ENOUGH_KEYS (attempt cancelled)")]
    token = _decode_root(encoded, otp)
    del otp, encoded
    ok = ctx.client.get("/v1/auth/token/lookup-self", headers={"X-Vault-Token": token}).status_code == 200
    if not ok:
        return checks + [Check("new root token valid", False, "decoded token rejected")]
    checks.append(_write_protected(root_file, token + "\n"))
    del token
    return checks + [Check("new root token generated", True,
                           f"in {root_file}; revert the listener flag, use it, then --retire-root again")]


def push_secret_to_aws(secret_arn: str, token_file: Path) -> Check:
    """Copy a 0600 token file into Secrets Manager without the value touching
    argv: the CLI reads it from a 0600 temp file via file://, then shredded."""
    fd, tmp = tempfile.mkstemp(prefix="bao-push-")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            fh.write("{\"token\": \"" + token_file.read_text(encoding="utf-8").strip() + "\"}")
        os.chmod(tmp, 0o600)
        p = subprocess.run(["aws", "secretsmanager", "put-secret-value",
                            "--secret-id", secret_arn, "--secret-string", f"file://{tmp}"],
                           capture_output=True, text=True, timeout=60)
    except (OSError, subprocess.SubprocessError) as exc:
        return Check(f"pushed {token_file.name} to Secrets Manager", False, f"AWS_CLI_FAILED ({type(exc).__name__})")
    finally:
        try:
            subprocess.run(["shred", "-u", tmp], timeout=30)
        except Exception:
            try:
                os.unlink(tmp)
            except OSError:
                pass
    if p.returncode != 0:
        return Check(f"pushed {token_file.name} to Secrets Manager", False,
                     f"PUT_SECRET_FAILED (exit {p.returncode})")
    return Check(f"pushed {token_file.name} to Secrets Manager", True, f"secret={secret_arn}")


def build_parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(description="Idempotent provisioner for SecurePAM's AWS OpenBao.")
    ap.add_argument("--addr", default=os.environ.get("OPENBAO_ADDR", "https://bao.securepam.internal"))
    ap.add_argument("--mount", default=os.environ.get("OPENBAO_MOUNT_POINT", "secret"))
    ap.add_argument("--seal", choices=["awskms", "shamir"], default="awskms")
    ap.add_argument("--shares", type=int, default=5)
    ap.add_argument("--threshold", type=int, default=3)
    ap.add_argument("--out-dir", default=str(Path.home() / ".securepam"))
    ap.add_argument("--admin-token-env", default="OPENBAO_ADMIN_TOKEN")
    ap.add_argument("--set-credential", choices=["win11-lab", "kali", "wazuh-dashboard"], default=None,
                    help="Store one registered credential via the writer identity.")
    ap.add_argument("--username", default=None)
    ap.add_argument("--rotate", choices=["app", "writer"], default=None)
    ap.add_argument("--verify-only", action="store_true",
                    help="Verify the app token (OPENBAO_TOKEN); with --verify-writer also the writer token file.")
    ap.add_argument("--verify-writer", action="store_true")
    ap.add_argument("--allow-unstored", action="append", default=[], choices=["win11-lab", "kali", "wazuh-dashboard"],
                    help="Registered credential(s) not stored yet: a 404 is reported as PENDING instead of FAIL.")
    ap.add_argument("--push-secrets", action="store_true")
    ap.add_argument("--app-secret-arn", default=os.environ.get("SECUREPAM_APP_SECRET_ARN", ""))
    ap.add_argument("--writer-secret-arn", default=os.environ.get("SECUREPAM_WRITER_SECRET_ARN", ""))
    ap.add_argument("--bootstrap-admin", action="store_true",
                    help="With the ROOT token: token roles, userpass, the securepam-admin user (hidden prompt).")
    ap.add_argument("--reset-admin-password", action="store_true",
                    help="With the ROOT token: set a new password for securepam-admin (hidden prompt).")
    ap.add_argument("--verify-admin", action="store_true",
                    help="Verify OPENBAO_ADMIN_TOKEN is the least-privilege administrator identity.")
    ap.add_argument("--escrow-root-arn", default=os.environ.get("SECUREPAM_ROOT_ESCROW_SECRET_ARN", ""),
                    help="Copy the root token file into this Secrets Manager secret (value via file://).")
    ap.add_argument("--retire-root", action="store_true",
                    help="Revoke the bootstrap root token after the administrator identity verifies.")
    ap.add_argument("--confirm-recovery-keys-custodied", action="store_true",
                    help="Required with --retire-root: recovery keys are held by their custodians.")
    ap.add_argument("--generate-root", action="store_true",
                    help="Break-glass: generate a new root token from the recovery-key quorum (hidden prompts).")
    ap.add_argument("--recovery-keys-file", default=None,
                    help="With --generate-root: read keys from this protected file instead of prompting.")
    ap.add_argument("--ca-cert", default=os.environ.get("OPENBAO_CA_CERT", "") or None)
    ap.add_argument("--timeout", type=float, default=8.0)
    return ap


def main(argv: Optional[List[str]] = None) -> int:
    import importlib  # import_module honours sys.modules (see rotate_token)
    verifier = importlib.import_module("scripts.verify_openbao_token")
    args = build_parser().parse_args(argv)
    out = Path(args.out_dir)
    ctx = Ctx(client=httpx.Client(base_url=args.addr, timeout=args.timeout,
                                  verify=args.ca_cert or True, trust_env=False),
              mount=args.mount, state_file=out / "openbao-aws-state.json", out_dir=out)

    if args.generate_root:
        root_file = out / "openbao-aws-root.txt"
        if root_file.exists():
            print(f"FAIL generate root - {root_file} already exists; move it aside first (never overwritten)")
            return 2
        if args.recovery_keys_file:
            keys = Path(args.recovery_keys_file).read_text(encoding="utf-8").split()
        else:
            if not sys.stdin.isatty():
                print("FAIL generate root - needs a terminal for the custodians' hidden prompts, or --recovery-keys-file")
                return 2
            n = int(ctx.client.get("/v1/sys/generate-root/attempt").json().get("required") or 0) or 3
            keys = [getpass.getpass(f"Recovery key {i + 1} of {n} (custodian types it; input hidden): ")
                    for i in range(n)]
        result = generate_root(ctx, root_file, keys)
        del keys
        return _report(result)

    admin_token = os.environ.get(args.admin_token_env, "")
    # A brand-new server has no admin token yet: init (below) creates it. Only then is a missing
    # token acceptable; the fresh root token is read back from its 0600 file for this run only.
    first_status = seal_status(ctx)
    fresh_server = (not args.verify_only) and "UNINITIALISED" in first_status.detail
    if not admin_token and sys.stdin.isatty() and not args.verify_only and not fresh_server:
        admin_token = getpass.getpass("OpenBao admin/bootstrap token (input hidden): ")
    if not admin_token and not fresh_server:
        print("FAIL administrator token - set OPENBAO_ADMIN_TOKEN or run on a terminal")
        return 2
    ctx.admin_headers = {"X-Vault-Token": admin_token}

    if args.verify_admin:
        return _report(verify_admin_token(ctx.client, admin_token))
    if args.retire_root:
        if not args.confirm_recovery_keys_custodied:
            print("FAIL retire root - pass --confirm-recovery-keys-custodied once the recovery keys are with "
                  "their custodians (without them a new root token can never be generated)")
            return 2
        return _report(retire_root(ctx, out / "openbao-aws-root.txt", admin_token))

    if args.verify_only:
        app_token = os.environ.get("OPENBAO_TOKEN", "")
        if not app_token:
            print("FAIL scoped token - OPENBAO_TOKEN is not set")
            return 2
        paths = verifier.required_data_paths(APP_POLICY_FILE.read_text(), args.mount)
        pending = [f"securepam/assets/{n}" for n in args.allow_unstored]
        checks = verifier.verify(ctx.client, admin_token, app_token, paths, args.mount,
                                 policy_name=APP_POLICY, allow_unstored=pending)
        if args.verify_writer:
            writer_file = out / "openbao-aws-writer-token"
            try:
                writer_token = writer_file.read_text(encoding="utf-8").strip()
            except OSError:
                writer_token = ""
            if not writer_token:
                checks.append(Check("writer token file readable", False, f"cannot read {writer_file}"))
            else:
                wpaths = verifier.required_data_paths(WRITER_POLICY_FILE.read_text(), args.mount)
                checks += verifier.verify_writer(ctx.client, admin_token, writer_token, wpaths, args.mount,
                                                 policy_name=WRITER_POLICY)
                del writer_token
        for c in checks:
            print(c.line())
        return 0 if checks and all(c.ok for c in checks) else 1

    checks: List[Check] = [seal_status(ctx)]
    if not checks[0].ok and ("UNINITIALISED" in checks[0].detail or "SEALED" in checks[0].detail):
        # A state to remediate, not a failure: reported, and the run's result depends on the remediation.
        checks[0] = Check("detected server state", True, checks[0].detail.split(" (")[0])
    if "UNINITIALISED" in checks[0].detail:
        root_file = out / "openbao-aws-root.txt"
        checks += initialize(ctx, args.shares, args.threshold,
                             out / "openbao-aws-recovery-keys.txt", root_file, seal=args.seal)
        if not admin_token and root_file.exists():
            ctx.admin_headers = {"X-Vault-Token": root_file.read_text(encoding="utf-8").strip()}
            checks.append(Check("using the new root token from its protected file for this run", True,
                                f"{root_file}; restrict/revoke it after recovery keys are custodied"))
        checks.append(seal_status(ctx))
    if (not checks[-1].ok and "SEALED" in checks[-1].detail) or checks[-1].detail == "SEALED":
        checks[-1] = Check("detected server state", True, "SEALED")
        if args.seal == "awskms":
            checks.append(Check("unseal", False, "SEALED_WITH_AUTO_UNSEAL (instance role/KMS misconfigured?)"))
        else:
            checks += unseal(ctx, out / "openbao-aws-recovery-keys.txt")
            checks.append(seal_status(ctx))
    if not checks[-1].ok:
        return _report(checks)
    if not _load_state(ctx).get("initialized"):
        _save_state(ctx, {**_load_state(ctx), "initialized": True})

    checks.append(ensure_kv_mount(ctx, args.mount))
    checks.append(ensure_audit_device(ctx))
    for name, path in ((APP_POLICY, APP_POLICY_FILE), (WRITER_POLICY, WRITER_POLICY_FILE),
                       (ADMIN_POLICY, ADMIN_POLICY_FILE)):
        try:
            hcl = path.read_text(encoding="utf-8")
        except OSError:
            checks.append(Check(f"policy {name} written", False, f"cannot read {path}"))
            return _report(checks)
        checks.append(ensure_policy(ctx, name, hcl))

    is_root = token_is_root(ctx)
    checks.append(ensure_token_role(ctx, APP_POLICY, APP_TOKEN_TTL, can_write=is_root))
    checks.append(ensure_token_role(ctx, WRITER_POLICY, WRITER_TOKEN_TTL, can_write=is_root))
    if args.bootstrap_admin or args.reset_admin_password:
        if not is_root:
            checks.append(Check("bootstrap administrator", False, "NEEDS_ROOT: run with the bootstrap root token"))
            return _report(checks)
        checks.append(ensure_userpass(ctx, can_write=True))
        password = os.environ.get("OPENBAO_ADMIN_PASSWORD", "")
        user_exists = ctx.client.get(f"/v1/auth/userpass/users/{ADMIN_USER}",
                                     headers=ctx.admin_headers).status_code == 200
        if not password and sys.stdin.isatty() and (args.reset_admin_password or not user_exists):
            password = getpass.getpass(f"New password for {ADMIN_USER} (input hidden, >= {MIN_ADMIN_PASSWORD_LENGTH}): ")
            if getpass.getpass("Repeat password: ") != password:
                checks.append(Check(f"administrator {ADMIN_USER}", False, "PASSWORDS_DIFFER"))
                return _report(checks)
        checks.append(ensure_admin_user(ctx, password or None, reset=args.reset_admin_password))
        if password and checks[-1].ok:
            token = admin_login(ctx.client, password)
            if not token:
                checks.append(Check("administrator login", False, "LOGIN_FAILED"))
            else:
                checks.append(Check("administrator login works (userpass)", True))
                checks += verify_admin_token(ctx.client, token)
                ctx.client.post("/v1/auth/token/revoke-self", headers={"X-Vault-Token": token})
                del token
        del password

    app_file, writer_file = out / "openbao-aws-app-token", out / "openbao-aws-writer-token"
    if args.rotate == "writer":
        checks += rotate_token(ctx, kind="writer", policies=[WRITER_POLICY], ttl=WRITER_TOKEN_TTL,
                               display_name="securepam-cred-writer", token_file=writer_file, state_key="writer")
    elif args.rotate == "app":
        checks += rotate_token(ctx, kind="app", policies=[APP_POLICY], ttl=APP_TOKEN_TTL,
                               display_name="securepam-backend", token_file=app_file, state_key="app")
    else:
        checks += ensure_token(ctx, kind="app", policies=[APP_POLICY], ttl=APP_TOKEN_TTL,
                               display_name="securepam-backend", token_file=app_file, state_key="app")
        checks += ensure_token(ctx, kind="writer", policies=[WRITER_POLICY], ttl=WRITER_TOKEN_TTL,
                               display_name="securepam-cred-writer", token_file=writer_file, state_key="writer")

    if args.set_credential:
        if not args.username and sys.stdin.isatty():
            args.username = input(f"Username for {args.set_credential}: ").strip() or None
        password = os.environ.get("OPENBAO_CRED_PASSWORD", "")
        if not password and sys.stdin.isatty():
            password = getpass.getpass(f"Password for {args.set_credential} (input hidden): ")
        if not password or not args.username:
            checks.append(Check(f"credential {args.set_credential} stored", False,
                                "need --username and OPENBAO_CRED_PASSWORD (or a terminal)"))
            return _report(checks)
        writer_token = writer_file.read_text(encoding="utf-8").strip()
        checks.append(store_credential(ctx, writer_token, args.set_credential, args.username, password))
        del password, writer_token

    if args.escrow_root_arn:
        root_file = out / "openbao-aws-root.txt"
        checks.append(push_secret_to_aws(args.escrow_root_arn, root_file) if root_file.exists()
                      else Check("escrow root token", False, f"no root token file at {root_file}"))

    if args.push_secrets:
        for path, arn in ((app_file, args.app_secret_arn), (writer_file, args.writer_secret_arn)):
            if not arn:
                checks.append(Check(f"pushed {path.name} to Secrets Manager", False,
                                    "set --app-secret-arn/--writer-secret-arn (or env)"))
            elif path.exists():
                checks.append(push_secret_to_aws(arn, path))
    return _report(checks)


def _report(checks: List[Check]) -> int:
    for c in checks:
        print(c.line())
    return 0 if checks and all(c.ok for c in checks) else 1


if __name__ == "__main__":
    sys.exit(main())
