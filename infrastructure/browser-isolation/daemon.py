"""
SecurePAM browser-isolation daemon. Runs inside its own container; only the SecurePAM backend talks to it
(loopback-published management port, bearer token). Per session:

  Xvfb :N  ->  Chromium (kiosk, own profile on tmpfs, proxy = this session's egress proxy)
           ->  x11vnc (password from the backend, one viewer, clipboard per policy)
  egress proxy: allows ONLY the registered host:port, connects to the IP pinned at session start
                (no DNS rebinding), never loopback/link-local/metadata, logs every denial.

Readiness and navigation are read from Chromium's DevTools endpoint on 127.0.0.1 inside the container:
a session is READY only when the top-level page is on the registered origin; a certificate error page
or a page on another origin is reported, never shown as ready. Nothing secret is logged.
"""

import asyncio
import hmac
import ipaddress
import json
import os
import shutil
import signal
import socket
import subprocess
import time
import urllib.request
import uuid
from typing import Dict, List, Optional

TOKEN = open(os.environ.get("TOKEN_FILE", "/run/secrets/isolation_token")).read().strip()
MAX_SESSIONS = int(os.environ.get("MAX_SESSIONS", "8"))
VNC_BASE = int(os.environ.get("VNC_BASE_PORT", "5910"))
SESSIONS_DIR = "/tmp/sessions"
WIDTH, HEIGHT = 1280, 800
BLOCKED_ALWAYS = [ipaddress.ip_network(n) for n in (
    "127.0.0.0/8", "::1/128", "169.254.0.0/16", "fe80::/10", "0.0.0.0/8", "::/128",
    "224.0.0.0/4", "ff00::/8", "100.64.0.0/10", "fd00:ec2::254/128")]

SESSIONS: Dict[str, "Session"] = {}


def log(event: str, **fields) -> None:
    print(json.dumps({"event": event, **fields}), flush=True)


TRUST_POLICY_FILE = os.environ.get("TRUST_POLICY_FILE", "/etc/securepam/trust/chromium-policy.json")


def trust_anchors(path: Optional[str] = None) -> List[dict]:
    """Operator-managed private CAs, each limited to named hosts. The file is the Chromium managed policy
    CACertificatesWithConstraints (Chromium reads the same file), so the browser and this pre-flight check
    trust exactly the same anchors for exactly the same names. Missing file: public CAs only."""
    import base64
    try:
        with open(path or TRUST_POLICY_FILE, "r", encoding="utf-8") as f:
            entries = json.load(f).get("CACertificatesWithConstraints") or []
    except (OSError, ValueError):
        return []
    anchors = []
    for e in entries:
        c = e.get("constraints") or {}
        dns, cidrs = list(c.get("permitted_dns_names") or []), list(c.get("permitted_cidrs") or [])
        if not (dns or cidrs):
            continue  # an unconstrained private CA is never honoured here (the generator refuses to write one)
        der = base64.b64decode(e["certificate"])
        anchors.append({"der": der, "dns": [d.lower().rstrip(".") for d in dns],
                        "cidrs": [ipaddress.ip_network(n, strict=False) for n in cidrs]})
    return anchors


def anchor_permits(anchor: dict, host: str) -> bool:
    try:
        addr = ipaddress.ip_address(host)
        return any(addr in net for net in anchor["cidrs"])
    except ValueError:
        h = host.lower().rstrip(".")
        return any(h == d or h.endswith("." + d) for d in anchor["dns"])


def leaf_names_within(der: bytes, anchor: dict) -> bool:
    """Every DNS/IP SAN of the leaf must fall inside the anchor's constraints (RFC 5280 name constraints,
    as Chromium enforces them for a policy-supplied CA). A leaf with no SAN at all is refused."""
    from cryptography import x509
    try:
        san = x509.load_der_x509_certificate(der).extensions.get_extension_for_class(x509.SubjectAlternativeName).value
    except (x509.ExtensionNotFound, ValueError):
        return False
    names = [str(n) for n in san.get_values_for_type(x509.DNSName)] + \
            [str(n) for n in san.get_values_for_type(x509.IPAddress)]
    return bool(names) and all(anchor_permits(anchor, n) for n in names)


def tls_check(ip: str, host: str, port: int, pin: Optional[str], anchors: Optional[List[dict]] = None) -> None:
    """The same trust decision Chromium makes, taken first so a session never starts on an error page.
    Always: full chain validation to a trusted root AND hostname/IP validation. Roots are the public CA
    store, plus any operator-configured private CA whose name constraints cover `host`. A pin (base64
    SHA-256 of the leaf SubjectPublicKeyInfo) is an ADDITIONAL check on top, never a replacement.
    Raises RuntimeError("TLS_VALIDATION_FAILED") on any failure."""
    import base64, hashlib, ssl
    from cryptography import x509
    from cryptography.hazmat.primitives import serialization
    contexts = [(ssl.create_default_context(), None)]
    for a in (trust_anchors() if anchors is None else anchors):
        if anchor_permits(a, host):
            contexts.append((ssl.create_default_context(cadata=a["der"]), a))  # this anchor only, no public roots
    der = None
    for ctx, anchor in contexts:
        try:
            with socket.create_connection((ip, port), timeout=8) as raw:
                with ctx.wrap_socket(raw, server_hostname=host) as tls:
                    der = tls.getpeercert(binary_form=True)
        except (ssl.SSLError, ssl.CertificateError):
            continue
        except OSError as exc:
            raise RuntimeError("TLS_VALIDATION_FAILED") from exc
        if anchor is not None and not leaf_names_within(der, anchor):
            der = None  # Chromium applies name constraints to EVERY SAN in the leaf ("Not permitted by name constraints")
            continue
        break
    if der is None:
        raise RuntimeError("TLS_VALIDATION_FAILED")
    if pin:
        spki = x509.load_der_x509_certificate(der).public_key().public_bytes(
            serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
        if not hmac.compare_digest(base64.b64encode(hashlib.sha256(spki).digest()).decode(), pin):
            raise RuntimeError("TLS_VALIDATION_FAILED")


def ip_blocked(ip: str) -> bool:
    addr = ipaddress.ip_address(ip)
    return any(addr in net for net in BLOCKED_ALWAYS)


class Session:
    def __init__(self, sid: str, slot: int, spec: dict) -> None:
        self.sid, self.slot, self.spec = sid, slot, spec
        self.display = f":{100 + slot}"
        self.vnc_port = VNC_BASE + slot
        self.cdp_port = 9300 + slot
        self.dir = os.path.join(SESSIONS_DIR, sid)
        self.procs: List[subprocess.Popen] = []
        self.proxy_server: Optional[asyncio.base_events.Server] = None
        self.proxy_port = 0
        self.pinned_ip: Optional[str] = None
        self.state, self.failure = "STARTING", None
        self.violations: List[dict] = []
        self.started = time.time()

    # -- egress proxy ----------------------------------------------------------------------------
    def allowed(self, host: str, port: int) -> bool:
        return host.lower().strip("[]") == self.spec["host"].lower() and port == self.spec["port"]

    def deny(self, host: str, port: int, why: str) -> None:
        if len(self.violations) < 200:
            self.violations.append({"at": time.time(), "host": host[:255], "port": port, "reason": why})
        log("destination_denied", session=self.sid, host=host[:255], port=port, reason=why)

    async def handle(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        try:
            head = await asyncio.wait_for(reader.readuntil(b"\r\n\r\n"), 15)
        except Exception:
            writer.close(); return
        line = head.split(b"\r\n", 1)[0].decode("latin-1", "replace")
        parts = line.split(" ")
        if len(parts) < 3:
            writer.close(); return
        method, target = parts[0].upper(), parts[1]
        if method == "CONNECT":
            host, _, port_s = target.rpartition(":")
            port = int(port_s) if port_s.isdigit() else -1
            tls = True
        else:
            # plain-HTTP absolute-form request: only for an HTTP application
            from urllib.parse import urlsplit
            u = urlsplit(target)
            host, port, tls = (u.hostname or ""), (u.port or (80 if u.scheme == "http" else -1)), False
        if not self.allowed(host, port) or (tls != (self.spec["scheme"] == "https")):
            self.deny(host, port, "NOT_REGISTERED_DESTINATION")
            writer.write(b"HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
            await writer.drain(); writer.close(); return
        try:
            up_r, up_w = await asyncio.wait_for(asyncio.open_connection(self.pinned_ip, port), 10)
        except Exception:
            writer.write(b"HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
            await writer.drain(); writer.close(); return
        if method == "CONNECT":
            writer.write(b"HTTP/1.1 200 Connection Established\r\n\r\n")
            await writer.drain()
        else:
            up_w.write(head)
        async def pump(a, b):
            try:
                while data := await a.read(65536):
                    b.write(data); await b.drain()
            except Exception:
                pass
            finally:
                try: b.close()
                except Exception: pass
        await asyncio.gather(pump(reader, up_w), pump(up_r, writer))

    # -- lifecycle ----------------------------------------------------------------------------------
    async def start(self) -> None:
        spec = self.spec
        infos = await asyncio.get_event_loop().getaddrinfo(spec["host"], spec["port"], type=socket.SOCK_STREAM)
        ips = [i[4][0] for i in infos]
        if not ips or any(ip_blocked(ip) for ip in ips):
            raise RuntimeError("DESTINATION_BLOCKED")
        self.pinned_ip = ips[0]
        if spec["scheme"] == "https":
            await asyncio.get_event_loop().run_in_executor(
                None, tls_check, self.pinned_ip, spec["host"], spec["port"], spec.get("tls_pin"))
        self.proxy_server = await asyncio.start_server(self.handle, "127.0.0.1", 0)
        self.proxy_port = self.proxy_server.sockets[0].getsockname()[1]
        os.makedirs(os.path.join(self.dir, "profile"), mode=0o700)
        # Plain-text password file read once by x11vnc ("rm:" makes x11vnc delete it after reading).
        # Not -rfbauth: libvncserver re-reads that file on every authentication, so it cannot be
        # removed while the session runs, and -storepasswd would put the password on a command line.
        pwfile = os.path.join(self.dir, "vncpasswd")
        fd = os.open(pwfile, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "w") as f:
            f.write(spec["vnc_password"] + "\n")
        # TMPDIR keeps Chromium's singleton dir inside the session dir (removed with it). The marker
        # follows every descendant, including Chromium's crashpad handler, which setsid()s out of
        # the process group, so stop() can find and kill whatever the session started.
        env = {"DISPLAY": self.display, "HOME": self.dir, "TMPDIR": self.dir, "PATH": os.environ["PATH"],
               "TZ": "UTC", SESSION_MARKER: self.sid}
        self.procs.append(subprocess.Popen(["Xvfb", self.display, "-screen", "0", f"{WIDTH}x{HEIGHT}x24", "-nolisten", "tcp"],
                                           env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                                           start_new_session=True))
        await asyncio.sleep(0.7)
        url = f"{spec['scheme']}://{spec['host']}:{spec['port']}{spec['path']}"
        args = ["chromium", "--kiosk", "--no-first-run", "--no-default-browser-check", "--disable-extensions",
                "--disable-sync", "--disable-background-networking", "--disable-component-update",
                "--disable-dev-shm-usage", "--no-sandbox", "--password-store=basic",
                f"--user-data-dir={os.path.join(self.dir, 'profile')}",
                f"--window-size={WIDTH},{HEIGHT}", "--window-position=0,0",
                f"--proxy-server=http://127.0.0.1:{self.proxy_port}", "--proxy-bypass-list=<-loopback>",
                "--remote-debugging-address=127.0.0.1", f"--remote-debugging-port={self.cdp_port}"]
        # No certificate-error overrides of any kind: Chromium validates the chain and the name itself,
        # trusting public roots plus the name-constrained private CAs of the managed trust policy.
        # The pin was already enforced (in addition) by tls_check before launch.
        args.append(url)
        self.procs.append(subprocess.Popen(args, env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                                           start_new_session=True))
        vnc = ["x11vnc", "-display", self.display, "-rfbport", str(self.vnc_port), "-passwdfile", f"rm:{pwfile}",
               "-forever", "-nevershared", "-noxdamage", "-quiet", "-nolookup", "-noipv6"]
        if not spec.get("clipboard_allowed"):
            vnc += ["-noclipboard", "-nosetclipboard"]
        self.procs.append(subprocess.Popen(vnc, env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                                           start_new_session=True))
        asyncio.get_event_loop().create_task(self.watch(spec.get("ttl_seconds", 1800)))

    def page(self) -> Optional[dict]:
        try:
            with urllib.request.urlopen(f"http://127.0.0.1:{self.cdp_port}/json/list", timeout=2) as r:
                pages = [p for p in json.load(r) if p.get("type") == "page"]
        except Exception:
            return None
        return pages[0] if pages else None

    async def watch(self, ttl: int) -> None:
        from urllib.parse import urlsplit
        registered = (self.spec["scheme"], self.spec["host"].lower(), self.spec["port"])
        deadline = self.started + 45
        while self.sid in SESSIONS:
            if time.time() - self.started > ttl:
                log("session_expired_in_daemon", session=self.sid); await stop(self.sid); return
            p = self.page()
            if p:
                u = urlsplit(p.get("url", ""))
                origin = (u.scheme, (u.hostname or "").lower(), u.port or (443 if u.scheme == "https" else 80))
                title = (p.get("title") or "").lower()
                # Chromium keeps the original URL while showing a certificate interstitial, so the
                # title is checked as well as chrome-error:// pages.
                interstitial = "privacy error" in title or "your connection is not private" in title
                if u.scheme == "chrome-error" or interstitial:
                    self.failure = "TLS_VALIDATION_FAILED" if (interstitial or "certificate" in title or "ssl" in title) \
                        else "NAVIGATION_FAILED"
                    if self.state != "READY":
                        self.state = "FAILED"
                    else:
                        self.deny(u.hostname or "", 0, self.failure)
                elif origin == registered:
                    if self.state == "STARTING":
                        self.state = "READY"; log("session_ready", session=self.sid)
                elif u.scheme in ("http", "https"):
                    self.deny(u.hostname or "", origin[2], "NAVIGATION_TO_UNREGISTERED_ORIGIN")
            if self.state == "STARTING" and time.time() > deadline:
                self.state, self.failure = "FAILED", self.failure or "NOT_READY_IN_TIME"
            await asyncio.sleep(1)

    def alive(self) -> List[int]:
        return sorted({p.pid for p in self.procs if p.poll() is None} | set(session_processes(self)))


SESSION_MARKER = "SECUREPAM_SESSION"


def session_processes(s: Session) -> List[int]:
    """Live (non-zombie) processes belonging to a session: members of the process groups it started,
    or carrying its environment marker. Zombies are not counted: init (compose `init: true`) reaps
    them, and they hold no memory, files or sockets."""
    groups = {p.pid for p in s.procs}
    marker = f"{SESSION_MARKER}={s.sid}".encode()
    found: List[int] = []
    if not os.path.isdir("/proc"):  # not Linux (unit tests on a developer machine)
        return found
    for name in os.listdir("/proc"):
        if not name.isdigit() or int(name) == os.getpid():
            continue
        try:
            with open(f"/proc/{name}/stat", "rb") as f:
                fields = f.read().rsplit(b")", 1)[1].split()
            if fields[0] == b"Z":
                continue
            if int(fields[2]) in groups:
                found.append(int(name)); continue
            with open(f"/proc/{name}/environ", "rb") as f:
                if marker in f.read().split(b"\0"):
                    found.append(int(name))
        except (OSError, IndexError, ValueError):
            continue
    return found


async def stop(sid: str) -> dict:
    s = SESSIONS.pop(sid, None)
    if s is None:
        return {"cleaned": True, "leftover": []}
    for p in s.procs:
        try: os.killpg(p.pid, signal.SIGTERM)
        except ProcessLookupError: pass
    for _ in range(30):
        if not s.alive(): break
        await asyncio.sleep(0.1)
    for p in s.procs:
        if p.poll() is None:
            try: os.killpg(p.pid, signal.SIGKILL)
            except ProcessLookupError: pass
    for _ in range(20):  # descendants that left the process groups (crashpad), found by marker
        stray = session_processes(s)
        if not stray: break
        for pid in stray:
            try: os.kill(pid, signal.SIGKILL)
            except ProcessLookupError: pass
        await asyncio.sleep(0.1)
    for p in s.procs:
        p.poll()  # reap our direct children
    await asyncio.sleep(0.2)
    if s.proxy_server:
        s.proxy_server.close()
    shutil.rmtree(s.dir, ignore_errors=True)
    leftover = s.alive() + ([s.dir] if os.path.exists(s.dir) else [])
    log("session_stopped", session=s.sid, leftover=len(leftover))
    return {"cleaned": not leftover, "leftover": [str(x) for x in leftover]}


# -- management API (tiny HTTP/1.1 server; loopback-published, bearer-token protected) -------------
async def respond(writer, code: int, body: dict) -> None:
    data = json.dumps(body).encode()
    writer.write(f"HTTP/1.1 {code} X\r\nContent-Type: application/json\r\nContent-Length: {len(data)}\r\nConnection: close\r\n\r\n".encode() + data)
    await writer.drain(); writer.close()


async def api(reader, writer) -> None:
    try:
        head = await asyncio.wait_for(reader.readuntil(b"\r\n\r\n"), 10)
        lines = head.decode("latin-1").split("\r\n")
        method, path, _ = lines[0].split(" ", 2)
        headers = {k.lower(): v.strip() for k, _, v in (l.partition(":") for l in lines[1:] if l)}
        body = await reader.readexactly(int(headers.get("content-length", "0") or 0)) if headers.get("content-length") else b""
    except Exception:
        writer.close(); return
    if path == "/health":
        return await respond(writer, 200, {"ok": True, "sessions": len(SESSIONS)})
    if not hmac.compare_digest(headers.get("authorization", ""), f"Bearer {TOKEN}"):
        return await respond(writer, 401, {"error": "unauthorized"})
    parts = path.strip("/").split("/")
    try:
        if method == "POST" and parts == ["sessions"]:
            spec = json.loads(body)
            sid = str(uuid.UUID(spec["session_id"]))
            if sid in SESSIONS:
                return await respond(writer, 409, {"error": "exists"})
            if spec.get("scheme") not in ("http", "https") or not (0 < int(spec["port"]) < 65536) \
                    or not str(spec.get("path", "/")).startswith("/") or len(str(spec.get("vnc_password", ""))) != 8:
                return await respond(writer, 400, {"error": "bad spec"})
            used = {s.slot for s in SESSIONS.values()}
            free = [i for i in range(MAX_SESSIONS) if i not in used]
            if not free:
                return await respond(writer, 503, {"error": "capacity"})
            s = Session(sid, free[0], {**spec, "port": int(spec["port"])})
            SESSIONS[sid] = s
            try:
                await s.start()
            except Exception as exc:
                await stop(sid)
                reason = str(exc) if str(exc) in ("DESTINATION_BLOCKED", "TLS_VALIDATION_FAILED") else "LAUNCH_FAILED"
                log("session_launch_failed", session=sid, reason=reason)
                return await respond(writer, 500 if reason == "LAUNCH_FAILED" else 422, {"error": reason})
            log("session_started", session=sid, slot=s.slot)
            return await respond(writer, 201, {"session_id": sid, "vnc_port": s.vnc_port})
        if len(parts) == 2 and parts[0] == "sessions":
            sid = str(uuid.UUID(parts[1]))
            if method == "GET":
                s = SESSIONS.get(sid)
                if s is None:
                    return await respond(writer, 404, {"state": "ENDED"})
                return await respond(writer, 200, {"state": s.state, "failure": s.failure, "violations": s.violations[-50:],
                                                   "processes_alive": len(s.alive())})
            if method == "DELETE":
                return await respond(writer, 200, await stop(sid))
    except (ValueError, KeyError, json.JSONDecodeError):
        return await respond(writer, 400, {"error": "bad request"})
    return await respond(writer, 404, {"error": "not found"})


async def main() -> None:
    os.makedirs(SESSIONS_DIR, mode=0o700, exist_ok=True)
    server = await asyncio.start_server(api, "0.0.0.0", 6090)
    log("daemon_listening", port=6090, max_sessions=MAX_SESSIONS)
    async with server:
        await server.serve_forever()


if __name__ == "__main__":
    asyncio.run(main())
