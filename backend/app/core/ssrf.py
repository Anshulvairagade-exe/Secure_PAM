"""
SSRF-safe target validation for registered Applications.

Scope of what this does and doesn't do (important — read before touching):

Applications ARE meant to point at internal/private-network services —
that's the entire point of a PAM web gateway (e.g. an admin portal on
10.0.x.x). This validator does NOT block private IP ranges (RFC 1918)
in general. It blocks the specific categories that are never a
legitimate registration target for ANY organization:

  - loopback (127.0.0.1, ::1) — would point the gateway at itself
  - link-local (169.254.0.0/16, fe80::/10) — this range also covers
    EVERY major cloud provider's instance metadata endpoint
    (169.254.169.254 for AWS/GCP/Azure/DigitalOcean alike), so one
    check covers both
  - the literal hostname "localhost" (and "*.localhost")
  - the literal GCP metadata hostname "metadata.google.internal"
  - multicast / unspecified / reserved IP ranges
  - malformed hosts, and anything that isn't HTTP/HTTPS

This is enforced only at REGISTRATION time (Application create/update,
admin-only). It is NOT a substitute for DNS-rebinding protection at
connection time — true rebinding defense means resolving the hostname
at the moment the Web Gateway actually connects and pinning that IP for
the life of the connection, which belongs to the future Web Gateway
phase, not CRUD validation. A hostname that resolves to a safe IP today
could resolve elsewhere tomorrow; this module only catches the static,
obvious cases up front.

"Do not allow user-controlled destination URLs" is enforced structurally,
not just by validation: callers never accept a raw target_url from the
client at all (see app/schemas/applications.py) — target_url is always
derived server-side from the validated hostname/port/protocol.
"""

import ipaddress
import re

from app.schemas.enums import Protocol

_HOSTNAME_RE = re.compile(
    r"^(?!-)[A-Za-z0-9-]{1,63}(?<!-)(\.(?!-)[A-Za-z0-9-]{1,63}(?<!-))*$"
)
_BLOCKED_HOSTNAMES = {"localhost", "metadata.google.internal"}


class SSRFValidationError(ValueError):
    """Raised when a registration target fails SSRF-safety checks."""


def validate_application_target(hostname: str, port: int, protocol: str) -> None:
    """Raise SSRFValidationError if this target is unsafe to register."""
    if protocol not in (Protocol.HTTP, Protocol.HTTP.value, Protocol.HTTPS, Protocol.HTTPS.value):
        raise SSRFValidationError("Applications only support HTTP or HTTPS.")

    if not (1 <= port <= 65535):
        raise SSRFValidationError("Port must be between 1 and 65535.")

    if not hostname or len(hostname) > 253:
        raise SSRFValidationError("Hostname is missing or too long.")

    hostname_lower = hostname.lower().rstrip(".")

    if hostname_lower in _BLOCKED_HOSTNAMES or hostname_lower.endswith(".localhost"):
        raise SSRFValidationError(f"'{hostname}' is not a valid registration target.")

    # If it parses as a literal IP, check the address category directly.
    try:
        ip = ipaddress.ip_address(hostname_lower)
    except ValueError:
        ip = None

    if ip is not None:
        if (
            ip.is_loopback
            or ip.is_link_local  # covers 169.254.169.254 cloud metadata too
            or ip.is_multicast
            or ip.is_unspecified
            or ip.is_reserved
        ):
            raise SSRFValidationError(f"'{hostname}' resolves to a disallowed address range.")
        return

    # Not an IP literal — validate as a syntactically sound hostname.
    # (Private-network DNS names like "admin.internal" are allowed — see
    # module docstring.)
    if not _HOSTNAME_RE.match(hostname):
        raise SSRFValidationError(f"'{hostname}' is not a valid hostname.")
