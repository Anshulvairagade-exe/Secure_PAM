"""
SIEM event sink: one structured, secret-free JSON line per audit event.

Delivery to Wazuh is by a Wazuh agent tailing this file (<localfile> with <log_format>json</log_format>),
the supported ingestion path for application events. SecurePAM never posts to the Wazuh *dashboard*
(a UI, not an ingestion API) and holds no Wazuh API credentials for this.

Defence in depth on top of the audit layer's own rule of never logging secrets: credential-like keys are
redacted and query strings are removed from anything that looks like a URL.
"""

import json
import logging
import os
import re
import threading
from typing import Any

from app.core.config import settings

logger = logging.getLogger("securepam.siem")
_LOCK = threading.Lock()
_SENSITIVE_KEY = re.compile(r"pass(word|wd)?|secret|token|cookie|authorization|credential|api[_-]?key|session[_-]?key|otp|mfa_code", re.I)
_URL_QUERY = re.compile(r"(https?://[^\s?#\"']+)[?#][^\s\"']*", re.I)


def scrub(value: Any, key: str = "") -> Any:
    if key and _SENSITIVE_KEY.search(key):
        return "[REDACTED]"
    if isinstance(value, dict):
        return {k: scrub(v, str(k)) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [scrub(v, key) for v in value]
    if isinstance(value, str):
        return _URL_QUERY.sub(r"\1", value)
    return value


def emit(event: dict) -> None:
    """Append one event. Never raises: a SIEM outage must not break the action being audited."""
    path = settings.SIEM_EVENT_LOG_PATH
    if not path:
        return
    line = json.dumps({"securepam": scrub(event)}, default=str, separators=(",", ":"))
    try:
        with _LOCK:
            fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o640)
            with os.fdopen(fd, "a", encoding="utf-8") as handle:
                handle.write(line + "\n")
    except OSError as exc:
        logger.error("siem sink write failed: %s", type(exc).__name__)
