"""
Structured application logging.

DEV_MODE: human-readable console output.
Otherwise: single-line JSON — suitable for log aggregation and SIEM export
(each line already matches the shape audit events use: timestamp, level,
logger, request_id, event, ...).

NEVER log secrets, passwords, tokens, or session cookies through this —
see app/models/audit.py's own comment on the same rule for audit events.
"""

import logging
import sys
from typing import Any

import structlog

from app.core.config import settings

_SHARED_PROCESSORS = [
    structlog.contextvars.merge_contextvars,
    structlog.stdlib.add_log_level,
    structlog.stdlib.add_logger_name,
    structlog.processors.TimeStamper(fmt="iso"),
]


def configure_logging() -> None:
    """Configure stdlib logging + structlog. Call once at startup."""
    renderer: Any = (
        structlog.dev.ConsoleRenderer()
        if settings.DEV_MODE
        else structlog.processors.JSONRenderer()
    )

    formatter = structlog.stdlib.ProcessorFormatter(
        foreign_pre_chain=_SHARED_PROCESSORS,
        processors=[structlog.stdlib.ProcessorFormatter.remove_processors_meta, renderer],
    )

    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(formatter)

    root_logger = logging.getLogger()
    root_logger.handlers = [handler]
    root_logger.setLevel(getattr(logging, settings.LOG_LEVEL.upper(), logging.INFO))

    structlog.configure(
        processors=_SHARED_PROCESSORS + [structlog.stdlib.ProcessorFormatter.wrap_for_formatter],
        logger_factory=structlog.stdlib.LoggerFactory(),
        wrapper_class=structlog.stdlib.BoundLogger,
        cache_logger_on_first_use=True,
    )

    # SQLAlchemy's own engine logger is extremely verbose at INFO.
    logging.getLogger("sqlalchemy.engine").setLevel(
        logging.INFO if settings.DEBUG else logging.WARNING
    )


def get_logger(name: str = "securepam") -> structlog.stdlib.BoundLogger:
    return structlog.get_logger(name)
