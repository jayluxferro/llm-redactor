"""Structured, secret-safe logging for operators.

Logs JSON lines to the ``llm_redactor`` logger at INFO. Never pass raw
user text, API keys, or restore maps — only counts, flags, and sizes.
"""

from __future__ import annotations

import json
import logging
from typing import Any

_LOGGER = logging.getLogger("llm_redactor")


def log_event(event: str, **fields: Any) -> None:
    """Emit one JSON log line. Values must be JSON-serializable and non-sensitive."""
    payload = {"event": event, **fields}
    _LOGGER.info(json.dumps(payload, default=str))


def configure_logging(*, level: int = logging.INFO) -> None:
    """Idempotent basicConfig for CLI/proxy when no logging config exists."""
    if not logging.root.handlers:
        logging.basicConfig(level=level, format="%(message)s")
