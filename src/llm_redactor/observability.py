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
    """Emit one JSON log line.

    All values must be JSON-serializable — passing non-serializable objects
    (API keys, raw spans, restore maps) raises TypeError so the bug is caught
    at the call site rather than silently stringified into logs.
    """
    payload = {"event": event, **fields}
    _LOGGER.info(json.dumps(payload))


def configure_logging(*, level: int = logging.INFO) -> None:
    """Idempotent basicConfig for CLI/proxy when no logging config exists."""
    if not _LOGGER.handlers:
        logging.basicConfig(level=level, format="%(message)s")
