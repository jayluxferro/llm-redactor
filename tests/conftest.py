"""Shared fixtures for llm-redactor tests."""

from __future__ import annotations

import pytest

from llm_redactor.config import Config


@pytest.fixture
def default_config() -> Config:
    return Config()
