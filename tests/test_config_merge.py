"""Tests for config YAML merge logic."""

from __future__ import annotations

import os
import tempfile
from pathlib import Path

import yaml

from llm_redactor.config import load_config


def test_load_default_config():
    """No file → all defaults."""
    c = load_config(None)
    assert c.transport.http_port == 7789
    assert c.pipeline.opt_b_redact.enabled is True
    assert c.pipeline.opt_d_tee.attestation_url == ""


def test_load_from_yaml():
    """YAML values override defaults."""
    raw = {
        "transport": {"http_port": 9999},
        "pipeline": {
            "opt_b_redact": {"strict": False},
            "opt_h_dp_noise": {"epsilon": 2.0, "enabled": True},
            "opt_d_tee": {"attestation_url": "https://att.example.com"},
        },
    }
    with tempfile.NamedTemporaryFile("w", suffix=".yaml", delete=False) as f:
        yaml.dump(raw, f)
        f.flush()
        c = load_config(Path(f.name))

    assert c.transport.http_port == 9999
    assert c.pipeline.opt_b_redact.strict is False
    assert c.pipeline.opt_h_dp_noise.epsilon == 2.0
    assert c.pipeline.opt_h_dp_noise.enabled is True
    assert c.pipeline.opt_d_tee.attestation_url == "https://att.example.com"
    # Unset values keep defaults.
    assert c.cloud_target.endpoint == "https://api.openai.com/v1"
    os.unlink(f.name)


def test_env_overrides(monkeypatch):
    """Environment variables override YAML and defaults."""
    monkeypatch.setenv("LLM_REDACTOR_HTTP_PORT", "1234")
    monkeypatch.setenv("LLM_REDACTOR_EPSILON", "1.5")
    monkeypatch.setenv("LLM_REDACTOR_LLM_VALIDATION", "true")
    monkeypatch.setenv("LLM_REDACTOR_PLACEHOLDER_REQUEST_TAG", "1")
    monkeypatch.setenv("LLM_REDACTOR_TOOLS_POLICY", "refuse")
    monkeypatch.setenv("LLM_REDACTOR_MCP_SESSION_CAP", "42")
    c = load_config(None)
    assert c.transport.http_port == 1234
    assert c.pipeline.opt_h_dp_noise.epsilon == 1.5
    assert c.pipeline.llm_validation.enabled is True
    assert c.pipeline.placeholder_request_tag is True
    assert c.transport.tools_policy == "refuse"
    assert c.transport.mcp_session_cap == 42


def test_missing_file_returns_defaults():
    """Non-existent file path → defaults."""
    c = load_config(Path("/nonexistent/config.yaml"))
    assert c.version == 1
    assert c.pipeline.opt_b_redact.enabled is True


def test_partial_yaml_preserves_other_defaults():
    """YAML that only sets one field leaves others at defaults."""
    raw = {"pipeline": {"opt_g_mpc": {"num_parties": 5}}}
    with tempfile.NamedTemporaryFile("w", suffix=".yaml", delete=False) as f:
        yaml.dump(raw, f)
        f.flush()
        c = load_config(Path(f.name))

    assert c.pipeline.opt_g_mpc.num_parties == 5
    assert c.pipeline.opt_g_mpc.embedding_dim == 768  # default preserved
    assert c.pipeline.opt_b_redact.enabled is True  # default preserved
    os.unlink(f.name)
