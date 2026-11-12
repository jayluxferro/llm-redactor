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


# ── fixes from the project audit ─────────────────────────────────────────


def test_unknown_config_keys_are_logged_not_silently_dropped(tmp_path, caplog) -> None:
    import logging

    from llm_redactor.config import load_config

    cfg_file = tmp_path / "c.yaml"
    cfg_file.write_text("transport:\n  tool_policy: refuse\npolicy: [all]\n")
    with caplog.at_level(logging.WARNING, logger="llm_redactor.config"):
        cfg = load_config(cfg_file)
    messages = " ".join(r.getMessage() for r in caplog.records)
    assert "transport.tool_policy" in messages  # the typo is named
    assert "policy should be a mapping" in messages
    assert cfg.transport.tools_policy == "redact"  # still loads, defaults intact


def test_unknown_tools_policy_fails_at_load(tmp_path, monkeypatch) -> None:
    import pytest

    from llm_redactor.config import load_config

    cfg_file = tmp_path / "c.yaml"
    cfg_file.write_text("transport:\n  tools_policy: refuze\n")  # typo: used to mean bypass
    with pytest.raises(ValueError, match="tools_policy"):
        load_config(cfg_file)
    monkeypatch.setenv("LLM_REDACTOR_TOOLS_POLICY", "refuze")
    with pytest.raises(ValueError, match="tools_policy"):
        load_config(None)


def test_explicit_missing_config_path_is_an_error(tmp_path) -> None:
    import pytest
    import typer

    from llm_redactor.cli import DEFAULT_CONFIG, _resolve_config

    assert str(_resolve_config(None)) == DEFAULT_CONFIG  # implicit default may be absent
    with pytest.raises(typer.BadParameter):
        _resolve_config(str(tmp_path / "typo.yaml"))


def test_custom_patterns_load_everywhere_and_survive_the_default_policy(tmp_path) -> None:
    from llm_redactor.config import Config
    from llm_redactor.detect import regex
    from llm_redactor.detect.orchestrator import apply_detection_config, detect_all
    from llm_redactor.detect.types import filter_by_categories

    patterns = tmp_path / "patterns.yaml"
    patterns.write_text('patterns:\n  project_code: "PROJ-\\\\d{4}"\n')
    cfg = Config()
    cfg.policy.extend_patterns_file = str(patterns)
    try:
        apply_detection_config(cfg)  # what serve / mcp / detect all call
        spans = filter_by_categories(detect_all("ticket PROJ-1234", use_ner=False), ["all"])
        assert [(s.kind, s.text) for s in spans] == [("project_code", "PROJ-1234")]
    finally:
        regex._custom_patterns.pop("project_code", None)


def test_removed_keys_warn_and_unsupported_version_fails(tmp_path, caplog) -> None:
    import logging

    import pytest

    from llm_redactor.config import load_config

    old = tmp_path / "old.yaml"
    old.write_text(
        "cloud_target:\n  backend: openai_compat\ntransport:\n  http: true\n"
        "policy:\n  strict_refuse_on_unknown_sensitive: false\n"
    )
    with caplog.at_level(logging.WARNING, logger="llm_redactor.config"):
        load_config(old)  # still loads
    text = " ".join(r.getMessage() for r in caplog.records)
    for key in (
        "cloud_target.backend",
        "transport.http",
        "policy.strict_refuse_on_unknown_sensitive",
    ):
        assert key in text
    future = tmp_path / "future.yaml"
    future.write_text("version: 2\n")
    with pytest.raises(ValueError, match="version"):
        load_config(future)


def test_every_example_config_loads_without_warnings(caplog) -> None:
    import logging
    from pathlib import Path

    from llm_redactor.config import load_config

    examples = sorted((Path(__file__).parents[1] / "examples").glob("*.yaml"))
    assert examples
    with caplog.at_level(logging.WARNING, logger="llm_redactor.config"):
        for path in examples:
            load_config(path)
    assert [r.getMessage() for r in caplog.records] == []
