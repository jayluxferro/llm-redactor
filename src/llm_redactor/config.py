"""Configuration loading and validation."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml


@dataclass
class LocalModelConfig:
    backend: str = "ollama"
    endpoint: str = "http://127.0.0.1:11434"
    chat_model: str = "llama3.2:3b"
    ner_model: str | None = None  # e.g. en_core_web_trf, xx_ent_wiki_sm
    ner_confidence_floor: float = 0.5  # drop NER results below this
    ner_labels_to_ignore: list[str] = field(
        default_factory=lambda: [
            "CARDINAL",
            "MONEY",
            "ORDINAL",
            "QUANTITY",
            "PRODUCT",
            "WORK_OF_ART",
            "LANGUAGE",
            "EVENT",
        ]
    )


@dataclass
class CloudTargetConfig:
    backend: str = "openai_compat"
    endpoint: str = "https://api.openai.com/v1"
    api_key_env: str = "OPENAI_API_KEY"


@dataclass
class OptionConfig:
    enabled: bool = False


@dataclass
class LLMValidationConfig:
    """Optional local LLM pass to filter NER false positives (Ollama)."""

    enabled: bool = False  # opt-in: adds one Ollama round-trip per text/message batch
    model: str = ""  # empty = use local_model.chat_model


@dataclass
class OptionBConfig(OptionConfig):
    enabled: bool = True
    strict: bool = True


@dataclass
class OptionCConfig(OptionConfig):
    require_validator_pass: bool = True


@dataclass
class OptionDConfig(OptionConfig):
    attestation_url: str = ""
    inference_url: str = ""


@dataclass
class OptionEConfig(OptionConfig):
    remote_url: str = ""
    local_layers: int = 4
    remote_layers: int = 24
    hidden_dim: int = 4096


@dataclass
class OptionFConfig(OptionConfig):
    sensitivity_threshold: float = 0.5


@dataclass
class OptionGConfig(OptionConfig):
    num_parties: int = 3
    embedding_dim: int = 768


@dataclass
class OptionHConfig(OptionConfig):
    epsilon: float = 4.0


@dataclass
class PipelineConfig:
    llm_validation: LLMValidationConfig = field(default_factory=LLMValidationConfig)
    # When true, each HTTP/proxy request gets random bytes in placeholders (e.g. ⟨EMAIL_1·a1b2c3d⟩).
    placeholder_request_tag: bool = False
    opt_a_local_only: OptionConfig = field(default_factory=OptionConfig)
    opt_b_redact: OptionBConfig = field(default_factory=OptionBConfig)
    opt_c_rephrase: OptionCConfig = field(default_factory=OptionCConfig)
    opt_d_tee: OptionDConfig = field(default_factory=OptionDConfig)
    opt_e_split: OptionEConfig = field(default_factory=OptionEConfig)
    opt_f_fhe: OptionFConfig = field(default_factory=OptionFConfig)
    opt_g_mpc: OptionGConfig = field(default_factory=OptionGConfig)
    opt_h_dp_noise: OptionHConfig = field(default_factory=OptionHConfig)


@dataclass
class PolicyConfig:
    strict_refuse_on_unknown_sensitive: bool = True
    categories: list[str] = field(
        default_factory=lambda: [
            "identity",
            "contact",
            "government_id",
            "financial",
            "medical",
            "temporal",
            "credential",
            "cloud_credential",
            "vendor_api_key",
            "private_key",
            "infrastructure",
        ]
    )
    extend_patterns_file: str = ".llm_redactor/patterns.yaml"


@dataclass
class TransportConfig:
    mcp: bool = True
    http: bool = True
    http_port: int = 7789
    # bypass: forward tool/function calls without redaction (default).
    # refuse: reject with 422 so nothing hits the cloud without redaction.
    tools_policy: str = "bypass"
    # Cap in-memory MCP scrub sessions (oldest evicted; restore then fails safely).
    mcp_session_cap: int = 2000


@dataclass
class Config:
    version: int = 1
    transport: TransportConfig = field(default_factory=TransportConfig)
    local_model: LocalModelConfig = field(default_factory=LocalModelConfig)
    cloud_target: CloudTargetConfig = field(default_factory=CloudTargetConfig)
    pipeline: PipelineConfig = field(default_factory=PipelineConfig)
    policy: PolicyConfig = field(default_factory=PolicyConfig)


def _merge_dataclass(dc_type: type, raw: dict[str, Any]) -> Any:
    """Recursively merge a raw dict into a dataclass, respecting defaults."""
    import dataclasses
    import typing

    # Resolve string annotations to real types.
    hints = typing.get_type_hints(dc_type)
    kwargs: dict[str, Any] = {}

    for f in dataclasses.fields(dc_type):
        if f.name not in raw:
            continue
        val = raw[f.name]
        resolved_type = hints.get(f.name)
        # If the resolved type is a dataclass, recurse.
        if isinstance(resolved_type, type) and dataclasses.is_dataclass(resolved_type):
            kwargs[f.name] = _merge_dataclass(resolved_type, val if isinstance(val, dict) else {})
        else:
            kwargs[f.name] = val

    return dc_type(**kwargs)


def _env_overrides(config: Config) -> Config:
    """Apply environment variable overrides (env > file > defaults)."""
    import os

    if ep := os.environ.get("LLM_REDACTOR_HTTP_PORT"):
        config.transport.http_port = int(ep)
    if ep := os.environ.get("LLM_REDACTOR_LOCAL_ENDPOINT"):
        config.local_model.endpoint = ep
    if ep := os.environ.get("LLM_REDACTOR_CLOUD_ENDPOINT"):
        config.cloud_target.endpoint = ep
    if ep := os.environ.get("LLM_REDACTOR_CLOUD_API_KEY_ENV"):
        config.cloud_target.api_key_env = ep
    if ep := os.environ.get("LLM_REDACTOR_EPSILON"):
        config.pipeline.opt_h_dp_noise.epsilon = float(ep)
    if os.environ.get("LLM_REDACTOR_LLM_VALIDATION", "").lower() in {"1", "true", "yes"}:
        config.pipeline.llm_validation.enabled = True
    if os.environ.get("LLM_REDACTOR_PLACEHOLDER_REQUEST_TAG", "").lower() in {"1", "true", "yes"}:
        config.pipeline.placeholder_request_tag = True
    if ep := os.environ.get("LLM_REDACTOR_TOOLS_POLICY"):
        config.transport.tools_policy = ep.strip().lower()
    if ep := os.environ.get("LLM_REDACTOR_MCP_SESSION_CAP"):
        config.transport.mcp_session_cap = int(ep)
    return config


def load_config(path: Path | None = None) -> Config:
    """Load config from YAML file with env overrides.

    Precedence: environment variables > YAML file > dataclass defaults.
    """
    if path is None or not path.exists():
        return _env_overrides(Config())

    raw: dict[str, Any] = yaml.safe_load(path.read_text()) or {}
    config = _merge_dataclass(Config, raw)
    return _env_overrides(config)
