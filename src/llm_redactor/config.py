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
    ner_model: str | None = None


@dataclass
class CloudTargetConfig:
    backend: str = "openai_compat"
    endpoint: str = "https://api.openai.com/v1"
    api_key_env: str = "OPENAI_API_KEY"


@dataclass
class OptionConfig:
    enabled: bool = False


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
        default_factory=lambda: ["pii", "secret", "org_identifier", "customer_name"]
    )
    extend_patterns_file: str = ".llm_redactor/patterns.yaml"


@dataclass
class TransportConfig:
    mcp: bool = True
    http: bool = True
    http_port: int = 7789


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
