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
class OptionHConfig(OptionConfig):
    epsilon: float = 4.0


@dataclass
class PipelineConfig:
    opt_a_local_only: OptionConfig = field(default_factory=OptionConfig)
    opt_b_redact: OptionBConfig = field(default_factory=OptionBConfig)
    opt_c_rephrase: OptionCConfig = field(default_factory=OptionCConfig)
    opt_d_tee: OptionConfig = field(default_factory=OptionConfig)
    opt_e_split: OptionConfig = field(default_factory=OptionConfig)
    opt_f_fhe: OptionConfig = field(default_factory=OptionConfig)
    opt_g_mpc: OptionConfig = field(default_factory=OptionConfig)
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


def load_config(path: Path | None = None) -> Config:
    """Load config from YAML file, falling back to defaults."""
    if path is None or not path.exists():
        return Config()

    raw: dict[str, Any] = yaml.safe_load(path.read_text()) or {}
    # TODO: merge raw dict into Config dataclass fields
    _ = raw
    return Config()
