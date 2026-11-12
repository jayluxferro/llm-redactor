"""Configuration loading and validation."""

from __future__ import annotations

import logging
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
    """Optional validation pass to filter detector false positives."""

    enabled: bool = False  # opt-in: adds one validation pass per text/message batch
    model: str = ""  # empty = use local_model.chat_model
    # "model" — ask a local Ollama chat model for KEEP/DROP verdicts (NER spans
    #   only; regex spans are auto-kept).
    # "rules" — deterministic checksum/shape rules per kind. No Ollama, and
    #   regex-sourced spans are validated too (a regex credit_card with a
    #   failing Luhn checksum is dropped instead of always kept).
    backend: str = "model"

    def __post_init__(self) -> None:
        # Fail at config load, not on the first request: an unknown backend
        # would otherwise silently fall through to whichever branch a caller
        # happens to compare first.
        if self.backend not in {"model", "rules"}:
            raise ValueError(
                f"pipeline.llm_validation.backend must be 'model' or 'rules', got {self.backend!r}"
            )


@dataclass
class ImageRedactionConfig:
    """Optional local ONNX image detector/redactor configuration.

    The model is intentionally not bundled: operators must download it themselves
    and accept its license before enabling this capability.
    """

    enabled: bool = False
    model_path: str = ""
    input_size: int = 384
    score_threshold: float = 0.8
    max_image_bytes: int = 10_000_000
    license_acknowledged: bool = False


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
    image_redaction: ImageRedactionConfig = field(default_factory=ImageRedactionConfig)
    # When true, each HTTP/proxy request gets random bytes in placeholders (e.g. ⟨EMAIL_1·a1b2c3d⟩).
    placeholder_request_tag: bool = False
    # "per_request" (random each request) or "per_conversation" (stable hash of
    # system + first user message). Stable tags keep redacted bytes identical
    # across a session's turns, which upstream prompt caching requires.
    placeholder_tag_mode: str = "per_request"
    # Run NER on tool output and tool-call arguments too (regex detection
    # always runs there).  On by default: tool results carry most of an
    # agent's sensitive data.  Turn off when that content is mostly source
    # code, where NER costs ~3 s per 100 KB uncached and tags identifiers as
    # organisations or people.
    tool_content_ner: bool = True
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
        # A generic proxy must protect every family unless an operator explicitly
        # narrows its policy.  ``all`` is expanded by ``resolve_categories``.
        default_factory=lambda: ["all"]
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
    mcp_session_cap: int = 10_000


@dataclass
class Config:
    version: int = 1
    transport: TransportConfig = field(default_factory=TransportConfig)
    local_model: LocalModelConfig = field(default_factory=LocalModelConfig)
    cloud_target: CloudTargetConfig = field(default_factory=CloudTargetConfig)
    pipeline: PipelineConfig = field(default_factory=PipelineConfig)
    policy: PolicyConfig = field(default_factory=PolicyConfig)


_LOG = logging.getLogger(__name__)


def _merge_dataclass(dc_type: type, raw: dict[str, Any], prefix: str = "") -> Any:
    """Recursively merge a raw dict into a dataclass, respecting defaults.

    Unknown keys are still ignored (old configs keep loading) but now logged:
    a typo such as ``tool_policy`` used to vanish silently, leaving the
    default in force with no hint why the setting had no effect.
    """
    import dataclasses
    import typing

    # Resolve string annotations to real types.
    hints = typing.get_type_hints(dc_type)
    kwargs: dict[str, Any] = {}
    names = {f.name for f in dataclasses.fields(dc_type)}
    for key in sorted(set(raw) - names, key=str):
        _LOG.warning("config: ignoring unknown key %s%s", prefix, key)

    for f in dataclasses.fields(dc_type):
        if f.name not in raw:
            continue
        val = raw[f.name]
        resolved_type = hints.get(f.name)
        # If the resolved type is a dataclass, recurse.
        if isinstance(resolved_type, type) and dataclasses.is_dataclass(resolved_type):
            if not isinstance(val, dict):
                _LOG.warning("config: %s%s should be a mapping; using defaults", prefix, f.name)
                val = {}
            kwargs[f.name] = _merge_dataclass(resolved_type, val, f"{prefix}{f.name}.")
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


def _validate_api_key_env(config: Config) -> None:
    """``api_key_env`` holds an env-var NAME, not a secret.

    Someone pasting the actual key produces a silent failure: os.getenv
    misses, auth passes through, and a raw secret sits in a config file
    (found in the wild by the config audit).  Fail loudly instead — a
    value that looks like a credential is a configuration error.
    """
    import re

    value = config.cloud_target.api_key_env
    if value and not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", value):
        preview = value[:6] + "…" if len(value) > 6 else value
        raise ValueError(
            f"cloud_target.api_key_env must be an environment variable NAME "
            f"(got {preview!r} — looks like a pasted secret; put the key in "
            f"the environment and reference it by name)"
        )


_TOOLS_POLICIES = frozenset({"bypass", "refuse"})


def _validate_tools_policy(config: Config) -> None:
    """Fail at load on an unknown tools_policy.

    The proxy compares against "refuse" only, so any other value, including a
    typo of "refuse", meant bypass: tool-bearing requests forwarded
    unredacted.  Same fail-at-load rule as LLMValidationConfig.backend.
    """
    policy = config.transport.tools_policy
    if policy not in _TOOLS_POLICIES:
        raise ValueError(f"transport.tools_policy must be 'bypass' or 'refuse', got {policy!r}")


def _validate(config: Config) -> Config:
    _validate_api_key_env(config)
    _validate_tools_policy(config)
    return config


def load_config(path: Path | None = None) -> Config:
    """Load config from YAML file with env overrides.

    Precedence: environment variables > YAML file > dataclass defaults.
    A missing file means defaults (callers that take an explicit path from
    the user check that it exists; see cli._resolve_config).
    """
    if path is None or not path.exists():
        return _validate(_env_overrides(Config()))

    raw: dict[str, Any] = yaml.safe_load(path.read_text()) or {}
    config = _merge_dataclass(Config, raw)
    return _validate(_env_overrides(config))
