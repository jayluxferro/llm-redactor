"""Tests for Options D–G pipeline and eval runner integration."""

from __future__ import annotations

import pytest

from evals.runner import (
    run_option_d_offline,
    run_option_e_offline,
    run_option_f_offline,
    run_option_g_offline,
)
from evals.schema import Annotation, Sample
from llm_redactor.config import Config
from llm_redactor.pipeline.option_d import OptionDPipeline
from llm_redactor.pipeline.option_e import OptionEPipeline
from llm_redactor.pipeline.option_f import OptionFPipeline
from llm_redactor.pipeline.option_g import OptionGPipeline


@pytest.fixture
def sample() -> Sample:
    return Sample(
        id="test-001",
        text="Contact alice@example.com for the quarterly report.",
        annotations=[
            Annotation(kind="email", text="alice@example.com", start=8, end=27),
        ],
    )


@pytest.fixture
def config() -> Config:
    return Config()


# --- Config tests ---


def test_option_d_config_fields():
    c = Config()
    assert c.pipeline.opt_d_tee.attestation_url == ""
    assert c.pipeline.opt_d_tee.inference_url == ""
    assert c.pipeline.opt_d_tee.enabled is False


def test_option_e_config_fields():
    c = Config()
    assert c.pipeline.opt_e_split.local_layers == 4
    assert c.pipeline.opt_e_split.remote_layers == 24
    assert c.pipeline.opt_e_split.hidden_dim == 4096


def test_option_f_config_fields():
    c = Config()
    assert c.pipeline.opt_f_fhe.sensitivity_threshold == 0.5


def test_option_g_config_fields():
    c = Config()
    assert c.pipeline.opt_g_mpc.num_parties == 3
    assert c.pipeline.opt_g_mpc.embedding_dim == 768


# --- Eval runner tests (offline stubs) ---


async def test_option_d_offline_leaks_everything(sample: Sample):
    """Option D sends plaintext to TEE — outgoing_text = original."""
    result = await run_option_d_offline(sample)
    assert result.option == "D"
    assert result.outgoing_text == sample.text
    assert result.mode == "offline"


async def test_option_e_offline_leaks_nothing(sample: Sample):
    """Option E sends activations, not tokens — outgoing_text = empty."""
    result = await run_option_e_offline(sample)
    assert result.option == "E"
    assert result.outgoing_text == ""
    assert result.latency_ms > 0


async def test_option_f_offline_leaks_nothing(sample: Sample):
    """Option F sends ciphertext — outgoing_text = empty."""
    result = await run_option_f_offline(sample)
    assert result.option == "F"
    assert result.outgoing_text == ""
    assert len(result.detections) == 1
    assert result.detections[0]["kind"] == "fhe_classification"


async def test_option_g_offline_leaks_nothing(sample: Sample):
    """Option G sends secret shares — outgoing_text = empty."""
    result = await run_option_g_offline(sample)
    assert result.option == "G"
    assert result.outgoing_text == ""
    assert result.latency_ms > 0


# --- Pipeline instantiation tests ---


def test_option_d_pipeline_instantiation(config: Config):
    p = OptionDPipeline(config=config)
    assert p.stats["requests"] == 0


def test_option_e_pipeline_instantiation(config: Config):
    p = OptionEPipeline(config=config)
    assert p.stats["requests"] == 0


def test_option_f_pipeline_instantiation(config: Config):
    p = OptionFPipeline(config=config)
    assert p.stats["requests"] == 0
    assert p.stats["classified_sensitive"] == 0


def test_option_g_pipeline_instantiation(config: Config):
    p = OptionGPipeline(config=config)
    assert p.stats["requests"] == 0
