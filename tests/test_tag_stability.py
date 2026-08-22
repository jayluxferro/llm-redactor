"""Tests for conversation-stable placeholder session tags."""

from llm_redactor.config import Config
from llm_redactor.pipeline.option_b import OptionBPipeline
from llm_redactor.transport.http_proxy import _placeholder_session_tag


def _pipeline(mode: str, enabled: bool = True) -> OptionBPipeline:
    cfg = Config()
    cfg.pipeline.placeholder_request_tag = enabled
    cfg.pipeline.placeholder_tag_mode = mode
    return OptionBPipeline(config=cfg, use_ner=False)


def _body(system: str = "sys", first_user: str = "hello") -> dict:
    return {
        "system": [{"type": "text", "text": system}],
        "messages": [
            {"role": "user", "content": first_user},
            {"role": "assistant", "content": "hi"},
        ],
    }


def test_per_conversation_tag_is_stable_across_turns() -> None:
    pipeline = _pipeline("per_conversation")
    # Turn N and turn N+1 of the same conversation (extra messages appended,
    # same system + first user) must derive the same tag.
    body_n = _body()
    body_n1 = _body()
    body_n1["messages"].append({"role": "user", "content": "next turn"})
    assert _placeholder_session_tag(body_n, pipeline) == _placeholder_session_tag(body_n1, pipeline)


def test_different_conversations_get_different_tags() -> None:
    pipeline = _pipeline("per_conversation")
    assert _placeholder_session_tag(
        _body(first_user="hello"), pipeline
    ) != _placeholder_session_tag(_body(first_user="different"), pipeline)


def test_per_request_mode_stays_random_and_disabled_returns_none() -> None:
    body = _body()
    per_request = _pipeline("per_request")
    assert _placeholder_session_tag(body, per_request) != _placeholder_session_tag(
        body, per_request
    )
    disabled = _pipeline("per_request", enabled=False)
    assert _placeholder_session_tag(body, disabled) is None
