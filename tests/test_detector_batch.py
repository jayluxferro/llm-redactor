"""Tests for the Burp-facing batched detection API."""

from fastapi.testclient import TestClient

from llm_redactor.config import Config
from llm_redactor.transport import http_proxy
from llm_redactor.transport.http_proxy import app, configure


def test_default_policy_redacts_all_categories():
    assert Config().policy.categories == ["all"]


def test_detector_batch_preserves_order_and_empty_values():
    configure(Config(), use_ner=False)
    client = TestClient(app)
    response = client.post(
        "/v1/redactor/detect-batch",
        json={"texts": ["mail alice@example.com", "", "key sk-abcdefghijklmnopqrstuvwxyz"]},
    )
    assert response.status_code == 200
    items = response.json()["items"]
    assert len(items) == 3
    assert items[0][0]["kind"] == "email"
    assert items[1] == []
    assert items[2][0]["kind"] == "openai_api_key"


def test_image_redaction_is_explicitly_disabled_by_default():
    configure(Config(), use_ner=False)
    client = TestClient(app)
    response = client.post(
        "/v1/redactor/redact-image",
        content=b"not-an-image",
        headers={"content-type": "image/png"},
    )
    assert response.status_code == 503
    assert "disabled" in response.json()["error"]


def test_image_redaction_endpoint_returns_redacted_bytes(monkeypatch):
    class FakeImageRedactor:
        def redact(self, source: bytes, media_type: str):
            assert source == b"source-image"
            assert media_type == "image/png"
            return b"redacted-image", [object(), object()]

    configure(Config(), use_ner=False)
    monkeypatch.setattr(http_proxy, "_image_redactor", FakeImageRedactor())
    response = TestClient(app).post(
        "/v1/redactor/redact-image",
        content=b"source-image",
        headers={"content-type": "image/png"},
    )

    assert response.status_code == 200
    assert response.content == b"redacted-image"
    assert response.headers["X-LLM-Redactor-Detections"] == "2"
