"""Tests for the Burp-facing batched detection API."""

from fastapi.testclient import TestClient

from llm_redactor.config import Config
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
