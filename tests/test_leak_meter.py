"""Tests for leak-meter placeholder handling.

Placeholders embed the kind name (``⟨PRIVATE_KEY_PEM_1⟩``), so measuring leaks
against raw outgoing text counts the placeholder's own words as surviving
sensitive content — a fully redacted private key scored as a 1.00 leak.
"""

from __future__ import annotations

from evals.leak_meter import measure_leaks
from evals.runner import RunResult
from evals.schema import Annotation, Sample


def _rr(text: str, outgoing: str) -> RunResult:
    return RunResult(
        sample_id="s1",
        option="B",
        original_text=text,
        outgoing_text=outgoing,
        response_text="",
        restored_text="",
        detections=[],
        reverse_map={},
        latency_ms=0.0,
        mode="offline",
    )


def test_placeholder_kind_name_is_not_a_leak():
    """A redacted PEM header is not a leak just because the placeholder that
    replaced it contains the word PRIVATE."""
    pem = "-----BEGIN RSA PRIVATE KEY-----"
    text = f'KEY="{pem}"'
    sample = Sample(
        id="s1",
        text=text,
        annotations=[Annotation(start=5, end=5 + len(pem), kind="pem_private_key", text=pem)],
    )
    lr = measure_leaks(sample, _rr(text, 'KEY="⟨PRIVATE_KEY_PEM_1⟩"'))
    assert lr.exact_leaks == 0
    assert lr.partial_leaks == 0
    assert lr.combined_leak_rate == 0.0


def test_surviving_text_still_counts_as_a_leak():
    """Stripping placeholders must not mask a genuine partial leak."""
    host = "cache-04.corp.globex.net"
    text = f"host is {host} today"
    sample = Sample(
        id="s1",
        text=text,
        annotations=[Annotation(start=8, end=8 + len(host), kind="hostname", text=host)],
    )
    # Only the first two labels were redacted; "globex.net" survived.
    lr = measure_leaks(sample, _rr(text, "host is ⟨HOSTNAME_INTERNAL_1⟩.globex.net today"))
    assert lr.combined_leak_rate > 0.0
