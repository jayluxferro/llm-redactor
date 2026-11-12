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


def _semantic_inputs():
    from evals.runner import RunResult
    from evals.schema import Annotation, Sample

    note = Annotation(0, 3, "implicit", "the")
    sample = Sample(id="s", text="the CFO of Acme", annotations=[note])
    rr = RunResult("s", "B", sample.text, "the CFO of ⟨ORG_1⟩", "", "", [], {}, 0.0, "offline")
    return sample, rr


def test_semantic_judge_failure_is_an_error_not_a_safe_verdict() -> None:
    # With Ollama down every sample used to score "safe": a 0% leak rate.
    import asyncio
    from unittest.mock import patch

    import httpx

    from evals.leak_meter import measure_semantic_leak

    async def down(*_a, **_k):
        raise httpx.ConnectError("down")

    with patch("httpx.AsyncClient.post", side_effect=down):
        result = asyncio.run(measure_semantic_leak(*_semantic_inputs()))
    assert result.judge_error and not result.still_identifies


def test_semantic_judge_verdict_tolerates_markdown() -> None:
    import asyncio
    from unittest.mock import patch

    from evals.leak_meter import measure_semantic_leak

    class Reply:
        def raise_for_status(self) -> None:
            pass

        def json(self) -> dict:
            return {"message": {"content": "**YES** - the title and company identify them"}}

    async def judge(*_a, **_k):
        return Reply()

    with patch("httpx.AsyncClient.post", side_effect=judge):
        result = asyncio.run(measure_semantic_leak(*_semantic_inputs()))
    assert result.still_identifies and not result.judge_error


def _oracle(sample):
    """Perfect redaction: every annotated span replaced by a placeholder."""
    from evals.runner import RunResult

    out, last = [], 0
    for i, ann in enumerate(sorted(sample.annotations, key=lambda a: a.start)):
        if ann.start < last:  # nested annotation, already covered
            continue
        out += [sample.text[last : ann.start], f"⟨X_{i}⟩"]
        last = ann.end
    out.append(sample.text[last:])
    return RunResult(sample.id, "oracle", sample.text, "".join(out), "", "", [], {}, 0.0, "offline")


def test_perfect_redaction_scores_zero_on_every_workload() -> None:
    # The metric's floor.  The old "any 4-char substring" definition scored
    # this oracle as leaking up to 71% (wl3).
    from pathlib import Path

    from evals.leak_meter import measure_leaks
    from evals.schema import read_workload

    workloads = Path(__file__).parents[1] / "evals" / "workloads"
    for path in sorted(workloads.glob("*/annotations.jsonl")):
        for sample in read_workload(path):
            result = measure_leaks(sample, _oracle(sample))
            assert (result.exact_leaks, result.partial_leaks) == (0, 0), (
                path.parent.name,
                sample.id,
            )


def test_partial_leak_needs_an_informative_token_not_seen_elsewhere() -> None:
    from evals.leak_meter import measure_leaks
    from evals.runner import RunResult
    from evals.schema import Annotation, Sample

    text = "Irene Martinez asked about the renewal."
    sample = Sample("p", text, [Annotation(0, 14, "person", "Irene Martinez")])

    def sent(outgoing: str) -> int:
        return measure_leaks(
            sample, RunResult("p", "B", text, outgoing, "", "", [], {}, 0.0, "x")
        ).partial_leaks

    assert sent("⟨PERSON_1⟩ asked about the renewal.") == 0  # "rene" in "renewal" is not a leak
    assert sent("Ms Martinez asked about the renewal.") == 1  # the surname survived


def test_false_discovery_rate_uses_span_overlap() -> None:
    import tempfile
    from pathlib import Path

    from evals.leak_meter import measure_workload
    from evals.runner import RunResult
    from evals.schema import Annotation, Sample, write_workload

    text = "Authorization: Bearer abcdefghijklmnopqrstuvwx today"
    token = Annotation(22, 46, "bearer_token", "abcdefghijklmnopqrstuvwx")
    with tempfile.TemporaryDirectory() as tmp:
        path = Path(tmp) / "annotations.jsonl"
        write_workload([Sample("s", text, [token])], path)
        detections = [
            {
                "kind": "bearer_token",
                "text": "Bearer abcdefghijklmnopqrstuvwx",
                "start": 15,
                "end": 46,
            },
            {"kind": "person", "text": "today", "start": 47, "end": 52},
            {"kind": "fhe_classification", "text": "label"},  # no offsets: not a span, skipped
        ]
        rr = RunResult("s", "B(route)", text, "", "", "", detections, {}, 0.0, "offline")
        summary = measure_workload(path, [rr], option="B")
    assert summary.false_discovery_rate == 0.5  # "Bearer <token>" overlaps the truth
    assert summary.option == "B"  # the requested option, not the route label


def test_pem_annotations_cover_the_whole_block() -> None:
    from pathlib import Path

    from evals.schema import read_workload

    wl2 = Path(__file__).parents[1] / "evals" / "workloads" / "wl2_secrets" / "annotations.jsonl"
    pems = [a for s in read_workload(wl2) for a in s.annotations if a.kind == "pem_private_key"]
    assert pems and all("-----END RSA PRIVATE KEY-----" in a.text for a in pems)


def test_p95_is_nearest_rank() -> None:
    from evals.report import EvalRow, add_latency_to_row

    row = EvalRow("B", "wl1", 0, 0, 0.0, 0.0, 0.0, 0.0)
    add_latency_to_row(row, [float(i) for i in range(1, 21)])  # 1..20
    assert row.latency_ms_p95 == 19.0  # ceil(0.95 * 20) = 19th value; was 20 (the max)
