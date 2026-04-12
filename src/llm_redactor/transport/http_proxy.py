"""FastAPI-based OpenAI-compatible HTTP proxy."""

from __future__ import annotations

from typing import Any

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

from ..config import Config
from ..pipeline.option_b import OptionBPipeline, RefusalError

app = FastAPI(title="llm-redactor", version="0.1.0")

# Initialized at startup via configure().
_pipeline: OptionBPipeline | None = None


def configure(config: Config, *, use_ner: bool = True) -> FastAPI:
    """Wire the pipeline into the app. Call before serving."""
    global _pipeline
    _pipeline = OptionBPipeline(config=config, use_ner=use_ner)
    return app


def _get_pipeline() -> OptionBPipeline:
    if _pipeline is None:
        raise RuntimeError("Proxy not configured — call configure() first")
    return _pipeline


@app.post("/v1/chat/completions")
async def chat_completions(request: Request) -> JSONResponse:
    """OpenAI-compatible chat completion endpoint with redaction."""
    body: dict[str, Any] = await request.json()
    pipeline = _get_pipeline()

    # Allow per-request overrides via extra_body.redactor.
    extra = body.get("extra_body", {}).get("redactor", {})
    strict_override = extra.get("strict")
    if strict_override is not None:
        pipeline.config.pipeline.opt_b_redact.strict = bool(strict_override)

    try:
        result = await pipeline.run(body)
    except RefusalError as e:
        return JSONResponse(
            status_code=422,
            content={
                "error": {
                    "type": "redactor_refused",
                    "reason": e.reason,
                    "detected_spans": [
                        {
                            "kind": s.kind,
                            "text_hint": f"...{s.text[:8]}...",
                            "confidence": s.confidence,
                        }
                        for s in e.spans
                    ],
                    "guidance": (
                        "Review the request and mark sensitive spans manually, "
                        "or disable strict mode with extra_body.redactor.strict=false."
                    ),
                },
            },
        )

    # Build the response with redactor metadata.
    response_body = result.response
    response_body["redactor"] = {
        "options_applied": result.options_applied,
        "detections": _summarize_detections(result.detections),
        "leak_audit": result.leak_audit,
    }

    return JSONResponse(content=response_body)


@app.get("/v1/redactor/stats")
async def redactor_stats() -> JSONResponse:
    """Aggregate counters since process start."""
    pipeline = _get_pipeline()
    return JSONResponse(content=pipeline.stats)


@app.get("/v1/redactor/config")
async def redactor_config() -> JSONResponse:
    """Read-only view of the current config."""
    pipeline = _get_pipeline()
    cfg = pipeline.config
    return JSONResponse(content={
        "pipeline": {
            "opt_b_redact": {
                "enabled": cfg.pipeline.opt_b_redact.enabled,
                "strict": cfg.pipeline.opt_b_redact.strict,
            },
        },
        "cloud_target": {
            "backend": cfg.cloud_target.backend,
            "endpoint": cfg.cloud_target.endpoint,
        },
    })


def _summarize_detections(detections: list) -> list[dict[str, Any]]:
    """Group detections by kind for the response metadata."""
    counts: dict[str, int] = {}
    for d in detections:
        counts[d.kind] = counts.get(d.kind, 0) + 1
    return [{"kind": k, "count": v} for k, v in counts.items()]
