"""CLI entry point."""

from __future__ import annotations

import asyncio
import os
from pathlib import Path

import typer
from rich.console import Console
from rich.table import Table

from .config import Config, load_config
from .observability import configure_logging

app = typer.Typer(name="llm-redactor", no_args_is_help=True)
console = Console()


def _apply_detection_config(cfg: Config) -> None:
    """Apply detection settings from config (NER model, confidence floor)."""
    from .detect.orchestrator import apply_detection_config

    apply_detection_config(cfg)


@app.command()
def serve(
    port: int = typer.Option(7789, help="HTTP proxy port"),
    host: str = typer.Option("127.0.0.1", "--host", help="HTTP bind host"),
    config_path: str = typer.Option("llm_redactor.yaml", "--config", help="Config file path"),
    upstream: str | None = typer.Option(None, "--upstream", help="Override the cloud upstream URL"),
    workers: int = typer.Option(
        0, "--workers", help="Worker processes (0 = auto: CPU count, capped at 8)"
    ),
    limit_concurrency: int = typer.Option(
        64,
        "--limit-concurrency",
        help="Max concurrent requests per worker before shedding load (503)",
    ),
) -> None:
    """Start the llm-redactor HTTP proxy."""
    import uvicorn

    # Validate the config up front so a bad path fails here with a clear message
    # rather than crashing every spawned worker. Detection/spaCy is NOT loaded
    # in this parent process: with workers > 1 each worker is a fresh spawn, so
    # every worker configures itself from the environment in its lifespan hook
    # (module globals set here would not survive the spawn).
    cfg = load_config(Path(config_path))
    resolved_upstream = upstream or cfg.cloud_target.endpoint

    # Hand the config to workers via the environment (inherited across spawn).
    os.environ["LLM_REDACTOR_CONFIG"] = str(Path(config_path))
    os.environ["LLM_REDACTOR_PORT"] = str(port)
    if upstream:
        os.environ["LLM_REDACTOR_UPSTREAM"] = upstream
        console.print(f"[dim]Upstream override: {upstream}[/dim]")

    configure_logging()

    worker_count = max(1, workers or min(os.cpu_count() or 2, 8))
    console.print(
        f"[bold]llm-redactor[/bold] proxy on {host}:{port} "
        f"(workers={worker_count}, upstream={resolved_upstream})"
    )
    uvicorn.run(
        "llm_redactor.transport.http_proxy:app",
        host=host,
        port=port,
        workers=worker_count,
        limit_concurrency=limit_concurrency,
        log_level="info",
    )


@app.command()
def mcp(
    config_path: str = typer.Option("llm_redactor.yaml", "--config", help="Config file path"),
) -> None:
    """Start the llm-redactor MCP stdio server."""
    from .transport.mcp_server import run_mcp

    cfg = load_config(Path(config_path))
    _apply_detection_config(cfg)
    asyncio.run(run_mcp(cfg))


@app.command()
def detect(
    text: str = typer.Argument(..., help="Text to scan for sensitive spans"),
    ner: bool = typer.Option(False, "--ner", help="Enable Presidio NER (slower, more accurate)"),
    redact: bool = typer.Option(False, "--redact", help="Show redacted output preview"),
    config_path: str = typer.Option("llm_redactor.yaml", "--config", help="Config file path"),
) -> None:
    """Dry-run: detect and optionally redact sensitive spans without sending anything."""
    from .detect.orchestrator import detect_all
    from .detect.regex import load_custom_patterns
    from .detect.types import filter_by_categories

    cfg = load_config(Path(config_path))
    _apply_detection_config(cfg)
    if cfg.policy.extend_patterns_file:
        load_custom_patterns(cfg.policy.extend_patterns_file)

    spans = detect_all(text, use_ner=ner)
    spans = filter_by_categories(spans, cfg.policy.categories)
    if not spans:
        console.print("[green]No sensitive spans detected.[/green]")
        return

    table = Table(title="Detected spans")
    table.add_column("Kind")
    table.add_column("Text")
    table.add_column("Confidence")
    table.add_column("Source")
    for s in spans:
        table.add_row(s.kind, s.text, f"{s.confidence:.2f}", s.source)
    console.print(table)

    if redact:
        from .redact.placeholder import redact as do_redact

        result = do_redact(text, spans)
        console.print("\n[bold]Redacted output:[/bold]")
        console.print(result.redacted_text)
        console.print(f"\n[dim]{len(result.reverse_map)} placeholder(s) in reverse map[/dim]")


if __name__ == "__main__":
    app()
