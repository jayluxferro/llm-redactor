"""CLI entry point."""

from __future__ import annotations

import asyncio
from pathlib import Path

import typer
from rich.console import Console
from rich.table import Table

from .config import Config, load_config

app = typer.Typer(name="llm-redactor", no_args_is_help=True)
console = Console()


@app.command()
def serve(
    port: int = typer.Option(7789, help="HTTP proxy port"),
    config_path: str = typer.Option("llm_redactor.yaml", "--config", help="Config file path"),
) -> None:
    """Start the llm-redactor HTTP proxy."""
    import uvicorn

    from .transport.http_proxy import configure

    cfg = load_config(Path(config_path))
    cfg.transport.http_port = port
    configure(cfg)

    console.print(f"[bold]llm-redactor[/bold] proxy on port {port}")
    uvicorn.run(
        "llm_redactor.transport.http_proxy:app",
        host="127.0.0.1",
        port=port,
        log_level="info",
    )


@app.command()
def mcp(
    config_path: str = typer.Option("llm_redactor.yaml", "--config", help="Config file path"),
) -> None:
    """Start the llm-redactor MCP stdio server."""
    from .transport.mcp_server import run_mcp

    cfg = load_config(Path(config_path))
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

    cfg = load_config(Path(config_path))
    if cfg.policy.extend_patterns_file:
        load_custom_patterns(cfg.policy.extend_patterns_file)

    spans = detect_all(text, use_ner=ner)
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
