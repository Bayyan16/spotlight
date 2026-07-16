"""spotlight sweep CLI entry point."""
from __future__ import annotations

import json
from pathlib import Path

import typer
from rich.console import Console
from rich.table import Table

from spotlight.orchestrator import Orchestrator

app = typer.Typer(help="Spotlight — the AI security engineer")
console = Console()


@app.command()
def sweep(
    repo: Path = typer.Argument(..., exists=True, file_okay=False, dir_okay=True),
    out: Path = typer.Option(Path("./sweep-run"), "--out"),
    surfaces: str = typer.Option("code", "--surfaces"),
    deployment_tier: str = typer.Option("t0-mock", "--deployment-tier"),
) -> None:
    """Run a Spotlight Sweep against a repo path."""
    console.rule(f"[bold]Spotlight Sweep[/bold] → {repo}")
    orch = Orchestrator()
    out.mkdir(parents=True, exist_ok=True)
    result = orch.run(repo, out_dir=out / repo.name)

    table = Table(title="Findings")
    table.add_column("ID"); table.add_column("Class"); table.add_column("CWE")
    table.add_column("Tier"); table.add_column("State"); table.add_column("Confidence")
    for f in result.findings:
        table.add_row(f["id"], f["class"], f["cwe"], f["tier"], f["state"], f"{f['confidence']:.2f}")
    console.print(table)
    console.print(f"\n[green]Attestation:[/green] {out / repo.name / 'attestation.json'}")


@app.command()
def serve(
    host: str = typer.Option("127.0.0.1", "--host"),
    port: int = typer.Option(8000, "--port"),
) -> None:
    """Start the FastAPI backend."""
    import uvicorn

    uvicorn.run("spotlight.api.app:app", host=host, port=port, reload=False)


if __name__ == "__main__":
    app()
