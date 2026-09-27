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


cortex_app = typer.Typer(help="Cortex — learned policy, experience ledger, governance")
app.add_typer(cortex_app, name="cortex")


def _open_cortex(root: Path | None):
    """Open the Cortex at `root`, or from SPOTLIGHT_CORTEX_DIR. Exits if absent."""
    import os

    from spotlight.cortex import Cortex

    target = str(root) if root else os.environ.get("SPOTLIGHT_CORTEX_DIR", "").strip()
    if not target:
        console.print(
            "[red]No Cortex configured.[/red] Pass --root or set "
            "SPOTLIGHT_CORTEX_DIR to the workspace memory directory."
        )
        raise typer.Exit(code=2)
    signer = None
    try:
        from spotlight.non_repudiation import Signer

        signer = Signer()
    except Exception as exc:  # noqa: BLE001 — verification still works unsigned
        console.print(f"[yellow]signer unavailable ({exc!r}); rows will be unsigned[/yellow]")
    return Cortex(root=Path(target), signer=signer)


@cortex_app.command("status")
def cortex_status(
    root: Path = typer.Option(None, "--root", help="Cortex directory"),
) -> None:
    """Show the active policy, ledger size and label coverage."""
    cortex = _open_cortex(root)
    status = cortex.status()
    ledger = status["ledger"]
    policy = status["policy"]
    console.rule("[bold]Spotlight Cortex[/bold]")
    console.print(
        f"policy       v{policy['version']} · [cyan]{policy['policy_id']}[/cyan]"
        f"{' (identity — nothing learned yet)' if policy['is_identity'] else ''}"
    )
    console.print(f"directives   {len(policy['directives'])}")
    console.print(
        f"ledger       {ledger['records']} rows · {ledger['distinct_findings']} findings · "
        f"{ledger['labeled']} labelled / {ledger['unlabeled']} unlabelled"
    )
    console.print(f"head         {ledger['head']}")
    console.print(
        f"cohorts      {status['cohorts']['actionable']} actionable / "
        f"{status['cohorts']['total']} total"
    )
    console.print(
        f"lessons      {status['lessons']['served']} served · "
        f"{status['lessons']['quarantined']} quarantined"
    )

    audit = status.get("active_policy_audit") or {}
    if audit.get("tp_demoted"):
        console.print(
            f"[red]WARNING[/red] the active policy now demotes "
            f"{audit['tp_demoted']} confirmed true positive(s) against the current "
            f"ledger — the next evolution cycle will retract it. Run "
            f"`spotlight cortex evolve` now."
        )
    elif audit.get("fp_demoted"):
        console.print(
            f"effect       {audit['fp_demoted']} known false positive(s) routed to "
            f"review by the active policy"
        )

    table = Table(title="Learned directives")
    table.add_column("Cohort"); table.add_column("Action"); table.add_column("n")
    table.add_column("TP/FP"); table.add_column("Precision"); table.add_column("Why")
    for key, d in sorted(policy["directives"].items()):
        table.add_row(
            key, d["action"], str(d["n_labeled"]), f"{d['tp']}/{d['fp']}",
            f"{d['precision_mean']:.2f} (≥{d['precision_lower']:.2f})",
            (d["rationale"] or "")[:60],
        )
    if policy["directives"]:
        console.print(table)


@cortex_app.command("verify")
def cortex_verify(
    root: Path = typer.Option(None, "--root", help="Cortex directory"),
) -> None:
    """Recompute the experience ledger's hash chain and signatures."""
    report = _open_cortex(root).verify().to_dict()
    colour = "green" if report["ok"] else "red"
    console.print(f"[{colour}]{'OK' if report['ok'] else 'FAILED'}[/{colour}] — {report['reason']}")
    console.print(
        f"records {report['records']} · signatures checked "
        f"{report['signatures_checked']} · head {report['head']}"
    )
    if not report["ok"]:
        console.print(f"[red]first break at row {report['broken_at']}[/red]")
        raise typer.Exit(code=1)


@cortex_app.command("evolve")
def cortex_evolve(
    root: Path = typer.Option(None, "--root", help="Cortex directory"),
    approver: str = typer.Option(
        None, "--approver",
        help="Your name — required to activate a non-conservative policy",
    ),
    dry_run: bool = typer.Option(False, "--dry-run", help="Propose and gate, activate nothing"),
) -> None:
    """Run one evolution cycle: calibrate → propose → gate → maybe activate."""
    cortex = _open_cortex(root)
    if dry_run:
        # Recorded: a dry run is a real proposal, and the governance log is
        # where "we looked at this and did not ship it" belongs.
        _print_proposal(cortex.propose(record=True).to_dict())
        return
    report = cortex.evolve(approver=approver)
    _print_proposal(report.proposal.to_dict())
    if report.retraction is not None:
        console.print(
            f"[red]RETRACTED[/red] {report.retraction.reason} — back to "
            f"evidence-only tiering (no gate, no human: restoring the evidence "
            f"reading can only reveal, never hide)"
        )
    act = report.activation
    colour = "green" if act.activated else "yellow"
    console.print(
        f"\n[{colour}]{'ACTIVATED' if act.activated else 'WITHHELD'}[/{colour}] "
        f"v{act.version} {act.policy_id} — {act.reason}"
        + (f" (approver: {act.approver})" if act.approver else "")
    )
    console.print(
        f"lessons refreshed {report.lessons_refreshed} · "
        f"quarantined {report.lessons_quarantined}"
    )


def _print_proposal(proposal: dict) -> None:
    shadow = proposal["shadow"]
    policy = proposal["policy"]
    console.rule("[bold]Proposal[/bold]")
    console.print(f"policy       v{policy['version']} {policy['policy_id']}")
    console.print(f"directives   {len(policy['directives'])}")
    console.print(
        "shadow       "
        f"replayed {shadow['rows_replayed']} · labelled {shadow['labeled_rows']} · "
        f"[red]TP demoted {shadow['tp_demoted']}[/red] · "
        f"[green]FP demoted {shadow['fp_demoted']}[/green] · "
        f"FP boosted {shadow['fp_boosted']}"
    )
    if proposal["invariant_violations"]:
        console.print("[red]invariant violations:[/red]")
        for v in proposal["invariant_violations"]:
            console.print(f"  · {v}")
    if proposal["gate_failures"]:
        console.print("[yellow]gate failures:[/yellow]")
        for v in proposal["gate_failures"]:
            console.print(f"  · {v}")
    console.print(
        f"admissible   {proposal['admissible']} · "
        f"requires human {proposal['requires_human']} · "
        f"auto-activatable {proposal['auto_activatable']}"
    )


@cortex_app.command("rollback")
def cortex_rollback(
    policy_id: str = typer.Argument(..., help="Policy id to re-activate"),
    approver: str = typer.Option(..., "--approver", help="Your name"),
    root: Path = typer.Option(None, "--root", help="Cortex directory"),
) -> None:
    """Re-point the active policy at an earlier, immutable version."""
    result = _open_cortex(root).rollback(policy_id, approver=approver)
    colour = "green" if result.activated else "red"
    console.print(f"[{colour}]{result.reason}[/{colour}] — v{result.version} {result.policy_id}")
    if not result.activated:
        raise typer.Exit(code=1)


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
