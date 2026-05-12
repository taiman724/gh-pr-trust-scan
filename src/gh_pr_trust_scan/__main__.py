"""CLI entry point for gh-pr-trust-scan."""
from __future__ import annotations

import json
import re

import typer

from .scanner import run_all_scanners
from .verdict import build_scan_result

app = typer.Typer(
    name="gh-pr-trust-scan",
    help="Evaluate AI-generated PR rejection risk for a GitHub repository.",
    add_completion=False,
)

VERDICT_COLOR = {
    "AVOID": typer.colors.RED,
    "WARN": typer.colors.YELLOW,
    "SAFE": typer.colors.GREEN,
}

SEVERITY_COLOR = {
    "HIGH": typer.colors.RED,
    "MEDIUM": typer.colors.YELLOW,
    "LOW": typer.colors.BRIGHT_BLACK,
}


def _parse_repo(repo_input: str) -> str:
    """Accept 'owner/repo' or full GitHub URL, return 'owner/repo'."""
    repo_input = repo_input.strip().rstrip("/")
    # Match full URL: https://github.com/owner/repo
    url_match = re.match(
        r"https?://(?:www\.)?github\.com/([^/]+/[^/]+?)(?:\.git)?$",
        repo_input,
        re.IGNORECASE,
    )
    if url_match:
        return url_match.group(1)
    # Expect 'owner/repo'
    if re.match(r"^[^/]+/[^/]+$", repo_input):
        return repo_input
    typer.echo(
        f"Error: cannot parse repo '{repo_input}'. "
        "Use 'owner/repo' or 'https://github.com/owner/repo'.",
        err=True,
    )
    raise typer.Exit(code=1)


@app.command()
def scan(
    repo: str = typer.Argument(..., help="'owner/repo' or full GitHub URL"),
    output_json: bool = typer.Option(
        False, "--json", help="Output results as JSON"
    ),
    gh_bin: str = typer.Option(
        "gh", "--gh-bin", help="Path to the gh CLI binary", envvar="GH_BIN"
    ),
) -> None:
    """Scan a GitHub repository for AI-PR rejection risk."""
    owner_repo = _parse_repo(repo)

    if not output_json:
        typer.echo(f"Scanning {owner_repo} ...")

    try:
        findings, stats = run_all_scanners(owner_repo, gh_bin=gh_bin)
    except Exception as exc:
        typer.echo(f"Error during scan: {exc}", err=True)
        raise typer.Exit(code=2)

    result = build_scan_result(owner_repo, findings, stats)

    if output_json:
        typer.echo(json.dumps(result.to_dict(), indent=2))
        return

    # ── Human-readable output ──────────────────────────────────────────────
    typer.echo(f"\nRepo: {result.repo}")
    verdict_styled = typer.style(
        result.verdict, fg=VERDICT_COLOR.get(result.verdict, typer.colors.WHITE), bold=True
    )
    typer.echo(f"Verdict: {verdict_styled}")

    if result.findings:
        typer.echo("\nFindings:")
        for finding in result.findings:
            sev_styled = typer.style(
                f"[{finding.severity:<6}]",
                fg=SEVERITY_COLOR.get(finding.severity, typer.colors.WHITE),
                bold=finding.severity == "HIGH",
            )
            loc = f" ({finding.file})" if finding.file else ""
            typer.echo(f"  {sev_styled} {finding.evidence}{loc}")

    typer.echo("\nStats:")
    typer.echo(f"  Last commit: {result.stats.last_commit}")
    typer.echo(f"  Open PRs: {result.stats.open_prs}")
    typer.echo(f"  Closed-no-merge PRs (last 30): {result.stats.closed_no_merge_last_30d}")
    if result.stats.flagged_closed_prs:
        typer.echo(f"  Flagged closed PRs: {result.stats.flagged_closed_prs}")


def main() -> None:
    app()


if __name__ == "__main__":
    main()
