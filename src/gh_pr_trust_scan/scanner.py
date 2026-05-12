"""Scanner functions for gh-pr-trust-scan.

All data retrieval goes through `gh api` / `gh pr list` subprocesses so that
the caller's existing `gh auth` session is reused — no token management needed.
"""
from __future__ import annotations

import json
import re
import subprocess
from datetime import datetime, timezone
from typing import Any

from .models import Finding, RepoStats
from .patterns import (
    COMPILED_TEXT_HIGH,
    COMPILED_TEXT_MEDIUM,
    COMPILED_WORKFLOW,
    REJECT_LABELS,
    SPAM_LABELS,
)

# ── gh subprocess helper ──────────────────────────────────────────────────

def _run_gh(args: list[str], gh_bin: str = "gh") -> tuple[int, str]:
    """Run a gh CLI command; return (returncode, stdout)."""
    result = subprocess.run(
        [gh_bin, *args],
        capture_output=True,
        text=True,
    )
    return result.returncode, result.stdout


def _gh_api(path: str, gh_bin: str = "gh") -> Any | None:
    """Call `gh api <path>` and return parsed JSON, or None on error."""
    rc, out = _run_gh(["api", path], gh_bin=gh_bin)
    if rc != 0:
        return None
    try:
        return json.loads(out)
    except json.JSONDecodeError:
        return None


def _gh_api_paginated(path: str, gh_bin: str = "gh", per_page: int = 100) -> list[Any]:
    """Fetch all pages of a list endpoint via gh api."""
    separator = "&" if "?" in path else "?"
    full_path = f"{path}{separator}per_page={per_page}"
    data = _gh_api(full_path, gh_bin=gh_bin)
    if data is None:
        return []
    if isinstance(data, list):
        return data
    # GitHub sometimes wraps in {"items": [...]}
    if isinstance(data, dict):
        for key in ("items", "workflow_runs", "labels"):
            if key in data:
                return data[key]
    return []


def _get_file_content(owner_repo: str, path: str, gh_bin: str = "gh") -> str | None:
    """Retrieve raw file content from a repo via gh api."""
    rc, out = _run_gh(
        ["api", f"repos/{owner_repo}/contents/{path}", "--jq", ".content"],
        gh_bin=gh_bin,
    )
    if rc != 0 or not out.strip():
        return None
    import base64
    try:
        decoded = base64.b64decode(out.strip().replace("\\n", "\n")).decode("utf-8", errors="replace")
        return decoded
    except Exception:
        return None


# ── Individual scanners ──────────────────────────────────────────────────

def scan_workflows(owner_repo: str, gh_bin: str = "gh") -> list[Finding]:
    """Scan .github/workflows/*.yml for trust-gate keywords."""
    findings: list[Finding] = []

    data = _gh_api(f"repos/{owner_repo}/contents/.github/workflows", gh_bin=gh_bin)
    if not isinstance(data, list):
        return findings

    for item in data:
        if not isinstance(item, dict):
            continue
        name: str = item.get("name", "")
        if not (name.endswith(".yml") or name.endswith(".yaml")):
            continue

        file_path = item.get("path", f".github/workflows/{name}")
        content = _get_file_content(owner_repo, file_path, gh_bin=gh_bin)
        if content is None:
            continue

        for pattern, entry in COMPILED_WORKFLOW:
            if pattern.search(content):
                findings.append(Finding(
                    severity=entry["severity"],
                    category=entry["category"],
                    evidence=entry["description"],
                    file=file_path,
                ))
                break  # one finding per file per pattern group

    return findings


def scan_text_file(
    owner_repo: str,
    file_path: str,
    gh_bin: str = "gh",
) -> list[Finding]:
    """Scan a single text file (CONTRIBUTING, README, PR template, etc.)."""
    findings: list[Finding] = []

    content = _get_file_content(owner_repo, file_path, gh_bin=gh_bin)
    if content is None:
        return findings

    lines = content.splitlines()

    def _check_patterns(
        compiled_list: list[tuple[re.Pattern, dict]],
    ) -> list[Finding]:
        results = []
        seen_categories: set[str] = set()
        for pattern, entry in compiled_list:
            if entry["category"] in seen_categories:
                continue
            for lineno, line in enumerate(lines, start=1):
                if pattern.search(line):
                    results.append(Finding(
                        severity=entry["severity"],
                        category=entry["category"],
                        evidence=f"{entry['description']} (line {lineno}): {line.strip()[:120]}",
                        file=file_path,
                    ))
                    seen_categories.add(entry["category"])
                    break
        return results

    findings.extend(_check_patterns(COMPILED_TEXT_HIGH))
    findings.extend(_check_patterns(COMPILED_TEXT_MEDIUM))
    return findings


def scan_contributing(owner_repo: str, gh_bin: str = "gh") -> list[Finding]:
    """Scan CONTRIBUTING.md / CONTRIBUTING.rst / docs/contributing.md."""
    findings: list[Finding] = []
    candidates = [
        "CONTRIBUTING.md",
        "CONTRIBUTING.rst",
        "docs/contributing.md",
        "docs/CONTRIBUTING.md",
    ]
    for path in candidates:
        findings.extend(scan_text_file(owner_repo, path, gh_bin=gh_bin))
    return findings


def scan_readme(owner_repo: str, gh_bin: str = "gh") -> list[Finding]:
    """Scan README.md / README.rst."""
    findings: list[Finding] = []
    for path in ["README.md", "README.rst"]:
        findings.extend(scan_text_file(owner_repo, path, gh_bin=gh_bin))
    return findings


def scan_pr_template(owner_repo: str, gh_bin: str = "gh") -> list[Finding]:
    """Scan .github/PULL_REQUEST_TEMPLATE.md."""
    return scan_text_file(
        owner_repo,
        ".github/PULL_REQUEST_TEMPLATE.md",
        gh_bin=gh_bin,
    )


def scan_code_of_conduct(owner_repo: str, gh_bin: str = "gh") -> list[Finding]:
    """Scan .github/CODE_OF_CONDUCT.md."""
    return scan_text_file(
        owner_repo,
        ".github/CODE_OF_CONDUCT.md",
        gh_bin=gh_bin,
    )


def scan_labels(owner_repo: str, gh_bin: str = "gh") -> list[Finding]:
    """Check repo labels for AI-rejection labels."""
    findings: list[Finding] = []

    labels = _gh_api_paginated(f"repos/{owner_repo}/labels", gh_bin=gh_bin)

    found_labels = []
    for label in labels:
        if not isinstance(label, dict):
            continue
        label_name: str = label.get("name", "").lower()
        for reject in REJECT_LABELS:
            if reject in label_name:
                found_labels.append(label.get("name", label_name))
                break

    if found_labels:
        findings.append(Finding(
            severity="MEDIUM",
            category="reject_label",
            evidence=f"AI-rejection labels found: {', '.join(found_labels)}",
            file=None,
        ))
    else:
        findings.append(Finding(
            severity="LOW",
            category="reject_label",
            evidence="No explicit AI ban label found",
            file=None,
        ))

    return findings


def scan_closed_prs(owner_repo: str, gh_bin: str = "gh") -> tuple[list[Finding], int, int]:
    """
    Scan recent closed PRs for spam labels.

    Returns:
        (findings, closed_no_merge_count, flagged_count)
    """
    findings: list[Finding] = []

    rc, out = _run_gh(
        [
            "pr", "list",
            "--repo", owner_repo,
            "--state", "closed",
            "--limit", "30",
            "--json", "number,title,labels,mergedAt",
        ],
        gh_bin=gh_bin,
    )

    if rc != 0 or not out.strip():
        return findings, 0, 0

    try:
        prs = json.loads(out)
    except json.JSONDecodeError:
        return findings, 0, 0

    closed_no_merge = sum(1 for pr in prs if not pr.get("mergedAt"))
    flagged = 0

    for pr in prs:
        pr_labels = [lbl.get("name", "").lower() for lbl in pr.get("labels", [])]
        for spam_label in SPAM_LABELS:
            if any(spam_label in pl for pl in pr_labels):
                flagged += 1
                break

    if flagged > 0:
        findings.append(Finding(
            severity="MEDIUM",
            category="spam_closed_prs",
            evidence=f"{flagged} closed PR(s) with spam/suspicious labels in last 30 entries",
            file=None,
        ))

    return findings, closed_no_merge, flagged


def gather_repo_stats(owner_repo: str, gh_bin: str = "gh") -> RepoStats:
    """Collect basic repo statistics."""
    stats = RepoStats()

    # Last commit date
    commits = _gh_api(f"repos/{owner_repo}/commits?per_page=1", gh_bin=gh_bin)
    if isinstance(commits, list) and commits:
        commit_date_str = (
            commits[0]
            .get("commit", {})
            .get("committer", {})
            .get("date", "")
        )
        if commit_date_str:
            try:
                commit_dt = datetime.fromisoformat(commit_date_str.replace("Z", "+00:00"))
                now = datetime.now(tz=timezone.utc)
                delta = now - commit_dt
                days = delta.days
                if days == 0:
                    stats.last_commit = "today"
                elif days == 1:
                    stats.last_commit = "1 day ago"
                else:
                    stats.last_commit = f"{days} days ago"
            except ValueError:
                stats.last_commit = commit_date_str

    # Open PR count
    rc, out = _run_gh(
        ["pr", "list", "--repo", owner_repo, "--state", "open", "--limit", "1", "--json", "number"],
        gh_bin=gh_bin,
    )
    if rc == 0 and out.strip():
        try:
            # gh returns array; for count we query the API
            repo_data = _gh_api(f"repos/{owner_repo}", gh_bin=gh_bin)
            if isinstance(repo_data, dict):
                stats.open_prs = repo_data.get("open_issues_count", 0)
        except Exception:
            pass

    return stats


def run_all_scanners(
    owner_repo: str,
    gh_bin: str = "gh",
) -> tuple[list[Finding], RepoStats]:
    """Run all scanners and return (findings, stats)."""
    findings: list[Finding] = []

    findings.extend(scan_workflows(owner_repo, gh_bin=gh_bin))
    findings.extend(scan_contributing(owner_repo, gh_bin=gh_bin))
    findings.extend(scan_readme(owner_repo, gh_bin=gh_bin))
    findings.extend(scan_pr_template(owner_repo, gh_bin=gh_bin))
    findings.extend(scan_code_of_conduct(owner_repo, gh_bin=gh_bin))
    findings.extend(scan_labels(owner_repo, gh_bin=gh_bin))

    pr_findings, closed_no_merge, flagged = scan_closed_prs(owner_repo, gh_bin=gh_bin)
    findings.extend(pr_findings)

    stats = gather_repo_stats(owner_repo, gh_bin=gh_bin)
    stats.closed_no_merge_last_30d = closed_no_merge
    stats.flagged_closed_prs = flagged

    return findings, stats
