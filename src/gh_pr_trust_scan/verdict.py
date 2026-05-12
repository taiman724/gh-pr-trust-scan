"""Verdict aggregation logic for gh-pr-trust-scan."""
from __future__ import annotations

from .models import Finding, ScanResult, Verdict


def compute_verdict(findings: list[Finding]) -> Verdict:
    """
    Aggregate findings into a verdict.

    Rules:
      - Any HIGH finding → AVOID
      - No HIGH + at least one MEDIUM → WARN
      - All LOW or no findings → SAFE
    """
    has_high = any(f.severity == "HIGH" for f in findings)
    has_medium = any(f.severity == "MEDIUM" for f in findings)

    if has_high:
        return "AVOID"
    if has_medium:
        return "WARN"
    return "SAFE"


def build_scan_result(
    repo: str,
    findings: list[Finding],
    stats,
) -> ScanResult:
    """Build a ScanResult from raw scanner output."""
    verdict = compute_verdict(findings)
    # Sort by severity (HIGH first, then MEDIUM, then LOW)
    order = {"HIGH": 0, "MEDIUM": 1, "LOW": 2}
    sorted_findings = sorted(findings, key=lambda f: order.get(f.severity, 99))
    return ScanResult(repo=repo, verdict=verdict, findings=sorted_findings, stats=stats)
