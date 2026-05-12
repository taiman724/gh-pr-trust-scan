"""Data models for gh-pr-trust-scan."""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Literal

Severity = Literal["HIGH", "MEDIUM", "LOW"]
Verdict = Literal["SAFE", "WARN", "AVOID"]


@dataclass
class Finding:
    severity: Severity
    category: str
    evidence: str
    file: str | None = None

    def to_dict(self) -> dict:
        return {
            "severity": self.severity,
            "category": self.category,
            "evidence": self.evidence,
            "file": self.file,
        }


@dataclass
class RepoStats:
    last_commit: str = "unknown"
    open_prs: int = 0
    closed_no_merge_last_30d: int = 0
    flagged_closed_prs: int = 0

    def to_dict(self) -> dict:
        return {
            "last_commit": self.last_commit,
            "open_prs": self.open_prs,
            "closed_no_merge_last_30d": self.closed_no_merge_last_30d,
            "flagged_closed_prs": self.flagged_closed_prs,
        }


@dataclass
class ScanResult:
    repo: str
    verdict: Verdict
    findings: list[Finding] = field(default_factory=list)
    stats: RepoStats = field(default_factory=RepoStats)

    def to_dict(self) -> dict:
        return {
            "repo": self.repo,
            "verdict": self.verdict,
            "findings": [f.to_dict() for f in self.findings],
            "stats": self.stats.to_dict(),
        }
