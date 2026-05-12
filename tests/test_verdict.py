"""Unit tests for verdict aggregation logic."""
from __future__ import annotations

from gh_pr_trust_scan.models import Finding, RepoStats
from gh_pr_trust_scan.verdict import build_scan_result, compute_verdict


def make_finding(severity: str, category: str = "test") -> Finding:
    return Finding(severity=severity, category=category, evidence="test evidence", file=None)


class TestComputeVerdict:
    def test_no_findings_is_safe(self):
        assert compute_verdict([]) == "SAFE"

    def test_only_low_is_safe(self):
        findings = [make_finding("LOW"), make_finding("LOW")]
        assert compute_verdict(findings) == "SAFE"

    def test_medium_without_high_is_warn(self):
        findings = [make_finding("MEDIUM")]
        assert compute_verdict(findings) == "WARN"

    def test_medium_and_low_is_warn(self):
        findings = [make_finding("MEDIUM"), make_finding("LOW")]
        assert compute_verdict(findings) == "WARN"

    def test_single_high_is_avoid(self):
        findings = [make_finding("HIGH")]
        assert compute_verdict(findings) == "AVOID"

    def test_high_overrides_medium(self):
        findings = [make_finding("HIGH"), make_finding("MEDIUM"), make_finding("LOW")]
        assert compute_verdict(findings) == "AVOID"

    def test_only_high_no_others(self):
        findings = [make_finding("HIGH", "trust_gate")]
        assert compute_verdict(findings) == "AVOID"


class TestBuildScanResult:
    def test_sorting_high_first(self):
        findings = [
            make_finding("LOW"),
            make_finding("HIGH"),
            make_finding("MEDIUM"),
        ]
        stats = RepoStats()
        result = build_scan_result("owner/repo", findings, stats)
        severities = [f.severity for f in result.findings]
        assert severities == ["HIGH", "MEDIUM", "LOW"]

    def test_repo_name_preserved(self):
        result = build_scan_result("owner/repo", [], RepoStats())
        assert result.repo == "owner/repo"

    def test_verdict_reflects_findings(self):
        findings = [make_finding("MEDIUM")]
        result = build_scan_result("owner/repo", findings, RepoStats())
        assert result.verdict == "WARN"

    def test_to_dict_structure(self):
        findings = [make_finding("HIGH", "trust_gate")]
        stats = RepoStats(last_commit="2 days ago", open_prs=5)
        result = build_scan_result("owner/repo", findings, stats)
        d = result.to_dict()
        assert d["repo"] == "owner/repo"
        assert d["verdict"] == "AVOID"
        assert len(d["findings"]) == 1
        assert d["findings"][0]["severity"] == "HIGH"
        assert d["stats"]["last_commit"] == "2 days ago"
        assert d["stats"]["open_prs"] == 5
