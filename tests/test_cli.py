"""CLI tests using typer's CliRunner."""
from __future__ import annotations

import json
from unittest.mock import patch

from typer.testing import CliRunner

from gh_pr_trust_scan.__main__ import app
from gh_pr_trust_scan.models import Finding, RepoStats, ScanResult

runner = CliRunner()


def _make_scan_result(verdict: str, findings: list[Finding] | None = None) -> ScanResult:
    if findings is None:
        findings = []
    stats = RepoStats(last_commit="2 days ago", open_prs=10, closed_no_merge_last_30d=3)
    return ScanResult(repo="owner/repo", verdict=verdict, findings=findings, stats=stats)


class TestParseRepo:
    def test_owner_slash_repo(self):
        with patch("gh_pr_trust_scan.__main__.run_all_scanners") as mock_scan:
            mock_scan.return_value = ([], RepoStats())
            runner.invoke(app, ["owner/repo"])
        mock_scan.assert_called_once_with("owner/repo", gh_bin="gh")

    def test_full_github_url(self):
        with patch("gh_pr_trust_scan.__main__.run_all_scanners") as mock_scan:
            mock_scan.return_value = ([], RepoStats())
            runner.invoke(app, ["https://github.com/owner/repo"])
        mock_scan.assert_called_once_with("owner/repo", gh_bin="gh")

    def test_url_with_trailing_slash(self):
        with patch("gh_pr_trust_scan.__main__.run_all_scanners") as mock_scan:
            mock_scan.return_value = ([], RepoStats())
            runner.invoke(app, ["https://github.com/owner/repo/"])
        mock_scan.assert_called_once_with("owner/repo", gh_bin="gh")

    def test_invalid_input_exits_with_error(self):
        result = runner.invoke(app, ["not-a-valid-repo-format"])
        assert result.exit_code != 0


class TestHumanOutput:
    def test_safe_verdict_shown(self):
        with patch("gh_pr_trust_scan.__main__.run_all_scanners") as mock_scan:
            mock_scan.return_value = ([], RepoStats(last_commit="today", open_prs=5))
            result = runner.invoke(app, ["owner/repo"])
        assert result.exit_code == 0
        assert "SAFE" in result.output
        assert "owner/repo" in result.output

    def test_avoid_verdict_shown(self):
        findings = [
            Finding(severity="HIGH", category="trust_gate", evidence="Fossier detected", file=".github/workflows/check.yml")
        ]
        with patch("gh_pr_trust_scan.__main__.run_all_scanners") as mock_scan:
            mock_scan.return_value = (findings, RepoStats())
            result = runner.invoke(app, ["owner/repo"])
        assert result.exit_code == 0
        assert "AVOID" in result.output
        assert "Fossier detected" in result.output

    def test_warn_verdict_shown(self):
        findings = [
            Finding(severity="MEDIUM", category="human_only_requirement", evidence="human-written", file="CONTRIBUTING.md")
        ]
        with patch("gh_pr_trust_scan.__main__.run_all_scanners") as mock_scan:
            mock_scan.return_value = (findings, RepoStats())
            result = runner.invoke(app, ["owner/repo"])
        assert result.exit_code == 0
        assert "WARN" in result.output

    def test_stats_shown(self):
        with patch("gh_pr_trust_scan.__main__.run_all_scanners") as mock_scan:
            mock_scan.return_value = ([], RepoStats(last_commit="3 days ago", open_prs=42))
            result = runner.invoke(app, ["owner/repo"])
        assert "3 days ago" in result.output
        assert "42" in result.output


class TestJsonOutput:
    def test_json_flag_produces_valid_json(self):
        findings = [
            Finding(severity="HIGH", category="trust_gate", evidence="Fossier detected", file=".github/workflows/foo.yml")
        ]
        with patch("gh_pr_trust_scan.__main__.run_all_scanners") as mock_scan:
            mock_scan.return_value = (findings, RepoStats())
            result = runner.invoke(app, ["owner/repo", "--json"])
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert data["repo"] == "owner/repo"
        assert data["verdict"] == "AVOID"
        assert len(data["findings"]) == 1
        assert data["findings"][0]["severity"] == "HIGH"

    def test_json_safe_verdict(self):
        with patch("gh_pr_trust_scan.__main__.run_all_scanners") as mock_scan:
            mock_scan.return_value = ([], RepoStats())
            result = runner.invoke(app, ["owner/repo", "--json"])
        data = json.loads(result.output)
        assert data["verdict"] == "SAFE"
        assert data["findings"] == []

    def test_json_warn_verdict(self):
        findings = [
            Finding(severity="MEDIUM", category="reject_label", evidence="no-ai label found", file=None)
        ]
        with patch("gh_pr_trust_scan.__main__.run_all_scanners") as mock_scan:
            mock_scan.return_value = (findings, RepoStats())
            result = runner.invoke(app, ["owner/repo", "--json"])
        data = json.loads(result.output)
        assert data["verdict"] == "WARN"

    def test_json_stats_included(self):
        stats = RepoStats(last_commit="1 day ago", open_prs=15, closed_no_merge_last_30d=7)
        with patch("gh_pr_trust_scan.__main__.run_all_scanners") as mock_scan:
            mock_scan.return_value = ([], stats)
            result = runner.invoke(app, ["owner/repo", "--json"])
        data = json.loads(result.output)
        assert data["stats"]["last_commit"] == "1 day ago"
        assert data["stats"]["open_prs"] == 15
        assert data["stats"]["closed_no_merge_last_30d"] == 7

    def test_json_no_scanning_message(self):
        """--json mode should not print 'Scanning ...' text."""
        with patch("gh_pr_trust_scan.__main__.run_all_scanners") as mock_scan:
            mock_scan.return_value = ([], RepoStats())
            result = runner.invoke(app, ["owner/repo", "--json"])
        assert "Scanning" not in result.output


class TestGhBinOption:
    def test_custom_gh_bin_passed_through(self):
        with patch("gh_pr_trust_scan.__main__.run_all_scanners") as mock_scan:
            mock_scan.return_value = ([], RepoStats())
            runner.invoke(app, ["owner/repo", "--gh-bin", "/usr/local/bin/gh"])
        mock_scan.assert_called_once_with("owner/repo", gh_bin="/usr/local/bin/gh")
