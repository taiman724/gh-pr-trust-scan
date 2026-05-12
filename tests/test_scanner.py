"""Unit tests for scanner functions using mock gh CLI data."""
from __future__ import annotations

import base64
import json
from pathlib import Path
from unittest.mock import MagicMock, patch

from gh_pr_trust_scan.scanner import (
    _get_file_content,
    scan_closed_prs,
    scan_labels,
    scan_text_file,
    scan_workflows,
)

FIXTURES = Path(__file__).parent / "fixtures"


def _encode(content: str) -> str:
    """Encode content as base64 string like GitHub API returns."""
    return base64.b64encode(content.encode()).decode()


def _make_run_result(returncode: int, stdout: str):
    result = MagicMock()
    result.returncode = returncode
    result.stdout = stdout
    return result


class TestGetFileContent:
    def test_returns_decoded_content(self):
        raw = "Hello world"
        encoded = base64.b64encode(raw.encode()).decode()
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = _make_run_result(0, encoded + "\n")
            content = _get_file_content("owner/repo", "README.md")
        assert content == "Hello world"

    def test_returns_none_on_nonzero_exit(self):
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = _make_run_result(1, "")
            content = _get_file_content("owner/repo", "MISSING.md")
        assert content is None

    def test_returns_none_on_empty_output(self):
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = _make_run_result(0, "")
            content = _get_file_content("owner/repo", "MISSING.md")
        assert content is None


class TestScanWorkflows:
    def _make_workflow_api_response(self, name: str, content: str) -> tuple:
        """Return (api_listing, encoded_content) for a workflow file."""
        listing = json.dumps([
            {"name": name, "path": f".github/workflows/{name}"}
        ])
        encoded = _encode(content)
        return listing, encoded

    def test_detects_fossier(self):
        fossier_content = (FIXTURES / "avoid_fossier" / ".github" / "workflows" / "pr-check.yml").read_text()
        listing = json.dumps([{"name": "pr-check.yml", "path": ".github/workflows/pr-check.yml"}])

        with patch("subprocess.run") as mock_run:
            def side_effect(args, **kwargs):
                cmd_str = " ".join(args)
                if "contents/.github/workflows\"" in cmd_str or (
                    "contents/.github/workflows" in cmd_str and "--jq" not in cmd_str
                ):
                    return _make_run_result(0, listing)
                # file content fetch
                return _make_run_result(0, _encode(fossier_content))

            mock_run.side_effect = side_effect
            findings = scan_workflows("owner/repo")

        assert any(f.severity == "HIGH" for f in findings)
        assert any("fossier" in f.evidence.lower() or "fossier" in f.category.lower()
                   for f in findings)

    def test_clean_workflow_no_findings(self):
        safe_content = (FIXTURES / "safe_repo" / ".github" / "workflows" / "build.yml").read_text()
        listing = json.dumps([{"name": "build.yml", "path": ".github/workflows/build.yml"}])

        with patch("subprocess.run") as mock_run:
            def side_effect(args, **kwargs):
                cmd_str = " ".join(args)
                if "--jq" not in cmd_str and "contents/.github/workflows" in cmd_str:
                    return _make_run_result(0, listing)
                return _make_run_result(0, _encode(safe_content))

            mock_run.side_effect = side_effect
            findings = scan_workflows("owner/repo")

        high_findings = [f for f in findings if f.severity == "HIGH"]
        assert len(high_findings) == 0

    def test_no_workflows_directory(self):
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = _make_run_result(1, "")
            findings = scan_workflows("owner/repo")
        assert findings == []


class TestScanTextFile:
    def test_detects_ai_ban_high(self):
        content = (FIXTURES / "ai_banned_contributing" / "CONTRIBUTING.md").read_text()

        with patch("subprocess.run") as mock_run:
            mock_run.return_value = _make_run_result(0, _encode(content))
            findings = scan_text_file("owner/repo", "CONTRIBUTING.md")

        high_findings = [f for f in findings if f.severity == "HIGH"]
        assert len(high_findings) > 0

    def test_clean_contributing_no_high(self):
        content = (FIXTURES / "safe_repo" / "CONTRIBUTING.md").read_text()

        with patch("subprocess.run") as mock_run:
            mock_run.return_value = _make_run_result(0, _encode(content))
            findings = scan_text_file("owner/repo", "CONTRIBUTING.md")

        high_findings = [f for f in findings if f.severity == "HIGH"]
        assert len(high_findings) == 0

    def test_missing_file_returns_empty(self):
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = _make_run_result(1, "")
            findings = scan_text_file("owner/repo", "MISSING.md")
        assert findings == []

    def test_detects_human_written_medium(self):
        content = "All submissions must be human-written and original."

        with patch("subprocess.run") as mock_run:
            mock_run.return_value = _make_run_result(0, _encode(content))
            findings = scan_text_file("owner/repo", "CONTRIBUTING.md")

        medium_findings = [f for f in findings if f.severity == "MEDIUM"]
        assert any("human" in f.evidence.lower() for f in medium_findings)

    def test_detects_no_ai_high(self):
        content = "We do not accept contributions made with no AI tools."

        with patch("subprocess.run") as mock_run:
            mock_run.return_value = _make_run_result(0, _encode(content))
            findings = scan_text_file("owner/repo", "CONTRIBUTING.md")

        high_findings = [f for f in findings if f.severity == "HIGH"]
        assert len(high_findings) > 0


class TestScanLabels:
    def test_detects_no_ai_label(self):
        labels = json.dumps([
            {"name": "bug", "color": "d73a4a"},
            {"name": "no-ai", "color": "ff0000"},
            {"name": "enhancement", "color": "a2eeef"},
        ])

        with patch("subprocess.run") as mock_run:
            mock_run.return_value = _make_run_result(0, labels)
            findings = scan_labels("owner/repo")

        medium_findings = [f for f in findings if f.severity == "MEDIUM"]
        assert len(medium_findings) > 0
        assert any("no-ai" in f.evidence for f in medium_findings)

    def test_no_reject_labels_returns_low(self):
        labels = json.dumps([
            {"name": "bug"},
            {"name": "feature"},
        ])

        with patch("subprocess.run") as mock_run:
            mock_run.return_value = _make_run_result(0, labels)
            findings = scan_labels("owner/repo")

        low_findings = [f for f in findings if f.severity == "LOW"]
        assert len(low_findings) > 0

    def test_ai_rejected_label_detected(self):
        labels = json.dumps([{"name": "ai-generated-rejected"}])

        with patch("subprocess.run") as mock_run:
            mock_run.return_value = _make_run_result(0, labels)
            findings = scan_labels("owner/repo")

        medium_findings = [f for f in findings if f.severity == "MEDIUM"]
        assert len(medium_findings) > 0


class TestScanClosedPRs:
    def test_detects_spam_labels(self):
        prs = json.dumps([
            {"number": 1, "title": "Fix bug", "labels": [{"name": "spam-likely"}], "mergedAt": None},
            {"number": 2, "title": "Add feature", "labels": [], "mergedAt": "2026-05-01T00:00:00Z"},
        ])

        with patch("subprocess.run") as mock_run:
            mock_run.return_value = _make_run_result(0, prs)
            findings, closed_no_merge, flagged = scan_closed_prs("owner/repo")

        assert flagged == 1
        assert closed_no_merge == 1
        assert any(f.severity == "MEDIUM" for f in findings)

    def test_no_spam_labels_no_findings(self):
        prs = json.dumps([
            {"number": 1, "title": "Merged PR", "labels": [{"name": "bug"}], "mergedAt": "2026-05-01T00:00:00Z"},
        ])

        with patch("subprocess.run") as mock_run:
            mock_run.return_value = _make_run_result(0, prs)
            findings, closed_no_merge, flagged = scan_closed_prs("owner/repo")

        assert flagged == 0
        assert findings == []

    def test_gh_failure_returns_empty(self):
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = _make_run_result(1, "")
            findings, closed_no_merge, flagged = scan_closed_prs("owner/repo")

        assert findings == []
        assert closed_no_merge == 0
        assert flagged == 0
