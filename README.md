# gh-pr-trust-scan

Evaluate whether a GitHub repository is likely to reject AI-assisted pull requests — before you fork it.

## Motivation

A growing number of open-source projects enforce explicit policies against AI-generated contributions. These range from automated "trust-gate" CI workflows (e.g. [fossier](https://github.com/PThorpe92/fossier)) to CONTRIBUTING.md clauses that label AI-assisted PRs as policy violations. Discovering these policies after you've already forked, implemented, and submitted a PR wastes everyone's time. `gh-pr-trust-scan` surfaces these signals upfront in a single CLI command — so you can make an informed decision before investing effort.

## How it differs from similar tools

Most PR-quality scanners focus on code review automation or detecting spam. `gh-pr-trust-scan` specifically targets the **contributor experience risk**: "Will this project reject my AI-assisted PR on ideological/policy grounds?" It does not evaluate code quality, licensing, or security vulnerabilities.

## Requirements

- Python 3.10+
- [GitHub CLI (`gh`)](https://cli.github.com/) authenticated (`gh auth login`)

## Installation

```bash
# With pipx (recommended — isolated environment)
pipx install gh-pr-trust-scan

# Or with pip
pip install gh-pr-trust-scan
```

During development (local clone):

```bash
pip install -e ".[dev]"
```

## Usage

```bash
# Basic scan
gh-pr-trust-scan owner/repo

# Full GitHub URL also works
gh-pr-trust-scan https://github.com/owner/repo

# JSON output for scripting / CI integration
gh-pr-trust-scan owner/repo --json

# Custom gh binary path
gh-pr-trust-scan owner/repo --gh-bin /usr/local/bin/gh
```

### Example output

```
Scanning tursodatabase/turso ...

Repo: tursodatabase/turso
Verdict: AVOID  (trust-gate detected)

Findings:
  [HIGH  ] Fossier auto-rejection workflow present (.github/workflows/pr-check.yml)
  [MEDIUM] 'human-written' requirement found (line 42): All submissions must be human-written (CONTRIBUTING.md)
  [LOW   ] No explicit AI ban label found

Stats:
  Last commit: 2 days ago
  Open PRs: 47
  Closed-no-merge PRs (last 30): 12
```

### JSON output

```bash
gh-pr-trust-scan owner/repo --json
```

```json
{
  "repo": "owner/repo",
  "verdict": "AVOID",
  "findings": [
    {
      "severity": "HIGH",
      "category": "trust_gate",
      "evidence": "Fossier action (PThorpe92/fossier) detected",
      "file": ".github/workflows/pr-check.yml"
    }
  ],
  "stats": {
    "last_commit": "2 days ago",
    "open_prs": 47,
    "closed_no_merge_last_30d": 12,
    "flagged_closed_prs": 0
  }
}
```

## Verdicts

| Verdict | Condition |
|---------|-----------|
| `AVOID` | At least one HIGH-severity finding (automated rejection gate present) |
| `WARN`  | No HIGH, but MEDIUM findings (discouraging policy language or labels) |
| `SAFE`  | All LOW or no findings (no explicit AI contribution policy detected) |

## What gets scanned

| Signal | Severity |
|--------|----------|
| `.github/workflows/*.yml` — fossier, trust-score, anti-slop, min-global-merge-ratio | HIGH |
| `CONTRIBUTING.md` / `README.md` / PR template / Code of Conduct — "no AI", "AI is not allowed", "AI tools are not permitted", "prohibit AI", "reject AI", "ban AI", "LLM not allowed", "Copilot is not allowed", "ChatGPT not allowed" | HIGH |
| Same files — "human-authored", "human-written", "disclose AI", "AI disclosure required" | MEDIUM |
| Repository labels — `no-ai`, `ai-rejected`, `human-only`, `ai-ban`, `ai-generated-rejected` | MEDIUM |
| Recent closed PRs with `spam-likely` / `suspicious-author` labels | MEDIUM |
| No AI ban labels found | LOW (informational) |

## Customizing patterns

All detection keywords are in `src/gh_pr_trust_scan/patterns.py`. To add your own:

```python
# patterns.py
WORKFLOW_PATTERNS.append({
    "pattern": r"my-custom-gate-action",
    "severity": "HIGH",
    "category": "trust_gate",
    "description": "Custom trust gate detected",
})
```

PRs adding new patterns for emerging tools are very welcome.

## Contributing

Contributions are welcome! The most impactful PRs are new detection patterns for trust-gate tools or AI-ban policy language that isn't yet covered. Please open an issue first to discuss significant changes.

```bash
# Set up dev environment
pip install -e ".[dev]"

# Run tests
pytest

# Run linter
ruff check src/ tests/
```

## Potential extensions

The following are out of scope for v0.1 but are good candidates for future PRs:

- GitHub token-based fallback (for unauthenticated use without `gh`)
- `--history` flag to check recent PR close reasons via GraphQL
- GitLab / Gitea support
- Config file for per-project allowlists

## License

MIT — see [LICENSE](LICENSE).

---

Built with AI assistance (Claude Sonnet 4.6 via Claude Code).
