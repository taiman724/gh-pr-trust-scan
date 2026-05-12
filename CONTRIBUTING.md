# Contributing to gh-pr-trust-scan

Thanks for your interest in contributing. This tool grows in value as
its pattern coverage grows, so contributions of new detection
patterns are especially welcome.

## Quick start

```bash
git clone https://github.com/taiman724/gh-pr-trust-scan
cd gh-pr-trust-scan
pip install -e ".[dev]"
pytest
```

## What we're looking for

- **New detection patterns** for trust-gate workflows or AI-ban
  policy language not currently covered. These are the highest-value
  contributions. Edit `src/gh_pr_trust_scan/patterns.py` and add an
  entry to the appropriate list. Include a fixture under
  `tests/fixtures/` and a test case.
- **Bug reports** for false positives or false negatives. Open an
  issue with the repository you scanned and the relevant section of
  its `CONTRIBUTING.md` or workflow file.
- **Documentation improvements** in the README and inline docstrings.
- **Platform support** — GitLab or Gitea scanners are out of scope
  for v0.1 but listed as candidates for v0.2; open an issue to
  discuss before implementing.

## What we will not accept

- Patterns targeting a specific maintainer or repository by name in a
  way that reads as a personal critique. The tool detects categories
  of policy signals; it does not maintain a public blocklist.
- Changes that fetch or store data beyond the GitHub CLI output for
  the scanned repository. No external telemetry, no metrics
  collection.
- PRs without tests for the added pattern, or with secrets in test
  fixtures.

## Pull request workflow

1. Fork and create a feature branch.
2. Add or update a pattern in `patterns.py`. If the pattern is for a
   policy phrase, include a fixture file under `tests/fixtures/` and
   a test that asserts the expected severity and category.
3. Run `pytest` locally. All tests must pass.
4. Run `ruff check src/ tests/`. Code must be lint-clean.
5. Open a PR against `master`. Include a brief example of a repo
   that would be detected (or a synthetic fixture if the example is
   sensitive).

## Disclosure of AI assistance

If your contribution was prepared with the help of an LLM-based
tool, please mention this in the PR description. The project itself
was prepared with AI assistance and we treat AI-assisted
contributions as first-class, provided they are reviewed and tested
by the contributor before submission.

## Code style

- Python 3.10+ syntax.
- `ruff` for linting (config in `pyproject.toml`).
- Type hints on all public functions.
- No new runtime dependencies without discussion in an issue first.

## License

By contributing, you agree that your contributions will be licensed
under the MIT License (see [`LICENSE`](LICENSE)).
