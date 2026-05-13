"""Detection keyword patterns for gh-pr-trust-scan.

Edit this file to add or remove patterns without touching scanner logic.
Each entry is a dict with keys:
  - pattern: regex string (case-insensitive by default)
  - severity: HIGH | MEDIUM | LOW
  - category: short category label
  - description: human-readable description
"""
from __future__ import annotations

import re
from typing import TypedDict


class PatternEntry(TypedDict):
    pattern: str
    severity: str
    category: str
    description: str


# ── Workflow patterns (HIGH severity) ───────────────────────────────────────
WORKFLOW_PATTERNS: list[PatternEntry] = [
    {
        "pattern": r"fossier",
        "severity": "HIGH",
        "category": "trust_gate",
        "description": "Fossier AI-rejection workflow detected",
    },
    {
        "pattern": r"PThorpe92/fossier",
        "severity": "HIGH",
        "category": "trust_gate",
        "description": "Fossier action (PThorpe92/fossier) detected",
    },
    {
        "pattern": r"trust-score",
        "severity": "HIGH",
        "category": "trust_gate",
        "description": "Trust-score gate detected in workflow",
    },
    {
        "pattern": r"peakoss/anti-slop",
        "severity": "HIGH",
        "category": "trust_gate",
        "description": "anti-slop action detected in workflow",
    },
    {
        "pattern": r"min-global-merge-ratio",
        "severity": "HIGH",
        "category": "trust_gate",
        "description": "min-global-merge-ratio gate detected",
    },
]

# ── Text-file patterns (MEDIUM severity) ────────────────────────────────────
TEXT_PATTERNS_HIGH: list[PatternEntry] = [
    {
        "pattern": r"\bno[\s\-]?AI\b",
        "severity": "HIGH",
        "category": "ai_ban_explicit",
        "description": "'no AI' prohibition found",
    },
    {
        "pattern": r"\bAI\s+is\s+not\s+allowed\b",
        "severity": "HIGH",
        "category": "ai_ban_explicit",
        "description": "'AI is not allowed' found",
    },
    {
        "pattern": r"\bAI\s+tools?\s+are\s+not\s+permitted\b",
        "severity": "HIGH",
        "category": "ai_ban_explicit",
        "description": "'AI tools are not permitted' found",
    },
    {
        "pattern": r"\bCopilot\s+is\s+not\s+allowed\b",
        "severity": "HIGH",
        "category": "ai_ban_explicit",
        "description": "'Copilot is not allowed' found",
    },
    {
        "pattern": r"\bChatGPT\s+not\s+allowed\b",
        "severity": "HIGH",
        "category": "ai_ban_explicit",
        "description": "'ChatGPT not allowed' found",
    },
    {
        "pattern": r"\bLLM\s+not\s+allowed\b",
        "severity": "HIGH",
        "category": "ai_ban_explicit",
        "description": "'LLM not allowed' found",
    },
    {
        "pattern": r"\bban\s+AI\b",
        "severity": "HIGH",
        "category": "ai_ban_explicit",
        "description": "'ban AI' found",
    },
    {
        "pattern": r"\bprohibit\s+AI\b",
        "severity": "HIGH",
        "category": "ai_ban_explicit",
        "description": "'prohibit AI' found",
    },
    {
        "pattern": r"\breject\s+AI\b",
        "severity": "HIGH",
        "category": "ai_ban_explicit",
        "description": "'reject AI' found",
    },
    {
        "pattern": r"\bNo\s+AI\s+attribution\b",
        "severity": "HIGH",
        "category": "ai_attribution_banned",
        "description": "'No AI attribution' policy found",
    },
    {
        "pattern": r"\b(?:do\s+not|don't)\s+(?:add|use|include)\s+[^.\n]*?Co[\s\-]Authored[\s\-]By\b",
        "severity": "HIGH",
        "category": "ai_attribution_banned",
        "description": "Co-Authored-By trailer ban found",
    },
]

TEXT_PATTERNS_MEDIUM: list[PatternEntry] = [
    {
        "pattern": r"\bhuman[\s\-]authored\b",
        "severity": "MEDIUM",
        "category": "human_only_requirement",
        "description": "'human-authored' requirement found",
    },
    {
        "pattern": r"\bhuman[\s\-]written\b",
        "severity": "MEDIUM",
        "category": "human_only_requirement",
        "description": "'human-written' requirement found",
    },
    {
        "pattern": r"\bdisclose\s+AI\b",
        "severity": "MEDIUM",
        "category": "ai_disclosure_required",
        "description": "AI disclosure requirement found",
    },
    {
        "pattern": r"\bAI\s+disclosure\s+required\b",
        "severity": "MEDIUM",
        "category": "ai_disclosure_required",
        "description": "AI disclosure required found",
    },
]

# ── Label patterns (MEDIUM severity) ────────────────────────────────────────
REJECT_LABELS: list[str] = [
    "no-ai",
    "ai-rejected",
    "human-only",
    "ai-ban",
    "ai-generated-rejected",
]

# ── Closed PR spam labels (for stats) ───────────────────────────────────────
SPAM_LABELS: list[str] = [
    "spam-likely",
    "suspicious-author",
]

# ── Pre-compiled patterns ─────────────────────────────────────────────────
def _compile(entries: list[PatternEntry]) -> list[tuple[re.Pattern, PatternEntry]]:
    return [(re.compile(e["pattern"], re.IGNORECASE), e) for e in entries]


COMPILED_WORKFLOW = _compile(WORKFLOW_PATTERNS)
COMPILED_TEXT_HIGH = _compile(TEXT_PATTERNS_HIGH)
COMPILED_TEXT_MEDIUM = _compile(TEXT_PATTERNS_MEDIUM)
