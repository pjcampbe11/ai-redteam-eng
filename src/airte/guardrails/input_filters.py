"""Input-side guardrails: prompt-injection heuristics + normalization.

These are *defense in depth*, not a silver bullet. Heuristic detection reduces
the attack surface; it does not replace architectural controls (privilege
separation, output handling, human-in-the-loop). See docs/secure-by-default.md.
"""
from __future__ import annotations

import re
import unicodedata
from dataclasses import dataclass

# Patterns that frequently indicate instruction-override / injection attempts.
_INJECTION_PATTERNS = [
    (r"ignore\s+(all\s+)?(previous|prior|above)\s+instructions", 0.9, "instruction override"),
    (r"disregard\s+(the\s+)?(system|previous)\b", 0.8, "instruction override"),
    (r"reveal|print|repeat.*(system\s+prompt|instructions|words\s+above)", 0.85, "prompt extraction"),
    (r"you\s+are\s+now\s+(dan|developer mode|unrestricted)", 0.9, "persona jailbreak"),
    (r"new\s+instructions?\s*:", 0.6, "instruction injection"),
    (r"(api[_-]?key|secret|password|token)\s*[:=]", 0.5, "secret solicitation"),
    (r"base64|rot13|decode\s+and\s+(run|follow)", 0.4, "obfuscation"),
]


@dataclass
class InjectionHeuristic:
    score: float
    matched: list[str]

    @property
    def is_suspicious(self) -> bool:
        return self.score >= 0.6


def normalize(text: str) -> str:
    """Defang common obfuscation: NFKC fold (homoglyphs/fullwidth), strip zero-width."""
    text = unicodedata.normalize("NFKC", text)
    text = re.sub(r"[​-‏‪-‮﻿]", "", text)  # zero-width / bidi
    return text


def scan_input(text: str) -> InjectionHeuristic:
    """Return a heuristic injection score in [0,1] and the reasons matched."""
    norm = normalize(text).lower()
    score = 0.0
    matched: list[str] = []
    for pattern, weight, label in _INJECTION_PATTERNS:
        if re.search(pattern, norm):
            score = max(score, weight)
            matched.append(label)
    return InjectionHeuristic(score=round(score, 2), matched=matched)
