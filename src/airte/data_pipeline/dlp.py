"""Data Loss Prevention controls for AI data pipelines.

Detects and classifies sensitive data BEFORE it enters a prompt, a RAG index,
or a fine-tuning set, and BEFORE model output leaves the trust boundary. This is
the enforcement point for the confidentiality boundaries described in
docs/secure-data-pipelines.md.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from enum import IntEnum


class Classification(IntEnum):
    PUBLIC = 0
    INTERNAL = 1
    CONFIDENTIAL = 2
    RESTRICTED = 3

    def __str__(self) -> str:
        return self.name


# (label, regex, classification)
_DETECTORS = [
    ("us_ssn", re.compile(r"\b\d{3}-\d{2}-\d{4}\b"), Classification.RESTRICTED),
    ("credit_card", re.compile(r"\b(?:\d[ -]*?){13,16}\b"), Classification.RESTRICTED),
    ("email", re.compile(r"\b[\w.+-]+@[\w-]+\.[\w.-]+\b"), Classification.CONFIDENTIAL),
    ("phone", re.compile(r"\b\+?\d[\d ().-]{8,}\d\b"), Classification.CONFIDENTIAL),
    ("ipv4", re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b"), Classification.INTERNAL),
    ("aws_key", re.compile(r"\bAKIA[0-9A-Z]{16}\b"), Classification.RESTRICTED),
    ("api_key", re.compile(r"\bsk-[A-Za-z0-9-]{16,}\b"), Classification.RESTRICTED),
]


def _luhn_ok(number: str) -> bool:
    digits = [int(c) for c in re.sub(r"\D", "", number)]
    if not 13 <= len(digits) <= 19:
        return False
    checksum, parity = 0, len(digits) % 2
    for i, d in enumerate(digits):
        if i % 2 == parity:
            d *= 2
            if d > 9:
                d -= 9
        checksum += d
    return checksum % 10 == 0


@dataclass
class DLPFinding:
    label: str
    classification: str
    start: int
    end: int
    excerpt: str


@dataclass
class DLPEngine:
    redaction: str = "[REDACTED:{label}]"
    findings: list[DLPFinding] = field(default_factory=list)
    # optional pluggable analyzer (e.g. Presidio); None => built-in regex detectors
    analyzer: object | None = None

    def scan(self, text: str) -> list[DLPFinding]:
        if self.analyzer is not None:
            self.findings = [
                DLPFinding(sp.label, str(sp.classification), sp.start, sp.end,
                           text[sp.start:sp.start + 4] + "…")
                for sp in self.analyzer.analyze(text)]
            return self.findings
        out: list[DLPFinding] = []
        for label, pat, cls in _DETECTORS:
            for m in pat.finditer(text):
                if label == "credit_card" and not _luhn_ok(m.group()):
                    continue            # reduce false positives
                out.append(DLPFinding(label, str(cls), m.start(), m.end(),
                                      m.group()[:4] + "…"))
        self.findings = out
        return out

    def max_classification(self, text: str) -> Classification:
        found = self.scan(text)
        if not found:
            return Classification.PUBLIC
        return max(Classification[f.classification] for f in found)

    def redact(self, text: str) -> str:
        """Return text with all detected sensitive spans redacted."""
        spans = sorted(self.scan(text), key=lambda f: f.start, reverse=True)
        out = text
        for f in spans:
            out = out[:f.start] + self.redaction.format(label=f.label) + out[f.end:]
        return out


def scan_text(text: str) -> list[DLPFinding]:
    return DLPEngine().scan(text)
