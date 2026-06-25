"""Pluggable PII analyzer interface for the DLP engine.

Defines a provider-agnostic ``PIIAnalyzer`` protocol returning ``PIISpan``s. Two
implementations ship:

* ``RegexPIIAnalyzer`` — always available, reuses the DLP detectors (no deps).
* ``PresidioPIIAnalyzer`` — optional, ML/NLP-backed via Microsoft Presidio,
  catching context-dependent PII (names, locations) that regex misses.

``DLPEngine`` accepts any analyzer, so you can upgrade detection without changing
call sites:

    from airte.data_pipeline import DLPEngine
    from airte.data_pipeline.pii_presidio import get_analyzer
    eng = DLPEngine(analyzer=get_analyzer("auto"))   # presidio if installed, else regex
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol, runtime_checkable

from .dlp import _DETECTORS, _luhn_ok, Classification


@dataclass(frozen=True)
class PIISpan:
    label: str
    start: int
    end: int
    classification: Classification
    score: float = 1.0


@runtime_checkable
class PIIAnalyzer(Protocol):
    def analyze(self, text: str) -> list[PIISpan]: ...


class RegexPIIAnalyzer:
    """Default analyzer: the high-precision regex detectors from dlp.py."""
    def analyze(self, text: str) -> list[PIISpan]:
        spans: list[PIISpan] = []
        for label, pat, cls in _DETECTORS:
            for m in pat.finditer(text):
                if label == "credit_card" and not _luhn_ok(m.group()):
                    continue
                spans.append(PIISpan(label, m.start(), m.end(), cls))
        return spans


# Map Presidio entity types -> our labels + classification.
_PRESIDIO_MAP = {
    "US_SSN": ("us_ssn", Classification.RESTRICTED),
    "CREDIT_CARD": ("credit_card", Classification.RESTRICTED),
    "EMAIL_ADDRESS": ("email", Classification.CONFIDENTIAL),
    "PHONE_NUMBER": ("phone", Classification.CONFIDENTIAL),
    "IP_ADDRESS": ("ipv4", Classification.INTERNAL),
    "PERSON": ("person", Classification.CONFIDENTIAL),
    "LOCATION": ("location", Classification.INTERNAL),
    "US_PASSPORT": ("passport", Classification.RESTRICTED),
    "IBAN_CODE": ("iban", Classification.RESTRICTED),
}


class PresidioPIIAnalyzer:  # pragma: no cover - requires presidio-analyzer
    """ML/NLP-backed analyzer using Microsoft Presidio."""
    def __init__(self, language: str = "en", score_threshold: float = 0.5):
        from presidio_analyzer import AnalyzerEngine
        self._engine = AnalyzerEngine()
        self._language = language
        self._threshold = score_threshold

    def analyze(self, text: str) -> list[PIISpan]:
        results = self._engine.analyze(text=text, language=self._language)
        spans: list[PIISpan] = []
        for r in results:
            if r.score < self._threshold:
                continue
            label, cls = _PRESIDIO_MAP.get(
                r.entity_type, (r.entity_type.lower(), Classification.CONFIDENTIAL))
            spans.append(PIISpan(label, r.start, r.end, cls, r.score))
        return spans


def get_analyzer(kind: str = "auto") -> PIIAnalyzer:
    """Return a PII analyzer. kind: 'regex' | 'presidio' | 'auto'."""
    kind = kind.lower()
    if kind == "regex":
        return RegexPIIAnalyzer()
    if kind == "presidio":
        return PresidioPIIAnalyzer()
    if kind == "auto":
        try:
            return PresidioPIIAnalyzer()
        except Exception:
            return RegexPIIAnalyzer()
    raise ValueError(f"unknown analyzer kind '{kind}'")
