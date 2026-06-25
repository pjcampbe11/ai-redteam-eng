"""Token and cost budgets — the application-layer control against unbounded
consumption / denial-of-wallet (OWASP LLM10).

Track tokens and spend per principal over a rolling window and hard-stop when a
cap is reached, before a request is sent to the (paid) model.
"""
from __future__ import annotations

import time
from dataclasses import dataclass, field


class BudgetExceeded(Exception):
    pass


@dataclass
class CostTracker:
    """Per-principal token + spend caps over a rolling time window."""
    max_tokens_per_window: int = 100_000
    max_usd_per_window: float = 5.0
    window_seconds: int = 3600
    # price per 1K tokens (input+output blended) for cost estimation
    usd_per_1k_tokens: float = 0.01
    _events: dict[str, list[tuple[float, int, float]]] = field(default_factory=dict)

    def _prune(self, subject: str) -> list[tuple[float, int, float]]:
        now = time.time()
        kept = [e for e in self._events.get(subject, [])
                if now - e[0] < self.window_seconds]
        self._events[subject] = kept
        return kept

    def estimate_cost(self, tokens: int) -> float:
        return round(tokens / 1000 * self.usd_per_1k_tokens, 6)

    def check_and_record(self, subject: str, tokens: int) -> None:
        """Raise BudgetExceeded if this request would breach a cap; else record."""
        events = self._prune(subject)
        used_tokens = sum(e[1] for e in events)
        used_usd = sum(e[2] for e in events)
        cost = self.estimate_cost(tokens)
        if used_tokens + tokens > self.max_tokens_per_window:
            raise BudgetExceeded(
                f"{subject}: token budget exceeded "
                f"({used_tokens}+{tokens} > {self.max_tokens_per_window})")
        if used_usd + cost > self.max_usd_per_window:
            raise BudgetExceeded(
                f"{subject}: spend budget exceeded "
                f"(${used_usd + cost:.2f} > ${self.max_usd_per_window:.2f})")
        events.append((time.time(), tokens, cost))

    def usage(self, subject: str) -> dict[str, float]:
        events = self._prune(subject)
        return {"tokens": sum(e[1] for e in events),
                "usd": round(sum(e[2] for e in events), 4),
                "requests": len(events)}
